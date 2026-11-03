from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message as MailMessage
import json
from pywebpush import webpush, WebPushException
import re
import qrcode
import os
import uuid
import time
import threading
import secrets
import hmac
import tempfile
from collections import defaultdict, deque
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from cryptography.hazmat.primitives import serialization

TAGVEE_BUILD = "SQA-HARDENING-PASS-2026-09-25"
# from gsm_gateway import make_call

app = Flask(__name__)

# Secret Key (will be used later for login sessions)
secret_key = os.getenv("TAGVEE_SECRET_KEY")
if not secret_key:
    raise RuntimeError("TAGVEE_SECRET_KEY environment variable is not set.")
app.config["SECRET_KEY"] = secret_key

# Session hardening: keep the owner logged in across tab closes/browser restarts
# while still protecting the cookie from JavaScript and cross-site requests.
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 7 * 24 * 60 * 60
app.config["SESSION_COOKIE_HTTPONLY"] = True
# Cookies are secure on the public HTTPS deployment; local HTTP remains testable.
app.config["SESSION_COOKIE_SECURE"] = os.getenv("TAGVEE_COOKIE_SECURE", "").lower() == "true"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Public URL: set TAGVEE_PUBLIC_BASE_URL to the deployed HTTPS URL.
app.config["PUBLIC_BASE_URL"] = os.getenv("TAGVEE_PUBLIC_BASE_URL", "").strip().rstrip("/")
if "TAGVEE_COOKIE_SECURE" not in os.environ:
    app.config["SESSION_COOKIE_SECURE"] = app.config["PUBLIC_BASE_URL"].startswith("https://")

# Managed PostgreSQL in production; local SQLite fallback for development.
database_url = os.getenv("DATABASE_URL", "sqlite:///smart_vehicle.db").strip()
if database_url.startswith("postgres://"):
    database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
elif database_url.startswith("postgresql://"):
    # requirements.txt installs psycopg v3, so explicitly select that SQLAlchemy driver.
    database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

# Email API (Resend) is preferred on cloud hosts that block SMTP ports.
app.config["RESEND_API_KEY"] = os.getenv("TAGVEE_RESEND_API_KEY", "").strip()
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("TAGVEE_MAIL_FROM", "tagveeofficial@gmail.com").strip()
# Optional SMTP fallback for local/other hosting providers.
app.config["MAIL_SERVER"] = os.getenv("TAGVEE_MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("TAGVEE_MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.getenv("TAGVEE_MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("TAGVEE_MAIL_USERNAME", "tagveeofficial@gmail.com")
app.config["MAIL_PASSWORD"] = os.getenv("TAGVEE_MAIL_PASSWORD", "")

# Initialize Database
db = SQLAlchemy(app)
# Email setup
mail = Mail(app)

# WEBRTC CALL STORAGE Prototype only

webrtc_calls = {}

# Keep temporary WebRTC signaling data from growing forever.
CALL_RING_TIMEOUT = 5 * 60
CALL_HISTORY_TIMEOUT = 10 * 60

# PUBLIC ALERT RATE LIMITING
# Prevent repeated Quick Alert requests from spamming an owner
# and repeatedly triggering database writes + email notifications.
ALERT_COOLDOWN = 30
ALERT_WINDOW = 10 * 60
ALERT_MAX_PER_WINDOW = 5
alert_attempts = defaultdict(deque)

def alert_rate_limited(client_key):
    """Return True when this client has exceeded the public alert limit."""
    now = time.time()
    attempts = alert_attempts[client_key]

    # Remove attempts outside the rolling time window.
    while attempts and now - attempts[0] > ALERT_WINDOW:
        attempts.popleft()

    # Block repeated taps immediately, then enforce the rolling limit.
    if attempts and now - attempts[-1] < ALERT_COOLDOWN:
        return True

    if len(attempts) >= ALERT_MAX_PER_WINDOW:
        return True

    attempts.append(now)
    return False

def cleanup_expired_calls():
    """Expire stale ringing calls and remove old finished calls."""
    now = time.time()
    expired_ids = []

    for call_id, call in list(webrtc_calls.items()):
        created_at = call.get("created_at", now)
        age = now - created_at
        status = call.get("status")

        if status == "ringing" and age > CALL_RING_TIMEOUT:
            call["status"] = "expired"
            call["ended_at"] = now

        elif status in {"ended", "rejected", "superseded", "expired"} and age > CALL_HISTORY_TIMEOUT:
            expired_ids.append(call_id)

    for call_id in expired_ids:
        webrtc_calls.pop(call_id, None)


# USER TABLE

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    phone = db.Column(
        db.String(20),
        nullable=False
    )

    vehicle_number = db.Column(
        db.String(50),
        nullable=False
    )

    vehicle_type = db.Column(
        db.String(50)
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )


# PUSH SUBSCRIPTION TABLE

class PushSubscription(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )

    endpoint = db.Column(
        db.Text,
        nullable=False,
        unique=True
    )

    p256dh = db.Column(
        db.String(255),
        nullable=False
    )

    auth = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

# Admin Table
class Admin(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

#Emergencycontact Table
class EmergencyContact(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )

    contact_name = db.Column(
        db.String(100),
        nullable=False
    )

    relationship = db.Column(
        db.String(50),
        nullable=False
    )

    phone = db.Column(
        db.String(20),
        nullable=False
    )

    # Email is the actual delivery channel for emergency-contact alerts.
    # The legacy phone column is retained for existing SQLite databases.
    email = db.Column(
        db.String(255),
        nullable=False
    )


# MSG TABLE
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, nullable=False)

    alert_type = db.Column(db.String(150), nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )


    # SCAN LOG TABLE 
class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, nullable=False)

    scan_time = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )


#  EMAIL FUNCTION

def send_email_notification(receiver_email, owner_name, alert_text):
    """Send notification through Resend HTTPS API, or configured SMTP fallback."""
    public_base_url = app.config.get("PUBLIC_BASE_URL", "").rstrip("/")
    login_url = f"{public_base_url}/login" if public_base_url else "the TAGVEE login page"
    body = f"""Hello {owner_name},

Someone has interacted with your TAGVEE QR code.

Alert:
{alert_text}

Please log in to TAGVEE to view details.

Login:
{login_url}

Thank you,
TAGVEE Team
"""
    api_key = app.config.get("RESEND_API_KEY", "")
    if api_key:
        payload = json.dumps({
            "from": app.config.get("MAIL_DEFAULT_SENDER", ""),
            "to": [receiver_email],
            "subject": "TAGVEE Vehicle Alert Notification",
            "text": body,
        }).encode("utf-8")
        req = Request(
            "https://api.resend.com/emails", data=payload,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "User-Agent": "TAGVEE"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=12) as response:
                return 200 <= response.status < 300
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            print("Email API notification failed; trying SMTP fallback:", error)

    if not app.config.get("MAIL_USERNAME") or not app.config.get("MAIL_PASSWORD"):
        print("Email not configured: set TAGVEE_RESEND_API_KEY and TAGVEE_MAIL_FROM.")
        return False
    msg = MailMessage(
        subject="TAGVEE Vehicle Alert Notification",
        sender=app.config["MAIL_DEFAULT_SENDER"],
        recipients=[receiver_email], body=body,
    )
    try:
        mail.send(msg)
        return True
    except Exception as error:
        print("Email notification failed:", error)
        return False


# CONTROLLED ERROR HANDLING
def _api_error(message, status_code):
    """Return JSON for API requests and safe HTML for normal pages."""
    if request.path.startswith("/api/"):
        return {"error": message}, status_code
    return f"<h2>{status_code} - {message}</h2>", status_code


@app.errorhandler(400)
def handle_bad_request(error):
    return _api_error("Bad request.", 400)


@app.errorhandler(403)
def handle_forbidden(error):
    return _api_error("Access denied.", 403)


@app.errorhandler(404)
def handle_not_found(error):
    return _api_error("Page or resource not found.", 404)


@app.errorhandler(405)
def handle_method_not_allowed(error):
    return _api_error("Method not allowed.", 405)


@app.errorhandler(429)
def handle_rate_limit(error):
    return _api_error("Too many requests. Please try again later.", 429)


@app.errorhandler(500)
def handle_internal_error(error):
    db.session.rollback()
    print("Internal server error:", error)
    return _api_error("Something went wrong. Please try again.", 500)


# HOME PAGE Route

# HOME PAGE Route
@app.route("/")
def home():
    return render_template("home.html")



# REGISTER PAGE
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        # Get Form Data
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        vehicle_number = request.form.get("vehicle_number", "").strip()
        vehicle_type = request.form.get("vehicle_type", "").strip()
        password = request.form.get("password", "")


        # VALIDATIONS

        # Name Validation
        if not name or len(name) > 100 or not re.fullmatch(r"[A-Za-z ]+", name):
            return "Name should contain only letters and spaces."

        # Email Validation
        if not email or len(email) > 120 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            return "Please enter a valid email address."

        # Phone Validation
        if not re.fullmatch(r"03\d{9}", phone):
            return "Phone number must start with 03 and contain 11 digits."

        # Vehicle Number Validation
        if not vehicle_number or len(vehicle_number) > 50 or not re.fullmatch(r"[A-Za-z0-9\- ]+", vehicle_number):
            return "Invalid vehicle number."

        # Vehicle Type Validation
        if not vehicle_type or len(vehicle_type) > 50 or not re.fullmatch(r"[A-Za-z0-9\- ]+", vehicle_type):
            return "Invalid vehicle type."

        # Password Validation
        if len(password) < 8:
            return "Password must be at least 8 characters long."

        # Duplicate Email Check
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return "Email already registered."

        # Hash Password
        hashed_password = generate_password_hash(password)

        # Create User Object
        user = User(
            name=name,
            email=email,
            phone=phone,
            vehicle_number=vehicle_number,
            vehicle_type=vehicle_type,
            password=hashed_password
        )

        # Save User
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")

#login route
@app.route("/login", methods=["GET", "POST"])
def login():

    # Preserve the page the user was trying to reach (especially /call-center)
    # when a push notification opens the site while the owner is logged out.
    if request.method == "GET":
        next_url = request.args.get("next", "")
        if next_url.startswith("/") and not next_url.startswith("//"):
            session["login_next"] = next_url
        else:
            session.pop("login_next", None)

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            session.clear()
            session.permanent = True
            session["user_id"] = user.id

            next_url = session.pop("login_next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)

            return redirect(url_for("dashboard"))

        return "Invalid Email or Password"

    return render_template("login.html")


# dashboard route
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])

    # QR path check
    qr_path = os.path.join(
        "static",
        "qr_codes",
        f"user_{user.id}.png"
    )

    qr_exists = os.path.exists(qr_path)

    # NEW ANALYTICS 

    total_scans = ScanLog.query.filter_by(user_id=user.id).count()

    total_alerts = Message.query.filter_by(user_id=user.id).count()

    recent_scans = ScanLog.query.filter_by(
        user_id=user.id
    ).order_by(
        ScanLog.scan_time.desc()
    ).limit(5).all()

    recent_alerts = Message.query.filter_by(
        user_id=user.id
    ).order_by(
        Message.created_at.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        user=user,
        qr_exists=qr_exists,

        # NEW DATA
        total_scans=total_scans,
        total_alerts=total_alerts,
        recent_scans=recent_scans,
        recent_alerts=recent_alerts
    )


# Edit Profile Route
@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        vehicle_number = request.form.get("vehicle_number", "").strip()
        vehicle_type = request.form.get("vehicle_type", "").strip()

        if not name or len(name) > 100 or not re.fullmatch(r"[A-Za-z ]+", name):
            return "Name should contain only letters and spaces."
        if not email or len(email) > 120 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            return "Please enter a valid email address."
        if not re.fullmatch(r"03\d{9}", phone):
            return "Phone number must start with 03 and contain 11 digits."
        if not vehicle_number or len(vehicle_number) > 50 or not re.fullmatch(r"[A-Za-z0-9\- ]+", vehicle_number):
            return "Invalid vehicle number."
        if not vehicle_type or len(vehicle_type) > 50 or not re.fullmatch(r"[A-Za-z0-9\- ]+", vehicle_type):
            return "Invalid vehicle type."

        duplicate = User.query.filter(User.email == email, User.id != user.id).first()
        if duplicate:
            return "Email already registered."

        user.name = name
        user.email = email
        user.phone = phone
        user.vehicle_number = vehicle_number
        user.vehicle_type = vehicle_type

        db.session.commit()

        return redirect(url_for("dashboard"))

    return render_template(
        "edit_profile.html",
        user=user
    )

#add contact route
@app.route("/add-contact", methods=["GET", "POST"])
def add_contact():

    if "user_id" not in session:
        return redirect(url_for("login"))

    existing_contact = EmergencyContact.query.filter_by(
        user_id=session["user_id"]
    ).first()

    if request.method == "POST":

        contact_name = request.form.get("contact_name", "").strip()
        relationship = request.form.get("relationship", "").strip()
        email = request.form.get("email", "").strip().lower()

        if (
            not contact_name
            or len(contact_name) > 100
            or not re.fullmatch(r"[A-Za-z ]+", contact_name)
        ):
            return "Contact name can contain letters only"

        if (
            not relationship
            or len(relationship) > 50
            or not re.fullmatch(r"[A-Za-z ]+", relationship)
        ):
            return "Relationship can contain letters only"

        if (
            not email
            or len(email) > 255
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        ):
            return "Please enter a valid email address"

        if existing_contact:
            existing_contact.contact_name = contact_name
            existing_contact.relationship = relationship
            existing_contact.phone = ""  # legacy field; no longer used
            existing_contact.email = email
        else:
            new_contact = EmergencyContact(
                user_id=session["user_id"],
                contact_name=contact_name,
                relationship=relationship,
                phone="",  # legacy field; no longer used
                email=email
            )
            db.session.add(new_contact)

        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template(
        "emergency_contact.html",
        contact=existing_contact
    )


# delete emergency contact 
@app.route("/delete-contact", methods=["POST"])
def delete_contact():


    if "user_id" not in session:
        return redirect(url_for("login"))

    contact = EmergencyContact.query.filter_by(
        user_id=session["user_id"]
    ).first()

    print(contact)

    if contact:
        db.session.delete(contact)
        db.session.commit()

    return redirect(url_for("dashboard"))


#QR Code route
@app.route("/generate-qr")
def generate_qr():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Prefer the configured public URL. If it is not configured, derive the
    # current origin from the page used to generate the QR. This prevents a
    # QR generated from the public Cloudflare dashboard from accidentally
    # embedding the old LAN address.
    public_base_url = os.getenv("TAGVEE_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not public_base_url:
        public_base_url = request.host_url.rstrip("/")

    qr_data = f"{public_base_url}/user/{user_id}"

    qr = qrcode.make(qr_data)

    file_path = os.path.join(
        "static",
        "qr_codes",
        f"user_{user_id}.png"
    )

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    qr.save(file_path)

    return redirect(url_for("dashboard"))

#public_profile route
@app.route("/user/<int:user_id>")
def public_profile(user_id):

    user = User.query.get_or_404(user_id)
    contact = EmergencyContact.query.filter_by(user_id=user_id).first()

    # Pass only public-safe emergency-contact details to the public page.
    public_contact = None
    if contact:
        public_contact = {
            "contact_name": contact.contact_name,
            "relationship": contact.relationship
        }

    # Save QR scan to database
    new_scan = ScanLog(
        user_id=user_id
    )

    db.session.add(new_scan)
    db.session.commit()

    # SECURITY: expose only the public identifier to the public template.
    # Private fields such as phone, email, and password hash are not passed to it.
    public_user = {"id": user.id}

    return render_template(
    "public_profile.html",
    user=public_user,
    contact=public_contact,
    success=request.args.get("success"),
    saved=request.args.get("saved")
    )


# VAPID KEY HANDLING
def _prepare_vapid_private_key():
    """
    Return (key_path, should_delete).
    pywebpush expects a PEM file path here, not a cryptography key object.
    """
    pem_text = os.getenv("TAGVEE_VAPID_PRIVATE_KEY", "").strip()

    if pem_text:
        # Support both real line breaks and literal \\n in environment values.
        pem_text = pem_text.replace("\\n", "\n")
        try:
            private_key = serialization.load_pem_private_key(
                pem_text.encode("utf-8"),
                password=None
            )
            # py_vapid expects an EC private key in traditional SEC1 PEM form.
            # Normalize PKCS#8 or other valid PEM wrappers to that exact format.
            from cryptography.hazmat.primitives.asymmetric import ec
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                app.logger.error("VAPID key must be an elliptic-curve private key.")
                return None, False
            if not isinstance(private_key.curve, ec.SECP256R1):
                app.logger.error("VAPID key must use the P-256 (secp256r1) curve.")
                return None, False
            normalized_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode("utf-8")
        except (ValueError, TypeError):
            app.logger.exception(
                "VAPID private key is invalid. Check the deployment secret format."
            )
            return None, False

        temp_file = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".pem", delete=False
        )
        try:
            temp_file.write(normalized_pem)
            temp_file.flush()
        finally:
            temp_file.close()
        return temp_file.name, True

    key_path = os.getenv("TAGVEE_VAPID_PRIVATE_KEY_PATH", "private_key.pem")
    if not os.path.isfile(key_path):
        return None, False
    return key_path, False


def _cleanup_temporary_vapid_key(key_path, should_delete):
    if should_delete and key_path:
        try:
            os.remove(key_path)
        except OSError:
            app.logger.warning("Could not remove temporary VAPID key file.")


# SEND PUSH NOTIFICATION
def send_push_notification_to_user(
    user_id,
    title,
    body,
    url="/dashboard"
):
    subscriptions = PushSubscription.query.filter_by(
        user_id=user_id
    ).all()

    if not subscriptions:
        app.logger.info(
            "No push subscriptions found for user %s",
            user_id
        )
        return 0

    vapid_key_path, delete_vapid_key = _prepare_vapid_private_key()
    if not vapid_key_path:
        app.logger.warning(
            "Push skipped: VAPID private key is not configured."
        )
        return 0

    payload = json.dumps({
        "title": title,
        "body": body,
        "url": url
    })

    sent_count = 0

    for subscription in subscriptions:
        subscription_info = {
            "endpoint": subscription.endpoint,
            "keys": {
                "p256dh": subscription.p256dh,
                "auth": subscription.auth
            }
        }

        try:
            webpush(
                subscription_info=subscription_info,
                data=payload,
                vapid_private_key=vapid_key_path,
                vapid_claims={
                    "sub": os.getenv(
                        "TAGVEE_VAPID_SUBJECT",
                        "mailto:tagveeofficial@gmail.com"
                    )
                }
            )

            sent_count += 1

            app.logger.info(
                "Push notification sent for subscription %s",
                subscription.id
            )

        except WebPushException as error:
            app.logger.warning(
                "Web Push Error for subscription %s: %s",
                subscription.id,
                error
            )

            if "410" in str(error) or "404" in str(error):
                db.session.delete(subscription)

        except Exception:
            app.logger.exception(
                "Unexpected push error for subscription %s",
                subscription.id
            )

    db.session.commit()
    _cleanup_temporary_vapid_key(vapid_key_path, delete_vapid_key)

    return sent_count



# WEBRTC SIGNALING routes
@app.route("/api/call/start/<int:user_id>", methods=["POST"])
def start_call(user_id):
    """Create a new WebRTC call and notify the vehicle owner."""

    cleanup_expired_calls()

    if not db.session.get(User, user_id):
        return {"error": "User not found"}, 404

    data = request.get_json(silent=True)
    if not data or "offer" not in data:
        return {"error": "Offer is required"}, 400

    # A new call replaces an older unanswered/ringing call for the same owner.
    # This prevents stale calls from blocking the caller with HTTP 409.
    now = time.time()
    for existing_call in webrtc_calls.values():
        if (
            existing_call.get("owner_id") == user_id
            and existing_call.get("status") == "ringing"
        ):
            existing_call["status"] = "superseded"
            existing_call["ended_at"] = now

    call_id = str(uuid.uuid4())
    caller_token = secrets.token_urlsafe(32)

    webrtc_calls[call_id] = {
        "caller_id": None,
        "caller_token": caller_token,
        "owner_id": user_id,
        "offer": data["offer"],
        "answer": None,
        "caller_candidates": [],
        "owner_candidates": [],
        "status": "ringing",
        "created_at": now
    }

    def send_call_push():
        with app.app_context():
            send_push_notification_to_user(
                user_id=user_id,
                title="📞 Incoming TAGVEE Call",
                body="Someone wants to speak with you about your vehicle.",
                url="/call-center"
            )

    threading.Thread(target=send_call_push, daemon=True).start()

    return {"success": True, "call_id": call_id, "caller_token": caller_token}


def _call_token_from_request():
    token = request.headers.get("X-Call-Token")
    if token:
        return token

    data = request.get_json(silent=True) or {}
    return data.get("caller_token")


def _caller_can_access(call):
    token = _call_token_from_request()
    stored = call.get("caller_token")
    return bool(token and stored and hmac.compare_digest(str(token), str(stored)))


def _owner_can_access(call):
    return session.get("user_id") == call.get("owner_id")


def _call_access_allowed(call, allow_caller=True, allow_owner=True):
    if allow_owner and _owner_can_access(call):
        return True
    if allow_caller and _caller_can_access(call):
        return True
    return False


@app.route("/api/call/<call_id>", methods=["GET"])
def get_call(call_id):
    cleanup_expired_calls()
    call = webrtc_calls.get(call_id)

    if not call:
        return {"error": "Call not found"}, 404

    if not _call_access_allowed(call):
        return {"error": "Unauthorized"}, 403

    return {
        "call_id": call_id,
        "offer": call["offer"],
        "answer": call["answer"],
        "caller_candidates": call["caller_candidates"],
        "owner_candidates": call["owner_candidates"],
        "status": call["status"]
    }

@app.route("/api/call/<call_id>/answer", methods=["POST"])
def submit_answer(call_id):

    cleanup_expired_calls()
    call = webrtc_calls.get(call_id)

    if not call:
        return {"error": "Call not found"}, 404

    if not _owner_can_access(call):
        return {"error": "Unauthorized"}, 403

    data = request.get_json(silent=True)

    if not data or "answer" not in data:
        return {"error": "Answer is required"}, 400

    call["answer"] = data["answer"]
    call["status"] = "accepted"

    return {
        "success": True
    }


@app.route("/api/call/<call_id>/candidate/<side>", methods=["POST"])
def add_candidate(call_id, side):

    cleanup_expired_calls()
    call = webrtc_calls.get(call_id)

    if not call:
        return {"error": "Call not found"}, 404

    if side not in ["caller", "owner"]:
        return {"error": "Invalid side"}, 400

    if side == "caller" and not _caller_can_access(call):
        return {"error": "Unauthorized"}, 403

    if side == "owner" and not _owner_can_access(call):
        return {"error": "Unauthorized"}, 403

    data = request.get_json(silent=True)

    if not data or "candidate" not in data:
        return {"error": "Candidate is required"}, 400

    if side == "caller":
        call["caller_candidates"].append(data["candidate"])

    else:
        call["owner_candidates"].append(data["candidate"])

    return {
        "success": True
    }


@app.route("/api/call/<call_id>/reject", methods=["POST"])
def reject_call(call_id):

    cleanup_expired_calls()
    call = webrtc_calls.get(call_id)

    if not call:
        return {
            "error": "Call not found"
        }, 404

    if not _owner_can_access(call):
        return {"error": "Unauthorized"}, 403

    call["status"] = "rejected"

    return {
        "success": True
    }


@app.route("/api/call/<call_id>/end", methods=["POST"])
def end_call(call_id):

    cleanup_expired_calls()
    call = webrtc_calls.get(call_id)

    if not call:
        return {
            "error": "Call not found"
        }, 404

    if not _call_access_allowed(call):
        return {"error": "Unauthorized"}, 403

    call["status"] = "ended"

    return {
        "success": True
    }


# OWNER CALL CENTER

@app.route("/call-center")
def call_center():

    if "user_id" not in session:
        return redirect(url_for("login", next="/call-center"))

    return render_template(
        "call_center.html",
        turn_username=os.getenv("TAGVEE_TURN_USERNAME", ""),
        turn_credential=os.getenv("TAGVEE_TURN_CREDENTIAL", "")
    )

#pending call route
@app.route("/api/owner/pending-call")
def pending_call():

    cleanup_expired_calls()

    if "user_id" not in session:
        return {"error": "Not logged in"}, 401

    owner_id = session["user_id"]

    for call_id, call in webrtc_calls.items():

        if (
            call["owner_id"] == owner_id
            and call["status"] == "ringing"
        ):

            return {
                "call_id": call_id
            }

    return {}

# PUSH NOTIFICATION SUBSCRIPTION
@app.route("/api/push/subscribe", methods=["POST"])
def subscribe_push():

    if "user_id" not in session:
        return {
            "error": "Not logged in"
        }, 401

    data = request.get_json()

    if not data:
        return {
            "error": "Subscription data required"
        }, 400

    endpoint = data.get("endpoint")
    keys = data.get("keys", {})

    p256dh = keys.get("p256dh")
    auth = keys.get("auth")

    if not endpoint or not p256dh or not auth:
        return {
            "error": "Invalid push subscription"
        }, 400

    existing_subscription = PushSubscription.query.filter_by(
        endpoint=endpoint
    ).first()

    if existing_subscription:

        existing_subscription.user_id = session["user_id"]
        existing_subscription.p256dh = p256dh
        existing_subscription.auth = auth

    else:

        new_subscription = PushSubscription(
            user_id=session["user_id"],
            endpoint=endpoint,
            p256dh=p256dh,
            auth=auth
        )

        db.session.add(new_subscription)

    db.session.commit()

    return {
        "success": True,
        "message": "Push subscription saved"
    }


# TEST PUSH NOTIFICATION
@app.route("/api/push/test", methods=["POST"])
def test_push_notification():

    if "user_id" not in session:
        return {"error": "Not logged in"}, 401

    subscriptions = PushSubscription.query.filter_by(
        user_id=session["user_id"]
    ).all()

    if not subscriptions:
        return {"error": "No push subscription found"}, 404

    vapid_key_path, delete_vapid_key = _prepare_vapid_private_key()
    if not vapid_key_path:
        return {
            "error": "Push notifications are not configured on this deployment."
        }, 503

    payload = json.dumps({
        "title": "TAGVEE Test",
        "body": "Push notifications are working!",
        "url": "/dashboard"
    })

    sent_count = 0

    for subscription in subscriptions:
        subscription_info = {
            "endpoint": subscription.endpoint,
            "keys": {
                "p256dh": subscription.p256dh,
                "auth": subscription.auth
            }
        }

        try:
            webpush(
                subscription_info=subscription_info,
                data=payload,
                vapid_private_key=vapid_key_path,
                vapid_claims={
                    "sub": os.getenv(
                        "TAGVEE_VAPID_SUBJECT",
                        "mailto:tagveeofficial@gmail.com"
                    )
                }
            )

            sent_count += 1

        except WebPushException as error:
            print(
                "Web Push Error for subscription:",
                subscription.id,
                error
            )

            if "410" in str(error) or "404" in str(error):
                db.session.delete(subscription)

        except Exception as error:
            app.logger.exception(
                "Unexpected push error for subscription %s",
                subscription.id
            )

    db.session.commit()
    _cleanup_temporary_vapid_key(vapid_key_path, delete_vapid_key)

    if sent_count > 0:
        return {
            "success": True,
            "message": "Test notification sent"
        }, 200

    return {
        "error": "The push notification could not be delivered. Check the server logs."
    }, 500

# CALL OWNER ROUTE - start the privacy-preserving WebRTC caller interface.
@app.route("/call-owner/<int:user_id>")
def call_owner(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return "Vehicle owner not found.", 404

    # Pass only the public ID. The owner's private phone number is never sent
    # to the visitor; the call is handled by the existing WebRTC endpoints.
    return render_template("call_owner.html", user={"id": user.id})


# CALL OWNER ROUTE - GSM GATEWAY
#@app.route("/call-owner/<int:user_id>")
#def call_owner(user_id):

    # find the vehicle owner
    user = User.query.get_or_404(user_id)

    # owner's private phone number
    phone_number = user.phone

    # ask the connected Android phone
    # to make the cellular call
    success = make_call(phone_number)

    #result to the person who scanned the QR
    if success:
        return f"""
        <div style="text-align:center; margin-top:80px; font-family:Arial;">

            <h2>📞 Calling Vehicle Owner...</h2>

            <p>
                The call has been initiated.
            </p>

            <a href="/user/{user.id}">
                ← Back to Vehicle Assistance
            </a>

        </div>
        """

    else:

        return f"""
        <div style="text-align:center; margin-top:80px; font-family:Arial;">

            <h2>⚠️ Unable to Start Call</h2>

            <p>
                The call could not be initiated.
                Please try again.
            </p>

            <a href="/user/{user.id}">
                ← Back to Vehicle Assistance
            </a>

        </div>
        """, 500

#call owner route
#@app.route("/call-owner/<int:user_id>")
#def call_owner(user_id):

    user = User.query.get_or_404(user_id)

    return f"""
    <script>
        window.location.href = "tel:{user.phone}";
    </script>

    <h2>📞 Calling Vehicle Owner...</h2>
    <p>If the call does not start automatically, your device may not support web calling.</p>

    <a href="/user/{user.id}">Go Back</a>
   """
#<a href="/call-owner/{{ user.id }}" class="public-btn btn-primary">

#msg sender route
#@app.route("/send-message/<int:user_id>", methods=["GET", "POST"])
#def send_message(user_id):

 #   user = User.query.get_or_404(user_id)

#    if request.method == "POST":

 #       sender_name = request.form["sender_name"]
  #      sender_phone = request.form["sender_phone"]
   #     message_text = request.form["message"]

      #  new_message = Message(
       #     user_id=user.id,
        #    sender_name=sender_name,
         #   sender_phone=sender_phone,
          #  message=message_text
        #)

     #   db.session.add(new_message)
    #    db.session.commit()

   #     return "Message Sent Successfully!"

  #  return render_template("send_message.html") """

# Only these alert messages are offered by the public vehicle profile.
QUICK_ALERTS = {
    "Please move your vehicle",
    "Vehicle is blocking the road",
    "Vehicle lights are on",
    "Possible accident",
    "Vehicle appears unsafe",
}

# msg alert route
@app.route("/send-alert/<int:user_id>/<path:alert_type>", methods=["POST"])
def send_alert(user_id, alert_type):

    if alert_type not in QUICK_ALERTS:
        return "<h2>Invalid alert type</h2>", 400

    # STEP 1: GET USER FROM DATABASE
    user = db.session.get(User, user_id)

    if not user:
        return "<h2>User not found</h2>", 404

    # STEP 2: RATE LIMIT PUBLIC ALERTS
    # Use the visitor IP + target owner so one visitor cannot repeatedly
    # trigger alerts for the same owner. This runs before DB/email work.
    client_key = f"{request.remote_addr or 'unknown'}:{user_id}"

    if alert_rate_limited(client_key):
        return (
            "<h2>Too many alerts</h2>"
            "<p>Please wait before sending another alert.</p>"
        ), 429

    # STEP 3: SAVE ALERT
    new_alert = Message(
        user_id=user_id,
        alert_type=alert_type
    )

    db.session.add(new_alert)
    db.session.commit()

    # STEP 4: SEND EMAIL
    email_sent = send_email_notification(
        receiver_email=user.email,
        owner_name=user.name,
        alert_text=alert_type
    )

    return redirect(url_for(
        "public_profile",
        user_id=user_id,
        success=1 if email_sent else None,
        saved=1 if not email_sent else None
    ))

# PUBLIC EMERGENCY CONTACT

EMERGENCY_CONTACT_ALERTS = {
    "owner_not_responding": "Owner is not responding.",
    "emergency_situation": "It is an emergency situation.",
    "vehicle_accident": "The vehicle appears to be involved in an accident.",
    "urgent_assistance": "Urgent assistance is needed for the vehicle owner.",
}

@app.route("/emergency-contact/<int:user_id>")
def show_emergency_contact(user_id):

    user = db.session.get(User, user_id)
    if not user:
        return "<h2>User not found</h2>", 404

    contact = EmergencyContact.query.filter_by(
        user_id=user_id
    ).first()

    # Only safe, non-sensitive values are sent to the public page.
    public_contact = None
    if contact:
        public_contact = {
            "contact_name": contact.contact_name,
            "relationship": contact.relationship,
        }

    return render_template(
        "view_emergency_contact.html",
        contact=public_contact,
        user_id=user_id
    )


def send_emergency_contact_email(
    receiver_email,
    relationship,
    owner_name,
    vehicle_number,
    situation
):
    body = f"""Hello,

Your {relationship}, {owner_name}, has an emergency involving vehicle {vehicle_number}.

Situation: {situation}

Kindly contact/help them as soon as possible.

This alert was sent through TAGVEE after someone scanned the vehicle's QR code.

TAGVEE Team
"""
    api_key = app.config.get("RESEND_API_KEY", "")
    sender = app.config.get("MAIL_DEFAULT_SENDER", "")
    if api_key:
        payload = json.dumps({
            "from": sender,
            "to": [receiver_email],
            "subject": "TAGVEE Emergency Contact Alert",
            "text": body,
        }).encode("utf-8")
        req = Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "TAGVEE",
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=12) as response:
                return 200 <= response.status < 300
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            app.logger.warning("Emergency-contact email API failed: %s", error)
            return False

    if not app.config.get("MAIL_USERNAME") or not app.config.get("MAIL_PASSWORD"):
        app.logger.warning("Emergency-contact email skipped: email provider is not configured.")
        return False

    msg = MailMessage(
        subject="TAGVEE Emergency Contact Alert",
        sender=sender or app.config["MAIL_USERNAME"],
        recipients=[receiver_email],
        body=body,
    )
    try:
        mail.send(msg)
        return True
    except Exception:
        app.logger.exception("Emergency-contact email failed")
        return False



@app.route("/send-emergency-contact-alert/<int:user_id>/<alert_type>", methods=["POST"])
def send_emergency_contact_alert(user_id, alert_type):

    situation = EMERGENCY_CONTACT_ALERTS.get(alert_type)
    if not situation:
        return "<h2>Invalid emergency alert</h2>", 400

    user = db.session.get(User, user_id)
    if not user:
        return "<h2>User not found</h2>", 404

    contact = EmergencyContact.query.filter_by(
        user_id=user_id
    ).first()

    if not contact or not contact.email:
        return "<h2>No emergency contact email is available.</h2>", 404

    client_key = f"emergency-contact:{request.remote_addr or 'unknown'}:{user_id}"
    if alert_rate_limited(client_key):
        return "<h2>Too many emergency alerts</h2><p>Please wait before sending another alert.</p>", 429

    email_sent = send_emergency_contact_email(
        receiver_email=contact.email,
        relationship=contact.relationship,
        owner_name=user.name,
        vehicle_number=user.vehicle_number,
        situation=situation
    )
    if not email_sent:
        return (
            "<h2>Emergency alert could not be delivered.</h2>"
            "<p>The notification provider is unavailable or not configured. "
            "Please contact emergency services directly if this is urgent.</p>"
        ), 502

    return redirect(url_for("show_emergency_contact", user_id=user_id, sent=1))


#emergency service route
@app.route("/emergency-services")
def emergency_services():

    return render_template(
        "emergency_services.html"
    )

# change password route
@app.route("/change-password", methods=["GET", "POST"])
def change_password():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])

    if request.method == "POST":

        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "").strip()

        if len(new_password) < 8:
            return "Password must be at least 8 characters"

        if not check_password_hash(
            user.password,
            old_password
        ):
            return "Current password is incorrect"

        user.password = generate_password_hash(
            new_password
        )

        db.session.commit()

        return redirect(url_for("dashboard"))

    return render_template(
        "change_password.html"
    )


# logout route
@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)
    return wrapped_view


# admin login route
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        admin = Admin.query.filter_by(
            username=username
        ).first()

        if admin and check_password_hash(
            admin.password,
            password
        ):

            session["admin_id"] = admin.id

            return redirect(
                url_for("admin_dashboard")
            )

        return "Invalid Credentials"

    return render_template(
        "admin_login.html"
    )


# admin dashboard route
@app.route("/admin-dashboard")
@admin_required
def admin_dashboard():

    users = User.query.all()

    total_users = User.query.count()

    total_contacts = EmergencyContact.query.count()

    total_alerts = Message.query.count()

    total_scans = ScanLog.query.count()

    return render_template( 
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        total_contacts=total_contacts,
        total_alerts=total_alerts,
        total_scans=total_scans
    )


# admin user search route
@app.route("/search-user")
@admin_required
def search_user():

    query = request.args.get("q")

    users = User.query.filter(

        (User.name.ilike(f"%{query}%")) |

        (User.email.ilike(f"%{query}%")) |

        (User.vehicle_number.ilike(f"%{query}%"))

    ).all()

    return render_template(
        "admin_dashboard.html",
        users=users
    )
    

# admin user profile view
@app.route("/admin-user/<int:user_id>")
@admin_required
def admin_user(user_id):

    user = User.query.get_or_404(user_id)

    return render_template(
        "admin_user.html",
        user=user
    )


# admin delete users
@app.route("/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):

    user = User.query.get_or_404(user_id)

    EmergencyContact.query.filter_by(
    user_id=user.id
    ).delete()

    Message.query.filter_by(
        user_id=user.id
    ).delete()

    ScanLog.query.filter_by(
        user_id=user.id
    ).delete()

    db.session.delete(user)

    db.session.commit()

    return redirect(url_for("admin_dashboard"))


#admin view user alerts
@app.route("/admin-alerts/<int:user_id>")
@admin_required
def admin_alerts(user_id):

    alerts = Message.query.filter_by(
        user_id=user_id
    ).all()

    return render_template(
        "admin_alerts.html",
        alerts=alerts
    )

#admin view scan history
@app.route("/admin-scans/<int:user_id>")
@admin_required
def admin_scans(user_id):

    scans = ScanLog.query.filter_by(
        user_id=user_id
    ).all()

    return render_template(
        "admin_scans.html",
        scans=scans
    )


#Alert History route
@app.route("/alerts")
def alerts():

    if "user_id" not in session:
        return redirect(url_for("login"))

    alerts = Message.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        Message.created_at.desc()
    ).all()

    return render_template(
        "alerts.html",
        alerts=alerts
    )


#Scan History route
@app.route("/scan-history")
def scan_history():

    if "user_id" not in session:
        return redirect(url_for("login"))

    scans = ScanLog.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        ScanLog.scan_time.desc()
    ).all()

    total_scans = len(scans)

    return render_template(
        "scan_history.html",
        scans=scans,
        total_scans=total_scans
    )



# RUN APPLICATION

# Create tables when the module is imported by Gunicorn in the initial demo deployment.
# For future schema changes, use proper database migrations instead of relying on create_all().
with app.app_context():
    db.create_all()
    # Optional one-time admin bootstrap for a fresh database.
    # Existing admin accounts are never overwritten.
    admin_username = os.getenv("TAGVEE_ADMIN_USERNAME", "").strip()
    admin_password = os.getenv("TAGVEE_ADMIN_PASSWORD", "")
    if admin_username and admin_password:
        existing_admin = Admin.query.filter_by(username=admin_username).first()
        if not existing_admin:
            db.session.add(Admin(
                username=admin_username,
                password=generate_password_hash(admin_password)
            ))
            db.session.commit()

if __name__ == "__main__":
    print(f"TAGVEE BUILD: {TAGVEE_BUILD}")
    local_https = os.getenv("TAGVEE_LOCAL_HTTPS", "false").lower() == "true"
    ssl_context = ("certs/192.168.100.18.pem", "certs/192.168.100.18-key.pem") if local_https else None
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False, use_reloader=False, ssl_context=ssl_context)
