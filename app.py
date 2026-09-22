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
from collections import defaultdict, deque

TAGVEE_BUILD = "UI-FINALIZATION-PASS-3"

app = Flask(__name__)

# Secret Key (will be used later for login sessions)
secret_key = os.getenv("TAGVEE_SECRET_KEY")
if not secret_key:
    raise RuntimeError("TAGVEE_SECRET_KEY environment variable is not set.")
app.config["SECRET_KEY"] = secret_key

app.config["PUBLIC_BASE_URL"] = os.getenv(
    "TAGVEE_PUBLIC_BASE_URL",
    "https://192.168.100.18:5000"
).rstrip("/")

# SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smart_vehicle.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#EMAIL CONFIG
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True

#dedicated project Gmail account
app.config["MAIL_USERNAME"] = "tagveeofficial@gmail.com"
app.config["MAIL_PASSWORD"] = os.getenv("TAGVEE_MAIL_PASSWORD", "")

# Email address that will send notifications
app.config["MAIL_DEFAULT_SENDER"] = "tagveeofficial@gmail.com"

# Web Push configuration
app.config["VAPID_PRIVATE_KEY"] = os.getenv(
    "TAGVEE_VAPID_PRIVATE_KEY_PATH",
    "private_key.pem"
)
app.config["VAPID_SUBJECT"] = os.getenv(
    "TAGVEE_VAPID_SUBJECT",
    "mailto:tagveeofficial@gmail.com"
)

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

def send_email_notification(
    receiver_email,
    owner_name,
    alert_text
):
    # Skip sending if email is not configured yet
    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        print("Email is not configured. Skipping email.")
        return False
    
    msg = MailMessage(

        subject="Vehicle Alert Notification",

        sender=app.config['MAIL_USERNAME'],

        recipients=[receiver_email]
    )

    msg.body = f"""
Hello {owner_name},

Someone has interacted with your Tagvee QR code.

Alert:
{alert_text}

Please login to Tagvee to view details.

Login:
{app.config["PUBLIC_BASE_URL"]}/login

Thank You,
Tagvee Team
"""

    try:
        mail.send(msg)
        return True
    except Exception as error:
        # Keep SMTP/provider details out of the user's browser.
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

        # --------------------
        # VALIDATIONS
        # --------------------

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

    qr_data = f"{app.config['PUBLIC_BASE_URL']}/user/{user_id}"

    qr = qrcode.make(qr_data)

    qr_directory = os.path.join("static", "qr_codes")
    os.makedirs(qr_directory, exist_ok=True)

    file_path = os.path.join(
        qr_directory,
        f"user_{user_id}.png"
    )

    qr.save(file_path)

    return redirect(url_for("dashboard"))

#public_profile route
@app.route("/user/<int:user_id>")
def public_profile(user_id):

    user = User.query.get_or_404(user_id)
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
    success=request.args.get("success")
    )


# WEBRTC CALL - CALLER

@app.route("/call-owner/<int:user_id>")
def call_owner(user_id):

    user = User.query.get_or_404(user_id)

    # SECURITY: the call page only needs the owner's public ID.
    # Do not pass the full User object (which contains the private phone number).
    public_user = {"id": user.id}

    return render_template(
        "call_owner.html",
        user=public_user
    )


# WEBRTC CALL - CALLER route
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
        print(
            f"No push subscriptions found for user {user_id}"
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
                vapid_private_key=app.config["VAPID_PRIVATE_KEY"],
                vapid_claims={
                    "sub": app.config["VAPID_SUBJECT"]
                }
            )

            sent_count += 1

            print(
                "Push notification sent:",
                subscription.id
            )

        except WebPushException as error:

            print(
                "Web Push Error for subscription:",
                subscription.id,
                error
            )

            if "410" in str(error) or "404" in str(error):

                db.session.delete(subscription)

    db.session.commit()

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

    return render_template("call_center.html")

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
        return {
            "error": "Not logged in"
        }, 401

    subscriptions = PushSubscription.query.filter_by(
        user_id=session["user_id"]
    ).all()

    if not subscriptions:
        return {
            "error": "No push subscription found"
        }, 404

    payload = json.dumps({
        "title": "TAGVEE Test",
        "body": "Push notifications are working!",
        "url": "/dashboard"
    })

    sent_count = 0
    expired_count = 0

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
                vapid_private_key=app.config["VAPID_PRIVATE_KEY"],
                vapid_claims={
                    "sub": app.config["VAPID_SUBJECT"]
                }
            )

            sent_count += 1

        except WebPushException as error:

            print(
                "Web Push Error for subscription:",
                subscription.id,
                error
            )

            # Subscription expired/unsubscribed.
            if "410" in str(error) or "404" in str(error):

                db.session.delete(subscription)
                expired_count += 1

    db.session.commit()

    if sent_count > 0:

        return {
            "success": True,
            "message": "Test notification sent"
        }

    return {
        "error": "All push subscriptions are expired or unavailable"
    }, 500

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

    # STEP 1: GET USER FROM DATABASE
    user = db.session.get(User, user_id)

    if not user:
        return "<h2>User not found</h2>", 404

    # Only predefined Quick Alerts are accepted.
    # This prevents arbitrary text from being injected into the alert/email flow.
    if alert_type not in QUICK_ALERTS:
        return "<h2>Invalid alert type</h2>", 400

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

    if not email_sent:
        return "<h2>Alert could not be delivered.</h2><p>Please try again later.</p>", 503

    return redirect(
        url_for(
            "public_profile",
            user_id=user_id,
            success=1
        )
    )

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
    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        print("Email is not configured. Skipping emergency-contact email.")
        return False

    msg = MailMessage(
        subject="TAGVEE Emergency Contact Alert",
        sender=app.config["MAIL_USERNAME"],
        recipients=[receiver_email]
    )

    msg.body = f"""Hello,

Your {relationship}, {owner_name}, has an emergency involving vehicle {vehicle_number}.

Situation: {situation}

Kindly contact/help them as soon as possible.

This alert was sent through TAGVEE after someone scanned the vehicle's QR code.

TAGVEE Team
"""

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
        return "<h2>Emergency alert could not be delivered.</h2><p>Please try again later.</p>", 503

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

    query = request.args.get("q", "").strip()

    if not query:
        return redirect(url_for("admin_dashboard"))

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

    PushSubscription.query.filter_by(
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

if __name__ == "__main__":
    print(f"TAGVEE BUILD: {TAGVEE_BUILD}")

    with app.app_context():
        db.create_all()

    ssl_cert = os.getenv(
        "TAGVEE_SSL_CERT",
        "certs/192.168.100.18.pem"
    )
    ssl_key = os.getenv(
        "TAGVEE_SSL_KEY",
        "certs/192.168.100.18-key.pem"
    )

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("TAGVEE_PORT", "5000")),
        debug=False,
        use_reloader=False,
        ssl_context=(ssl_cert, ssl_key)
    )
