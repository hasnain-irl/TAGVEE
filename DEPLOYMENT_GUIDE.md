# TAGVEE deployment (Render + Neon)

This package is prepared for a cloud-hosted Flask deployment. The computer running locally is not needed after deployment.

## Important limitations
- Render Free web services sleep after about 15 minutes without traffic, then need time to wake up. The URL remains stable, but the first request after sleeping can be slow.
- Use Neon PostgreSQL for persistent data. Do not use SQLite on Render for production data; the free filesystem is ephemeral.
- QR image files written to `static/qr_codes/` are ephemeral on Render. Regenerate them if they disappear after a restart/deploy; long-term use should store QR images in object storage or generate them on demand.
- WebRTC signaling state is stored in process memory, so a deploy/restart interrupts active calls. Keep one worker for this version.
- Push notifications require a valid VAPID private key file. Do not upload that key to GitHub. If the key is absent, push sending is skipped cleanly.
- Email notifications need a working Resend account/API key and a verified sender/domain. Emergency-contact email uses the same Resend/SMTP provider path. Email is skipped if no provider is configured.

## Deploy steps
1. Push this folder to a GitHub repository (or upload/replace the current repository files). Do not commit `.env`, `private_key.pem`, certificates, or a real database.
2. Create a free Neon PostgreSQL project and copy its pooled or direct connection string. It must include `sslmode=require`.
3. In Render, create a **Web Service** connected to the repository. Render should detect `render.yaml`; otherwise use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app --workers 1 --threads 4 --timeout 120`
4. Set these environment variables in Render:
   - `TAGVEE_SECRET_KEY`: a long random secret (Render may generate it for you).
   - `TAGVEE_PUBLIC_BASE_URL`: the final URL shown by Render, e.g. `https://tagvee-xxxx.onrender.com`.
   - `DATABASE_URL`: the Neon PostgreSQL connection string.
   - `TAGVEE_RESEND_API_KEY` and `TAGVEE_MAIL_FROM`: only if email alerts are required; `TAGVEE_MAIL_FROM` must be a sender verified by Resend.
   - `TAGVEE_TURN_USERNAME` and `TAGVEE_TURN_CREDENTIAL`: optional TURN service credentials. Configure fresh credentials before relying on cross-network audio calls.
   - `TAGVEE_ADMIN_USERNAME` and `TAGVEE_ADMIN_PASSWORD`: optional; set both to seed an admin account in a fresh database. Use a strong unique password.
   - `TAGVEE_VAPID_PRIVATE_KEY_PATH=/etc/secrets/private_key.pem` and `TAGVEE_VAPID_SUBJECT=mailto:your-contact@example.com` if push notifications are required.
5. If push is required, add `private_key.pem` under Render **Secret Files** at `/etc/secrets/private_key.pem`. Never commit it to GitHub.
6. Deploy, wait for the build to finish, then open the Render URL and test registration, login, QR generation, public QR privacy, alert submission, email, push, and calls.

## Before you put real users' data on it
This is a deployment adaptation, not a security certification. Review admin credentials/access controls, database migrations, rate limiting across processes, privacy, backups, and call signaling. Run a full end-to-end test first.

## Security notes for this release candidate
- The uploaded calling templates contained hard-coded TURN credentials. They have been removed from the templates; set fresh `TAGVEE_TURN_USERNAME` and `TAGVEE_TURN_CREDENTIAL` values in the hosting environment if TURN relay is needed.
- Quick Alert accepts only the five message strings presented by the public profile.
- This is still a demo deployment, not a security audit. WebRTC call signaling is stored in process memory and active calls can be lost on restart. The free Render service may sleep; QR image files on its ephemeral disk may disappear and need regeneration.
- `db.create_all()` creates missing tables but does not migrate existing table schemas. Use a fresh cloud database for initial deployment; do not point it at an old SQLite schema without migration.
- Before real-world use, test alert/email behavior, owner privacy, registration/login, QR URLs, calls across different networks, and database persistence after a restart.
