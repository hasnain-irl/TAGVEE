# TAGVEE release candidate review

## What was merged
- Deployment configuration from the previously supplied Render package: environment-based secret key, `DATABASE_URL` support for PostgreSQL with SQLite fallback, public base URL, Resend/SMTP configuration, Gunicorn start configuration.
- The eight current files from `required files01.zip` were overlaid on the deployment package (current `app.py` was reconciled with deployment configuration).
- Current call owner/call centre templates and service worker are preserved.

## Fixes applied
- Quick Alert route accepts only the five alert strings present in `public_profile.html`.
- TURN credentials were removed from both calling templates and replaced with `TAGVEE_TURN_USERNAME` / `TAGVEE_TURN_CREDENTIAL` environment settings.
- Session cookies default to Secure on a configured HTTPS public URL while allowing local HTTP testing.
- QR generation uses `TAGVEE_PUBLIC_BASE_URL` when configured and creates the QR directory if needed.
- Push notification sending checks that the VAPID private-key file exists and skips cleanly if not configured.
- Emergency-contact email supports the same Resend or SMTP configuration as owner alerts and reports provider failure instead of falsely showing success.
- Owner Quick Alert UI now distinguishes “saved but email delivery could not be confirmed” from successful email delivery.
- Optional initial admin seeding is supported via `TAGVEE_ADMIN_USERNAME` and `TAGVEE_ADMIN_PASSWORD` for a fresh database only.
- Added simple fallback logo/favicon assets because the uploaded deployment bundle did not include the referenced original image files.

## Static checks performed
- Python AST/syntax compilation: passed.
- Jinja2 syntax parsing for all packaged HTML templates: passed.
- Render template references: all referenced template files are present.
- Render YAML parse: passed.
- Hard-coded TURN credentials in calling templates: none found.

## Not yet verified
- Runtime Flask tests were not possible in this environment because Flask, Flask-SQLAlchemy, Flask-Mail, pywebpush, and psycopg are not installed here and external package downloads are unavailable.
- No live Neon database, Render service, Resend account, VAPID key, or fresh TURN credentials were connected.
- Cross-network WebRTC, email delivery, push notifications, registration/login, QR generation, and persistence must be tested after deployment.
- The public GitHub repository could not be fetched directly from this session; this package was built from the files supplied in chat and the previously supplied deployment ZIP, not from a fresh clone.

## Known limitations / before real users
- Render free filesystem is ephemeral: QR PNGs may disappear after restart/deploy and should be regenerated or moved to object storage.
- WebRTC signaling is in process memory; active calls can be lost on restart. One Gunicorn worker is configured.
- `db.create_all()` creates missing tables but does not migrate old schemas. Use a fresh Neon database for initial launch.
- TURN credentials included in the uploaded files should be considered exposed and rotated. Do not reuse them.
- Set `TAGVEE_PUBLIC_BASE_URL` to the final HTTPS Render URL, then redeploy.
- For email, configure a verified sender with Resend; setting an API key alone is not enough.
