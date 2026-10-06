# LocalConnect

LocalConnect is a local-services marketplace migrated from native PHP to a production-oriented Python/Flask application while preserving the existing HTML/CSS/JavaScript UI, legacy `.php` URLs, MySQL/MariaDB data model, roles, workflows and billing behavior.

## Production stack

- Python 3.13.15
- Flask + Jinja2
- Flask-SQLAlchemy / SQLAlchemy
- PyMySQL with external MySQL/MariaDB
- Flask-WTF CSRF protection
- Gunicorn
- Existing HTML5/CSS3/vanilla JavaScript, Bootstrap and Font Awesome assets
- Render Native Python Web Service (no Docker, Apache, Nginx or PHP runtime required)

The old PHP files are retained as migration/parity reference material. Production requests are handled by Flask, including compatibility routes such as `/auth/login.php`, `/provider/dashboard.php` and the other audited legacy paths.

## Architecture

```text
app.py                     Flask entry point / application factory
config/settings.py         environment-driven application configuration
extensions.py              SQLAlchemy and CSRF extensions
routes/                     public/auth/customer/provider/business/admin/billing/API/webhook routes
services/                   auth, marketplace, billing and storage business logic
models/                     SQLAlchemy mappings for the effective MySQL schema
templates/                  Jinja2 templates preserving the existing UI
assets/                     existing CSS, JavaScript and static images
database/                   canonical schema, production migrations and schema manifest
scripts/                    config/schema checks, DB initialization/migrations, workers, upload sync
tests/                      Python migration tests plus retained legacy regression evidence
docs/                       audit, route/database mapping and deployment documentation
```

## Local installation

Python 3.13 is recommended.

```bash
python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows PowerShell
# .\\venv\\Scripts\\Activate.ps1

pip install -r requirements.txt
```

Copy `.env.example` to a local `.env` or export the corresponding environment variables. Do not commit real secrets.

For local MySQL/MariaDB, configure either `DATABASE_URL` or `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` and `DB_PASSWORD`.

For an empty development database:

```bash
python scripts/init_db.py
python scripts/init_db.py --yes
```

For an existing database, inspect migration status first and back up production data before applying anything:

```bash
python scripts/migrate_db.py
python scripts/migrate_db.py --preflight --apply
python scripts/check_db_schema.py
```

Run locally with:

```bash
python app.py
```

or with Gunicorn on Linux/macOS:

```bash
gunicorn app:app --bind 0.0.0.0:8000
```

No XAMPP, WAMP, Apache, PHP or Docker is required for the Flask application.

## Environment variables

Production configuration is environment-only. Important variables include:

- `APP_ENV=production`
- `APP_URL=https://...`
- `SECRET_KEY` (32+ bytes of random secret material; base64/hex forms are supported)
- `APP_KEY` only while legacy encrypted admin-MFA records still require it
- `DATABASE_URL` or the `DB_*` variables
- SMTP settings: `APP_MAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- upload settings, with production persistent storage at `/var/data/localconnect/uploads`
- Razorpay settings when the Razorpay payment method is enabled

See `.env.example` and `docs/DEPLOYMENT.md` for the full list.

## Persistent uploads

Profile images, business logos and portfolio files keep the existing database/public path format `uploads/...`. In production, bytes are stored on the Render persistent disk mounted at `/var/data/localconnect/uploads`.

Uploads are size-bounded, format-restricted to JPEG/PNG/WebP, dimension/pixel-bounded, decoded and re-encoded, EXIF-normalized, randomly named and resolved only through managed paths.

## Authentication and authorization

The Flask application implements customer/provider/business/admin authentication, secure sessions, password hashing, verification/reset flows, role guards, blocked-account enforcement, admin MFA and recent re-authentication for sensitive administration. Existing compatible PHP password hashes and legacy admin-MFA encrypted values are supported during migration.

Authorization is enforced server-side. Browser form mutations are CSRF-protected. The Razorpay webhook is the intentional CSRF exception and verifies the provider signature over the raw request body.

## Database

The effective MySQL/MariaDB schema contains the audited marketplace, auth/security, billing and subscription tables. Production code does not use `db.create_all()` as a migration system. Use the versioned SQL migration runner and schema checker.

Runtime DB credentials should be least-privilege. Migration credentials can be supplied separately where the managed database requires elevated DDL permissions.

## Tests

The repository contains Python static/runtime suites and retained legacy regression tests. Useful release checks include:

```bash
python -m compileall -q app.py config routes services models utils database scripts
python -m pytest -q tests/python
python tools/secret_scan.py
python scripts/check_config.py
python scripts/check_db_schema.py
```

Runtime tests that require Flask/PyMySQL and database connectivity must run in an environment where dependencies are installable and the intended MySQL/MariaDB instance is reachable.

## Render deployment

`render.yaml` defines a Native Python web service:

- Build: `pip install -r requirements.txt`
- Pre-deploy: `python scripts/check_config.py && python scripts/check_db_schema.py`
- Start: `gunicorn app:app --bind 0.0.0.0:$PORT`
- Health: `/health` (includes a primary database `SELECT 1` probe)
- Persistent upload disk: `/var/data/localconnect/uploads`
- Payment reconciliation cron: `python scripts/payment_reconciliation_worker.py --limit=20` every 5 minutes

The cron service reuses the web service database/payment secrets, does not require the upload persistent disk, and drains bounded payment-reconciliation jobs after transient processing failures.

Set all `sync: false` values in the Render dashboard before deployment. Initialize/apply the database schema safely before the pre-deploy schema gate is expected to pass. See `docs/DEPLOYMENT.md`.

## Payment safety

Razorpay checkout uses server-side order creation, immutable checkout snapshots, signed callback/webhook verification and server reconciliation before entitlement activation. Manual payments remain pending until privileged review. Payment state changes and entitlement activation are transactional.

`PAYMENT_ALLOW_LIVE=false` is intentionally the default. Do not enable live payment credentials until sandbox end-to-end checkout/webhook/reconciliation tests and production smoke testing have passed with the real merchant account.

## Production notes

- `/health` returns HTTP 200 only when the app can also reach the primary database.
- Production enforces HTTPS, secure cookies, trusted hosts, CSP, HSTS policy and safe error responses.
- Render's normal filesystem is ephemeral; permanent user uploads must remain on the attached persistent disk or be migrated to object storage in a future architecture.
- A Render persistent disk is single-instance storage, so horizontal multi-instance scaling requires moving uploads to shared object storage first.
- Historical `PRODUCTION_PHASE*.md` and PHP hardening artifacts are retained as migration evidence; `docs/DEPLOYMENT.md` is the current deployment source of truth.

