# TrustVault — Secure Document Sharing

TrustVault is a Flask prototype for document-level access control and an auditable document activity trail. It demonstrates login, role restrictions, private file storage, read/edit grants, revocation, search, and hash-linked audit events. It is a hackathon starter, not a production-certified security product.

## Features

- Roles: `admin`, `owner`, `viewer`. Public registration always creates a `viewer`. An admin can promote users.
- Upload: owners and admins can upload PDF, TXT, DOCX, XLSX, PNG, JPG/JPEG files up to 10 MB.
- Private storage: files are stored under `instance/private_uploads` by default, outside the static web directory.
- Document grants: owner can grant named active users `read` or `edit`; revocation is checked against the database on every request.
- Search: document name, owner email, category, start date and end date. Results are limited to documents owned by or granted to the signed-in user.
- Audit: successful and denied access attempts, uploads, downloads, edits, deletion, permission changes, role changes and authentication events.
- Admin page: recent audit activity, user list, role changes, and audit-chain verification. Admin role alone does not grant access to file contents.
- CSRF protection, password hashing, upload allowlist, size limit and baseline security headers.

## Requirements

- Python 3.11+ recommended
- Git (for repository history)

## Run locally on Windows

1. Extract the ZIP and open a terminal in the `TrustVault` folder.
2. Create a virtual environment:

   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Create the local environment file and set a secret:

   ```bat
   copy .env.example .env
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

   Copy the generated value into `.env` as `SECRET_KEY=...`. Never commit `.env`.

5. Run the application:

   ```bat
   python app.py
   ```

6. Open http://127.0.0.1:5000. Register a user. New users are viewers. To upload, an administrator must promote the account to `owner`.

## Bootstrap an administrator

Before the first run, you can set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`. If that email does not already exist, the app creates the first admin account. Use a unique password of at least 12 characters. Do not publish real credentials. Remove the bootstrap variables after setup and keep the password secret. For a hackathon deployment, provide demo credentials to judges through the intended submission channel, not by committing production secrets to the repository.

## Tests

```bat
pytest -q
```

The tests use a temporary SQLite database and temporary private upload directory. Add a test for every security claim and every new route.

## Environment variables

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session and CSRF secret; must be strong and private |
| `DATABASE_URL` | Database URL; defaults to local SQLite |
| `UPLOAD_FOLDER` | Private file storage directory |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Optional first-admin bootstrap |
| `COOKIE_SECURE` | Set `true` behind HTTPS in production |
| `FLASK_DEBUG` | Development debug switch; keep false in production |

## Deployment notes

- Use managed PostgreSQL and set `DATABASE_URL` to a supported PostgreSQL URL. `psycopg` is included.
- Set `SECRET_KEY` in the host's secret manager, not in source control. Set `COOKIE_SECURE=true` when HTTPS is correctly configured.
- Configure persistent private storage or private object storage. The local filesystem may be ephemeral on some hosts. Never put uploads in `static/`.
- Use a production WSGI server (`gunicorn app:app` on Linux; `Procfile` included). Do not run Flask debug mode in production.
- Add database migrations, backups, storage ACLs, monitoring, rate limiting, MFA/SSO, malware scanning and external audit anchoring before handling real confidential files.
- Test revocation, cross-user access and all routes against the deployed environment.

## Documentation

- [`API.md`](API.md): route permissions and behavior.
- [`THREATS.md`](THREATS.md): threat register and known limitations.
- [`PROMPTS.md`](PROMPTS.md): AI usage log template; replace planning placeholders with real dated evidence as you work.

## Important limitations

This prototype has not been independently security audited. The audit hash chain detects modifications relative to a trusted checkpoint but can be rebuilt by an attacker with full database write access. The allowlist does not inspect true file content. Previously downloaded files cannot be revoked. Do not use this as-is for real confidential documents.
