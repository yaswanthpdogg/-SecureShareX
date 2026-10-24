import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
login_manager.login_view = "login"
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "xlsx", "png", "jpg", "jpeg"}
MAX_BYTES = 10 * 1024 * 1024


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer", index=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    storage_name = db.Column(db.String(80), nullable=False, unique=True)
    original_name = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(120), nullable=False, default="application/octet-stream")
    size_bytes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    level = db.Column(db.String(10), nullable=False)  # read or edit
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    granted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    document = db.relationship("Document")
    user = db.relationship("User", foreign_keys=[user_id])
    granted_by = db.relationship("User", foreign_keys=[granted_by_id])
    __table_args__ = (db.UniqueConstraint("document_id", "user_id", name="uq_document_user_grant"),)


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    actor_email = db.Column(db.String(254), nullable=False, default="anonymous")
    action = db.Column(db.String(60), nullable=False, index=True)
    document_id = db.Column(db.Integer, nullable=True, index=True)
    target_user_id = db.Column(db.Integer, nullable=True)
    outcome = db.Column(db.String(20), nullable=False)
    details = db.Column(db.Text, nullable=False, default="{}")
    previous_hash = db.Column(db.String(64), nullable=False)
    event_hash = db.Column(db.String(64), nullable=False, unique=True)


def record_event(action, outcome="success", document_id=None, target_user_id=None, details=None, actor=None):
    """Append a hash-linked audit event. External anchoring is needed for strong tamper evidence."""
    actor = actor if actor is not None else (current_user if current_user.is_authenticated else None)
    previous = db.session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    previous_hash = previous.event_hash if previous else "0" * 64
    event_time = utcnow()
    payload = {
        "occurred_at": event_time.isoformat(),
        "actor_id": actor.id if actor else None,
        "actor_email": actor.email if actor else "anonymous",
        "action": action,
        "document_id": document_id,
        "target_user_id": target_user_id,
        "outcome": outcome,
        "details": details or {},
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    event = AuditEvent(
        occurred_at=event_time, actor_id=payload["actor_id"], actor_email=payload["actor_email"], action=action,
        document_id=document_id, target_user_id=target_user_id, outcome=outcome,
        details=json.dumps(details or {}, sort_keys=True), previous_hash=previous_hash, event_hash=event_hash,
    )
    db.session.add(event)
    db.session.flush()
    return event


def verify_audit_chain():
    previous_hash = "0" * 64
    for event in AuditEvent.query.order_by(AuditEvent.id.asc()).all():
        event_time = event.occurred_at
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        payload = {
            "occurred_at": event_time.isoformat(),
            "actor_id": event.actor_id,
            "actor_email": event.actor_email,
            "action": event.action,
            "document_id": event.document_id,
            "target_user_id": event.target_user_id,
            "outcome": event.outcome,
            "details": json.loads(event.details or "{}"),
            "previous_hash": previous_hash,
        }
        # Hash uses a stored timestamp, so normalize event payload to the original audit representation.
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if event.previous_hash != previous_hash or event.event_hash != expected:
            return False
        previous_hash = event.event_hash
    return True


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    return user if user and user.active else None


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///trustvault.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
        REMEMBER_COOKIE_HTTPONLY=True,
        MAX_CONTENT_LENGTH=MAX_BYTES,
        UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", str(Path(app.instance_path) / "private_uploads")),
    )
    if test_config:
        app.config.update(test_config)
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
        app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace("postgres://", "postgresql://", 1)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    with app.app_context():
        db.create_all()
        # Optional first-admin bootstrap. Set both values before first startup; do not use public registration for this.
        admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if admin_email and admin_password and not User.query.filter_by(email=admin_email).first():
            admin = User(email=admin_email, role="admin")
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()

    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    def can_read(user, document):
        if not user.is_authenticated or not user.active or document.deleted_at is not None:
            return False
        if document.owner_id == user.id:
            return True
        grant = Permission.query.filter_by(document_id=document.id, user_id=user.id).first()
        return bool(grant and grant.level in {"read", "edit"})

    def can_edit(user, document):
        if not user.is_authenticated or not user.active or document.deleted_at is not None:
            return False
        if document.owner_id == user.id:
            return True
        grant = Permission.query.filter_by(document_id=document.id, user_id=user.id).first()
        return bool(grant and grant.level == "edit")

    def get_authorized_document(document_id, action="read"):
        document = db.session.get(Document, document_id)
        allowed = bool(document and (can_edit(current_user, document) if action == "edit" else can_read(current_user, document)))
        if not allowed:
            record_event("document_access", "denied", document_id=document_id, details={"requested_action": action})
            db.session.commit()
            abort(404)
        return document

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
        return response

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not email or "@" not in email or len(email) > 254:
                flash("Enter a valid email address.", "error")
            elif len(password) < 12:
                flash("Password must contain at least 12 characters.", "error")
            elif User.query.filter_by(email=email).first():
                flash("An account with that email already exists.", "error")
            else:
                user = User(email=email, role="viewer")
                user.set_password(password)
                db.session.add(user)
                record_event("user_registered", details={"new_role": "viewer"}, actor=None)
                # Registration actor is the new user for the audit event.
                db.session.flush()
                event = AuditEvent.query.order_by(AuditEvent.id.desc()).first()
                # Do not rewrite audit records; a follow-up event captures registration identity after account creation.
                record_event("registration_completed", details={"user_id": user.id}, actor=user)
                db.session.commit()
                flash("Account created. Ask an administrator to promote you to document owner if needed.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = User.query.filter_by(email=email, active=True).first()
            if user and user.check_password(password):
                login_user(user)
                record_event("login", details={"result": "success"}, actor=user)
                db.session.commit()
                return redirect(url_for("dashboard"))
            record_event("login", "denied", details={"email": email[:254]})
            db.session.commit()
            flash("Invalid email or password.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        record_event("logout")
        db.session.commit()
        logout_user()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        query = Document.query.filter(Document.deleted_at.is_(None))
        if current_user.role == "admin":
            # Admin sees metadata only, not file content, unless independently granted access.
            query = query.filter(or_(Document.owner_id == current_user.id, Document.id.in_(db.session.query(Permission.document_id).filter_by(user_id=current_user.id))))
        else:
            shared_ids = db.session.query(Permission.document_id).filter_by(user_id=current_user.id).subquery()
            query = query.filter(or_(Document.owner_id == current_user.id, Document.id.in_(shared_ids)))
        name = request.args.get("name", "").strip()
        category = request.args.get("category", "").strip()
        owner = request.args.get("owner", "").strip().lower()
        start = request.args.get("start", "").strip()
        end = request.args.get("end", "").strip()
        if name:
            query = query.filter(Document.name.ilike(f"%{name}%"))
        if category:
            query = query.filter(Document.category.ilike(f"%{category}%"))
        if owner:
            query = query.join(User, Document.owner_id == User.id).filter(User.email.ilike(f"%{owner}%"))
        if start:
            try:
                query = query.filter(Document.created_at >= datetime.fromisoformat(start).replace(tzinfo=timezone.utc))
            except ValueError:
                flash("Invalid start date.", "error")
        if end:
            try:
                query = query.filter(Document.created_at < datetime.fromisoformat(end).replace(tzinfo=timezone.utc).replace(hour=23, minute=59, second=59))
            except ValueError:
                flash("Invalid end date.", "error")
        docs = query.order_by(Document.created_at.desc()).all()
        for doc in docs:
            doc.user_can_edit = can_edit(current_user, doc)
        return render_template("dashboard.html", documents=docs)

    @app.route("/documents/upload", methods=["GET", "POST"])
    @login_required
    def upload_document():
        if current_user.role not in {"owner", "admin"}:
            abort(403)
        if request.method == "POST":
            file = request.files.get("file")
            name = request.form.get("name", "").strip()
            category = request.form.get("category", "General").strip() or "General"
            if not file or not file.filename:
                flash("Choose a file to upload.", "error")
            elif not allowed_file(file.filename):
                flash("File type not allowed. Allowed: PDF, TXT, DOCX, XLSX, PNG, JPG.", "error")
            elif not name or len(name) > 255 or len(category) > 80:
                flash("Enter a valid document name and category.", "error")
            else:
                original = secure_filename(file.filename)
                if not original:
                    flash("Invalid filename.", "error")
                    return render_template("upload.html")
                storage_name = uuid4().hex
                path = Path(app.config["UPLOAD_FOLDER"]) / storage_name
                file.save(path)
                size = path.stat().st_size
                if size > MAX_BYTES:
                    path.unlink(missing_ok=True)
                    abort(413)
                doc = Document(name=name, category=category, owner_id=current_user.id, storage_name=storage_name,
                               original_name=original, mime_type=file.mimetype or "application/octet-stream", size_bytes=size)
                db.session.add(doc)
                db.session.flush()
                record_event("document_upload", document_id=doc.id, details={"name": name, "category": category, "size_bytes": size})
                db.session.commit()
                flash("Document uploaded.", "success")
                return redirect(url_for("dashboard"))
        return render_template("upload.html")

    @app.route("/documents/<int:document_id>/download")
    @login_required
    def download_document(document_id):
        doc = get_authorized_document(document_id, "read")
        path = Path(app.config["UPLOAD_FOLDER"]) / doc.storage_name
        if not path.is_file():
            record_event("document_download", "error", document_id=doc.id, details={"reason": "file_missing"})
            db.session.commit()
            abort(404)
        record_event("document_download", document_id=doc.id, details={"size_bytes": doc.size_bytes})
        db.session.commit()
        return send_file(path, as_attachment=True, download_name=doc.original_name, mimetype="application/octet-stream", conditional=False)

    @app.route("/documents/<int:document_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_document(document_id):
        doc = get_authorized_document(document_id, "edit")
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            category = request.form.get("category", "General").strip() or "General"
            if not name or len(name) > 255 or len(category) > 80:
                flash("Enter a valid name and category.", "error")
            else:
                old_name = doc.name
                doc.name, doc.category, doc.updated_at = name, category, utcnow()
                record_event("document_edit", document_id=doc.id, details={"old_name": old_name, "new_name": name, "category": category})
                db.session.commit()
                flash("Document details updated.", "success")
                return redirect(url_for("dashboard"))
        return render_template("edit_document.html", document=doc)

    @app.route("/documents/<int:document_id>/delete", methods=["POST"])
    @login_required
    def delete_document(document_id):
        doc = get_authorized_document(document_id, "edit")
        if doc.owner_id != current_user.id and current_user.role != "admin":
            abort(403)
        doc.deleted_at = utcnow()
        record_event("document_delete", document_id=doc.id, details={"name": doc.name, "mode": "soft_delete"})
        db.session.commit()
        flash("Document moved to deleted state.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/documents/<int:document_id>/permissions", methods=["GET", "POST"])
    @login_required
    def permissions(document_id):
        doc = db.session.get(Document, document_id)
        if not doc or doc.deleted_at is not None:
            abort(404)
        if doc.owner_id != current_user.id:
            record_event("permission_manage", "denied", document_id=document_id)
            db.session.commit()
            abort(404)
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            level = request.form.get("level", "read")
            target = User.query.filter_by(email=email, active=True).first()
            if not target or target.id == current_user.id or level not in {"read", "edit"}:
                flash("Choose an existing active user and a valid permission.", "error")
            else:
                grant = Permission.query.filter_by(document_id=doc.id, user_id=target.id).first()
                old_level = grant.level if grant else None
                if grant:
                    grant.level = level
                    grant.granted_by_id = current_user.id
                    grant.created_at = utcnow()
                else:
                    db.session.add(Permission(document_id=doc.id, user_id=target.id, level=level, granted_by_id=current_user.id))
                record_event("permission_grant", document_id=doc.id, target_user_id=target.id,
                             details={"email": target.email, "old_level": old_level, "new_level": level})
                db.session.commit()
                flash("Permission saved.", "success")
                return redirect(url_for("permissions", document_id=doc.id))
        grants = Permission.query.filter_by(document_id=doc.id).all()
        return render_template("permissions.html", document=doc, grants=grants)

    @app.route("/documents/<int:document_id>/permissions/<int:grant_id>/revoke", methods=["POST"])
    @login_required
    def revoke_permission(document_id, grant_id):
        doc = db.session.get(Document, document_id)
        grant = db.session.get(Permission, grant_id)
        if not doc or doc.owner_id != current_user.id or not grant or grant.document_id != doc.id:
            record_event("permission_revoke", "denied", document_id=document_id, details={"grant_id": grant_id})
            db.session.commit()
            abort(404)
        target_id = grant.user_id
        target_email = grant.user.email
        db.session.delete(grant)
        record_event("permission_revoke", document_id=doc.id, target_user_id=target_id, details={"email": target_email})
        db.session.commit()
        flash("Access revoked. Future requests will be denied.", "success")
        return redirect(url_for("permissions", document_id=doc.id))

    @app.route("/admin")
    @login_required
    def admin_dashboard():
        if current_user.role != "admin":
            abort(403)
        events = AuditEvent.query.order_by(AuditEvent.id.desc()).limit(200).all()
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin.html", events=events, users=users, chain_valid=verify_audit_chain())

    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @login_required
    def change_role(user_id):
        if current_user.role != "admin":
            abort(403)
        user = db.session.get(User, user_id)
        role = request.form.get("role", "")
        if not user or role not in {"admin", "owner", "viewer"}:
            abort(400)
        old_role = user.role
        user.role = role
        record_event("user_role_change", target_user_id=user.id, details={"email": user.email, "old_role": old_role, "new_role": role})
        db.session.commit()
        flash("User role updated.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="File too large. Maximum size is 10 MB."), 413

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You are not allowed to perform this action."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="This resource was not found or you do not have access to it."), 404

    return app


app = create_app()

if __name__ == "__main__":
    if os.environ.get("SECRET_KEY", "dev-only-change-this-secret") == "dev-only-change-this-secret":
        print("WARNING: Using development SECRET_KEY. Set SECRET_KEY in .env before deployment.")
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
