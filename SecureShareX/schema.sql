-- Reference schema for PostgreSQL. The Flask-SQLAlchemy models in app.py are authoritative.
CREATE TABLE "user" (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash VARCHAR(256) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','owner','viewer')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE document (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(80) NOT NULL DEFAULT 'General',
  owner_id BIGINT NOT NULL REFERENCES "user"(id),
  storage_name VARCHAR(80) NOT NULL UNIQUE,
  original_name VARCHAR(255) NOT NULL,
  mime_type VARCHAR(120) NOT NULL DEFAULT 'application/octet-stream',
  size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ NULL
);
CREATE TABLE permission (
  id BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL REFERENCES document(id),
  user_id BIGINT NOT NULL REFERENCES "user"(id),
  level VARCHAR(10) NOT NULL CHECK (level IN ('read','edit')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  granted_by_id BIGINT NOT NULL REFERENCES "user"(id),
  UNIQUE(document_id,user_id)
);
CREATE TABLE audit_event (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_id BIGINT NULL REFERENCES "user"(id),
  actor_email VARCHAR(254) NOT NULL,
  action VARCHAR(60) NOT NULL,
  document_id BIGINT NULL,
  target_user_id BIGINT NULL,
  outcome VARCHAR(20) NOT NULL,
  details TEXT NOT NULL DEFAULT '{}',
  previous_hash VARCHAR(64) NOT NULL,
  event_hash VARCHAR(64) NOT NULL UNIQUE
);
CREATE INDEX ix_document_owner_created ON document(owner_id, created_at DESC);
CREATE INDEX ix_permission_user_document ON permission(user_id, document_id);
CREATE INDEX ix_audit_occurred_action ON audit_event(occurred_at DESC, action);
