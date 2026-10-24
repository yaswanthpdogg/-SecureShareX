import io
import os
import pytest
from app import create_app, db, User, Document, Permission, AuditEvent, verify_audit_chain

@pytest.fixture()
def app(tmp_path):
    upload_dir = tmp_path / "uploads"
    test_app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key-not-for-production",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "UPLOAD_FOLDER": str(upload_dir),
        "MAX_CONTENT_LENGTH": 10 * 1024 * 1024,
    })
    with test_app.app_context():
        db.drop_all()
        db.create_all()
    yield test_app
    with test_app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture()
def client(app):
    return app.test_client()

def make_user(app, email, role):
    with app.app_context():
        user = User(email=email, role=role)
        user.set_password("correct-horse-battery")
        db.session.add(user)
        db.session.commit()
        return user.id

def login(client, email):
    return client.post('/login', data={'email': email, 'password': 'correct-horse-battery'}, follow_redirects=True)

def test_registration_always_creates_viewer(client, app):
    response = client.post('/register', data={'email': 'new@example.com', 'password': 'correct-horse-battery', 'role': 'admin'}, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        user = User.query.filter_by(email='new@example.com').one()
        assert user.role == 'viewer'
        assert user.password_hash != 'correct-horse-battery'

def test_dashboard_requires_login(client):
    response = client.get('/dashboard')
    assert response.status_code in (302, 401)

def test_user_cannot_download_another_users_document(client, app, tmp_path):
    owner_id = make_user(app, 'owner@example.com', 'owner')
    make_user(app, 'intruder@example.com', 'viewer')
    with app.app_context():
        doc = Document(name='Secret', category='Legal', owner_id=owner_id, storage_name='secret.bin', original_name='secret.pdf', mime_type='application/pdf', size_bytes=6)
        db.session.add(doc); db.session.commit(); doc_id = doc.id
        (tmp_path / 'uploads' / 'secret.bin').write_bytes(b'secret')
    login(client, 'intruder@example.com')
    response = client.get(f'/documents/{doc_id}/download')
    assert response.status_code == 404
    with app.app_context():
        assert AuditEvent.query.filter_by(action='document_access', outcome='denied', document_id=doc_id).count() == 1

def test_granted_read_can_download_but_cannot_edit(client, app, tmp_path):
    owner_id = make_user(app, 'owner2@example.com', 'owner')
    viewer_id = make_user(app, 'viewer2@example.com', 'viewer')
    with app.app_context():
        doc = Document(name='Shared', category='General', owner_id=owner_id, storage_name='shared.bin', original_name='shared.txt', mime_type='text/plain', size_bytes=5)
        db.session.add(doc); db.session.flush()
        db.session.add(Permission(document_id=doc.id, user_id=viewer_id, level='read', granted_by_id=owner_id)); db.session.commit(); doc_id=doc.id
        (tmp_path / 'uploads' / 'shared.bin').write_bytes(b'hello')
    login(client, 'viewer2@example.com')
    assert client.get(f'/documents/{doc_id}/download').status_code == 200
    assert client.get(f'/documents/{doc_id}/edit').status_code == 404

def test_revoked_user_cannot_download(client, app, tmp_path):
    owner_id = make_user(app, 'owner3@example.com', 'owner')
    viewer_id = make_user(app, 'viewer3@example.com', 'viewer')
    with app.app_context():
        doc = Document(name='Revoked', category='General', owner_id=owner_id, storage_name='revoked.bin', original_name='revoked.txt', mime_type='text/plain', size_bytes=6)
        db.session.add(doc); db.session.flush()
        grant = Permission(document_id=doc.id, user_id=viewer_id, level='read', granted_by_id=owner_id)
        db.session.add(grant); db.session.commit(); doc_id=doc.id; grant_id=grant.id
        (tmp_path / 'uploads' / 'revoked.bin').write_bytes(b'secret')
    login(client, 'owner3@example.com')
    response = client.post(f'/documents/{doc_id}/permissions/{grant_id}/revoke')
    assert response.status_code == 302
    client.post('/logout')
    login(client, 'viewer3@example.com')
    assert client.get(f'/documents/{doc_id}/download').status_code == 404

def test_viewer_cannot_upload(client, app):
    make_user(app, 'viewer4@example.com', 'viewer')
    login(client, 'viewer4@example.com')
    assert client.get('/documents/upload').status_code == 403

def test_read_grant_cannot_edit_document(client, app):
    owner_id = make_user(app, 'owner4@example.com', 'owner')
    viewer_id = make_user(app, 'viewer5@example.com', 'viewer')
    with app.app_context():
        doc=Document(name='Read only',category='General',owner_id=owner_id,storage_name='ro.bin',original_name='ro.txt',mime_type='text/plain',size_bytes=1)
        db.session.add(doc);db.session.flush();db.session.add(Permission(document_id=doc.id,user_id=viewer_id,level='read',granted_by_id=owner_id));db.session.commit();doc_id=doc.id
    login(client, 'viewer5@example.com')
    assert client.post(f'/documents/{doc_id}/edit', data={'name':'Changed','category':'General'}).status_code == 404

def test_audit_chain_detects_tampering(app):
    with app.app_context():
        user=User(email='auditor@example.com',role='owner'); user.set_password('correct-horse-battery'); db.session.add(user); db.session.commit()
        from app import record_event
        record_event('test_event', actor=user, details={'ok': True}); db.session.commit()
        assert verify_audit_chain() is True
        event=AuditEvent.query.first(); event.action='changed_without_rehash'; db.session.commit()
        assert verify_audit_chain() is False
