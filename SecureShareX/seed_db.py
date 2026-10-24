from app import app, db, User, Document, Permission

with app.app_context():
    # 1. Fetch your current logged-in user account
    current_viewer = User.query.filter_by(email="hxclassy9960@gmail.com").first()
    
    # 2. Fetch or create the mock document owner
    mock_owner = User.query.filter_by(email="owner@example.com").first()
    if not mock_owner:
        mock_owner = User(email="owner@example.com", role="viewer")
        mock_owner.set_password("password123")
        db.session.add(mock_owner)
        db.session.commit()

    # 3. Create the document owned by the mock owner
    test_doc = Document(
        name="test_document.pdf",
        category="Finance",
        owner_id=mock_owner.id,
        storage_name="unique_test_storage_key_123",
        original_name="test_document.pdf",
        mime_type="application/pdf",
        size_bytes=1024
    )
    db.session.add(test_doc)
    db.session.commit()

    # 4. CRITICAL FIX: Share the document explicitly with your active user account
    if current_viewer:
        share_permission = Permission(
            document_id=test_doc.id,
            user_id=current_viewer.id,
            level="read",  # Gives read permission to pass the filter query check
            granted_by_id=mock_owner.id
        )
        db.session.add(share_permission)
        db.session.commit()
        print("Success! Document inserted and permission shared with hxclassy9960@gmail.com.")
    else:
        print("Error: Could not find user account 'hxclassy9960@gmail.com' in the database.")