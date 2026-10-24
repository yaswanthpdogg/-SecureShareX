import os
from app import app, db, User, Document, Permission

# Define paths matching your project layout
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'instance', 'private_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Define our exact static identifier
FIXED_STORAGE_NAME = "my_exact_test_file_id"

with app.app_context():
    # 1. Clear out older mock documents to avoid collision issues
    Document.query.filter_by(name="test_document.pdf").delete()
    db.session.commit()

    # 2. Grab your logged in user accounts
    current_viewer = User.query.filter_by(email="hxclassy9960@gmail.com").first()
    mock_owner = User.query.filter_by(email="owner@example.com").first()

    # 3. Insert the clean document entry with our fixed static identifier string
    test_doc = Document(
        name="test_document.pdf",
        category="Finance",
        owner_id=mock_owner.id if mock_owner else 1,
        storage_name=FIXED_STORAGE_NAME,
        original_name="test_document.pdf",
        mime_type="application/pdf",
        size_bytes=1024
    )
    db.session.add(test_doc)
    db.session.commit()

    # 4. Bind the view access permission settings record
    if current_viewer and mock_owner:
        # Clear duplicate permission paths if any exist
        Permission.query.filter_by(document_id=test_doc.id, user_id=current_viewer.id).delete()
        
        share_permission = Permission(
            document_id=test_doc.id,
            user_id=current_viewer.id,
            level="read",
            granted_by_id=mock_owner.id
        )
        db.session.add(share_permission)
        db.session.commit()

    # 5. Automatically create the matching physical file item on disk storage folder
    target_file_path = os.path.join(UPLOAD_FOLDER, FIXED_STORAGE_NAME)
    with open(target_file_path, "w") as f:
        f.write("This is placeholder text inside the dummy testing document file.")

    print(f"✅ Success! Database entry matching file created at: {target_file_path}")