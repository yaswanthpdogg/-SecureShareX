import os

# Locate your target project folder structure path 
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TARGET_PATH = os.path.join(BASE_DIR, 'instance', 'private_uploads', 'my_exact_test_file_id')

# Minimalist binary valid PDF structure header block layout bytes
VALID_PDF_BYTES = b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\n0000000101 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF'

# Overwrite the dummy file with actual valid binary PDF headers
with open(TARGET_PATH, 'wb') as f:
    f.write(VALID_PDF_BYTES)

print("✅ Successfully injected genuine PDF structural data headers into the backend storage file!")