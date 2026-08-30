# upload_validation.py
# Shared validation for user-uploaded print documents before they're forwarded to
# Cloudinary. Mirrors khelomore-server/.../Handlers/upload_validation.py's structure and
# reasoning, adapted for documents instead of images.

ALLOWED_DOCUMENT_CONTENT_TYPES = {"application/pdf", "image/jpeg", "image/png"}
# Matches quickprint-hub's existing UI copy ("PDF, DOCX, PNG · up to 50 MB").
MAX_DOCUMENT_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

# .docx real page counts need a rendering engine (LibreOffice headless or similar) —
# deliberately out of scope for v1 (see plan). Recognized here only so the upload
# endpoint can give a clear, specific rejection message instead of a generic
# "unsupported file type".
DOCX_CONTENT_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
}


def validate_document_upload(uploaded_file):
    """
    Returns None if the file is an acceptable print-job upload, otherwise an error
    message. Content-Type is client-supplied and not proof of real file content — the
    actual page-counting step in uploads.py additionally verifies a PDF genuinely parses
    as one, which is a much stronger check than trusting this header.
    """
    if uploaded_file is None:
        return "A document is required."

    content_type = getattr(uploaded_file, "content_type", None)
    if content_type in DOCX_CONTENT_TYPES:
        return "DOCX isn't supported yet — please convert to PDF first."
    if content_type not in ALLOWED_DOCUMENT_CONTENT_TYPES:
        return f"Unsupported file type '{content_type}'. Allowed: PDF, PNG, JPEG."

    size = getattr(uploaded_file, "size", None)
    if size is not None and size > MAX_DOCUMENT_UPLOAD_BYTES:
        return f"File too large ({size} bytes). Maximum allowed is {MAX_DOCUMENT_UPLOAD_BYTES} bytes."

    return None
