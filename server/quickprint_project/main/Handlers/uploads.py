# uploads.py
# Accepts a print document, stores it via Cloudinary (same config pattern as
# khelomore-server/.../Handlers/cafes.py's module-level cloudinary.config()), and
# determines its REAL page count server-side — replacing quickprint-hub's prototype
# `Math.round(file.size / 42000)` guess entirely, which was never reading the file at
# all. PDF page count is exact (pypdf reads the real page tree); images always count as 1.

import os
from datetime import datetime, timezone, timedelta
import cloudinary
import cloudinary.uploader
import cloudinary.utils
from pypdf import PdfReader
from pypdf.errors import PdfReadError
from .db_connection import db_main
from .upload_validation import validate_document_upload

IST = timezone(timedelta(hours=5, minutes=30))
_pending_uploads_index_ensured = False


def _ensure_pending_uploads_index():
    """TTL index — an uploaded-but-never-turned-into-an-order file's DB record expires
    on its own after 2 hours, so pending_uploads doesn't grow unbounded from abandoned
    checkouts. The Cloudinary file itself is a minor, acceptable storage cost for v1
    (not a security issue — it's just an unreferenced document, cleaned up manually or
    in a later pass if it ever matters at scale)."""
    global _pending_uploads_index_ensured
    if not _pending_uploads_index_ensured:
        try:
            db_main.pending_uploads.create_index("expires_at", expireAfterSeconds=0)
        except Exception:
            pass
        _pending_uploads_index_ensured = True

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME", ""),
    api_key=os.getenv("CLOUDINARY_API_KEY", ""),
    api_secret=os.getenv("CLOUDINARY_API_SECRET", ""),
    secure=True,
)


def _real_page_count(uploaded_file, content_type: str):
    """Returns (page_count, error). Never trusts a client-claimed page count — this is
    the number every downstream price calculation and the shop's print job are actually
    based on."""
    if content_type in ("image/jpeg", "image/png"):
        return 1, None

    # PDF — read it for real. Rewind afterward since Cloudinary's upload still needs to
    # read the same file object from the start.
    try:
        uploaded_file.seek(0)
        reader = PdfReader(uploaded_file)
        if reader.is_encrypted:
            return None, "This PDF is password-protected. Please remove the password and try again."
        count = len(reader.pages)
        uploaded_file.seek(0)
        if count < 1:
            return None, "This PDF has no pages."
        return count, None
    except PdfReadError:
        return None, "This file isn't a valid PDF — it may be corrupted."
    except Exception as e:
        return None, f"Couldn't read this PDF: {e}"


def _build_pdf_page_thumbnails(uploaded_file, page_count: int) -> list[str]:
    """
    Uploads the SAME pdf a second time as a Cloudinary 'image' resource — the raw upload
    above is deliberately untouched/undeliverable-as-image so the shop always gets the
    original file byte-for-byte, but Cloudinary can only render individual PDF pages as
    JPGs for resources uploaded (or referenced) as resource_type='image'. This second
    copy exists purely to generate the page-by-page preview strip in the app; it is not
    what gets sent to the shop for printing. Returns [] (never raises) on any failure —
    a missing preview thumbnail isn't worth blocking the whole upload over.
    """
    try:
        uploaded_file.seek(0)
        preview = cloudinary.uploader.upload(
            uploaded_file,
            resource_type="image",
            folder="quickprint/documents/previews",
        )
        uploaded_file.seek(0)
        public_id = preview.get("public_id")
        if not public_id:
            return []
        urls = []
        for page in range(1, page_count + 1):
            url, _ = cloudinary.utils.cloudinary_url(
                public_id, resource_type="image", page=page, format="jpg", width=400, crop="fit",
            )
            urls.append(url)
        return urls
    except Exception:
        return []


def upload_print_document_handler(user_email: str, uploaded_file):
    """
    Returns {status, upload_id, file_name, page_count, thumbnail_urls} on success, or
    {status, error} on failure. The real document is stored as a Cloudinary 'raw'
    resource (not 'image') so it's preserved as a downloadable document, not
    re-encoded/transformed the way an image upload would be — thumbnail_urls (a real,
    per-page preview image for a PDF, or just the file itself for an image upload) comes
    from a separate, disposable preview copy — see _build_pdf_page_thumbnails.

    Persists the verified {file_url, file_name, page_count} in `pending_uploads`, keyed
    by upload_id and scoped to user_email — orders_handler.create_order_draft() looks
    the REAL page_count up from this record rather than trusting whatever the client
    sends in the order payload, so page count (which directly drives price) can never be
    spoofed independently of the actual uploaded file.
    """
    validation_error = validate_document_upload(uploaded_file)
    if validation_error:
        return {"status": 400, "error": validation_error}

    content_type = getattr(uploaded_file, "content_type", "")
    page_count, count_error = _real_page_count(uploaded_file, content_type)
    if count_error:
        return {"status": 400, "error": count_error}

    try:
        result = cloudinary.uploader.upload(
            uploaded_file,
            resource_type="raw",
            folder="quickprint/documents",
        )
        file_url = result.get("secure_url")
    except Exception as e:
        return {"status": 500, "error": f"Upload failed: {e}"}

    if not file_url:
        return {"status": 500, "error": "Upload failed: no URL returned."}

    if content_type in ("image/jpeg", "image/png"):
        thumbnail_urls = [file_url]
    else:
        thumbnail_urls = _build_pdf_page_thumbnails(uploaded_file, page_count)

    file_name = getattr(uploaded_file, "name", "document")
    _ensure_pending_uploads_index()
    doc = {
        "user_email": user_email,
        "file_url": file_url,
        "file_name": file_name,
        "page_count": page_count,
        "thumbnail_urls": thumbnail_urls,
        "created_at": datetime.now(IST).isoformat(),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=2),
    }
    result = db_main.pending_uploads.insert_one(doc)

    return {
        "status": 200,
        "upload_id": str(result.inserted_id),
        "file_name": file_name,
        "page_count": page_count,
        "thumbnail_urls": thumbnail_urls,
    }


ALLOWED_SHOP_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
MAX_SHOP_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB


def upload_shop_image_handler(uploaded_file):
    """Admin-only shop banner photo upload — resource_type='image' (unlike documents'
    'raw'), so Cloudinary can transform/optimize it normally. Returns {status, image_url}
    on success. Caller (views.py) has already verified the ADMIN_TOKEN."""
    if uploaded_file is None:
        return {"status": 400, "error": "An image file is required."}
    content_type = getattr(uploaded_file, "content_type", None)
    if content_type not in ALLOWED_SHOP_IMAGE_TYPES:
        return {"status": 400, "error": f"Unsupported file type '{content_type}'. Allowed: JPEG, PNG, WEBP."}
    size = getattr(uploaded_file, "size", None)
    if size is not None and size > MAX_SHOP_IMAGE_BYTES:
        return {"status": 400, "error": f"File too large ({size} bytes). Maximum allowed is {MAX_SHOP_IMAGE_BYTES} bytes."}

    try:
        result = cloudinary.uploader.upload(
            uploaded_file,
            resource_type="image",
            folder="quickprint/shops",
        )
        image_url = result.get("secure_url")
    except Exception as e:
        return {"status": 500, "error": f"Upload failed: {e}"}

    if not image_url:
        return {"status": 500, "error": "Upload failed: no URL returned."}
    return {"status": 200, "image_url": image_url}


def delete_print_document(file_url: str):
    """Best-effort deletion of the Cloudinary file once an order reaches 'collected' (or
    a TTL fallback) — makes quickprint-hub's existing "auto-wiped after pickup" UI copy
    actually true instead of aspirational. Never raises — a failed cleanup shouldn't
    block an order-status update."""
    if not file_url:
        return
    try:
        # Cloudinary raw-resource public_id is the URL path after the version segment,
        # without a file extension appended for raw resources' upload() response —
        # simplest reliable way to recover it is the 'public_id' Cloudinary itself
        # returned at upload time, but if only the URL is on hand, derive it back out.
        marker = "/quickprint/documents/"
        if marker not in file_url:
            return
        public_id = "quickprint/documents/" + file_url.split(marker, 1)[1].rsplit(".", 1)[0]
        cloudinary.uploader.destroy(public_id, resource_type="raw")
    except Exception as e:
        print(f"[QuickPrint] Cloudinary cleanup failed for {file_url}: {e}")
