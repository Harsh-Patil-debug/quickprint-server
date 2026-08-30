# partner_applications.py
# Handlers for print-shop partnership applications submitted via quickprint-hub's public
# "Partner With Us" form. Mirrors khelomore-server/.../Handlers/partner_applications.py's
# structure exactly, field names swapped for a print shop instead of a gaming cafe
# (shopName/ratePerPageBW/ratePerPageColor/printerCount/capabilities instead of
# cafeName/pricePerHour/pcCount/specs).

from datetime import datetime, timezone, timedelta
import cloudinary
import cloudinary.uploader
from bson import ObjectId
from .db_connection import db_main
from .upload_validation import validate_image_upload
from . import input_validation

IST = timezone(timedelta(hours=5, minutes=30))

# Optional fields: stored if provided, never required.
_OPTIONAL_FIELDS = [
    "openingHours", "website", "instagram", "mapsLink", "message",
    "latitude", "longitude", "capabilities", "imageUrl",
]

# Public, unauthenticated form — cap how many photos a single submission can attach.
_MAX_PHOTOS = 3


def get_partner_applications_handler():
    """Fetches all partner applications (super admin only, enforced at the view layer)."""
    try:
        cursor = db_main.partner_applications.find({})
        apps = []
        for doc in cursor:
            app = {
                "id": str(doc["_id"]),
                "shopName": doc.get("shopName", ""),
                "ownerName": doc.get("ownerName", ""),
                "phone": doc.get("phone", ""),
                "email": doc.get("email", ""),
                "city": doc.get("city", ""),
                "state": doc.get("state", ""),
                "address": doc.get("address", ""),
                "area": doc.get("area", ""),
                "printerCount": doc.get("printerCount", 0),
                "ratePerPageBW": doc.get("ratePerPageBW"),
                "ratePerPageColor": doc.get("ratePerPageColor"),
                "status": doc.get("status", "pending"),
                "submittedAt": doc.get("submittedAt") or datetime.now(IST).isoformat(),
                "photos": doc.get("photos", []),
                "logo": doc.get("logo", ""),
            }
            for field in _OPTIONAL_FIELDS:
                app[field] = doc.get(field, "")
            apps.append(app)
        return {"status": "success", "applications": apps}, 200
    except Exception as e:
        return {"status": "error", "message": f"Failed to retrieve applications: {e}"}, 500


def create_partner_application_handler(data, files=None):
    """
    Creates a new partner application. `files` (optional) may contain a multi-file
    "photos" upload and a single "logo" upload — both go to Cloudinary. A failed/invalid
    image upload does not fail the whole application; it's just omitted.
    """
    try:
        shop_name = data.get("shopName")
        owner_name = data.get("ownerName")
        phone = data.get("phone")
        email = data.get("email")
        city = data.get("city")
        state = data.get("state")
        address = data.get("address")
        printer_count = data.get("printerCount")
        area = data.get("area")
        rate_bw = data.get("ratePerPageBW")
        rate_color = data.get("ratePerPageColor")

        if not shop_name or not owner_name or not phone or not email or not city or not state \
           or not address or not printer_count or not area or rate_bw is None:
            return {"status": "error", "message": "All required fields must be filled in."}, 400

        # SECURITY: this is a fully public, unauthenticated form-submission endpoint — every
        # field below only ever had a client-side check, which a direct POST bypasses.
        validation_error = (
            input_validation.validate_text(shop_name, "Shop name", max_len=100)
            or input_validation.validate_text(owner_name, "Owner name", max_len=80)
            or input_validation.validate_phone(phone)
            or input_validation.validate_email(email)
            or input_validation.validate_text(city, "City", max_len=60)
            or input_validation.validate_text(state, "State", max_len=60)
            or input_validation.validate_text(address, "Address", max_len=400)
            or input_validation.validate_text(area, "Area", max_len=100)
        )
        if validation_error:
            return {"status": "error", "message": validation_error}, 400

        printer_count, printer_count_error = input_validation.parse_bounded_number(
            printer_count, "Printer count", min_val=1, max_val=99
        )
        if printer_count_error:
            return {"status": "error", "message": printer_count_error}, 400

        rate_bw, rate_bw_error = input_validation.parse_bounded_number(
            rate_bw, "Rate per page (B&W)", min_val=0, max_val=1000, is_float=True
        )
        if rate_bw_error:
            return {"status": "error", "message": rate_bw_error}, 400

        rate_color_val = None
        if rate_color:
            rate_color_val, err = input_validation.parse_bounded_number(
                rate_color, "Rate per page (Color)", min_val=0, max_val=1000, is_float=True
            )
            if err:
                return {"status": "error", "message": err}, 400

        for coord_field, label, bound in (("latitude", "Latitude", 90), ("longitude", "Longitude", 180)):
            value = data.get(coord_field)
            if value:
                _, err = input_validation.parse_bounded_number(value, label, min_val=-bound, max_val=bound, is_float=True)
                if err:
                    return {"status": "error", "message": err}, 400

        for field in ("website", "mapsLink", "imageUrl"):
            value = data.get(field)
            if value:
                err = input_validation.validate_url(value, field)
                if err:
                    return {"status": "error", "message": err}, 400

        optional_text_limits = {"openingHours": 80, "instagram": 80, "message": 800, "capabilities": 200}
        for field, max_len in optional_text_limits.items():
            value = data.get(field)
            if value:
                err = input_validation.validate_text(value, field, max_len=max_len, required=False)
                if err:
                    return {"status": "error", "message": err}, 400

        doc = {
            "shopName": shop_name,
            "ownerName": owner_name,
            "phone": phone,
            "email": email,
            "city": city,
            "state": state,
            "address": address,
            "printerCount": printer_count,
            "area": area,
            "ratePerPageBW": rate_bw,
            "status": "pending",
            "submittedAt": datetime.now(IST).isoformat(),
        }
        if rate_color_val is not None:
            doc["ratePerPageColor"] = rate_color_val
        for field in _OPTIONAL_FIELDS:
            value = data.get(field)
            if value:
                doc[field] = value

        photo_urls = []
        logo_url = ""
        if files:
            photo_files = files.getlist("photos") if hasattr(files, "getlist") else ([files["photos"]] if "photos" in files else [])
            photo_files = photo_files[:_MAX_PHOTOS]
            for photo_file in photo_files:
                validation_error = validate_image_upload(photo_file)
                if validation_error:
                    continue  # skip invalid files silently rather than fail the whole application
                try:
                    result = cloudinary.uploader.upload(photo_file, folder="quickprint/partner_applications")
                    url = result.get("secure_url")
                    if url:
                        photo_urls.append(url)
                except Exception as upload_err:
                    print(f"[Cloudinary] Partner application photo upload failed: {upload_err}")

            if "logo" in files:
                logo_file = files["logo"]
                validation_error = validate_image_upload(logo_file)
                if not validation_error:
                    try:
                        result = cloudinary.uploader.upload(logo_file, folder="quickprint/partner_applications")
                        logo_url = result.get("secure_url") or ""
                    except Exception as upload_err:
                        print(f"[Cloudinary] Partner application logo upload failed: {upload_err}")

        if photo_urls:
            doc["photos"] = photo_urls
        if logo_url:
            doc["logo"] = logo_url

        res = db_main.partner_applications.insert_one(doc)
        doc["id"] = str(res.inserted_id)
        doc.pop("_id", None)
        return {"status": "success", "application": doc}, 201
    except Exception as e:
        return {"status": "error", "message": f"Failed to submit application: {e}"}, 500


def update_partner_application_status_handler(app_id, status_val):
    """Updates the status of a partner application (super admin only)."""
    try:
        oid = ObjectId(app_id)
    except Exception:
        return {"status": "error", "message": "Invalid application ID format."}, 400
    enum_error = input_validation.validate_enum(status_val, {"pending", "approved", "rejected"}, "Status")
    if enum_error:
        return {"status": "error", "message": enum_error}, 400
    try:
        res = db_main.partner_applications.update_one({"_id": oid}, {"$set": {"status": status_val}})
        if res.matched_count == 0:
            return {"status": "error", "message": "Application not found."}, 404
        return {"status": "success", "message": f"Application status updated to {status_val}."}, 200
    except Exception as e:
        return {"status": "error", "message": f"Failed to update application: {e}"}, 500
