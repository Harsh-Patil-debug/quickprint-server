# auth_middleware.py
# Mirrors khelomore-server/.../Handlers/auth_middleware.py's shape exactly, including its
# cookie fallback: an Authorization: Bearer header is tried first, falling back to this
# role's own HttpOnly cookie (set at verify_otp time — see views.py) if there's no header.
# The cookie fallback matters for browser requests where a page load can't easily attach a
# custom header (e.g. a plain <a>/<form> navigation) and keeps sessions alive for visitors
# whose browser blocks localStorage in some contexts but not first-party cookies.

import hmac
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from . import auth_handler


def _extract_token(request, cookie_name: str = None):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1].strip()
    if cookie_name:
        return request.COOKIES.get(cookie_name)
    return None


def authenticate_customer_request(request):
    """
    Validates the Bearer token (or qp_customer_token cookie) and requires role ==
    'customer'. Returns (email, None) if successful. Returns (None, Response) if not.
    """
    token = _extract_token(request, "qp_customer_token")
    if not token:
        return None, Response({"error": "Authorization token missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        payload = auth_handler.verify_token(token)
    except Exception as e:
        return None, Response({"error": f"Invalid token: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
    if payload["role"] != "customer":
        return None, Response({"error": "A customer account is required."}, status=status.HTTP_403_FORBIDDEN)
    return payload["email"], None


def authenticate_shop_staff_request(request):
    """
    Validates the Bearer token, requires role == 'shop_staff', and returns the staff
    member's own shop_id — every shop-dashboard endpoint scopes its query to THIS
    shop_id, never one supplied by the client, so a shop can only ever act on its own
    order queue.
    Returns ({email, shop_id}, None) if successful. Returns (None, Response) if not.
    """
    token = _extract_token(request, "qp_shop_token")
    if not token:
        return None, Response({"error": "Authorization token missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        payload = auth_handler.verify_token(token)
    except Exception as e:
        return None, Response({"error": f"Invalid token: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
    if payload["role"] != "shop_staff":
        return None, Response({"error": "A shop staff account is required."}, status=status.HTTP_403_FORBIDDEN)

    from .db_connection import db_main
    staff = db_main.shop_staff.find_one({"email": payload["email"], "status": "Active"})
    if not staff:
        return None, Response({"error": "Shop staff account not found or inactive."}, status=status.HTTP_403_FORBIDDEN)
    return {"email": payload["email"], "shop_id": staff.get("shop_id"), "role": staff.get("role", "staff")}, None


def authenticate_admin_request(request):
    """
    Validates the static platform ADMIN_TOKEN. Returns (True, None) or (False, Response).
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return False, Response({"error": "Authorization header missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
    parts = auth_header.split(" ")
    if len(parts) < 2:
        return False, Response({"error": "Authorization header is malformed"}, status=status.HTTP_401_UNAUTHORIZED)
    token = parts[1].strip()
    expected_token = getattr(settings, "ADMIN_TOKEN", "")
    if not expected_token or not hmac.compare_digest(token, expected_token):
        return False, Response({"error": "Invalid admin authorization token"}, status=status.HTTP_401_UNAUTHORIZED)
    return True, None


def authenticate_super_admin_request(request):
    """
    Validates EITHER the static ADMIN_TOKEN OR a dynamic super_admin JWT — same dual-path
    model as khelomore-server's authenticate_super_admin_request. The static token stays
    valid so nothing that already used it (e.g. the admin panel's original hardcoded
    VITE_ADMIN_TOKEN setup) breaks; a real logged-in super admin's JWT works too, and is
    what the login/signup flow now issues. Returns (identifier, None) on success —
    identifier is "super_admin_static" for the static-token path, or the admin's own email
    for a real session — or (None, Response) on failure.
    """
    token = _extract_token(request, "qp_super_admin_token")
    if not token:
        return None, Response({"error": "Authorization token missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)

    expected_static = getattr(settings, "ADMIN_TOKEN", "")
    # Constant-time comparison — a plain == leaks how many leading characters matched via
    # response timing, in principle letting an attacker recover ADMIN_TOKEN byte-by-byte
    # over many requests. Low practical risk over the internet (network jitter dwarfs the
    # signal), but hmac.compare_digest closes it for free.
    if expected_static and hmac.compare_digest(token, expected_static):
        return "super_admin_static", None

    try:
        payload = auth_handler.verify_token(token)
    except Exception as e:
        return None, Response({"error": f"Invalid token: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
    if payload["role"] != "super_admin":
        return None, Response({"error": "Access denied. Not a super admin."}, status=status.HTTP_403_FORBIDDEN)

    from .db_connection import db_main
    admin = db_main.super_admin.find_one({"email": payload["email"]})
    if not admin:
        return None, Response({"error": "Access denied. Not a super admin."}, status=status.HTTP_403_FORBIDDEN)
    if admin.get("status") != "Active":
        return None, Response({"error": "Super admin account is not active."}, status=status.HTTP_403_FORBIDDEN)
    return payload["email"], None
