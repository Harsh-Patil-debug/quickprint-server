# auth_middleware.py
# Mirrors khelomore-server/.../Handlers/auth_middleware.py's shape exactly, simplified
# for QuickPrint's Bearer-only auth (no cookie fallback — see middleware.py's note on
# why) and two-role model (customer / shop_staff, distinguished by the JWT's own "role"
# claim from auth_handler.generate_token, not by which cookie arrived).

from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from . import auth_handler


def _extract_bearer_token(request):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1].strip()
    return None


def authenticate_customer_request(request):
    """
    Validates the Bearer token and requires role == 'customer'.
    Returns (email, None) if successful. Returns (None, Response) if validation fails.
    """
    token = _extract_bearer_token(request)
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
    token = _extract_bearer_token(request)
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
    Validates the static platform ADMIN_TOKEN — used only for the one-time shop-seeding
    endpoint (there's no super-admin panel in v1). Returns (True, None) or (False, Response).
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return False, Response({"error": "Authorization header missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
    parts = auth_header.split(" ")
    if len(parts) < 2:
        return False, Response({"error": "Authorization header is malformed"}, status=status.HTTP_401_UNAUTHORIZED)
    token = parts[1].strip()
    expected_token = getattr(settings, "ADMIN_TOKEN", "")
    if not expected_token or token != expected_token:
        return False, Response({"error": "Invalid admin authorization token"}, status=status.HTTP_401_UNAUTHORIZED)
    return True, None
