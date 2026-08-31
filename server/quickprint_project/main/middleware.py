# middleware.py
# CSRF-style protection for cookie-authenticated requests.
# Mirrors khelomore-server/.../middleware.py's OriginValidationMiddleware exactly. Now
# actually active: verify_otp issues qp_customer_token / qp_shop_token /
# qp_super_admin_token HttpOnly cookies (SameSite=None, since the web frontends live on
# separate origins from this API), so without this middleware any website could trigger
# authenticated state-changing requests using a logged-in visitor's cookies.

from django.conf import settings
from django.http import JsonResponse

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_COOKIE_NAMES = ("qp_customer_token", "qp_shop_token", "qp_super_admin_token")


class OriginValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self._is_forged_cross_origin_request(request):
            return JsonResponse({"error": "Cross-origin request rejected."}, status=403)
        return self.get_response(request)

    def _is_forged_cross_origin_request(self, request):
        allowed_origins = getattr(settings, "ALLOWED_ORIGINS", [])
        if not allowed_origins:
            return False  # not configured yet — don't block traffic until it is

        if request.method not in UNSAFE_METHODS:
            return False

        # A valid Bearer header is already unforgeable by a third-party site, so its
        # presence makes the request safe regardless of what cookies happen to ride
        # along (see khelomore-server's middleware.py for the Android incidental-cookie
        # bug this specific check guards against).
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and len(auth_header) > len("Bearer "):
            return False

        if not AUTH_COOKIE_NAMES or not any(request.COOKIES.get(name) for name in AUTH_COOKIE_NAMES):
            return False  # not cookie-authenticated — Authorization-header requests are safe

        source = request.headers.get("Origin") or request.headers.get("Referer")
        if not source:
            return False

        return not any(source == o or source.startswith(o + "/") for o in allowed_origins)
