# middleware.py
# CSRF-style protection for cookie-authenticated requests.
# Mirrors khelomore-server/.../middleware.py's OriginValidationMiddleware structurally.
#
# QuickPrint's web apps (customer hub, shop dashboard) are Bearer-token-only for v1 — no
# auth cookies are issued, so AUTH_COOKIE_NAMES is empty and this middleware is currently
# a structural no-op (kept in place, same as khelomore-server, so it activates
# automatically the moment any cookie-based auth flow is added, without needing to wire
# up this protection from scratch under time pressure later).

from django.conf import settings
from django.http import JsonResponse

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_COOKIE_NAMES = ()  # e.g. ("qp_customer_token", "qp_shop_token") if cookie auth is added


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
