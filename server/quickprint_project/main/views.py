"""
QuickPrint — API Views
─────────────────────────────────────────────────────────────────────────────
Thin wrappers only, matching khelomore-server/.../gaming_project/main/views.py's
convention exactly. Business logic lives exclusively in Handlers/. Each Handler
function here already returns a dict containing its own "status" key (the HTTP
status code) — every view just pops that off and returns the rest as the body.
─────────────────────────────────────────────────────────────────────────────
"""

from urllib.parse import quote, urlparse
from django.conf import settings
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.parsers import MultiPartParser, FormParser
from .Handlers import (
    status_check,
    auth_handler,
    auth_middleware,
    shops,
    uploads,
    orders_handler,
    partner_applications,
)


def _respond(result: dict) -> Response:
    status_code = result.pop("status")
    return Response(result, status=status_code)


def _is_allowed_oauth_redirect_target(target: str) -> bool:
    """
    SECURITY: `return_url`/`state` is unauthenticated, attacker-influenceable input that
    becomes the final redirect target after Google auth completes (carrying the session
    token in the query string). Only our own frontends' exact origins may be used — NOT
    an arbitrary https:// URL. Ported from khelomore-server/.../views.py's
    _is_allowed_oauth_redirect_target, minus the bookmyconsole:// / exp:// mobile-scheme
    cases QuickPrint doesn't have (web-only, no native app).
    """
    if not target:
        return False
    try:
        parsed = urlparse(target)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin in settings.ALLOWED_ORIGINS:
                return True
            if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1"):
                return True
    except Exception:
        pass
    return False


# ── Status ─────────────────────────────────────────────────────────────────────

class StatusCheckView(APIView):
    """GET /status/ — server health check (public)"""
    def get(self, request):
        return Response(status_check.status_check())


# ── Customer auth ──────────────────────────────────────────────────────────────

class CustomerRegisterView(APIView):
    """POST /auth/register/ — Body: { email, password, name }"""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        data = request.data
        result = auth_handler.register_customer(
            email=data.get("email", ""),
            password=data.get("password", ""),
            name=data.get("name", ""),
        )
        return _respond(result)


class CustomerLoginView(APIView):
    """POST /auth/login/ — Body: { email, password }"""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        data = request.data
        result = auth_handler.login_customer(
            email=data.get("email", ""),
            password=data.get("password", ""),
        )
        return _respond(result)


class CustomerGoogleLoginRedirectView(APIView):
    """
    GET /auth/google/login/?return_url=<frontend URL to land on after login>
    Redirects to Google's login page. Mirrors khelomore-server's
    BookMyConsoleGoogleLoginView exactly — same redirect-based Authorization Code flow.
    """
    def get(self, request):
        return_url = request.query_params.get("return_url", settings.CUSTOMER_WEB_URL)
        if not _is_allowed_oauth_redirect_target(return_url):
            return Response({"error": "Unauthorized redirect target."}, status=400)

        redirect_uri = f"{settings.BACKEND_URL}/api/v1/main/auth/google/callback/"
        auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={settings.GOOGLE_CLIENT_ID}"
            f"&redirect_uri={quote(redirect_uri, safe='')}"
            "&response_type=code"
            "&scope=openid%20email%20profile"
            "&prompt=select_account"
            f"&state={quote(return_url, safe='')}"
        )
        response = HttpResponse(status=302)
        response["Location"] = auth_url
        return response


class CustomerGoogleCallbackView(APIView):
    """
    GET /auth/google/callback/
    Receives the auth code from Google, verifies it, and redirects back to the frontend
    with the session attached. Mirrors khelomore-server's BookMyConsoleGoogleCallbackView,
    minus the mobile-app cookie/scheme handling QuickPrint (web-only) doesn't need.

    SECURITY: the session is carried as an AES-256-CBC encrypted_response + iv, never a
    raw token — khelomore-server never puts a directly-usable token in a redirect URL
    either, for good reason: URLs land in server access logs, browser history, and
    (if the landing page loads any third-party resource before clearing the URL) the
    Referer header sent to that third party. An encrypted blob in the same spot is inert
    without the separate ENCRYPTION_KEY, which never appears in the URL itself.
    """
    def get(self, request):
        code = request.query_params.get("code")
        state = request.query_params.get("state", settings.CUSTOMER_WEB_URL)
        if not code:
            return Response({"error": "Auth code not provided."}, status=400)
        if not _is_allowed_oauth_redirect_target(state):
            return Response({"error": "Unauthorized redirect target."}, status=403)

        redirect_uri = f"{settings.BACKEND_URL}/api/v1/main/auth/google/callback/"
        result = auth_handler.google_login_customer_via_code(code, redirect_uri)
        if result.get("status") != 200:
            return _respond(result)

        import json
        response_json = json.dumps({"token": result["token"], "user": result["user"]})
        enc_resp, iv = auth_handler.encrypt_data(response_json)

        separator = "&" if "?" in state else "?"
        redirect_url = f"{state}{separator}encrypted_response={quote(enc_resp)}&iv={quote(iv)}"
        response = HttpResponse(status=302)
        response["Location"] = redirect_url
        return response


class CustomerLogoutView(APIView):
    """POST /auth/logout/ — Body: { } (Bearer token in Authorization header)"""
    def post(self, request):
        email, error_response = auth_middleware.authenticate_customer_request(request)
        if error_response:
            return error_response
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split(" ")[1].strip() if auth_header.startswith("Bearer ") else ""
        auth_handler.revoke_token(token)
        return Response({"message": "Logged out."}, status=200)


class CustomerMeView(APIView):
    """GET /auth/me/ — resolves the current customer from their Bearer token"""
    def get(self, request):
        email, error_response = auth_middleware.authenticate_customer_request(request)
        if error_response:
            return error_response
        from .Handlers.db_connection import db_main
        user = db_main.users.find_one({"email": email})
        if not user:
            return Response({"error": "Account not found."}, status=404)
        return Response({"id": str(user["_id"]), "email": email, "name": user.get("name", "")})


# ── Super admin auth ────────────────────────────────────────────────────────────
# Email+password + OTP, AES-256-CBC encrypted payloads — same security model as
# khelomore-server's super_admin flow. Register is itself gated so only an
# already-authenticated super admin (or the static ADMIN_TOKEN) can provision another
# one; the very first account is created via create_super_admin.py (see that script).

def _reject_unauthorized_super_admin_register(request):
    """SECURITY: without this, anyone could hit /super-admin/register/ and self-provision
    a super admin account. Returns a 403 Response if blocked, otherwise None."""
    _, error_response = auth_middleware.authenticate_super_admin_request(request)
    if error_response:
        return Response({"error": "Not authorized to create a super admin account."}, status=403)
    return None


class SuperAdminRegisterView(APIView):
    """POST /super-admin/register/ — Body: { name, email, password, iv } (AES-CBC encrypted)"""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        guard_error = _reject_unauthorized_super_admin_register(request)
        if guard_error:
            return guard_error
        data = request.data
        result, status_code = auth_handler.register_super_admin(
            name_enc=data.get("name", ""),
            email_enc=data.get("email", ""),
            password_enc=data.get("password", ""),
            iv=data.get("iv", ""),
        )
        return Response(result, status=status_code)


class SuperAdminLoginView(APIView):
    """POST /super-admin/login/ — Body: { email, password, iv } (AES-CBC encrypted)"""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        data = request.data
        result, status_code = auth_handler.login_super_admin(
            email_enc=data.get("email", ""),
            password_enc=data.get("password", ""),
            iv=data.get("iv", ""),
        )
        return Response(result, status=status_code)


class SuperAdminVerifyOTPView(APIView):
    """POST /super-admin/verify-otp/ — Body: { email, otp_code, iv } (AES-CBC encrypted)"""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        data = request.data
        result, status_code = auth_handler.verify_super_admin_otp(
            email_enc=data.get("email", ""),
            otp_enc=data.get("otp_code", ""),
            iv=data.get("iv", ""),
        )
        return Response(result, status=status_code)


class SuperAdminResendOTPView(APIView):
    """POST /super-admin/resend-otp/ — Body: { email, iv } (AES-CBC encrypted)"""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        data = request.data
        result, status_code = auth_handler.resend_super_admin_otp(
            email_enc=data.get("email", ""),
            iv=data.get("iv", ""),
        )
        return Response(result, status=status_code)


class SuperAdminMeView(APIView):
    """GET /super-admin/me/ — resolves the current super admin from their Bearer JWT.
    The static-ADMIN_TOKEN path (authenticate_super_admin_request's other branch) has no
    real account behind it, so it returns a synthetic identity here rather than 404ing."""
    def get(self, request):
        identifier, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        if identifier == "super_admin_static":
            return Response({"user": {"id": "static", "email": "", "name": "Platform Admin", "role": "super_admin"}})
        from .Handlers.db_connection import db_main
        admin = db_main.super_admin.find_one({"email": identifier})
        if not admin:
            return Response({"error": "Account not found."}, status=404)
        return Response({"user": {"id": str(admin["_id"]), "email": identifier, "name": admin.get("name", ""), "role": "super_admin"}})


class SuperAdminLogoutView(APIView):
    """POST /super-admin/logout/ — same auth-then-revoke shape as CustomerLogoutView /
    ShopStaffLogoutView, for consistency (revoking is a self-only action either way — a
    caller can only ever revoke the exact token they already hold — but requiring a valid
    session first keeps this endpoint from being a no-auth-required token-string parser)."""
    def post(self, request):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split(" ")[1].strip() if auth_header.startswith("Bearer ") else ""
        auth_handler.revoke_token(token)
        return Response({"message": "Logged out."}, status=200)


# ── Partner applications ────────────────────────────────────────────────────────

class PartnerApplicationListCreateView(APIView):
    """
    POST /partner-applications/ — submit a new application (public, unauthenticated)
    GET /partner-applications/ — list applications (super admin only)
    """
    parser_classes = (MultiPartParser, FormParser)
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        result, status_code = partner_applications.create_partner_application_handler(request.data, request.FILES)
        return Response(result, status=status_code)

    def get(self, request):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        result, status_code = partner_applications.get_partner_applications_handler()
        return Response(result, status=status_code)


class PartnerApplicationDetailView(APIView):
    """PATCH /partner-applications/<app_id>/ — update application status (super admin only)"""
    def patch(self, request, app_id):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        status_val = request.data.get("status")
        if not status_val:
            return Response({"error": "Status is required."}, status=400)
        result, status_code = partner_applications.update_partner_application_status_handler(app_id, status_val)
        return Response(result, status=status_code)


# ── Shop staff auth ─────────────────────────────────────────────────────────────

class ShopStaffRegisterView(APIView):
    """POST /shop-auth/register/ — super-admin-provisioned only. Body: { email, password, name, shop_id, role }.
    Uses authenticate_super_admin_request (static ADMIN_TOKEN OR a real super_admin
    session), matching every other admin-surface endpoint — previously this was the one
    endpoint still gated on the static token alone, which meant a logged-in super admin
    (as opposed to whoever holds the raw secret) couldn't use it."""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        data = request.data
        result = auth_handler.register_shop_staff(
            email=data.get("email", ""),
            password=data.get("password", ""),
            name=data.get("name", ""),
            shop_id=data.get("shop_id", ""),
            role=data.get("role", "staff"),
        )
        return _respond(result)


class ShopOwnerSignupView(APIView):
    """
    POST /shop-auth/signup/ — public self-service signup for a shop OWNER. Body:
    { email, password, name }. Mirrors khelomore-server's cafe-owner self-registration:
    no ADMIN_TOKEN needed, but the email must already be listed as a shop's owner_email
    (set by the super admin via the 'Add Print Shop' form) or this returns 403.
    """
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        data = request.data
        result = auth_handler.register_shop_owner(
            email=data.get("email", ""),
            password=data.get("password", ""),
            name=data.get("name", ""),
        )
        return _respond(result)


class ShopStaffLoginView(APIView):
    """POST /shop-auth/login/ — Body: { email, password }"""
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request):
        data = request.data
        result = auth_handler.login_shop_staff(
            email=data.get("email", ""),
            password=data.get("password", ""),
        )
        return _respond(result)


class ShopStaffLogoutView(APIView):
    """POST /shop-auth/logout/"""
    def post(self, request):
        staff, error_response = auth_middleware.authenticate_shop_staff_request(request)
        if error_response:
            return error_response
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split(" ")[1].strip() if auth_header.startswith("Bearer ") else ""
        auth_handler.revoke_token(token)
        return Response({"message": "Logged out."}, status=200)


class ShopStaffMeView(APIView):
    """GET /shop-auth/me/"""
    def get(self, request):
        staff, error_response = auth_middleware.authenticate_shop_staff_request(request)
        if error_response:
            return error_response
        return Response(staff)


# ── Shops ────────────────────────────────────────────────────────────────────────

class ShopListView(APIView):
    """GET /shops/?lat=&lng=&radius_km=&color=&spiral=&open24=&sort= — public directory"""
    def get(self, request):
        q = request.query_params
        result = shops.get_shops_handler(
            lat=q.get("lat"),
            lng=q.get("lng"),
            radius_km=q.get("radius_km"),
            color=q.get("color") == "true",
            spiral=q.get("spiral") == "true",
            open24=q.get("open24") == "true",
            sort=q.get("sort", "distance"),
        )
        return _respond(result)


class ShopDetailView(APIView):
    """GET /shops/<shop_id>/?lat=&lng="""
    def get(self, request, shop_id):
        q = request.query_params
        result = shops.get_shop_by_id_handler(shop_id, lat=q.get("lat"), lng=q.get("lng"))
        return _respond(result)


class ShopProfileView(APIView):
    """GET/PATCH /shop/profile/ — the authenticated shop staff member's OWN shop.
    Editing (PATCH) is owner-tier only; staff can still view via GET."""
    def get(self, request):
        staff, error_response = auth_middleware.authenticate_shop_staff_request(request)
        if error_response:
            return error_response
        result = shops.get_shop_by_id_handler(staff["shop_id"])
        return _respond(result)

    def patch(self, request):
        staff, error_response = auth_middleware.authenticate_shop_staff_request(request)
        if error_response:
            return error_response
        if staff["role"] != "owner":
            return Response({"error": "Only the shop owner can edit shop settings."}, status=403)
        result = shops.update_shop_handler(staff["shop_id"], request.data)
        return _respond(result)


class ShopSeedView(APIView):
    """POST /shops/seed/ — one-time idempotent seed, platform ADMIN_TOKEN required"""
    def post(self, request):
        is_admin, error_response = auth_middleware.authenticate_admin_request(request)
        if error_response:
            return error_response
        result = shops.seed_shops_handler()
        return _respond(result)


class ShopParseMapsUrlView(APIView):
    """
    GET /shops/parse-maps-url/?url=... — resolves a Google Maps link (CORS-safe).
    Public/unauthenticated, matching khelomore-server's CafeParseMapsUrlView exactly:
    stateless, read-only, only ever follows a redirect for Google's own shortener host.
    """
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "upload"  # same "makes an outbound network call per request" reasoning

    def get(self, request):
        url = request.query_params.get("url")
        if not url:
            return Response({"error": "Missing 'url' parameter."}, status=400)
        result = shops.parse_google_maps_url_handler(url)
        if result.get("status") == "error":
            return Response(result, status=400)
        return Response(result, status=200)


# ── Shops (super admin) ──────────────────────────────────────────────────────────

class AdminShopListCreateView(APIView):
    """
    GET /admin/shops/ — every shop, including soft-deleted ones.
    POST /admin/shops/ — onboard a new shop. Body accepts every ADMIN_EDITABLE_SHOP_FIELDS
    key (name/area/address/phone/lat/lng required) plus optional owner_password — if
    present alongside owner_email/owner_name, a shop_staff 'owner' login is provisioned
    for the new shop in the same request, matching the real-world "onboard a shop and
    hand them a login" admin action in one step.
    """
    def get(self, request):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        result = shops.admin_list_all_shops_handler()
        return _respond(result)

    def post(self, request):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        data = request.data
        result = shops.admin_create_shop_handler(data)
        if result.get("status") != 201:
            return _respond(result)

        shop = result["shop"]
        owner_password = data.get("owner_password", "")
        if owner_password and data.get("owner_email"):
            staff_result = auth_handler.register_shop_staff(
                email=data.get("owner_email", ""),
                password=owner_password,
                name=data.get("owner_name", ""),
                shop_id=shop["id"],
                role="owner",
            )
            if staff_result.get("status") == 201:
                shop["staffAccountCreated"] = True
            else:
                # Shop was created successfully either way — surface the login-provisioning
                # error without discarding the shop, so an admin can just add the login
                # separately (e.g. via ShopStaffRegisterView) instead of losing the shop too.
                shop["staffAccountCreated"] = False
                shop["staffAccountError"] = staff_result.get("error")

        return Response({"shop": shop}, status=201)


class AdminShopDetailView(APIView):
    """PATCH /admin/shops/<shop_id>/ — edit any field on any shop.
    DELETE /admin/shops/<shop_id>/ — soft-delete (is_active=False)."""
    def patch(self, request, shop_id):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        result = shops.admin_update_shop_handler(shop_id, request.data)
        return _respond(result)

    def delete(self, request, shop_id):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        result = shops.admin_delete_shop_handler(shop_id)
        return _respond(result)


class AdminShopRestoreView(APIView):
    """POST /admin/shops/<shop_id>/restore/ — undo a soft-delete."""
    def post(self, request, shop_id):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        result = shops.admin_restore_shop_handler(shop_id)
        return _respond(result)


class AdminShopImageUploadView(APIView):
    """POST /admin/shops/upload-image/ — multipart shop banner photo upload to Cloudinary."""
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        _, error_response = auth_middleware.authenticate_super_admin_request(request)
        if error_response:
            return error_response
        result = uploads.upload_shop_image_handler(request.FILES.get("file"))
        return _respond(result)


# ── Uploads ──────────────────────────────────────────────────────────────────────

class PrintDocumentUploadView(APIView):
    """POST /uploads/document/ — multipart file upload, requires a logged-in customer"""
    parser_classes = (MultiPartParser, FormParser)
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "upload"

    def post(self, request):
        email, error_response = auth_middleware.authenticate_customer_request(request)
        if error_response:
            return error_response
        uploaded_file = request.FILES.get("file")
        result = uploads.upload_print_document_handler(email, uploaded_file)
        return _respond(result)


# ── Orders (customer) ───────────────────────────────────────────────────────────

class OrderDraftCreateView(APIView):
    """POST /orders/draft/ — Body: { shop_id, upload_id, color, duplex, paper, range_mode, custom_range, copies, addons }"""
    def post(self, request):
        email, error_response = auth_middleware.authenticate_customer_request(request)
        if error_response:
            return error_response
        data = request.data
        result = orders_handler.create_order_draft(
            user_email=email,
            shop_id=data.get("shop_id", ""),
            upload_id=data.get("upload_id", ""),
            cfg={
                "color": data.get("color"),
                "duplex": data.get("duplex", False),
                "paper": data.get("paper"),
                "range_mode": data.get("range_mode"),
                "custom_range": data.get("custom_range", ""),
                "copies": data.get("copies", 1),
                "addons": data.get("addons") or [],
            },
        )
        return _respond(result)


class OrderConfirmPaymentView(APIView):
    """POST /orders/<order_id>/confirm/ — Body: { cashfree_order_id }"""
    def post(self, request, order_id):
        email, error_response = auth_middleware.authenticate_customer_request(request)
        if error_response:
            return error_response
        result = orders_handler.confirm_order_payment(
            order_id=order_id,
            user_email=email,
            cashfree_order_id=request.data.get("cashfree_order_id", ""),
        )
        return _respond(result)


class OrderDetailView(APIView):
    """GET /orders/<order_id>/"""
    def get(self, request, order_id):
        email, error_response = auth_middleware.authenticate_customer_request(request)
        if error_response:
            return error_response
        result = orders_handler.get_order_handler(order_id, email)
        return _respond(result)


class MyOrdersListView(APIView):
    """GET /orders/mine/"""
    def get(self, request):
        email, error_response = auth_middleware.authenticate_customer_request(request)
        if error_response:
            return error_response
        result = orders_handler.list_my_orders_handler(email)
        return _respond(result)


# ── Orders (shop dashboard) ─────────────────────────────────────────────────────

class ShopQueueListView(APIView):
    """GET /shop/queue/ — the authenticated shop staff member's OWN shop's live queue"""
    def get(self, request):
        staff, error_response = auth_middleware.authenticate_shop_staff_request(request)
        if error_response:
            return error_response
        result = orders_handler.list_shop_queue_handler(staff["shop_id"])
        return _respond(result)


class ShopOrderHistoryView(APIView):
    """GET /shop/orders/ — all-time order history for the authenticated shop's own shop
    (revenue/analytics page). Distinct from /shop/queue/, which is live-queue only."""
    def get(self, request):
        staff, error_response = auth_middleware.authenticate_shop_staff_request(request)
        if error_response:
            return error_response
        result = orders_handler.list_shop_order_history_handler(staff["shop_id"])
        return _respond(result)


class ShopOrderStatusUpdateView(APIView):
    """POST /shop/queue/<order_id>/status/ — Body: { status }"""
    def post(self, request, order_id):
        staff, error_response = auth_middleware.authenticate_shop_staff_request(request)
        if error_response:
            return error_response
        result = orders_handler.update_order_status_handler(
            order_id=order_id,
            shop_id=staff["shop_id"],
            new_status=request.data.get("status", ""),
        )
        return _respond(result)
