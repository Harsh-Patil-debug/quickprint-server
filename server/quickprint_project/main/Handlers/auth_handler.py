# auth_handler.py
# Customer + shop-staff authentication for QuickPrint.
# Mirrors khelomore-server/.../Handlers/auth_handler.py's core primitives (JWT
# issue/verify/revoke, Argon2id password hashing) exactly. Simpler than
# khelomore-server's own auth in two deliberate ways: (1) email+password/Google only, no
# OTP flow (khelomore-server's OTP machinery is BookMyConsole-specific and not part of
# what was asked for here); (2) email is stored the same way khelomore-server actually
# stores it — plain, not field-encrypted — since khelomore-server does NOT use the
# encrypt-at-rest + search-digest pattern some other apps this session used (verified by
# reading its real auth_handler.py rather than assuming).

import os
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
from .db_connection import db_main
from . import input_validation

IST = timezone(timedelta(hours=5, minutes=30))

JWT_SECRET = os.getenv("JWT_SECRET", "")
if not JWT_SECRET:
    # SECURITY: never sign/verify JWTs with an empty key — that makes every token
    # trivially forgeable by anyone. Same fail-loud posture as khelomore-server.
    raise RuntimeError("JWT_SECRET environment variable is not set.")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# Customer sessions: 30 days. Shop-staff sessions (control a real order queue) get a
# shorter lifetime, same reasoning as khelomore-server's JWT_ADMIN_EXP_DELTA_SECONDS for
# its cafe-owner/super-admin panels.
JWT_CUSTOMER_EXP_DELTA_SECONDS = int(os.getenv("JWT_CUSTOMER_EXP_DELTA_SECONDS", "2592000"))
JWT_SHOP_EXP_DELTA_SECONDS = int(os.getenv("JWT_SHOP_EXP_DELTA_SECONDS", "86400"))

ph = PasswordHasher(
    # Same OWASP low-memory Argon2id recommendation as khelomore-server, sized for a
    # small/free-tier hosting instance rather than a beefy dedicated machine.
    time_cost=2,
    memory_cost=19 * 1024,  # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    return ph.hash(plain_password)


def verify_password(stored_hash: str, input_password: str) -> bool:
    try:
        return ph.verify(stored_hash, input_password)
    except VerifyMismatchError:
        return False


def generate_token(email: str, role: str = "customer") -> str:
    """role is 'customer' or 'shop_staff' — determines session lifetime and which
    collection callers should look the account up in (see get_user_collection)."""
    exp_seconds = JWT_SHOP_EXP_DELTA_SECONDS if role == "shop_staff" else JWT_CUSTOMER_EXP_DELTA_SECONDS
    payload = {
        "email": email,
        "role": role,
        "jti": uuid.uuid4().hex,
        "exp": datetime.now(IST) + timedelta(seconds=exp_seconds),
    }
    return jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)


def revoke_token(token: str) -> None:
    """Invalidates a token server-side (logout) so a leaked/stolen token stops working
    immediately instead of remaining valid for its full lifetime. Safe to call with an
    already-expired or malformed token (no-op) — mirrors khelomore-server exactly."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
    except Exception:
        return
    jti = payload.get("jti")
    if not jti:
        return
    exp_ts = payload.get("exp")
    expires_at = (
        datetime.fromtimestamp(exp_ts, tz=timezone.utc)
        if exp_ts
        else (datetime.now(timezone.utc) + timedelta(days=31))
    )
    db_main.revoked_tokens.create_index("expires_at", expireAfterSeconds=0)
    db_main.revoked_tokens.update_one(
        {"jti": jti},
        {"$set": {"jti": jti, "expires_at": expires_at}},
        upsert=True,
    )


def verify_token(token: str) -> dict:
    """Verifies JWT and returns {email, role} if valid, otherwise raises. A token with no
    jti can never be revoked, so — same as khelomore-server — treat that as invalid
    rather than unrevocable."""
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    jti = payload.get("jti")
    if not jti:
        raise jwt.InvalidTokenError("Token missing jti claim.")
    if db_main.revoked_tokens.find_one({"jti": jti}):
        raise jwt.InvalidTokenError("Token has been revoked.")
    return {"email": payload["email"], "role": payload.get("role", "customer")}


def get_user_collection(role: str):
    return db_main.shop_staff if role == "shop_staff" else db_main.users


def register_customer(email: str, password: str, name: str = ""):
    """Email+password signup. No OTP — the user is Active immediately, matching the
    email+password/Google auth choice (OTP verification wasn't asked for here)."""
    dec_email = (email or "").strip().lower()
    error = input_validation.validate_email(dec_email) or input_validation.validate_password_strength(password)
    if error:
        return {"status": 400, "error": error}

    if db_main.users.find_one({"email": dec_email}):
        return {"status": 409, "error": "An account with this email already exists."}

    doc = {
        "email": dec_email,
        "name": name.strip() if name else dec_email.split("@")[0],
        "password_hash": hash_password(password),
        "google_id": None,
        "status": "Active",
        "created_at": datetime.now(IST).isoformat(),
    }
    result = db_main.users.insert_one(doc)
    token = generate_token(dec_email, role="customer")
    return {
        "status": 201,
        "token": token,
        "user": {"id": str(result.inserted_id), "email": dec_email, "name": doc["name"]},
    }


def login_customer(email: str, password: str):
    dec_email = (email or "").strip().lower()
    user = db_main.users.find_one({"email": dec_email})
    if not user or not user.get("password_hash"):
        return {"status": 401, "error": "Invalid email or password."}
    if user.get("status") != "Active":
        return {"status": 403, "error": "This account is not active."}
    if not verify_password(user["password_hash"], password):
        return {"status": 401, "error": "Invalid email or password."}

    token = generate_token(dec_email, role="customer")
    return {
        "status": 200,
        "token": token,
        "user": {"id": str(user["_id"]), "email": dec_email, "name": user.get("name", "")},
    }


def _get_or_create_google_user(idinfo: dict):
    """Shared account resolution for a verified Google idinfo payload. Returns
    (result_dict_or_None, error_dict_or_None) — exactly one is non-None."""
    dec_email = (idinfo.get("email") or "").strip().lower()
    if not dec_email or not idinfo.get("email_verified"):
        return None, {"status": 401, "error": "Google account email is not verified."}
    google_id = idinfo.get("sub")
    name = idinfo.get("name", dec_email.split("@")[0])

    user = db_main.users.find_one({"email": dec_email})
    if not user:
        doc = {
            "email": dec_email,
            "name": name,
            "password_hash": None,
            "google_id": google_id,
            "status": "Active",
            "created_at": datetime.now(IST).isoformat(),
        }
        result = db_main.users.insert_one(doc)
        user_id = str(result.inserted_id)
    else:
        if user.get("status") != "Active":
            return None, {"status": 403, "error": "This account is not active."}
        if not user.get("google_id"):
            db_main.users.update_one({"_id": user["_id"]}, {"$set": {"google_id": google_id}})
        user_id = str(user["_id"])

    token = generate_token(dec_email, role="customer")
    return {"status": 200, "token": token, "user": {"id": user_id, "email": dec_email, "name": name}}, None


def google_login_customer_via_code(code: str, redirect_uri: str):
    """
    Exchanges a Google OAuth authorization `code` for tokens, verifies the resulting ID
    token, and logs in or auto-creates the account. Ported to match
    khelomore-server/.../Handlers/auth_handler.py's bookmyconsole_google_auth_code_verify
    exactly — same redirect-based Authorization Code flow, called from
    CustomerGoogleCallbackView after Google redirects the browser back with `code`.
    `redirect_uri` must be byte-for-byte identical to the one used to build the original
    authorization URL (CustomerGoogleLoginRedirectView) — Google rejects a mismatch.
    """
    import requests

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    token_response = requests.post(token_url, data=data)
    if token_response.status_code != 200:
        return {"status": 400, "error": "Google token exchange failed."}

    id_token_sent = token_response.json().get("id_token")
    if not id_token_sent:
        return {"status": 400, "error": "No ID token received from Google."}

    try:
        idinfo = google_id_token.verify_oauth2_token(
            id_token_sent, google_requests.Request(), settings.GOOGLE_CLIENT_ID
        )
    except Exception as e:
        return {"status": 401, "error": f"Invalid Google token: {e}"}

    result, error = _get_or_create_google_user(idinfo)
    return error if error else result


def register_shop_staff(email: str, password: str, name: str, shop_id: str, role: str = "staff"):
    """Admin-direct provisioning (see auth_middleware.authenticate_admin_request) — used by
    the super-admin panel's 'Add Print Shop' form when an admin sets the owner's password
    themselves at onboarding time. See register_shop_owner below for the other, more
    common path: the owner self-registers once the admin has listed their email on a shop.
    Kept here rather than in shops.py since it's account creation, not shop-directory logic."""
    from bson import ObjectId
    dec_email = (email or "").strip().lower()
    error = input_validation.validate_email(dec_email) or input_validation.validate_password_strength(password)
    if error:
        return {"status": 400, "error": error}
    if not shop_id or not ObjectId.is_valid(shop_id):
        return {"status": 400, "error": "A valid shop_id is required."}
    if not db_main.shops.find_one({"_id": ObjectId(shop_id)}):
        return {"status": 404, "error": "Shop not found."}
    if db_main.shop_staff.find_one({"email": dec_email}):
        return {"status": 409, "error": "An account with this email already exists."}

    doc = {
        "email": dec_email,
        "name": name.strip() if name else dec_email.split("@")[0],
        "password_hash": hash_password(password),
        "shop_id": shop_id,
        "role": role if role in ("owner", "staff") else "staff",
        "status": "Active",
        "created_at": datetime.now(IST).isoformat(),
    }
    result = db_main.shop_staff.insert_one(doc)
    return {
        "status": 201,
        "staff": {"id": str(result.inserted_id), "email": dec_email, "name": doc["name"], "shop_id": shop_id, "role": doc["role"]},
    }


def register_shop_owner(email: str, password: str, name: str):
    """
    Public self-service signup for a print shop's OWNER — mirrors
    khelomore-server/.../Handlers/auth_handler.py's bookmyconsole_register exactly for its
    is_cafe_owner_signup branch: `cafe_exists = db_main.cafes.find_one({"owner_email":
    dec_email, ...})`, rejecting with "This email is not authorized..." if no cafe lists
    it. Same gate here, against shops.owner_email instead of cafes.owner_email — a shop
    must already have this email set as its owner_email (via the super-admin panel's 'Add
    Print Shop' form) before that person can create their own login. No ADMIN_TOKEN
    involved: the authorization comes from the email match, not a bearer credential,
    which is what makes this safe to expose publicly.
    """
    dec_email = (email or "").strip().lower()
    error = input_validation.validate_email(dec_email) or input_validation.validate_password_strength(password)
    if error:
        return {"status": 400, "error": error}

    shop = db_main.shops.find_one({"owner_email": dec_email, "is_active": {"$ne": False}})
    if not shop:
        return {"status": 403, "error": "This email is not authorized. Please contact the platform Super Admin to list your shop first."}

    if db_main.shop_staff.find_one({"email": dec_email}):
        return {"status": 409, "error": "An account with this email already exists. Please log in instead."}

    doc = {
        "email": dec_email,
        "name": name.strip() if name else shop.get("owner_name") or dec_email.split("@")[0],
        "password_hash": hash_password(password),
        "shop_id": str(shop["_id"]),
        "role": "owner",
        "status": "Active",
        "created_at": datetime.now(IST).isoformat(),
    }
    result = db_main.shop_staff.insert_one(doc)
    token = generate_token(dec_email, role="shop_staff")
    return {
        "status": 201,
        "token": token,
        "staff": {
            "id": str(result.inserted_id), "email": dec_email, "name": doc["name"],
            "shop_id": doc["shop_id"], "role": "owner",
        },
    }


def login_shop_staff(email: str, password: str):
    dec_email = (email or "").strip().lower()
    staff = db_main.shop_staff.find_one({"email": dec_email})
    if not staff or not staff.get("password_hash"):
        return {"status": 401, "error": "Invalid email or password."}
    if staff.get("status") != "Active":
        return {"status": 403, "error": "This account is not active."}
    if not verify_password(staff["password_hash"], password):
        return {"status": 401, "error": "Invalid email or password."}

    token = generate_token(dec_email, role="shop_staff")
    return {
        "status": 200,
        "token": token,
        "staff": {
            "id": str(staff["_id"]),
            "email": dec_email,
            "name": staff.get("name", ""),
            "shop_id": staff.get("shop_id"),
            "role": staff.get("role", "staff"),
        },
    }
