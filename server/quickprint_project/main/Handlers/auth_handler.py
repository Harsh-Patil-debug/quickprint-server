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
import json
import base64
import hmac
import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
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
# Super admin sessions get the same short lifetime as shop-staff — the platform's most
# sensitive login surface shouldn't stay valid for 30 days like a customer session.
JWT_SUPER_ADMIN_EXP_DELTA_SECONDS = int(os.getenv("JWT_SUPER_ADMIN_EXP_DELTA_SECONDS", "86400"))

# ── Super admin OTP auth — AES-256-CBC field encryption, same security model as
# khelomore-server's super_admin flow (see that file's own ENCRYPTION_KEY/encrypt_data/
# decrypt_data/hash_otp for the exact pattern this ports). Only the super_admin auth
# surface uses this — customer/shop_staff auth deliberately stays plain email+password
# (see the module docstring above for why that was a prior, separate decision).
ENCRYPTION_KEY = base64.b64decode(os.getenv("ENCRYPTION_KEY", ""))
if not ENCRYPTION_KEY:
    raise RuntimeError("ENCRYPTION_KEY environment variable is not set.")
SUPER_ADMIN_OTP_EXPIRY_MINUTES = int(os.getenv("SUPER_ADMIN_OTP_EXPIRY_MINUTES", "2"))
MAX_OTP_ATTEMPTS = int(os.getenv("MAX_OTP_ATTEMPTS", "5"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "45"))


def encrypt_data(plain_text: str, key: bytes = None):
    """Returns (ciphertext_b64, iv_b64). A fresh random IV every call — never reuse an IV
    across encryptions under CBC, that breaks its confidentiality guarantees."""
    key = key or ENCRYPTION_KEY
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))
    return base64.b64encode(encrypted_bytes).decode("utf-8"), base64.b64encode(iv).decode("utf-8")


def decrypt_data(encrypted_data: str, iv: str) -> str:
    try:
        iv_bytes = base64.b64decode(iv)
        encrypted_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv_bytes)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        return decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


def hash_otp(otp: str) -> str:
    """HMAC-SHA256, not Argon2id like passwords — a 6-digit OTP's real protection is its
    short expiry + MAX_OTP_ATTEMPTS lockout (both enforced before this is ever compared),
    so a fast HMAC is the right tool: defense-in-depth against a DB leak, not the primary
    defense. Same reasoning as khelomore-server's own hash_otp."""
    return hmac.new(ENCRYPTION_KEY, otp.encode("utf-8"), "sha256").hexdigest()


def verify_otp_hash(stored_hash: str, input_otp: str) -> bool:
    if not stored_hash or not input_otp:
        return False
    return hmac.compare_digest(hash_otp(input_otp), stored_hash)

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
    """role is 'customer', 'shop_staff', or 'super_admin' — determines session lifetime and
    which collection callers should look the account up in (see get_user_collection)."""
    if role == "shop_staff":
        exp_seconds = JWT_SHOP_EXP_DELTA_SECONDS
    elif role == "super_admin":
        exp_seconds = JWT_SUPER_ADMIN_EXP_DELTA_SECONDS
    else:
        exp_seconds = JWT_CUSTOMER_EXP_DELTA_SECONDS
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
    if role == "shop_staff":
        return db_main.shop_staff
    if role == "super_admin":
        return db_main.super_admin
    return db_main.users


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


# ── Super admin auth — email+password + OTP, AES-256-CBC encrypted payloads ─────────────
# Mirrors khelomore-server's super_admin flow: register/login are step 1 (verify
# credentials, email an OTP, no session yet), verify_super_admin_otp is step 2 (checks the
# OTP, issues the JWT). Creating a NEW super_admin account (register) is itself gated by
# auth_middleware.authenticate_super_admin_request at the view layer — see views.py's
# reject_unauthorized_super_admin_role equivalent — so only an already-authenticated super
# admin (or the static ADMIN_TOKEN) can provision another one. The very first account has
# to be created via a one-off script that calls register_super_admin directly (see
# create_super_admin.py), the same bootstrap approach khelomore-server itself uses.

def register_super_admin(name_enc, email_enc, password_enc, iv):
    """Step 1 of signup — creates a Pending super_admin doc, emails an OTP, no JWT yet."""
    try:
        dec_name = decrypt_data(name_enc, iv).strip()
        dec_email = decrypt_data(email_enc, iv).strip().lower()
        dec_password = decrypt_data(password_enc, iv)
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    error = (
        input_validation.validate_text(dec_name, "Full name", max_len=40)
        or input_validation.validate_email(dec_email)
        or input_validation.validate_password_strength(dec_password)
    )
    if error:
        return {"error": error}, 400

    if db_main.super_admin.find_one({"email": dec_email}):
        return {"error": "An account with this email already exists."}, 400

    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(IST) + timedelta(minutes=SUPER_ADMIN_OTP_EXPIRY_MINUTES)
    db_main.super_admin.insert_one({
        "name": dec_name,
        "email": dec_email,
        "password_hash": ph.hash(dec_password),
        "status": "Pending",
        "otp_code": hash_otp(otp_code),
        "otp_expiry": otp_expiry,
        "role": "super_admin",
        "created_at": datetime.now(IST).isoformat(),
    })

    from .email_handler import send_otp_email
    send_otp_email(dec_email, otp_code, name=dec_name, purpose="signup")

    response_json = json.dumps({"message": "OTP sent to your email.", "email": dec_email})
    enc_resp, iv2 = encrypt_data(response_json)
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


def login_super_admin(email_enc, password_enc, iv):
    """Step 1 of login — verifies credentials, emails an OTP, no JWT yet."""
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
        dec_password = decrypt_data(password_enc, iv)
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    admin = db_main.super_admin.find_one({"email": dec_email})
    if not admin:
        return {"error": "Invalid email or password."}, 401
    if admin.get("status") == "Suspended":
        return {"error": "This account has been suspended."}, 403

    # SECURITY: bound password-guessing against a known email.
    locked_until = admin.get("login_locked_until")
    if locked_until:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc).astimezone(IST)
        if datetime.now(IST) < locked_until:
            return {"error": "Too many failed login attempts. Please try again later."}, 429

    if not verify_password(admin["password_hash"], dec_password):
        attempts = int(admin.get("login_attempts", 0)) + 1
        update_fields = {"login_attempts": attempts}
        if attempts >= MAX_LOGIN_ATTEMPTS:
            update_fields["login_locked_until"] = datetime.now(IST) + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        db_main.super_admin.update_one({"_id": admin["_id"]}, {"$set": update_fields})
        return {"error": "Invalid email or password."}, 401

    if admin.get("login_attempts") or admin.get("login_locked_until"):
        db_main.super_admin.update_one({"_id": admin["_id"]}, {"$unset": {"login_attempts": "", "login_locked_until": ""}})

    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(IST) + timedelta(minutes=SUPER_ADMIN_OTP_EXPIRY_MINUTES)
    db_main.super_admin.update_one(
        {"_id": admin["_id"]},
        {"$set": {"otp_code": hash_otp(otp_code), "otp_expiry": otp_expiry}, "$unset": {"otp_attempts": ""}},
    )

    from .email_handler import send_otp_email
    send_otp_email(dec_email, otp_code, name=admin.get("name", "Admin"), purpose="login")

    response_json = json.dumps({"message": "OTP sent to your email.", "email": dec_email})
    enc_resp, iv2 = encrypt_data(response_json)
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


def verify_super_admin_otp(email_enc, otp_enc, iv):
    """Step 2 (login + signup) — validates the OTP, activates the account, issues a JWT."""
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
        dec_otp = decrypt_data(otp_enc, iv).strip()
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    admin = db_main.super_admin.find_one({"email": dec_email})
    if not admin:
        return {"error": "Session not found. Please start again."}, 404
    if admin.get("status") == "Suspended":
        return {"error": "This account has been suspended."}, 403

    stored_otp = admin.get("otp_code")
    otp_exp = admin.get("otp_expiry")
    if not stored_otp or not otp_exp:
        return {"error": "No OTP request found."}, 400
    if otp_exp.tzinfo is None:
        otp_exp = otp_exp.replace(tzinfo=timezone.utc).astimezone(IST)
    if datetime.now(IST) > otp_exp:
        return {"error": "OTP has expired. Please request a new code."}, 400

    if not verify_otp_hash(stored_otp, dec_otp):
        # SECURITY: bound OTP guessing — a 6-digit code has 1,000,000 possibilities, so
        # unlimited attempts would make it brute-forceable.
        attempts = int(admin.get("otp_attempts", 0)) + 1
        if attempts >= MAX_OTP_ATTEMPTS:
            db_main.super_admin.update_one(
                {"_id": admin["_id"]},
                {"$unset": {"otp_code": "", "otp_expiry": "", "otp_attempts": ""}},
            )
            return {"error": "Too many incorrect attempts. Please request a new code."}, 429
        db_main.super_admin.update_one({"_id": admin["_id"]}, {"$set": {"otp_attempts": attempts}})
        return {"error": "Invalid verification code."}, 400

    is_new = admin.get("status") == "Pending"
    update_fields = {"$unset": {"otp_code": "", "otp_expiry": "", "otp_attempts": ""}}
    if is_new:
        update_fields["$set"] = {"status": "Active"}
    db_main.super_admin.update_one({"_id": admin["_id"]}, update_fields)

    token = generate_token(dec_email, role="super_admin")
    response_data = {
        "token": token,
        "message": "Verification successful",
        "user": {
            "id": str(admin["_id"]),
            "email": dec_email,
            "name": admin.get("name", "Admin"),
            "role": "super_admin",
        },
    }
    enc_resp, iv2 = encrypt_data(json.dumps(response_data))
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


def resend_super_admin_otp(email_enc, iv):
    """Re-generates and re-sends the OTP for an existing super_admin account (404s if none
    exists — this can only ever re-send for an account, never create or promote one)."""
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    admin = db_main.super_admin.find_one({"email": dec_email})
    if not admin:
        return {"error": "No account found for this email."}, 404

    # SECURITY: cooldown so resending can't be used to dodge the OTP-attempt lockout by
    # requesting a fresh code just before hitting the attempt cap.
    prev_expiry = admin.get("otp_expiry")
    if prev_expiry:
        if prev_expiry.tzinfo is None:
            prev_expiry = prev_expiry.replace(tzinfo=timezone.utc).astimezone(IST)
        last_sent = prev_expiry - timedelta(minutes=SUPER_ADMIN_OTP_EXPIRY_MINUTES)
        elapsed = (datetime.now(IST) - last_sent).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait_for = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            return {"error": f"Please wait {wait_for}s before requesting another code."}, 429

    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(IST) + timedelta(minutes=SUPER_ADMIN_OTP_EXPIRY_MINUTES)
    db_main.super_admin.update_one(
        {"_id": admin["_id"]},
        {"$set": {"otp_code": hash_otp(otp_code), "otp_expiry": otp_expiry}, "$unset": {"otp_attempts": ""}},
    )

    from .email_handler import send_otp_email
    send_otp_email(dec_email, otp_code, name=admin.get("name", "Admin"), purpose="resend")

    enc_resp, iv2 = encrypt_data('{"message": "New OTP sent to your email."}')
    return {"encrypted_response": enc_resp, "iv": iv2}, 200
