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

# ── Access + refresh tokens ──────────────────────────────────────────────────────────
# Standard two-token pattern (OWASP-recommended), replacing the single 24h JWT every
# request used to carry directly. The ACCESS token is what's actually sent as
# Authorization: Bearer on every API call — short-lived on purpose, so a leaked one is
# only dangerous for a few minutes even if nobody notices. The REFRESH token is what
# actually represents "the user stays logged in for 24h without re-entering credentials"
# — it's opaque (not a JWT), stored server-side as a hash (same principle as OTP/password
# storage: never keep the raw secret at rest), delivered only via an HttpOnly cookie
# scoped to the refresh endpoint's own path (never sent on ordinary API calls, so it's
# not exposed by the same XSS/log-leakage surface the access token is), and ROTATED on
# every use: each refresh call revokes the token that was just spent and issues a new
# one in its place. If an already-rotated (i.e. already-spent) refresh token is ever
# presented again, that's a signal of theft — see revoke_refresh_family below — and the
# whole session lineage is revoked defensively, not just that one token.
ACCESS_TOKEN_EXP_SECONDS = int(os.getenv("ACCESS_TOKEN_EXP_SECONDS", "1800"))  # 30 min
REFRESH_TOKEN_EXP_SECONDS = int(os.getenv("REFRESH_TOKEN_EXP_SECONDS", "86400"))  # 24h

# ── OTP auth — AES-256-CBC field encryption, same security model as khelomore-server's
# super_admin flow, now applied uniformly to ALL THREE roles (customer, shop_staff,
# super_admin): every traditional (non-Google) login and every self-service signup is a
# two-step email+password -> OTP -> JWT flow, exactly like khelomore-server's own
# bookmyconsole_register/bookmyconsole_login/bookmyconsole_verify_otp/
# bookmyconsole_forgot_password/bookmyconsole_reset_password (see those for the pattern
# every function below ports). Google sign-in skips OTP for the same reason
# khelomore-server's does — Google has already verified that identity.
ENCRYPTION_KEY = base64.b64decode(os.getenv("ENCRYPTION_KEY", ""))
if not ENCRYPTION_KEY:
    raise RuntimeError("ENCRYPTION_KEY environment variable is not set.")
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
# Super admin's is the platform's most sensitive login surface — a valid code shouldn't
# sit in an inbox as long as a customer's.
SUPER_ADMIN_OTP_EXPIRY_MINUTES = int(os.getenv("SUPER_ADMIN_OTP_EXPIRY_MINUTES", "2"))
MAX_OTP_ATTEMPTS = int(os.getenv("MAX_OTP_ATTEMPTS", "5"))
MAX_PASSWORD_RESET_ATTEMPTS = MAX_OTP_ATTEMPTS
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "45"))


def _otp_expiry_minutes(role: str) -> int:
    return SUPER_ADMIN_OTP_EXPIRY_MINUTES if role == "super_admin" else OTP_EXPIRY_MINUTES


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


def generate_access_token(email: str, role: str = "customer") -> str:
    """Short-lived (ACCESS_TOKEN_EXP_SECONDS) JWT — this is what's actually sent as
    Authorization: Bearer on every API call. role is 'customer', 'shop_staff', or
    'super_admin' — determines which collection callers should look the account up in
    (see get_user_collection)."""
    payload = {
        "email": email,
        "role": role,
        "jti": uuid.uuid4().hex,
        "exp": datetime.now(IST) + timedelta(seconds=ACCESS_TOKEN_EXP_SECONDS),
    }
    return jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)


def revoke_token(token: str) -> None:
    """Invalidates an access token server-side (logout) so a leaked/stolen one stops
    working immediately instead of remaining valid for its full lifetime. Safe to call
    with an already-expired or malformed token (no-op) — mirrors khelomore-server exactly."""
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
    """Verifies an access-token JWT and returns {email, role} if valid, otherwise raises.
    A token with no jti can never be revoked, so — same as khelomore-server — treat that
    as invalid rather than unrevocable."""
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    jti = payload.get("jti")
    if not jti:
        raise jwt.InvalidTokenError("Token missing jti claim.")
    if db_main.revoked_tokens.find_one({"jti": jti}):
        raise jwt.InvalidTokenError("Token has been revoked.")
    return {"email": payload["email"], "role": payload.get("role", "customer")}


# ── Refresh tokens ────────────────────────────────────────────────────────────────────
# Opaque (not a JWT) random tokens, stored server-side as a SHA-256 hash keyed by a
# family_id — same "never store the raw secret" principle as OTPs and passwords. Every
# refresh call rotates: the presented token is marked used, a new one is issued sharing
# the same family_id. A family_id ties together every token that ever descended from one
# original login, which is what makes reuse detection possible below.

def _hash_refresh_token(raw_token: str) -> str:
    import hashlib
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _issue_refresh_token(email: str, role: str, family_id: str = None) -> str:
    """Creates a new refresh token doc and returns the RAW token (only ever returned
    once, at issuance — never logged, never stored anywhere but this one response)."""
    import secrets
    raw_token = secrets.token_urlsafe(48)
    family_id = family_id or uuid.uuid4().hex
    db_main.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)
    db_main.refresh_tokens.insert_one({
        "token_hash": _hash_refresh_token(raw_token),
        "email": email,
        "role": role,
        "family_id": family_id,
        "used": False,
        "created_at": datetime.now(IST).isoformat(),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXP_SECONDS),
    })
    return raw_token


def issue_token_pair(email: str, role: str) -> tuple[str, str]:
    """Issues a fresh (access_token, refresh_token) pair for a brand-new session — called
    at login/signup OTP verification and at Google sign-in. Returns (access, refresh)."""
    return generate_access_token(email, role), _issue_refresh_token(email, role)


def refresh_access_token(raw_refresh_token: str, role: str):
    """
    Validates + rotates a refresh token, returning a NEW (access_token, refresh_token)
    pair on success. Returns None on any failure (wrong type, expired, unknown, wrong
    role, or already-used — in the already-used case this ALSO revokes every other token
    in that same family, since presenting an already-rotated token is the standard signal
    that a refresh token was stolen: the legitimate client and an attacker both tried to
    use the same one, and whichever used it second is the tell).

    SECURITY/ROBUSTNESS: the "claim" (mark used) is a single atomic find_one_and_update,
    not a separate find_one + update_one — the two-step version had a genuine TOCTOU race
    where two near-simultaneous refresh calls could both read used=False before either
    write landed, both proceed to rotate, and neither trip reuse-detection. The role check
    is folded into the same atomic filter so a client can never burn a token that doesn't
    even belong to it.
    """
    if not raw_refresh_token or not isinstance(raw_refresh_token, str):
        return None
    token_hash = _hash_refresh_token(raw_refresh_token)

    doc = db_main.refresh_tokens.find_one_and_update(
        {"token_hash": token_hash, "role": role, "used": False},
        {"$set": {"used": True}},
    )
    if doc is None:
        existing = db_main.refresh_tokens.find_one({"token_hash": token_hash})
        if not existing or existing.get("role") != role:
            return None
        if existing.get("used"):
            # SECURITY: reuse of an already-rotated refresh token — revoke the whole family.
            db_main.refresh_tokens.update_many(
                {"family_id": existing["family_id"]},
                {"$set": {"used": True, "revoked_reason": "reuse_detected"}},
            )
        return None

    expires_at = doc.get("expires_at")
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at and datetime.now(timezone.utc) > expires_at:
        # Already claimed above (burned) — an expired token can never be validly reused
        # regardless, and this keeps a second presentation of it consistent (it'll now
        # correctly read as "already used" rather than "still expired-but-unclaimed").
        return None

    new_refresh = _issue_refresh_token(doc["email"], doc["role"], family_id=doc["family_id"])
    new_access = generate_access_token(doc["email"], doc["role"])
    return new_access, new_refresh


def revoke_refresh_family(raw_refresh_token: str) -> None:
    """Revokes every token descended from the same login as raw_refresh_token — called on
    logout, so a stolen-but-not-yet-used refresh token from that session stops working
    immediately too, not just the current access token. Safe to call with an unknown,
    malformed, or wrong-type token (no-op)."""
    if not raw_refresh_token or not isinstance(raw_refresh_token, str):
        return
    doc = db_main.refresh_tokens.find_one({"token_hash": _hash_refresh_token(raw_refresh_token)})
    if not doc:
        return
    db_main.refresh_tokens.update_many(
        {"family_id": doc["family_id"]},
        {"$set": {"used": True, "revoked_reason": "logout"}},
    )


def get_user_collection(role: str):
    if role == "shop_staff":
        return db_main.shop_staff
    if role == "super_admin":
        return db_main.super_admin
    return db_main.users


# ── Unified OTP auth — register / login / verify_otp / resend_otp / forgot / reset ──────
# One implementation shared by customer, shop_staff (self-service owner signup only —
# admin-direct provisioning is register_shop_staff below, a different trust model), and
# super_admin. Ported from khelomore-server's own bookmyconsole_register/_login/
# _verify_otp/_forgot_password/_reset_password, which are themselves role-parameterized
# the same way.

def _build_user_response(role: str, doc: dict) -> dict:
    """Shapes the {user: {...}} part of a verify_otp response — shop_staff carries
    shop_id/role fields the other two don't need."""
    base = {"id": str(doc["_id"]), "email": doc["email"], "name": doc.get("name", "")}
    if role == "shop_staff":
        base["shop_id"] = doc.get("shop_id")
        base["role"] = doc.get("role", "staff")
    else:
        base["role"] = role
    return base


def register(name_enc, email_enc, password_enc, iv, role: str):
    """Step 1 of signup — creates a Pending account doc, emails an OTP, no JWT yet.
    role='shop_staff' here is ALWAYS the public self-service owner-signup path (mirrors
    register_shop_owner's old behaviour): the email must already be listed as a shop's
    owner_email, set by the super admin via 'Add Print Shop' — same authorization-by-
    email-match as khelomore-server's is_cafe_owner_signup branch. Admin-direct shop
    staff provisioning (no self-verification needed, the admin already vouches for them)
    stays in register_shop_staff, a separate function with no OTP step."""
    try:
        dec_name = decrypt_data(name_enc, iv).strip()
        dec_email = decrypt_data(email_enc, iv).strip().lower()
        dec_password = decrypt_data(password_enc, iv)
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    error = (
        input_validation.validate_text(dec_name, "Name", max_len=80)
        or input_validation.validate_email(dec_email)
        or input_validation.validate_password_strength(dec_password)
    )
    if error:
        return {"error": error}, 400

    coll = get_user_collection(role)
    shop = None
    if role == "shop_staff":
        shop = db_main.shops.find_one({"owner_email": dec_email, "is_active": {"$ne": False}})
        if not shop:
            return {"error": "This email is not authorized. Please contact the platform Super Admin to list your shop first."}, 403

    if coll.find_one({"email": dec_email}):
        return {"error": "An account with this email already exists."}, 400

    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(IST) + timedelta(minutes=_otp_expiry_minutes(role))
    doc = {
        "name": dec_name,
        "email": dec_email,
        "password_hash": ph.hash(dec_password),
        "status": "Pending",
        "otp_code": hash_otp(otp_code),
        "otp_expiry": otp_expiry,
        "role": "owner" if role == "shop_staff" else role,
        "created_at": datetime.now(IST).isoformat(),
    }
    if role == "customer":
        doc["google_id"] = None
    if role == "shop_staff":
        doc["shop_id"] = str(shop["_id"])
        if not dec_name:
            doc["name"] = shop.get("owner_name") or dec_email.split("@")[0]

    coll.insert_one(doc)

    from .email_handler import send_otp_email
    send_otp_email(dec_email, otp_code, name=doc["name"] or dec_email.split("@")[0], purpose="signup")

    response_json = json.dumps({"message": "OTP sent to your email.", "email": dec_email})
    enc_resp, iv2 = encrypt_data(response_json)
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


# ── Super admin invites ──────────────────────────────────────────────────────────────
# Authorization-by-email-match for super_admin accounts, same principle as shops'
# owner_email for shop owners: an existing super admin invites an email here, and that
# specific email can then hit /super-admin/register/ itself with no bearer token needed
# (see is_super_admin_invited, checked by SuperAdminRegisterView before falling back to
# requiring an authenticated admin). Kept in its own collection rather than a field on the
# super_admin doc since an invite exists before any account does.

def invite_super_admin(email: str, invited_by: str):
    dec_email = (email or "").strip().lower()
    error = input_validation.validate_email(dec_email)
    if error:
        return {"error": error}, 400
    if db_main.super_admin.find_one({"email": dec_email}):
        return {"error": "An account with this email already exists."}, 400
    if db_main.super_admin_invites.find_one({"email": dec_email}):
        return {"error": "This email has already been invited."}, 400
    db_main.super_admin_invites.insert_one({
        "email": dec_email,
        "invited_by": invited_by,
        "invited_at": datetime.now(IST).isoformat(),
    })
    return {"message": f"Invited {dec_email}. They can now create their own account at the console's login page."}, 200


def list_super_admin_invites():
    docs = list(db_main.super_admin_invites.find({}).sort("invited_at", -1))
    return {
        "invites": [
            {"email": d["email"], "invitedBy": d.get("invited_by", ""), "invitedAt": d.get("invited_at", "")}
            for d in docs
        ]
    }, 200


def revoke_super_admin_invite(email: str):
    dec_email = (email or "").strip().lower()
    result = db_main.super_admin_invites.delete_one({"email": dec_email})
    if result.deleted_count == 0:
        return {"error": "No pending invite for this email."}, 404
    return {"message": "Invite revoked."}, 200


def is_super_admin_invited(email: str) -> bool:
    return db_main.super_admin_invites.find_one({"email": (email or "").strip().lower()}) is not None


def consume_super_admin_invite(email: str):
    """Called once an invited email's account is actually created, so the pending-invites
    list accurately reflects who's still waiting to sign up, not who already has."""
    db_main.super_admin_invites.delete_one({"email": (email or "").strip().lower()})


def login(email_enc, password_enc, iv, role: str):
    """Step 1 of login — verifies credentials, emails an OTP, no JWT yet."""
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
        dec_password = decrypt_data(password_enc, iv)
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    coll = get_user_collection(role)
    user = coll.find_one({"email": dec_email})
    if not user or not user.get("password_hash"):
        return {"error": "Invalid email or password."}, 401
    if user.get("status") in ("Blocked", "Suspended"):
        return {"error": "This account has been suspended. Please contact support."}, 403

    # SECURITY: bound password-guessing against a known email.
    locked_until = user.get("login_locked_until")
    if locked_until:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc).astimezone(IST)
        if datetime.now(IST) < locked_until:
            return {"error": "Too many failed login attempts. Please try again later."}, 429

    if not verify_password(user["password_hash"], dec_password):
        attempts = int(user.get("login_attempts", 0)) + 1
        update_fields = {"login_attempts": attempts}
        if attempts >= MAX_LOGIN_ATTEMPTS:
            update_fields["login_locked_until"] = datetime.now(IST) + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        coll.update_one({"_id": user["_id"]}, {"$set": update_fields})
        return {"error": "Invalid email or password."}, 401

    if user.get("login_attempts") or user.get("login_locked_until"):
        coll.update_one({"_id": user["_id"]}, {"$unset": {"login_attempts": "", "login_locked_until": ""}})

    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(IST) + timedelta(minutes=_otp_expiry_minutes(role))
    coll.update_one(
        {"_id": user["_id"]},
        {"$set": {"otp_code": hash_otp(otp_code), "otp_expiry": otp_expiry}, "$unset": {"otp_attempts": ""}},
    )

    from .email_handler import send_otp_email
    send_otp_email(dec_email, otp_code, name=user.get("name", "User"), purpose="login")

    response_json = json.dumps({"message": "OTP sent to your email.", "email": dec_email})
    enc_resp, iv2 = encrypt_data(response_json)
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


def verify_otp(email_enc, otp_enc, iv, role: str):
    """Step 2 (login + signup) — validates the OTP, activates the account, issues a JWT."""
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
        dec_otp = decrypt_data(otp_enc, iv).strip()
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    coll = get_user_collection(role)
    user = coll.find_one({"email": dec_email})
    if not user:
        return {"error": "Session not found. Please start again."}, 404
    if user.get("status") in ("Blocked", "Suspended"):
        return {"error": "This account has been suspended. Please contact support."}, 403

    stored_otp = user.get("otp_code")
    otp_exp = user.get("otp_expiry")
    if not stored_otp or not otp_exp:
        return {"error": "No OTP request found."}, 400
    if otp_exp.tzinfo is None:
        otp_exp = otp_exp.replace(tzinfo=timezone.utc).astimezone(IST)
    if datetime.now(IST) > otp_exp:
        return {"error": "OTP has expired. Please request a new code."}, 400

    if not verify_otp_hash(stored_otp, dec_otp):
        # SECURITY: bound OTP guessing — a 6-digit code has 1,000,000 possibilities, so
        # unlimited attempts would make it brute-forceable.
        attempts = int(user.get("otp_attempts", 0)) + 1
        if attempts >= MAX_OTP_ATTEMPTS:
            coll.update_one(
                {"_id": user["_id"]},
                {"$unset": {"otp_code": "", "otp_expiry": "", "otp_attempts": ""}},
            )
            return {"error": "Too many incorrect attempts. Please request a new code."}, 429
        coll.update_one({"_id": user["_id"]}, {"$set": {"otp_attempts": attempts}})
        return {"error": "Invalid verification code."}, 400

    is_new = user.get("status") == "Pending"
    update_fields = {"$unset": {"otp_code": "", "otp_expiry": "", "otp_attempts": ""}}
    if is_new:
        update_fields["$set"] = {"status": "Active"}
    coll.update_one({"_id": user["_id"]}, update_fields)

    access_token, refresh_token = issue_token_pair(dec_email, role)
    response_data = {
        "token": access_token,
        "refresh_token": refresh_token,
        "message": "Verification successful",
        "user": _build_user_response(role, user),
    }
    enc_resp, iv2 = encrypt_data(json.dumps(response_data))
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


def resend_otp(email_enc, iv, role: str):
    """Re-generates and re-sends the OTP for an existing account (404s if none exists —
    this can only ever re-send for an account, never create or promote one)."""
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    coll = get_user_collection(role)
    user = coll.find_one({"email": dec_email})
    if not user:
        return {"error": "No account found for this email."}, 404

    # SECURITY: cooldown so resending can't be used to dodge the OTP-attempt lockout by
    # requesting a fresh code just before hitting the attempt cap.
    prev_expiry = user.get("otp_expiry")
    if prev_expiry:
        if prev_expiry.tzinfo is None:
            prev_expiry = prev_expiry.replace(tzinfo=timezone.utc).astimezone(IST)
        last_sent = prev_expiry - timedelta(minutes=_otp_expiry_minutes(role))
        elapsed = (datetime.now(IST) - last_sent).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait_for = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            return {"error": f"Please wait {wait_for}s before requesting another code."}, 429

    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(IST) + timedelta(minutes=_otp_expiry_minutes(role))
    coll.update_one(
        {"_id": user["_id"]},
        {"$set": {"otp_code": hash_otp(otp_code), "otp_expiry": otp_expiry}, "$unset": {"otp_attempts": ""}},
    )

    from .email_handler import send_otp_email
    send_otp_email(dec_email, otp_code, name=user.get("name", "User"), purpose="resend")

    enc_resp, iv2 = encrypt_data('{"message": "New OTP sent to your email."}')
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


def forgot_password(email_enc, iv, role: str):
    """
    Step 1 of password reset: if an account exists for this email, emails it a reset OTP.

    SECURITY: always returns the same generic message regardless of whether the account
    exists, is Google-only (no password to reset), or is suspended — revealing any of
    that would let an attacker enumerate registered emails. Only the actual reset step
    needs the OTP to have genuinely been sent, which it silently isn't for any of those
    cases. Mirrors khelomore-server's bookmyconsole_forgot_password exactly.
    """
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    error = input_validation.validate_email(dec_email)
    if error:
        return {"error": error}, 400

    generic_message = {"message": "If an account exists for this email, a password reset code has been sent."}

    def _respond():
        enc_resp, iv2 = encrypt_data(json.dumps(generic_message))
        return {"encrypted_response": enc_resp, "iv": iv2}, 200

    coll = get_user_collection(role)
    user = coll.find_one({"email": dec_email})
    if not user or user.get("status") in ("Blocked", "Suspended") or not user.get("password_hash"):
        return _respond()

    prev_expiry = user.get("reset_otp_expiry")
    if prev_expiry:
        if prev_expiry.tzinfo is None:
            prev_expiry = prev_expiry.replace(tzinfo=timezone.utc).astimezone(IST)
        last_sent = prev_expiry - timedelta(minutes=_otp_expiry_minutes(role))
        elapsed = (datetime.now(IST) - last_sent).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            return _respond()

    otp_code = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(IST) + timedelta(minutes=_otp_expiry_minutes(role))
    coll.update_one(
        {"_id": user["_id"]},
        {"$set": {"reset_otp_code": hash_otp(otp_code), "reset_otp_expiry": otp_expiry},
         "$unset": {"reset_otp_attempts": ""}},
    )

    from .email_handler import send_otp_email
    send_otp_email(dec_email, otp_code, name=user.get("name", "User"), purpose="password_reset")

    return _respond()


def reset_password(email_enc, otp_enc, new_password_enc, iv, role: str):
    """Step 2 of password reset: verify the reset OTP and set a new password."""
    try:
        dec_email = decrypt_data(email_enc, iv).strip().lower()
        dec_otp = decrypt_data(otp_enc, iv).strip()
        dec_new_password = decrypt_data(new_password_enc, iv)
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}, 400

    password_error = input_validation.validate_password_strength(dec_new_password)
    if password_error:
        return {"error": password_error}, 400

    coll = get_user_collection(role)
    user = coll.find_one({"email": dec_email})
    invalid_response = {"error": "Invalid or expired reset code. Please request a new one."}, 400
    if not user:
        return invalid_response

    stored_otp = user.get("reset_otp_code")
    otp_exp = user.get("reset_otp_expiry")
    if not stored_otp or not otp_exp:
        return invalid_response

    if otp_exp.tzinfo is None:
        otp_exp = otp_exp.replace(tzinfo=timezone.utc).astimezone(IST)
    if datetime.now(IST) > otp_exp:
        return {"error": "Reset code has expired. Please request a new one."}, 400

    if not verify_otp_hash(stored_otp, dec_otp):
        attempts = int(user.get("reset_otp_attempts", 0)) + 1
        if attempts >= MAX_PASSWORD_RESET_ATTEMPTS:
            coll.update_one(
                {"_id": user["_id"]},
                {"$unset": {"reset_otp_code": "", "reset_otp_expiry": "", "reset_otp_attempts": ""}},
            )
            return {"error": "Too many incorrect attempts. Please request a new code."}, 429
        coll.update_one({"_id": user["_id"]}, {"$set": {"reset_otp_attempts": attempts}})
        return {"error": "Invalid reset code."}, 400

    new_password_hash = ph.hash(dec_new_password)
    coll.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"password_hash": new_password_hash},
            "$unset": {
                "reset_otp_code": "", "reset_otp_expiry": "", "reset_otp_attempts": "",
                "login_attempts": "", "login_locked_until": "",
            },
        },
    )

    response_data = {"message": "Password reset successfully. Please log in with your new password."}
    enc_resp, iv2 = encrypt_data(json.dumps(response_data))
    return {"encrypted_response": enc_resp, "iv": iv2}, 200


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

    access_token, refresh_token = issue_token_pair(dec_email, "customer")
    return {
        "status": 200,
        "token": access_token,
        "refresh_token": refresh_token,
        "user": {"id": user_id, "email": dec_email, "name": name},
    }, None


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


def delete_account(email: str, role: str):
    """Permanently deletes an account and its personal data — required by Google Play for
    any app that supports account creation. Ported from khelomore-server's
    bookmyconsole_delete_account: the account document itself is hard-deleted, but orders
    (customer) are anonymized rather than hard-deleted — a print shop's own revenue/queue
    history shouldn't disappear because a customer deleted their account, only the
    deleted person's identifiers should stop pointing at them. Also revokes every access
    and refresh token so a copy of either captured before deletion stops working
    immediately instead of remaining valid until natural expiry."""
    coll = get_user_collection(role)
    user = coll.find_one({"email": email})
    if not user:
        return {"status": 404, "error": "Account not found."}

    if role != "shop_staff":
        anon_email = f"deleted-{user['_id']}@quickprint.deleted"
        db_main.orders.update_many(
            {"user_email": email},
            {"$set": {"user_email": anon_email}},
        )

    db_main.refresh_tokens.update_many(
        {"email": email, "role": role},
        {"$set": {"used": True, "revoked_reason": "account_deleted"}},
    )
    coll.delete_one({"_id": user["_id"]})

    return {"status": 200, "message": "Account and personal data deleted."}


