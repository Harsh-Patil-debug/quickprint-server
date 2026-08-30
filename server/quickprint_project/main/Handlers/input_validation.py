# input_validation.py
# Shared server-side validation for user-submitted fields. Ported directly from
# khelomore-server/.../Handlers/input_validation.py — every check here already exists as
# a client-side HTML attribute in quickprint-hub, but a client-side check is only ever a
# UX nicety, trivially bypassed by anyone calling the API directly. These are the real,
# unbypassable versions.
#
# Every function returns None if the value is acceptable, otherwise a human-readable
# error string.

import re
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")
PHONE_DIGIT_COUNT_RE = re.compile(r"\d")

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def validate_email(email: str) -> str | None:
    if not email or not isinstance(email, str):
        return "A valid email address is required."
    if len(email) > 254:
        return "Email address is too long."
    if not EMAIL_RE.match(email.strip()):
        return "Please enter a valid email address."
    return None


def validate_phone(phone: str, required: bool = True) -> str | None:
    if not phone:
        return "A valid phone number is required." if required else None
    if not isinstance(phone, str):
        return "Please enter a valid phone number."
    digit_count = len(PHONE_DIGIT_COUNT_RE.findall(phone))
    if digit_count < 7 or digit_count > 15 or not PHONE_RE.match(phone.strip()):
        return "Please enter a valid phone number (7-15 digits)."
    return None


def validate_url(url: str, field_name: str = "URL", required: bool = False) -> str | None:
    if not url:
        return f"{field_name} is required." if required else None
    if not isinstance(url, str) or len(url) > 2048:
        return f"{field_name} is too long."
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return f"Please enter a valid {field_name}."
    # SECURITY: only http(s) — rejects javascript:, data:, file:, and other schemes that
    # could be abused if this value is ever rendered as a clickable link.
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return f"Please enter a valid {field_name}."
    return None


def validate_password_strength(password: str) -> str | None:
    if not password or not isinstance(password, str):
        return "A password is required."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    return None


def validate_text(value: str, field_name: str, max_len: int, required: bool = True, min_len: int = 0) -> str | None:
    if not value or not isinstance(value, str) or not value.strip():
        return f"{field_name} is required." if required else None
    if len(value) < min_len:
        return f"{field_name} must be at least {min_len} characters."
    if len(value) > max_len:
        return f"{field_name} must be at most {max_len} characters."
    return None


def parse_bounded_number(value, field_name: str, min_val=None, max_val=None, is_float: bool = False, required: bool = True):
    """
    Parses a client-supplied value (which may already be an int/float, or a numeric
    string, or — if a client is attempting NoSQL injection or just sending garbage — a
    dict, list, or malformed string) into a bounded number.

    Returns (parsed_value, error_message). On success error_message is None. On failure
    parsed_value is None and error_message explains why.
    """
    if value is None or value == "":
        if required:
            return None, f"{field_name} is required."
        return None, None
    try:
        parsed = float(value) if is_float else int(value)
    except (TypeError, ValueError):
        return None, f"{field_name} must be a number."
    if min_val is not None and parsed < min_val:
        return None, f"{field_name} must be at least {min_val}."
    if max_val is not None and parsed > max_val:
        return None, f"{field_name} must be at most {max_val}."
    return parsed, None


def validate_latitude(value) -> str | None:
    _, err = parse_bounded_number(value, "Latitude", min_val=-90, max_val=90, is_float=True, required=True)
    return err


def validate_longitude(value) -> str | None:
    _, err = parse_bounded_number(value, "Longitude", min_val=-180, max_val=180, is_float=True, required=True)
    return err


def validate_enum(value, allowed: set, field_name: str, required: bool = True) -> str | None:
    if not value:
        return f"{field_name} is required." if required else None
    if value not in allowed:
        return f"{field_name} must be one of: {', '.join(sorted(allowed))}."
    return None
