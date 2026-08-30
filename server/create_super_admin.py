"""
create_super_admin.py — one-off bootstrap for QuickPrint's first super admin account.

SuperAdminRegisterView (POST /super-admin/register/) deliberately requires an
already-authenticated super admin (or the static ADMIN_TOKEN) to create a NEW super_admin
account — otherwise anyone could self-provision one. That guard lives at the view layer,
so this script bypasses it on purpose by calling auth_handler.register_super_admin()
directly, then verifies the OTP (printed to this console — DEBUG=True logs it) so the
account is Active and ready to log in with, no email needed for this one-time step.

Usage:
    python create_super_admin.py <name> <email>

You'll be prompted for the password interactively (not as a CLI argument — an argument
would land in your shell history and be visible to anything reading the process list
while this runs).

Example:
    python create_super_admin.py "Harsh Patil" harsh@quickprint.app

After this, log in normally at the admin panel's /login page — subsequent super admin
accounts can be created from within the app itself once you're logged in.
"""

import os
import sys
import base64
import getpass
import django

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "server.settings")
django.setup()

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from quickprint_project.main.Handlers import auth_handler
from quickprint_project.main.Handlers.db_connection import db_main


def _encrypt(plain: str, iv_bytes: bytes) -> str:
    cipher = AES.new(auth_handler.ENCRYPTION_KEY, AES.MODE_CBC, iv_bytes)
    enc = cipher.encrypt(pad(plain.encode("utf-8"), AES.block_size))
    return base64.b64encode(enc).decode("utf-8")


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    name, email = sys.argv[1], sys.argv[2].strip().lower()

    if db_main.super_admin.find_one({"email": email}):
        print(f"A super admin account already exists for {email}. Nothing to do.")
        sys.exit(1)

    password = getpass.getpass("Set a password for this account: ")
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("Passwords did not match.")
        sys.exit(1)

    iv_bytes = get_random_bytes(16)
    iv_b64 = base64.b64encode(iv_bytes).decode("utf-8")
    name_enc = _encrypt(name, iv_bytes)
    email_enc = _encrypt(email, iv_bytes)
    password_enc = _encrypt(password, iv_bytes)

    print(f"\n[1/2] Registering {email}...")
    result, status = auth_handler.register_super_admin(name_enc, email_enc, password_enc, iv_b64)
    if status != 200:
        print(f"Registration failed: {result}")
        sys.exit(1)

    # otp_code is stored hashed, not retrievable — DEBUG=True already printed the real
    # code to this console above (via email_handler.send_otp_email), so just ask for it.
    otp_code = input("Enter the OTP printed above to activate this account: ").strip()

    verify_iv_bytes = get_random_bytes(16)
    verify_iv_b64 = base64.b64encode(verify_iv_bytes).decode("utf-8")
    email_enc_verify = _encrypt(email, verify_iv_bytes)
    otp_enc_verify = _encrypt(otp_code, verify_iv_bytes)

    print("[2/2] Verifying OTP and activating account...")
    verify_result, verify_status = auth_handler.verify_super_admin_otp(email_enc_verify, otp_enc_verify, verify_iv_b64)
    if verify_status != 200:
        print(f"Verification failed: {verify_result}")
        sys.exit(1)

    print(f"\nSuper admin account for {email} is now Active. Log in at the admin panel's /login page.")


if __name__ == "__main__":
    main()
