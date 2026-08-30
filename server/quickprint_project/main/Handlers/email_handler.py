# email_handler.py
# Sends the super-admin OTP email via Brevo's HTTP transactional email API. Mirrors
# khelomore-server/.../Handlers/email_handler.py exactly — not raw SMTP, since most PaaS
# free tiers (Render included) silently black-hole outbound SMTP instead of refusing it,
# which hangs the worker forever. An HTTPS API call fails fast/cleanly if Brevo is down.

import os
from email.utils import parseaddr
from dotenv import load_dotenv
from django.conf import settings

load_dotenv()

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")

_parsed_name, _parsed_email = parseaddr(os.getenv("EMAIL_SENDER", ""))
SENDER_EMAIL = _parsed_email or "no-reply@quickprint.app"
SENDER_NAME = _parsed_name or "QuickPrint"

SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "") or SENDER_EMAIL


def _send_email(recipient: str, subject: str, html_body: str) -> bool:
    if not BREVO_API_KEY or not SENDER_EMAIL:
        print(f"[EMAIL] Brevo credentials missing — skipping send to {recipient}")
        return False

    import requests

    try:
        response = requests.post(
            BREVO_API_URL,
            headers={
                "accept": "application/json",
                "api-key": BREVO_API_KEY,
                "content-type": "application/json",
            },
            json={
                "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
                "to": [{"email": recipient}],
                "subject": subject,
                "htmlContent": html_body,
            },
            timeout=15,
        )
        if response.status_code >= 400:
            print(f"[EMAIL] Brevo API Error {response.status_code}: {response.text}")
            return False
        print(f"[EMAIL] Sent '{subject}' to {recipient}")
        return True
    except Exception as e:
        print(f"[EMAIL] Brevo request failed: {e}")
        return False


def send_otp_email(recipient: str, otp: str, name: str = "Admin", purpose: str = "login") -> bool:
    """purpose: 'login' | 'signup' | 'resend'"""
    # SECURITY: OTP codes must never hit server logs in production — only print in local
    # dev (DEBUG=True), same posture as khelomore-server.
    if settings.DEBUG:
        print("\n" + "=" * 55)
        print(f"[QUICKPRINT] SUPER ADMIN OTP — {purpose.upper()}")
        print(f"  Name    : {name}")
        print(f"  Email   : {recipient}")
        print(f"  OTP Code: {otp}")
        print("=" * 55 + "\n")

    action_label = "Sign Up" if purpose == "signup" else "Login"
    subject = f"QuickPrint — Your {action_label} Verification Code: {otp}"

    html_body = f"""
    <html>
    <body style="margin:0;padding:0;background-color:#F4F5F7;font-family:Arial,Helvetica,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#F4F5F7;padding:50px 20px;">
        <tr><td align="center">
          <table width="480" cellpadding="0" cellspacing="0"
                 style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08);">
            <tr>
              <td align="center" style="background:#111827;padding:32px 0;">
                <p style="margin:0;font-size:20px;font-weight:bold;color:#ffffff;letter-spacing:1px;">
                  🖨️ QuickPrint Super Admin
                </p>
              </td>
            </tr>
            <tr>
              <td style="padding:32px 40px;text-align:center;">
                <p style="color:#4B5563;font-size:14px;margin-bottom:24px;">
                  Hi <strong>{name}</strong>, use the code below to verify your identity.
                </p>
                <div style="background:#F4F5F7;border-radius:12px;padding:24px 0;margin:0 auto 24px;max-width:280px;">
                  <p style="margin:0;font-size:36px;letter-spacing:10px;color:#111827;font-weight:bold;">{otp}</p>
                </div>
                <p style="color:#9CA3AF;font-size:12px;margin:0;">
                  This code expires in a few minutes. Never share it with anyone.
                </p>
              </td>
            </tr>
            <tr>
              <td align="center" style="border-top:1px solid #E5E7EB;padding:16px 40px;">
                <p style="margin:0;font-size:10px;color:#9CA3AF;">© QuickPrint. All rights reserved.</p>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """

    return _send_email(recipient, subject, html_body)
