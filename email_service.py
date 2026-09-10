"""Transactional email delivery for DishFinder account emails."""

from hashlib import sha256
from html import escape
import os
from urllib.parse import quote

import httpx


RESEND_EMAILS_URL = "https://api.resend.com/emails"


class EmailConfigurationError(RuntimeError):
    """Raised when required email configuration is missing or invalid."""


class EmailDeliveryError(RuntimeError):
    """Raised when the transactional email provider rejects a request."""


def _verification_url(verification_token: str) -> str:
    base_url = os.environ.get("FRONTEND_URL", "").strip().rstrip("/")
    if not base_url.startswith(("https://", "http://")):
        raise EmailConfigurationError(
            "FRONTEND_URL must be the public http(s) origin that serves the API"
        )
    return f"{base_url}/api/auth/verify-email?token={quote(verification_token, safe='')}"


def send_verification_email(email: str, verification_token: str) -> None:
    """Send a mobile-friendly verification email through Resend's HTTPS API."""
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    sender = os.environ.get("EMAIL_FROM", "").strip()
    app_name = os.environ.get("APP_NAME", "DishFinder").strip() or "DishFinder"
    expiry_minutes = os.environ.get("EMAIL_VERIFICATION_EXPIRE_MINUTES", "60").strip()

    if not api_key or not sender:
        raise EmailConfigurationError(
            "RESEND_API_KEY and EMAIL_FROM must be configured"
        )

    verification_url = _verification_url(verification_token)
    safe_app_name = escape(app_name)
    safe_url = escape(verification_url, quote=True)

    text_content = (
        f"Welcome to {app_name}!\n\n"
        f"Verify your email address within {expiry_minutes} minutes:\n{verification_url}\n\n"
        "If you did not create this account, you can ignore this email."
    )
    html_content = f"""\
<!doctype html>
<html lang="en">
  <body style="margin:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#303743;">
    <div style="display:none;max-height:0;overflow:hidden;">Verify your email to finish creating your {safe_app_name} account.</div>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f3f4f6;padding:28px 12px;">
      <tr><td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border-radius:16px;overflow:hidden;">
          <tr><td style="background:#303743;padding:24px;text-align:center;color:#D6C5AB;font-size:26px;font-weight:700;">{safe_app_name}</td></tr>
          <tr><td style="padding:32px 28px;">
            <h1 style="margin:0 0 16px;font-size:24px;line-height:1.3;">Verify your email</h1>
            <p style="margin:0 0 24px;font-size:16px;line-height:1.6;color:#555d68;">Welcome to {safe_app_name}. Please confirm your email address to finish creating your account.</p>
            <p style="margin:0 0 24px;text-align:center;">
              <a href="{safe_url}" style="display:inline-block;background:#D6C5AB;color:#303743;text-decoration:none;font-size:16px;font-weight:700;padding:14px 24px;border-radius:10px;">Verify Email</a>
            </p>
            <p style="margin:0 0 18px;font-size:14px;line-height:1.6;color:#6b7280;">This verification link expires in {escape(expiry_minutes)} minutes. If you did not create this account, no action is needed.</p>
            <p style="margin:0;font-size:13px;line-height:1.6;color:#6b7280;word-break:break-all;">If the button does not work, open this link:<br><a href="{safe_url}" style="color:#5f503d;">{safe_url}</a></p>
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>
"""

    try:
        response = httpx.post(
            RESEND_EMAILS_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Idempotency-Key": f"email-verification-{sha256(verification_token.encode()).hexdigest()}",
                "User-Agent": "dishfinder-api/1.0",
            },
            json={
                "from": sender,
                "to": [email],
                "subject": f"Verify your {app_name} email",
                "text": text_content,
                "html": html_content,
            },
            timeout=20,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        # Do not expose provider responses: they may contain account or recipient details.
        raise EmailDeliveryError("Resend could not deliver the verification email") from exc
