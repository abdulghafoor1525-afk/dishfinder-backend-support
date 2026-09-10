"""SMTP email delivery for DishFinder account emails."""

from email.message import EmailMessage
from html import escape
import os
import smtplib
import ssl
from urllib.parse import quote


class EmailConfigurationError(RuntimeError):
    """Raised when required SMTP configuration is missing or invalid."""


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _verification_url(verification_token: str) -> str:
    base_url = os.environ.get("FRONTEND_URL", "").strip().rstrip("/")
    if not base_url.startswith(("https://", "http://")):
        raise EmailConfigurationError(
            "FRONTEND_URL must be the public http(s) origin that serves the API"
        )
    return f"{base_url}/api/auth/verify-email?token={quote(verification_token, safe='')}"


def send_verification_email(email: str, verification_token: str) -> None:
    """Send a mobile-friendly email without logging credentials or the token."""
    host = os.environ.get("SMTP_HOST", "").strip()
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASS", "")
    sender = os.environ.get("EMAIL_FROM", "").strip()
    app_name = os.environ.get("APP_NAME", "DishFinder").strip() or "DishFinder"
    expiry_minutes = os.environ.get("EMAIL_VERIFICATION_EXPIRE_MINUTES", "60").strip()
    secure = _env_bool("SMTP_SECURE")

    try:
        port = int(os.environ.get("SMTP_PORT", "465" if secure else "587"))
    except ValueError as exc:
        raise EmailConfigurationError("SMTP_PORT must be a number") from exc

    if not all((host, user, password, sender)):
        raise EmailConfigurationError(
            "SMTP_HOST, SMTP_USER, SMTP_PASS, and EMAIL_FROM must be configured"
        )

    verification_url = _verification_url(verification_token)
    safe_app_name = escape(app_name)
    safe_url = escape(verification_url, quote=True)

    message = EmailMessage()
    message["Subject"] = f"Verify your {app_name} email"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Welcome to {app_name}!\n\n"
        f"Verify your email address within {expiry_minutes} minutes:\n{verification_url}\n\n"
        "If you did not create this account, you can ignore this email."
    )
    message.add_alternative(
        f"""\
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
""",
        subtype="html",
    )

    context = ssl.create_default_context()
    if secure:
        with smtplib.SMTP_SSL(host, port, timeout=20, context=context) as smtp:
            smtp.login(user, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.ehlo()
            if _env_bool("SMTP_STARTTLS", True):
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(user, password)
            smtp.send_message(message)
