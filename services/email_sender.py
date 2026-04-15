"""
SMTP email sender service for Spambuster.
Handles sending emails via user-configured SMTP settings.
"""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple

from services.credentials import get_credentials_manager, SMTPCredentials


class SMTPEmailSender:
    """Sends emails via SMTP using user-configured credentials."""

    def __init__(self, credentials: SMTPCredentials):
        self.credentials = credentials

    @property
    def is_configured(self) -> bool:
        return self.credentials.is_configured()

    def send_email(self, to: str, subject: str, html_body: str,
                   text_body: str = None) -> Tuple[bool, str]:
        """
        Send an email via SMTP.

        Args:
            to: Recipient email address
            subject: Email subject
            html_body: HTML email body
            text_body: Optional plain text fallback

        Returns:
            Tuple of (success, error_message)
        """
        if not self.is_configured:
            return False, "SMTP is not configured"

        msg = MIMEMultipart("alternative")
        msg["From"] = self.credentials.from_address
        msg["To"] = to
        msg["Subject"] = subject

        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            if self.credentials.use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.credentials.server, self.credentials.port,
                                  timeout=15) as server:
                    server.starttls(context=context)
                    server.login(self.credentials.username, self.credentials.password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(self.credentials.server, self.credentials.port,
                                  timeout=15) as server:
                    server.login(self.credentials.username, self.credentials.password)
                    server.send_message(msg)

            return True, ""
        except smtplib.SMTPAuthenticationError:
            return False, "Authentication failed. Check your username and password."
        except smtplib.SMTPConnectError:
            return False, f"Could not connect to {self.credentials.server}:{self.credentials.port}"
        except smtplib.SMTPException as e:
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"

    def send_test_email(self, to: str) -> Tuple[bool, str]:
        """Send a test email to verify SMTP configuration."""
        html_body = """
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 500px; margin: 0 auto; padding: 32px;">
            <div style="text-align: center; margin-bottom: 24px;">
                <div style="font-size: 48px;">&#128123;</div>
                <h1 style="color: #dc2626; margin: 8px 0;">Spambusters</h1>
                <p style="color: #666;">SMTP Configuration Test</p>
            </div>
            <div style="background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px; padding: 16px; text-align: center;">
                <p style="color: #166534; margin: 0; font-weight: 600;">Your SMTP settings are working correctly!</p>
            </div>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 24px;">
                This is a test email from Spambusters. Who ya gonna call?
            </p>
        </div>
        """
        return self.send_email(
            to=to,
            subject="Spambusters - SMTP Test Successful",
            html_body=html_body,
            text_body="Your Spambusters SMTP settings are working correctly!"
        )


def _get_admin_user_id() -> int:
    """Get the first admin user's ID for global SMTP credentials."""
    from database import get_db_connection
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM auth_users WHERE is_admin = 1 ORDER BY id LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row["id"] if row else 1


def get_email_sender(user_id: int = None) -> SMTPEmailSender:
    """
    Get an email sender using global SMTP credentials.

    SMTP credentials are stored under the admin user but shared globally.
    The user_id parameter is accepted for API consistency but SMTP config
    is always loaded from the admin account.
    """
    admin_id = _get_admin_user_id()
    manager = get_credentials_manager()
    credentials = manager.get_smtp_credentials(admin_id)
    return SMTPEmailSender(credentials)
