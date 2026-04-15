"""
Weekly email report scheduler for Spambuster.
Generates and sends Ghostbusters-themed HTML email reports.
"""
import logging
from datetime import datetime, timedelta
from typing import Tuple

from database import (
    get_stats, get_spam_stats_by_day, get_all_sender_stats,
    get_user_setting, set_user_setting, get_db_connection
)
from services.email_sender import get_email_sender

logger = logging.getLogger(__name__)


def generate_report_html(user_id: int) -> str:
    """Generate a Ghostbusters/Spambuster-themed HTML email report."""
    overall_stats = get_stats(user_id)
    daily_stats = get_spam_stats_by_day(user_id, days=7)
    top_spammers = get_all_sender_stats(user_id, limit=5)

    # All-time overall protection rate — shown as a single bar
    overall_rate = overall_stats["protection_rate"]
    overall_total = overall_stats["total_emails"]

    # This week's numbers (from the 7-day daily breakdown)
    week_total = sum(d["total"] for d in daily_stats)
    week_spam = sum(d["spam"] for d in daily_stats)
    week_safe = sum(d["safe"] for d in daily_stats)

    # Date range for the report header
    week_end = datetime.now()
    week_start = week_end - timedelta(days=6)
    period_label = f"{week_start.strftime('%b %d')} \u2013 {week_end.strftime('%b %d, %Y')}"

    actions = overall_stats["actions_taken"]
    action_breakdown = overall_stats.get("action_breakdown", {})

    # Top spammers table rows
    spammer_rows = ""
    for s in top_spammers:
        if s["spam_count"] > 0:
            spam_pct = round(s["spam_count"] / s["total_emails"] * 100) if s["total_emails"] > 0 else 0
            spammer_rows += f"""
            <tr>
                <td style="padding: 8px 12px; border-bottom: 1px solid #333; color: #ccc; font-size: 13px;">{s['email_address']}</td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #333; color: #ef4444; text-align: center; font-size: 13px;">{s['spam_count']}</td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #333; color: #999; text-align: center; font-size: 13px;">{spam_pct}%</td>
            </tr>"""

    # Action breakdown rows
    action_rows = ""
    for action, count in action_breakdown.items():
        label = action.replace("_", " ").title()
        action_rows += f"""
        <tr>
            <td style="padding: 6px 12px; border-bottom: 1px solid #333; color: #ccc; font-size: 13px;">{label}</td>
            <td style="padding: 6px 12px; border-bottom: 1px solid #333; color: #f59e0b; text-align: center; font-size: 13px;">{count}</td>
        </tr>"""

    # Daily trend sparkline (simple text-based)
    daily_labels = ""
    daily_spam_cells = ""
    daily_safe_cells = ""
    for d in daily_stats[-7:]:
        day_name = datetime.strptime(d["date"], "%Y-%m-%d").strftime("%a") if d.get("date") else "?"
        daily_labels += f'<td style="padding: 4px 6px; color: #999; font-size: 11px; text-align: center;">{day_name}</td>'
        daily_spam_cells += f'<td style="padding: 4px 6px; color: #ef4444; font-size: 12px; text-align: center; font-weight: 600;">{d["spam"]}</td>'
        daily_safe_cells += f'<td style="padding: 4px 6px; color: #22c55e; font-size: 12px; text-align: center;">{d["safe"]}</td>'

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
    <body style="margin: 0; padding: 0; background: #0a0a0a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <div style="max-width: 600px; margin: 0 auto; background: #111; border: 1px solid #222;">

            <!-- Header Banner -->
            <div style="background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); padding: 32px; text-align: center;">
                <div style="font-size: 48px; margin-bottom: 8px;">&#128123;</div>
                <h1 style="color: white; margin: 0; font-size: 28px; letter-spacing: 1px;">SPAMBUSTERS</h1>
                <p style="color: rgba(255,255,255,0.8); margin: 8px 0 0; font-size: 14px;">Weekly Protection Report</p>
                <p style="color: rgba(255,255,255,0.6); margin: 4px 0 0; font-size: 12px;">{period_label}</p>
            </div>

            <!-- This Week Stats Grid -->
            <div style="padding: 24px 24px 8px;">
                <p style="color: #666; font-size: 11px; margin: 0 0 12px; text-transform: uppercase; letter-spacing: 1px;">This week</p>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="width: 33%; text-align: center; padding: 12px 8px;">
                            <div style="font-size: 28px; font-weight: 700; color: #60a5fa;">{week_total}</div>
                            <div style="font-size: 11px; color: #999; margin-top: 4px;">SCANNED</div>
                        </td>
                        <td style="width: 33%; text-align: center; padding: 12px 8px;">
                            <div style="font-size: 28px; font-weight: 700; color: #ef4444;">{week_spam}</div>
                            <div style="font-size: 11px; color: #999; margin-top: 4px;">SPAM</div>
                        </td>
                        <td style="width: 33%; text-align: center; padding: 12px 8px;">
                            <div style="font-size: 28px; font-weight: 700; color: #22c55e;">{week_safe}</div>
                            <div style="font-size: 11px; color: #999; margin-top: 4px;">SAFE</div>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Overall Protection Bar -->
            <div style="padding: 8px 24px 24px;">
                <div style="background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; padding: 14px 16px;">
                    <div style="color: #666; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Overall protection rate</div>
                    <div style="background: #333; border-radius: 4px; height: 8px; overflow: hidden;">
                        <div style="background: linear-gradient(90deg, #22c55e, #16a34a); height: 100%; width: {overall_rate}%; border-radius: 4px;"></div>
                    </div>
                    <div style="display: table; width: 100%; margin-top: 6px;">
                        <div style="display: table-cell; color: #22c55e; font-size: 20px; font-weight: 700;">{overall_rate}%</div>
                        <div style="display: table-cell; text-align: right; color: #555; font-size: 11px; vertical-align: bottom;">{overall_total} emails all-time</div>
                    </div>
                </div>
            </div>

            <!-- Daily Breakdown -->
            <div style="padding: 0 24px 24px;">
                <h2 style="color: #eee; font-size: 16px; margin: 0 0 16px; border-bottom: 1px solid #333; padding-bottom: 8px;">
                    Daily Breakdown
                </h2>
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 8px;">
                    <tr>{daily_labels}</tr>
                    <tr>{daily_spam_cells}</tr>
                    <tr>{daily_safe_cells}</tr>
                </table>
                <div style="display: flex; gap: 16px; font-size: 12px; color: #999; justify-content: center;">
                    <span><span style="color: #ef4444;">&#9632;</span> Spam ({week_spam})</span>
                    <span><span style="color: #22c55e;">&#9632;</span> Safe ({week_safe})</span>
                </div>
            </div>

            <!-- Top Spam Senders -->
            {"" if not spammer_rows else f'''
            <div style="padding: 0 24px 24px;">
                <h2 style="color: #eee; font-size: 16px; margin: 0 0 16px; border-bottom: 1px solid #333; padding-bottom: 8px;">
                    Top Spam Senders
                </h2>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <th style="padding: 8px 12px; color: #999; font-size: 11px; text-align: left; border-bottom: 1px solid #444;">SENDER</th>
                        <th style="padding: 8px 12px; color: #999; font-size: 11px; text-align: center; border-bottom: 1px solid #444;">SPAM</th>
                        <th style="padding: 8px 12px; color: #999; font-size: 11px; text-align: center; border-bottom: 1px solid #444;">RATE</th>
                    </tr>
                    {spammer_rows}
                </table>
            </div>
            '''}

            <!-- Action Breakdown -->
            {"" if not action_rows else f'''
            <div style="padding: 0 24px 24px;">
                <h2 style="color: #eee; font-size: 16px; margin: 0 0 16px; border-bottom: 1px solid #333; padding-bottom: 8px;">
                    Actions Taken
                </h2>
                <table style="width: 100%; border-collapse: collapse;">
                    {action_rows}
                </table>
                <p style="color: #999; font-size: 12px; margin-top: 8px;">Total actions: {actions}</p>
            </div>
            '''}

            <!-- CTA -->
            <div style="padding: 24px; text-align: center; border-top: 1px solid #333;">
                <p style="color: #999; font-size: 13px; margin: 0 0 16px;">Who ya gonna call?</p>
            </div>

            <!-- Footer -->
            <div style="padding: 16px 24px; background: #0a0a0a; text-align: center;">
                <p style="color: #666; font-size: 11px; margin: 0;">
                    Spambusters Weekly Report &bull; Generated automatically
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    return html


def send_report_now(user_id: int) -> Tuple[bool, str]:
    """Send a report immediately for the given user (manual trigger)."""
    report_email = get_user_setting(user_id, "report_email", "")
    sender = get_email_sender()

    if not sender.is_configured:
        return False, "SMTP is not configured"

    if not report_email:
        report_email = sender.credentials.from_address
    if not report_email:
        return False, "No recipient email configured"

    html = generate_report_html(user_id)
    return sender.send_email(
        to=report_email,
        subject="Spambusters - Weekly Protection Report",
        html_body=html,
        text_body="Your Spambusters weekly report is available. Please view this email in an HTML-capable client."
    )


def check_and_send_reports():
    """Check all users and send reports where due."""
    today = datetime.now().strftime("%A").lower()
    today_date = datetime.now().strftime("%Y-%m-%d")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Find users with reports enabled
    cursor.execute("""
        SELECT DISTINCT us.user_id
        FROM user_settings us
        WHERE us.setting_key = 'report_enabled' AND us.setting_value = '1'
    """)
    user_ids = [row["user_id"] for row in cursor.fetchall()]
    conn.close()

    for user_id in user_ids:
        try:
            report_day = get_user_setting(user_id, "report_day", "monday")
            if report_day != today:
                continue

            # Check if already sent today
            last_sent = get_user_setting(user_id, "last_report_sent", "")
            if last_sent == today_date:
                continue

            success, msg = send_report_now(user_id)
            if success:
                set_user_setting(user_id, "last_report_sent", today_date)
                logger.info(f"Weekly report sent for user {user_id}")
            else:
                logger.warning(f"Failed to send report for user {user_id}: {msg}")
        except Exception as e:
            logger.error(f"Error sending report for user {user_id}: {e}")
