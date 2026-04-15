"""
Discord bot integration for Spambuster.
Sends notifications about suspicious emails and allows labeling via button interactions.
Uses discord.py with gateway connection to stay online and handle interactions.
Per-user support for multi-tenant SaaS.
"""
import logging
import os
import asyncio
import threading
from datetime import datetime
from typing import Optional, Callable, Dict
import discord
from discord import Interaction, ButtonStyle
from discord.ui import View, Button
import aiohttp

logger = logging.getLogger(__name__)

from config import Config


class DiscordBot(discord.Client):
    """Discord bot client that stays online and handles interactions."""

    def __init__(self, user_id: int, channel_id: str, label_callback: Callable = None):
        """
        Initialize Discord bot for a specific user.

        Args:
            user_id: User ID for label callbacks
            channel_id: Discord channel ID for notifications
            label_callback: Optional callback for labeling emails
        """
        intents = discord.Intents.default()
        super().__init__(intents=intents)

        self.user_id = user_id
        self.channel_id = channel_id
        self.label_callback = label_callback or self._default_label_callback
        self._activity_type = "watching"
        self._activity_name = "for spam emails"
        self._ready_event = asyncio.Event()

    def _default_label_callback(self, email_id: int, is_spam: bool):
        """Default callback - imports database function to avoid circular import."""
        from database import label_email
        label_email(self.user_id, email_id, is_spam)

    def _handle_email_action(self, action: str, email_id: int, user_id: int = None) -> str:
        """Handle various email actions from Discord buttons/dropdowns."""
        from database import label_email, add_to_list, get_db_connection, log_deleted_email

        uid = user_id or self.user_id

        if action == "spam":
            label_email(uid, email_id, True)
            return "Marked as spam"
        elif action == "safe":
            label_email(uid, email_id, False)
            return "Marked as safe"
        elif action == "delete":
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT message_id, sender, subject, spam_score FROM emails WHERE id = ? AND user_id = ?",
                (email_id, uid)
            )
            row = cursor.fetchone()
            conn.close()
            if not row:
                return "Email not found"

            # Attempt actual IMAP delete
            try:
                from services.email_service import get_email_service
                email_service = get_email_service(uid)
                if not email_service.connection:
                    email_service.connect()

                imap_uid = email_service.find_uid_by_message_id(row["message_id"])
                if imap_uid:
                    # Save EML backup before deletion
                    eml_path = self._save_eml_backup(uid, email_service, imap_uid, row)

                    if email_service.delete_email(imap_uid):
                        log_deleted_email(
                            user_id=uid,
                            email_id=email_id,
                            message_id=row["message_id"],
                            sender=row["sender"],
                            subject=row["subject"],
                            spam_score=row["spam_score"] or 0.0,
                            eml_file_path=eml_path
                        )
                        label_email(uid, email_id, True)
                        return "Email deleted from server"
                    else:
                        label_email(uid, email_id, True)
                        return "Failed to delete from IMAP, marked as spam"
                else:
                    label_email(uid, email_id, True)
                    return "Email not found on IMAP server, marked as spam"
            except Exception as e:
                label_email(uid, email_id, True)
                return f"Delete error: {str(e)[:80]}, marked as spam"

        elif action == "movetospam":
            label_email(uid, email_id, True)
            return "Marked as spam"
        elif action == "whitelist":
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT sender FROM emails WHERE id = ? AND user_id = ?",
                (email_id, uid)
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                add_to_list(uid, row["sender"], "whitelist", "Added via Discord")
                label_email(uid, email_id, False)
                return f"Added {row['sender']} to whitelist"
            return "Email not found"
        elif action == "blacklist":
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT sender FROM emails WHERE id = ? AND user_id = ?",
                (email_id, uid)
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                add_to_list(uid, row["sender"], "blacklist", "Added via Discord")
                label_email(uid, email_id, True)
                return f"Added {row['sender']} to blacklist"
            return "Email not found"
        elif action == "restore":
            label_email(uid, email_id, False)
            return "Marked as safe (restore manually from spam folder if needed)"
        return "Unknown action"

    def _save_eml_backup(self, user_id: int, email_service, imap_uid: bytes, email_row: dict) -> str:
        """Save an email as .eml backup before deletion."""
        import os
        from config import Config

        try:
            user_eml_path = os.path.join(Config.EML_STORAGE_PATH, str(user_id))
            os.makedirs(user_eml_path, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_id = email_row["message_id"].replace("<", "").replace(">", "").replace("/", "_")[:50]
            filename = f"{timestamp}_{safe_id}.eml"
            filepath = os.path.join(user_eml_path, filename)

            # Fetch raw email from IMAP
            status, msg_data = email_service.connection.fetch(imap_uid, "(RFC822)")
            if status == "OK" and msg_data[0][1]:
                with open(filepath, "wb") as f:
                    f.write(msg_data[0][1])
                return filepath
        except Exception as e:
            logger.error("Failed to save .eml backup: %s", e)
        return ""

    async def on_ready(self):
        """Called when bot is connected and ready."""
        logger.info("Discord bot connected as %s", self.user)
        await self.update_activity(self._activity_type, self._activity_name)
        self._ready_event.set()

    async def on_interaction(self, interaction: Interaction):
        """Handle button and dropdown interactions."""
        if interaction.type == discord.InteractionType.component:
            custom_id = interaction.data.get("custom_id", "")

            # Handle button clicks: format is {action}_{email_id}_{token}
            if custom_id.startswith(("spam_", "safe_", "delete_", "movetospam_")):
                parts = custom_id.split("_", 2)
                if len(parts) == 3:
                    action, email_id_str, token = parts
                    try:
                        email_id = int(email_id_str)

                        # Validate token
                        from database import validate_discord_action_token, invalidate_discord_action_token
                        token_user_id = validate_discord_action_token(token, email_id)
                        if token_user_id is None:
                            await interaction.response.send_message(
                                "This action has expired or is invalid.", ephemeral=True)
                            return

                        result = self._handle_email_action(action, email_id, user_id=token_user_id)
                        invalidate_discord_action_token(token)
                        await interaction.response.send_message(result, ephemeral=True)
                    except (ValueError, Exception) as e:
                        await interaction.response.send_message(f"Error: {e}", ephemeral=True)
                return

            # Handle dropdown selection: format is {action}_{email_id}_{token}
            if custom_id.startswith("actions_"):
                values = interaction.data.get("values", [])
                if values:
                    selected = values[0]
                    parts = selected.split("_", 2)
                    if len(parts) == 3:
                        action, email_id_str, token = parts
                        try:
                            email_id = int(email_id_str)

                            from database import validate_discord_action_token, invalidate_discord_action_token
                            token_user_id = validate_discord_action_token(token, email_id)
                            if token_user_id is None:
                                await interaction.response.send_message(
                                    "This action has expired or is invalid.", ephemeral=True)
                                return

                            result = self._handle_email_action(action, email_id, user_id=token_user_id)
                            invalidate_discord_action_token(token)
                            await interaction.response.send_message(result, ephemeral=True)
                        except (ValueError, Exception) as e:
                            await interaction.response.send_message(f"Error: {e}", ephemeral=True)
                return

    async def update_activity(self, activity_type: str = "watching", name: str = "for spam emails"):
        """Update the bot's activity/presence."""
        self._activity_type = activity_type
        self._activity_name = name

        activity_types = {
            "playing": discord.ActivityType.playing,
            "streaming": discord.ActivityType.streaming,
            "listening": discord.ActivityType.listening,
            "watching": discord.ActivityType.watching,
            "competing": discord.ActivityType.competing,
        }

        act_type = activity_types.get(activity_type.lower(), discord.ActivityType.watching)
        activity = discord.Activity(type=act_type, name=name)
        await self.change_presence(activity=activity, status=discord.Status.online)

    async def send_spam_alert(self, email_id: int, sender: str, subject: str,
                              spam_score: float, prediction: str,
                              content_preview: str = "", token: str = "") -> bool:
        """Send a spam alert with interactive buttons."""
        if not self.channel_id:
            return False

        try:
            channel = self.get_channel(int(self.channel_id))
            if not channel:
                channel = await self.fetch_channel(int(self.channel_id))

            if not channel:
                return False

            # Build embed
            threat_color = self._get_threat_color(spam_score)
            threat_emoji = self._get_threat_emoji(spam_score)
            confidence_pct = int(spam_score * 100)

            embed = discord.Embed(
                title=f"{threat_emoji} Suspicious Email Detected",
                color=threat_color
            )
            embed.add_field(name="Subject", value=self._truncate(subject, 200) or "(No subject)", inline=False)
            embed.add_field(name="Sender", value=self._truncate(sender, 100), inline=True)
            embed.add_field(name="Confidence", value=f"{confidence_pct}%", inline=True)
            embed.add_field(name="Prediction", value=prediction.upper(), inline=True)

            if content_preview:
                embed.add_field(name="Preview", value=f"```{self._truncate(content_preview, 300)}```", inline=False)

            embed.set_footer(text=f"Email ID: {email_id} | Spambuster")

            # Create view with buttons and dropdown (token secures button actions)
            view = SpamAlertView(email_id, token=token)

            await channel.send(embed=embed, view=view)
            return True

        except Exception as e:
            logger.error("Discord send error: %s", e)
            return False

    async def send_summary(self, total_scanned: int, spam_found: int, mode: str) -> bool:
        """Send a scan summary."""
        if not self.channel_id:
            return False

        try:
            channel = self.get_channel(int(self.channel_id))
            if not channel:
                channel = await self.fetch_channel(int(self.channel_id))

            embed = discord.Embed(title="Scan Complete", color=0x00D4FF)
            embed.add_field(name="Emails Scanned", value=str(total_scanned), inline=True)
            embed.add_field(name="Threats Found", value=str(spam_found), inline=True)
            embed.add_field(name="Mode", value=mode.title(), inline=True)

            await channel.send(embed=embed)
            return True
        except Exception as e:
            logger.error("Discord send error: %s", e)
            return False

    def _truncate(self, text: str, max_length: int = 100) -> str:
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..."

    def _get_threat_color(self, spam_score: float) -> int:
        if spam_score >= 0.8:
            return 0xDC3545  # Red
        elif spam_score >= 0.6:
            return 0xFFC107  # Yellow
        return 0x28A745  # Green

    def _get_threat_emoji(self, spam_score: float) -> str:
        if spam_score >= 0.8:
            return "🚨"
        elif spam_score >= 0.6:
            return "⚠️"
        return "✅"


class SpamAlertView(View):
    """Discord UI view with spam/safe buttons and action dropdown."""

    def __init__(self, email_id: int, token: str = ""):
        super().__init__(timeout=None)  # Persistent view
        self.email_id = email_id

        # Quick action buttons with token embedded in custom_id
        self.add_item(Button(
            style=ButtonStyle.danger,
            label="Spam",
            custom_id=f"spam_{email_id}_{token}",
            emoji="🚫"
        ))
        self.add_item(Button(
            style=ButtonStyle.success,
            label="Safe",
            custom_id=f"safe_{email_id}_{token}",
            emoji="✅"
        ))
        self.add_item(Button(
            style=ButtonStyle.danger,
            label="Delete",
            custom_id=f"delete_{email_id}_{token}",
            emoji="🗑️"
        ))
        self.add_item(Button(
            style=ButtonStyle.primary,
            label="Move to Spam",
            custom_id=f"movetospam_{email_id}_{token}",
            emoji="📁"
        ))

        # Dropdown for more actions with token in values
        self.add_item(discord.ui.Select(
            custom_id=f"actions_{email_id}_{token}",
            placeholder="More actions...",
            options=[
                discord.SelectOption(label="Whitelist Sender", value=f"whitelist_{email_id}_{token}", description="Always trust this sender", emoji="✅"),
                discord.SelectOption(label="Blacklist Sender", value=f"blacklist_{email_id}_{token}", description="Always block this sender", emoji="🚫"),
                discord.SelectOption(label="Restore to Inbox", value=f"restore_{email_id}_{token}", description="Move back to inbox", emoji="📥"),
            ]
        ))


class DiscordNotifier:
    """
    Manages Discord bot lifecycle and provides sync interface for sending messages.
    Runs the bot in a background thread with its own event loop.
    Per-user support for multi-tenant SaaS.
    """

    def __init__(self, user_id: int):
        """
        Initialize Discord notifier for a specific user.

        Args:
            user_id: User ID for credential lookup
        """
        self.user_id = user_id
        self._credentials = None

        self._bot: Optional[DiscordBot] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def _get_credentials(self):
        """Get Discord credentials for this user."""
        if self._credentials is None:
            from services.credentials import get_credentials_manager
            manager = get_credentials_manager()
            self._credentials = manager.get_discord_credentials(self.user_id)
        return self._credentials

    @property
    def webhook_url(self) -> str:
        """Get webhook URL for this user."""
        return self._get_credentials().webhook_url

    @property
    def bot_token(self) -> str:
        """Get bot token for this user."""
        return self._get_credentials().bot_token

    @property
    def channel_id(self) -> str:
        """Get channel ID for this user."""
        return self._get_credentials().channel_id

    @property
    def is_configured(self) -> bool:
        """Check if Discord is configured for this user."""
        creds = self._get_credentials()
        return creds.is_webhook_configured() or creds.is_bot_configured()

    @property
    def is_online(self) -> bool:
        """Check if bot is online."""
        return self._running and self._bot is not None and self._bot.is_ready()

    def start_bot(self):
        """Start the Discord bot in a background thread."""
        if self._running or not self.bot_token:
            return False

        self._running = True
        self._thread = threading.Thread(target=self._run_bot, daemon=True)
        self._thread.start()
        return True

    def _run_bot(self):
        """Run the bot in its own event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        self._bot = DiscordBot(self.user_id, self.channel_id)

        try:
            self._loop.run_until_complete(self._bot.start(self.bot_token))
        except Exception as e:
            logger.error("Discord bot error for user %s: %s", self.user_id, e)
        finally:
            self._running = False

    def stop_bot(self):
        """Stop the Discord bot."""
        if not self._running or not self._bot:
            return

        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._bot.close(), self._loop)
        self._running = False

    def set_activity(self, activity_type: str, name: str) -> bool:
        """Set the bot's activity. Returns True if successful."""
        if not self.is_online:
            return False

        future = asyncio.run_coroutine_threadsafe(
            self._bot.update_activity(activity_type, name),
            self._loop
        )
        try:
            future.result(timeout=5)
            return True
        except Exception as e:
            logger.warning("Failed to set activity: %s", e)
            return False

    def get_activity(self) -> dict:
        """Get current activity settings."""
        if self._bot:
            return {
                "type": self._bot._activity_type,
                "name": self._bot._activity_name,
                "online": self.is_online
            }
        return {"type": "watching", "name": "for spam emails", "online": False}

    def send_spam_alert(self, email_id: int, sender: str, subject: str,
                        spam_score: float, prediction: str,
                        content_preview: str = "", token: str = "") -> bool:
        """Send a spam alert. Uses bot if online, falls back to webhook."""
        if not self.is_configured:
            return False

        # Try bot first if online
        if self.is_online and self._bot and self._loop:
            future = asyncio.run_coroutine_threadsafe(
                self._bot.send_spam_alert(email_id, sender, subject, spam_score, prediction,
                                          content_preview, token=token),
                self._loop
            )
            try:
                return future.result(timeout=10)
            except Exception as e:
                logger.warning("Bot send failed, falling back to webhook: %s", e)

        # Fallback to webhook (no buttons, token not needed)
        return self._send_webhook_alert(email_id, sender, subject, spam_score, prediction, content_preview)

    def _send_webhook_alert(self, email_id: int, sender: str, subject: str,
                            spam_score: float, prediction: str, content_preview: str = "") -> bool:
        """Send alert via webhook (fallback, no buttons)."""
        if not self.webhook_url:
            return False

        import requests

        threat_color = 0xDC3545 if spam_score >= 0.8 else (0xFFC107 if spam_score >= 0.6 else 0x28A745)
        threat_emoji = "🚨" if spam_score >= 0.8 else ("⚠️" if spam_score >= 0.6 else "✅")

        embed = {
            "title": f"{threat_emoji} Suspicious Email Detected",
            "color": threat_color,
            "fields": [
                {"name": "Subject", "value": (subject[:200] if subject else "(No subject)"), "inline": False},
                {"name": "Sender", "value": sender[:100], "inline": True},
                {"name": "Confidence", "value": f"{int(spam_score * 100)}%", "inline": True},
                {"name": "Prediction", "value": prediction.upper(), "inline": True},
            ],
            "footer": {"text": f"Email ID: {email_id} | Spambuster (webhook - buttons unavailable)"}
        }

        if content_preview:
            embed["fields"].append({"name": "Preview", "value": f"```{content_preview[:300]}```", "inline": False})

        try:
            response = requests.post(self.webhook_url, json={"embeds": [embed]}, timeout=10)
            return response.status_code in (200, 204)
        except Exception as e:
            logger.error("Webhook error: %s", e)
            return False

    def send_test_notification(self) -> tuple[bool, str]:
        """
        Send a test notification to verify Discord configuration.
        Returns: (success: bool, error_message: str)
        """
        creds = self._get_credentials()

        if not self.is_configured:
            return False, "Discord is not configured. Please set up a webhook URL or bot token."

        # Check what's configured
        has_bot = bool(creds.bot_token and creds.channel_id)
        has_webhook = bool(creds.webhook_url)

        # Try bot first if online
        if self.is_online and self._bot and self._loop:
            if not self.channel_id:
                return False, "Bot is online but no channel ID is configured."

            async def _send_test():
                try:
                    channel = self._bot.get_channel(int(self.channel_id))
                    if not channel:
                        channel = await self._bot.fetch_channel(int(self.channel_id))
                    if channel:
                        embed = discord.Embed(
                            title="🧪 Test Notification",
                            description="Your Discord integration is working correctly!",
                            color=0x22c55e
                        )
                        embed.set_footer(text="Spambuster")
                        await channel.send(embed=embed)
                        return True, ""
                    return False, f"Channel {self.channel_id} not found or bot doesn't have access to it."
                except Exception as e:
                    return False, f"Bot error: {str(e)}"

            future = asyncio.run_coroutine_threadsafe(_send_test(), self._loop)
            try:
                result = future.result(timeout=10)
                if result[0]:  # If bot succeeded
                    return result
                # Otherwise fall through to webhook
                logger.warning("Bot test send failed, falling back to webhook: %s", result[1])
            except Exception as e:
                logger.warning("Bot test send failed, falling back to webhook: %s", e)

        # Fallback to webhook
        if self.webhook_url:
            import requests
            embed = {
                "title": "🧪 Test Notification",
                "description": "Your Discord integration is working correctly!",
                "color": 0x22c55e,
                "footer": {"text": "Spambuster"}
            }
            try:
                response = requests.post(self.webhook_url, json={"embeds": [embed]}, timeout=10)
                if response.status_code in (200, 204):
                    return True, ""
                return False, f"Webhook returned status {response.status_code}: {response.text[:100]}"
            except requests.exceptions.Timeout:
                return False, "Webhook request timed out. Check your webhook URL and network connection."
            except requests.exceptions.RequestException as e:
                return False, f"Webhook error: {str(e)}"

        # More specific error message based on what's configured
        if has_bot and not has_webhook:
            return False, "Bot is configured but not started. Click 'Start Bot' button first, or add a webhook URL as fallback."
        elif has_webhook and not has_bot:
            return False, "Webhook is configured but failed to send. Check if the webhook URL is valid."
        else:
            return False, "Both bot and webhook are configured but neither is working. Bot may be offline and webhook URL may be invalid."

    def send_summary(self, total_scanned: int, spam_found: int, mode: str) -> bool:
        """Send scan summary."""
        if not self.is_configured:
            return False

        if self.is_online and self._bot and self._loop:
            future = asyncio.run_coroutine_threadsafe(
                self._bot.send_summary(total_scanned, spam_found, mode),
                self._loop
            )
            try:
                return future.result(timeout=10)
            except Exception:
                pass

        # Fallback to webhook
        if self.webhook_url:
            import requests
            embed = {
                "title": "Scan Complete",
                "color": 0x00D4FF,
                "fields": [
                    {"name": "Emails Scanned", "value": str(total_scanned), "inline": True},
                    {"name": "Threats Found", "value": str(spam_found), "inline": True},
                    {"name": "Mode", "value": mode.title(), "inline": True},
                ]
            }
            try:
                response = requests.post(self.webhook_url, json={"embeds": [embed]}, timeout=10)
                return response.status_code in (200, 204)
            except Exception:
                pass

        return False


# Per-user notifier instances cache
_discord_notifiers: Dict[int, DiscordNotifier] = {}


def get_discord_notifier(user_id: int) -> DiscordNotifier:
    """
    Get the Discord notifier instance for a specific user.

    Args:
        user_id: User ID

    Returns:
        DiscordNotifier instance for the user
    """
    global _discord_notifiers
    if user_id not in _discord_notifiers:
        _discord_notifiers[user_id] = DiscordNotifier(user_id)
    return _discord_notifiers[user_id]


def clear_discord_notifier_cache(user_id: int = None):
    """
    Clear cached Discord notifier instances.

    Args:
        user_id: Specific user to clear, or None for all users
    """
    global _discord_notifiers
    if user_id is not None:
        notifier = _discord_notifiers.pop(user_id, None)
        if notifier:
            notifier.stop_bot()
    else:
        for notifier in _discord_notifiers.values():
            notifier.stop_bot()
        _discord_notifiers.clear()
