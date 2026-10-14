"""Send alerts to the screen, a log file, and optionally email."""

import os
import smtplib
from email.message import EmailMessage

from .inventory import now


def describe(dev):
    label = dev.get("name") or dev.get("hostname") or "unknown name"
    return f"{dev['ip']:<15}  {dev['mac']}  {label}"


def build_new_device_message(devices):
    lines = [f"VYTRON found {len(devices)} unapproved device(s) on your network:", ""]
    lines += [describe(d) for d in devices]
    lines += ["", "If you recognize a device, approve it with:",
              "    python -m vytron approve <MAC> --name \"Front desk PC\"",
              "If you don't recognize it, unplug it or block it at your switch/router."]
    return "\n".join(lines)


def email_settings():
    """Read email settings from environment variables. None if not set up."""
    host = os.environ.get("VYTRON_SMTP_HOST")
    to = os.environ.get("VYTRON_ALERT_TO")
    if not host or not to:
        return None
    return {
        "host": host,
        "port": int(os.environ.get("VYTRON_SMTP_PORT", "587")),
        "user": os.environ.get("VYTRON_SMTP_USER", ""),
        "password": os.environ.get("VYTRON_SMTP_PASSWORD", ""),
        "to": to,
        "from": os.environ.get("VYTRON_ALERT_FROM") or os.environ.get("VYTRON_SMTP_USER") or to,
    }


def send_email(subject, body, settings):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings["from"]
    msg["To"] = settings["to"]
    msg.set_content(body)
    with smtplib.SMTP(settings["host"], settings["port"], timeout=30) as smtp:
        smtp.starttls()
        if settings["user"]:
            smtp.login(settings["user"], settings["password"])
        smtp.send_message(msg)


def alert(subject, body, log_path):
    print(f"\n*** ALERT: {subject} ***\n{body}\n")
    with open(log_path, "a") as f:
        f.write(f"[{now()}] {subject}\n{body}\n\n")
    settings = email_settings()
    if settings:
        try:
            send_email(f"[VYTRON] {subject}", body, settings)
        except (OSError, smtplib.SMTPException) as e:
            print(f"(Could not send alert email: {e})")
