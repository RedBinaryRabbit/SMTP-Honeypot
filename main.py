import smtpd
import asyncore
from email.parser import BytesParser
from email import policy
import string
import os
import requests
import json

# --- Discord Webhook Configuration ---
# It is highly recommended to set the webhook URL via an environment variable for security.
# Example: export DISCORD_WEBHOOK_URL='your_webhook_url_here'
DISCORD_WEBHOOK_URL = os.environ.get(
    "DISCORD_WEBHOOK_URL",
    "https://discordapp.com/api/webhooks/xxxxx/xxxxxxx"
)

def sanitize_input(data: str, max_length: int = 4096) -> str:
    """Sanitizes input by removing non-printable characters and truncating."""
    truncated_data = data[:max_length]
    printable = set(string.printable)
    sanitized_data = "".join(filter(lambda x: x in printable, truncated_data))
    return sanitized_data

def send_discord_notification(peer, mailfrom, rcpttos, subject, body):
    """Sends a notification to the configured Discord webhook."""
    if not DISCORD_WEBHOOK_URL:
        print("!!! Discord Webhook URL not configured. Skipping notification. !!!")
        return

    fields = [
        {"name": "Sender IP (Peer)", "value": f"`{peer[0]}:{peer[1]}`", "inline": True},
        {"name": "Mail From", "value": f"`{mailfrom}`", "inline": True},
        {"name": "Recipient(s)", "value": f"`{', '.join(rcpttos)}`", "inline": False},
        {"name": "Subject", "value": subject, "inline": False},
    ]

    # Split body into chunks of 1024 characters
    body_chunks = [body[i:i + 1024] for i in range(0, len(body), 1024)]

    for i, chunk in enumerate(body_chunks):
        field_name = "Body" if i == 0 else f"Body (cont. {i+1})"
        fields.append({"name": field_name, "value": "```\n{}\n```".format(chunk), "inline": False})

    embed = {
        "title": "📧 New Email Caught by Honeypot",
        "color": 3066993, # Green color
        "fields": fields
    }

    payload = {
        "username": "SMTP Honeypot",
        "embeds": [embed]
    }

    try:
        response = requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(payload), headers={"Content-Type": "application/json"})
        response.raise_for_status()
        print("--> Discord notification sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"!!! ERROR sending Discord notification: {e} !!!")


class CustomSMTPServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        # --- 1. Log to file ---
        try:
            with open('records.txt', 'a') as f:
                f.write('---------- New message received ----------\n')
                f.write(f'Peer: {peer}\n')
                f.write(f'Mail from: {mailfrom}\n')
                f.write(f'Rcpt to: {", ".join(rcpttos)}\n')

                parser = BytesParser(policy=policy.default)
                msg = parser.parsebytes(data)

                subject = sanitize_input(msg.get("subject", "(no subject)"))
                f.write(f'Subject: {subject}\n')

                body_str = "(no plain text body found)"
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        cdispo = str(part.get("Content-Disposition"))
                        if ctype == "text/plain" and "attachment" not in cdispo:
                            body_bytes = part.get_payload(decode=True)
                            body_str = sanitize_input(body_bytes.decode('utf-8', errors='ignore'))
                            break
                else:
                    body_bytes = msg.get_payload(decode=True)
                    body_str = sanitize_input(body_bytes.decode('utf-8', errors='ignore'))

                f.write("Body:\n")
                f.write(body_str + '\n')
                f.write('----------------------------------------\n')

        except IOError as e:
            print(f"!!! ERROR WRITING TO FILE: {e} !!!")
            return # Exit if file writing fails

        # --- 2. Send Discord Notification ---
        send_discord_notification(peer, mailfrom, rcpttos, subject, body_str)

        return

def main():
    print("Starting SMTP Honeypot on port 25...")
    if "discordapp.com" in DISCORD_WEBHOOK_URL:
         print("--> Discord notifications ENABLED.")
    else:
        print("--> Discord notifications DISABLED (invalid or no webhook URL).")

    server = CustomSMTPServer(('0.0.0.0', 25), None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        print("\nHoneypot stopped by user.")


if __name__ == '__main__':
    main()
