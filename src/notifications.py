import requests
import os
import sys
import argparse

def send_telegram_message(message):
    """Sends a message to the configured Telegram chat."""
    token = os.environ.get("TELEGRAM_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    
    if not token or not chat_id:
        print("Telegram credentials not found. Skipping notification.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        print("Telegram notification sent.")
    except Exception as e:
        print(f"Failed to send Telegram notification: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send Telegram Notification")
    parser.add_argument("message", help="Message to send")
    args = parser.parse_args()
    
    send_telegram_message(args.message)
