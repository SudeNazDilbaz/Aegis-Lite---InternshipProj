import os
import requests
from dotenv import load_dotenv


load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_telegram_alert(message: str) -> bool:
    if not BOT_TOKEN or not CHAT_ID:
        print("Telegram configuration is missing.")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message,
    }

    try:
        response = requests.post(
            url,
            data=payload,
            timeout=5,
        )

        if response.ok:
            return True

        return False

    except requests.RequestException:
        return False