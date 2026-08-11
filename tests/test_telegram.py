from aegis_lite.telegram_alert import send_telegram_alert


print("========== TELEGRAM ALERT TEST ==========\n")

message = (
    "🛡️ Aegis-Lite Test Alert\n\n"
    "Telegram alert service is working successfully."
)

result = send_telegram_alert(message)

if result:
    print("PASS - Telegram alert sent successfully.")
else:
    print("FAIL - Telegram alert could not be sent.")

import aegis_lite.telegram_alert as telegram_alert


print("\n========== MISSING CONFIGURATION TEST ==========\n")

original_token = telegram_alert.BOT_TOKEN

telegram_alert.BOT_TOKEN = None

result = telegram_alert.send_telegram_alert(
    "This message should not be sent."
)

if not result:
    print("PASS - Missing configuration handled correctly.")
else:
    print("FAIL - Missing configuration was not handled correctly.")

telegram_alert.BOT_TOKEN = original_token    