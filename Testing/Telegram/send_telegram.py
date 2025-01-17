from auth import TELEGRAM_ACCESS_TOKEN, TELEGRAM_CHAT_ID
import requests
import random
import string

message = "hello from your telegram bot"
characters = string.ascii_letters + string.digits   
message = ''.join(random.choice(characters) for i in range(4096))

url = f"https://api.telegram.org/bot{TELEGRAM_ACCESS_TOKEN}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&text={message}"
print(url)
print(requests.get(url).json())