from auth import ACCESS_TOKEN, CHAT_ID
import requests

message = "hello from your telegram bot"
url = f"https://api.telegram.org/bot{ACCESS_TOKEN}/sendMessage?chat_id={CHAT_ID}&text={message}"
print(url)
print(requests.get(url).json())