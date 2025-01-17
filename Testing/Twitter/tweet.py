import sys
import tweepy
from auth import ACCESS_TOKEN, ACCESS_SECRET, API_KEY, API_SECRET


consumer_key = API_KEY
consumer_secret = API_SECRET
access_token = ACCESS_TOKEN
access_token_secret = ACCESS_SECRET

client = tweepy.Client(
    consumer_key=consumer_key, consumer_secret=consumer_secret,
    access_token=access_token, access_token_secret=access_token_secret
)

response = client.create_tweet(
    text="This Tweet was Tweeted using Tweepy and Twitter API v2!"
)

print(response)

print(f"https://x.com/user/status/{response.data['id']}")