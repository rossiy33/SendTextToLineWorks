
from datetime import datetime
import json

import jwt
import requests
from urllib import parse

with open("line-works-api.json", "r")as f:
    cert = json.loads(f.read())
API_ID = cert["api_id"]
SERVER_LIST_ID = cert["list_id"]
SERVER_LIST_PRIVATEKEY = cert["list_key"]
SERVER_API_CONSUMER_KEY = cert["consumer_key"]
BOTNO = cert["BOT_1"]
cert = None

# Line Works ID
MYID = "{Line Works ID}"


# JWTの生成
def get_jwstoken():
    current_time = datetime.now().timestamp()

    iss = SERVER_LIST_ID
    iat = current_time
    exp = current_time + 3600   # 1時間有効
    secret = SERVER_LIST_PRIVATEKEY

    jwstoken = jwt.encode(
        {
            "iss": iss,
            "iat": iat,
            "exp": exp
        }, secret, algorithm="RS256")

    return jwstoken.decode('utf-8')


# TOKENの発行
def set_server_token():
    url = f'https://authapi.worksmobile.com/b/{API_ID}/server/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    params = {
        "grant_type": parse.quote("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        "assertion": get_jwstoken()
    }

    r = requests.post(url=url, data=params, headers=headers)
    if not r.status_code == 200:
        print(f"token_response: {r.status_code} {r.content}")

    resp = r.json()
    return resp["access_token"]


# メッセージ送信
def send_message(msg):
    url = f'https://apis.worksmobile.com/r/{API_ID}/message/v1/bot/{BOTNO}/message/push'

    headers = {
        'Content-Type': 'application/json',
        'charset': 'UTF-8',
        'consumerKey': SERVER_API_CONSUMER_KEY,
        'Authorization': "Bearer " + set_server_token()
    }
    params = {
        'accountId': MYID,
        'content': {'type': 'text', 'text': msg}
    }

    # ポスト
    r = requests.post(url=url, headers=headers, data=json.dumps(params))

    if r.status_code == 401 or r.status_code == 403:
        headers["Authorization"] = "Bearer " + set_server_token()
        r = requests.post(url=url, headers=headers, data=json.dumps(params))

    if r.status_code == 200:
        return f"Line Works Sending: True"

    return f"Line Works Sending: False", r.status_code, r.reason


if __name__ == '__main__':
    print(send_message('ここに送られるよ'))
