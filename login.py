#!/usr/bin/env python3
"""Log in to Bluetti the way the Android app does and save the app token.

The web/OAuth login token is NOT accepted by the app's live-data channel;
you need the token issued by the app login endpoint:

    POST https://gw.bluettipower.com/accessToken   (form-urlencoded)
    header: x-app-key: 1783AF460D4D0615365940C9D3A   (the app's own key)

Recipe (recovered from the app's LoginViewModel, verified live 2026-11-19):
    password field = SHA256(plaintext), uppercase hex
    passOpen field = AES-256/ECB/PKCS7 encrypt of the plaintext, keyed with
                     MD5(SHA256-upper-hex of the plaintext) uppercase hex
                     (32 ASCII chars = the 32 key bytes), lowercase hex out

Credentials come from BLUETTI_USERNAME / BLUETTI_PASSWORD env vars, or a
credentials.json next to this script: {"username": "...", "password": "..."}
The full login response is saved to app-token.json (mode 600) — its
data.token is what mqtt_client.py consumes, and data.refresh can renew it.

Be gentle: don't hammer this endpoint. One successful login lasts ~31 days.
"""
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP_KEY = "1783AF460D4D0615365940C9D3A"
LOGIN_URL = "https://gw.bluettipower.com/accessToken"


def load_credentials():
    u = os.environ.get("BLUETTI_USERNAME")
    p = os.environ.get("BLUETTI_PASSWORD")
    if u and p:
        return u, p
    path = os.path.join(HERE, "credentials.json")
    if os.path.exists(path):
        d = json.load(open(path))
        return d["username"], d["password"]
    print("set BLUETTI_USERNAME/BLUETTI_PASSWORD or create credentials.json")
    sys.exit(4)


def main():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    username, plaintext = load_credentials()
    sha_upper = hashlib.sha256(plaintext.encode()).hexdigest().upper()
    key = hashlib.md5(sha_upper.encode()).hexdigest().upper().encode()
    pass_open = AES.new(key, AES.MODE_ECB).encrypt(
        pad(plaintext.encode(), 16)).hex()

    form = {
        "phoneCountry": "",
        "username": username,
        "password": sha_upper,
        "passOpen": pass_open,
        "encryptedpwd": "",
        "authType": "",
        "verifyCode": "",
        "country": "",
    }
    req = urllib.request.Request(
        LOGIN_URL,
        data=urllib.parse.urlencode(form).encode(),
        headers={"x-app-key": APP_KEY,
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        resp = json.loads(r.read())

    if resp.get("msgCode") != 0 or "token" not in (resp.get("data") or {}):
        print("login failed:", resp.get("msgCode"), resp.get("message"))
        return 1
    out = os.path.join(HERE, "app-token.json")
    with open(out, "w") as f:
        json.dump(resp, f, indent=2)
    os.chmod(out, 0o600)
    print("app token saved to app-token.json (ttl %s s)"
          % resp["data"].get("ttl"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
