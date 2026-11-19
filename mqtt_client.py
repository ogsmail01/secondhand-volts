#!/usr/bin/env python3
"""Bluetti live state via the official app's MQTT path (works for share-member accounts).

Chain (all reverse-engineered from the official Android app v3.1.5 and proven live):
  1. App token (SSO /accessToken login) from app-token.json -> data.token.
  2. GET /api/midppkic/cert/app/v2/now/utc-time via curl with app headers and
     Authorization: <app token>, NO x-sid header (an x-sid header, or urllib's
     Title-Cased headers, makes the signature chain fail).
     -> server utc ms (body data), X-Signature header, x-iot-server header.
  3. certPassword = AES/ECB/PKCS7-decrypt(key=sign1, hex(X-Signature)) where
     sign1 = BluettiCertUtils.getRequestSign(sid=token.split('.')[1],
             url='/api/midppkic/cert/app/v2/now/utc-time', utc).
     getRequestSign: MD5 hex UPPER of 'k=v&...' over the TreeMap-sorted keys
     {currentUtcTime=lowercase hex of utc, url, x-app-key=APP_ID,
      x-app-ver='3.1.5', x-os='android', x-sid}.
  4. uid from GET /api/bluuc/uc/v1/basic/get (app token).
     TOTP2 = TotpUtils.generateTotp(uid, deviceId, utcMs);
     sign2 = getRequestSign(sid, '/api/midppkic/cert/app/v1/pfx', int(TOTP2));
     x-app-resource = AES/ECB encrypt of certPassword under sign2, lowercase hex.
  5. POST /api/midppkic/cert/app/v1/pfx -> PKCS#12 (opens with certPassword).
  6. MQTT over mutual TLS (CA = bluetti-ca.crt, the app-bundled PowerOak CA;
     OpenSSL SECLEVEL=1 needed for the small RSA key):
       broker = x-iot-server host (iotus.bluettipower.com:18760)
       username = 'tid:' + token.split('.')[1]
       password = TotpUtils.generateTotp(token.split('.')[1], token.split('.')[0], utcMs)
       clientId = md5 hex of 'BLUETTI_ANDROID&' + uuid4 + '&' + currentTimeMillis
     Subscribe PUB/<MODEL>/<SUBSN>; the device pushes its full register
     dump cyclically (~15 frames per burst, each frame twice).
  7. Parse: in each frame, bytes [12:14] = block address (BE), [14:16] = word
     count, value bytes start at offset 17. The home/realtime block is
     address 100 (ModbusV2Dispatcher.dispatch case 100 -> handleHomeData ->
     ProtocolParserV2.parseHomeData). Field offsets within the value:
       packTotalSoc   u16be @ 4   (clamped to 100)
       totalDCPower   u32 @ 80, totalACPower u32 @ 84, totalPVPower u32 @ 88,
       totalGridPower u32 @ 92  -- u32s are half-swapped (bit32HexSwap):
       value = (raw & 0xFFFF) << 16 | raw >> 16 on the BE u32, i.e. the two
       16-bit halves trade places.
     Sanity anchors in the same block: deviceModel ASCII @ 20..31,
     rateVoltage u16be @ 138 (120), rateFrequency u16be @ 140 (6000 = 60.00 Hz).

Requires: paho-mqtt, cryptography, pycryptodome, curl on PATH.
Writes mqtt-state.json next to this script. Never prints secrets.
"""
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
APP_ID = "1783AF460D4D0615365940C9D3A"
APP_VER = "3.1.5"
GW = "https://gwpry.bluettipower.com"
UTC_URL = "/api/midppkic/cert/app/v2/now/utc-time"
PFX_URL = "/api/midppkic/cert/app/v1/pfx"
MODEL = os.environ.get("BLUETTI_MODEL", "EL300")
SUBSN = os.environ.get("BLUETTI_SUBSN", "")
TOPIC = "PUB/%s/%s" % (MODEL, SUBSN)
LISTEN_SECONDS = 50

# ---------------- TotpUtils port (exact) ----------------
_TOTP_SHARED = "ga3sa4hj6kfl"
_TOTP_STEP = 30
_TOTP_T0 = 1371517200


def _build_k(s, s2):
    sub3 = _TOTP_SHARED[: len(_TOTP_SHARED) - len(_TOTP_SHARED) // 2]
    return s[:2] + sub3 + s2 + _TOTP_SHARED.replace(sub3, "") + s[-2:]


def _totp_encrypt(msg: bytes, key: bytes) -> bytes:
    h1 = hashlib.md5(msg).hexdigest().upper()
    h2 = hashlib.md5(key).hexdigest().upper()
    out = []
    for i in range(len(h1)):
        out.append(h2[i])
        out.append(h1[i])
    return "".join(out).encode("utf-8")


def _truncate(b: bytes) -> str:
    i = b[-1] & 0x0F
    v = ((b[i] & 0x7F) << 24 | (b[i + 1] & 0xFF) << 16 |
         (b[i + 2] & 0xFF) << 8 | (b[i + 3] & 0xFF)) % 100000000
    return str(v).rjust(8, "0")


def generate_totp(s, s2, t_ms):
    t = t_ms
    if t > 9999999999:
        t //= 1000
    counter = (t - _TOTP_T0) // _TOTP_STEP
    msg = bytes.fromhex(format(counter, "X").rjust(16, "0"))
    return _truncate(_totp_encrypt(msg, _build_k(s, s2).encode("utf-8")))


def request_sign(sid, url, utc_long):
    params = {
        "currentUtcTime": format(utc_long, "x"),
        "url": url,
        "x-app-key": APP_ID,
        "x-app-ver": APP_VER,
        "x-os": "android",
        "x-sid": sid,
    }
    joined = "&".join("%s=%s" % (k, params[k]) for k in sorted(params))
    return hashlib.md5(joined.encode("utf-8")).hexdigest().upper()


# ---------------- HTTP via curl (header case + no x-sid matter) ----------------
def curl(url, token, devid, extra_headers=None, post=False, out_path=None):
    tmp = tempfile.mkdtemp(prefix="bluetti-")
    hf, bf = os.path.join(tmp, "h"), os.path.join(tmp, "b")
    cmd = ["curl", "-sS", "-m", "30", "-D", hf, "-o", out_path or bf,
           "-H", "Authorization: " + token,
           "-H", "x-app-key: " + APP_ID,
           "-H", "x-os: android",
           "-H", "x-app-ver: " + APP_VER,
           "-H", "Accept-Language: en-US",
           "-H", "x-device-id: " + devid]
    for h in extra_headers or []:
        cmd += ["-H", h]
    if post:
        cmd += ["-X", "POST"]
    cmd.append(url)
    subprocess.run(cmd, capture_output=True, text=True, check=True)
    headers = {}
    for line in open(hf).read().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = None if out_path else open(bf).read()
    return headers, body


# ---------------- frame parsing ----------------
def _u16be(v, off):
    return int.from_bytes(v[off:off + 2], "big")


def _u32_hs(v, off):
    raw = int.from_bytes(v[off:off + 4], "big")
    return ((raw & 0xFFFF) << 16) | (raw >> 16)


def parse_home_frame(payload):
    """Return parsed home-data dict if this payload carries the addr-100 block."""
    if len(payload) < 17 + 142:
        return None
    if payload[0] != 0x01 or payload[1] != 0xF8:
        return None
    addr = int.from_bytes(payload[12:14], "big")
    if addr != 100:
        return None
    v = payload[17:]
    model = "".join(chr(c) for c in v[20:32] if c != 0)
    known = {"EL300", "LE030", MODEL.upper()}
    if not any(k in model.upper() for k in known):
        return None
    soc = min(100, _u16be(v, 4))
    rate_v = _u16be(v, 138)
    if rate_v not in (100, 110, 120, 127, 220, 230, 240):
        return None
    return {
        "soc_pct": soc,
        "pv_w": _u32_hs(v, 88),
        "grid_w": _u32_hs(v, 92),
        "ac_load_w": _u32_hs(v, 84),
        "dc_load_w": _u32_hs(v, 80),
    }


def main():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, pkcs12)
    import paho.mqtt.client as mqtt

    if not SUBSN:
        print("set BLUETTI_SUBSN (the numeric part of your device serial, "
              "e.g. serial EL3001234567890123 -> 1234567890123)")
        return 4
    token = json.load(open(os.path.join(HERE, "app-token.json")))["data"]["token"]
    parts = token.split(".")
    devid_path = os.path.join(HERE, "mqtt-device-id.txt")
    if os.path.exists(devid_path):
        devid = open(devid_path).read().strip()
    else:
        devid = str(uuid.uuid4())
        with open(devid_path, "w") as f:
            f.write(devid)
        os.chmod(devid_path, 0o600)

    # 1) server time + signature + broker
    headers, body = curl(GW + UTC_URL, token, devid)
    utc = int(json.loads(body)["data"])
    sig = headers["x-signature"]
    iot = headers.get("x-iot-server", "iotus.bluettipower.com:18760")
    host, port = iot.rsplit(":", 1)[0], int(iot.rsplit(":", 1)[1])

    # 2) cert password from the utc-time signature
    sign1 = request_sign(parts[1], UTC_URL, utc)
    certpw = unpad(AES.new(sign1.encode(), AES.MODE_ECB)
                   .decrypt(bytes.fromhex(sig)), 16)

    # 3) uid for the pfx TOTP
    _, ubody = curl(GW + "/api/bluuc/uc/v1/basic/get", token, devid)
    uid = json.loads(ubody)["data"]["uid"]

    # 4) pfx download
    totp2 = generate_totp(uid, devid, utc)
    sign2 = request_sign(parts[1], PFX_URL, int(totp2))
    xar = AES.new(sign2.encode(), AES.MODE_ECB).encrypt(
        pad(certpw, 16)).hex()
    tmp = tempfile.mkdtemp(prefix="bluetti-")
    p12_path = os.path.join(tmp, "cert.p12")
    curl(GW + PFX_URL, token, devid,
         extra_headers=["x-app-resource: " + xar], post=True, out_path=p12_path)
    key, cert, _ = pkcs12.load_key_and_certificates(
        open(p12_path, "rb").read(), certpw)
    pem_path = os.path.join(tmp, "client.pem")
    with open(pem_path, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM,
                                  PrivateFormat.TraditionalOpenSSL,
                                  NoEncryption()))
        f.write(cert.public_bytes(Encoding.PEM))
    os.chmod(pem_path, 0o600)

    # 5) MQTT connect + subscribe
    username = "tid:" + parts[1]
    password = generate_totp(parts[1], parts[0], utc)
    client_id = hashlib.md5(
        ("BLUETTI_ANDROID&" + str(uuid.uuid4()) + "&" +
         str(int(time.time() * 1000))).encode()).hexdigest()

    result = {"state": None, "topic": None, "rc": None}

    def on_connect(client, userdata, flags, rc):
        result["rc"] = rc
        if rc == 0:
            client.subscribe(TOPIC, qos=0)

    def on_message(client, userdata, msg):
        parsed = parse_home_frame(bytes(msg.payload))
        if parsed is not None:
            result["state"] = parsed
            result["topic"] = msg.topic

    ctx = ssl.create_default_context(
        cafile=os.path.join(HERE, "bluetti-ca.crt"))
    ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    ctx.load_cert_chain(certfile=pem_path)
    c = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311,
                    clean_session=True)
    c.username_pw_set(username, password)
    c.tls_set_context(ctx)
    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(host, port, keepalive=90)
    c.loop_start()
    t0 = time.time()
    while time.time() - t0 < LISTEN_SECONDS:
        if result["rc"] not in (None, 0):
            break
        if result["state"] is not None and time.time() - t0 > 20:
            break  # one full dump cycle is enough; values repeat identically
        time.sleep(0.25)
    c.loop_stop()
    c.disconnect()

    if result["rc"] != 0:
        print("MQTT CONNACK rc=%s (auth/connect failed)" % result["rc"])
        return 2
    if result["state"] is None:
        print("connected but no addr-100 home frame parsed")
        return 3

    out = dict(result["state"])
    out["raw_topic"] = result["topic"]
    out["captured_at_utc"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    state_path = os.path.join(HERE, "mqtt-state.json")
    with open(state_path, "w") as f:
        json.dump(out, f, indent=2)
    os.chmod(state_path, 0o600)
    print("live state:", json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
