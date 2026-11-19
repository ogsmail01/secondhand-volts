# secondhand-volts

**Live power data for a Bluetti device that was *shared* to your account.**

If someone shares a Bluetti power station with you (Bluetti app → device
sharing), the device lands on your account — but every cloud API you can
find returns it as **offline with zeroed state**, forever, even while the
owner's app shows it live. This project gets the real numbers anyway, by
talking to Bluetti's cloud the same way the official Android app does:
over MQTT with mutual TLS and a custom one-time-password scheme.

Tested with an Elite 300 (EL300) shared to a second account, against the
US region, November 2026. Reverse-engineered from the official Android
app v3.1.5. Unofficial; not affiliated with Bluetti or PowerOak. Use it
with your own account and devices shared to you.

## The problem, proven

For a share-*member* account, all of these report the device offline /
zero / empty while it is actually online and reporting:

- `GET /api/bluiotdata/ha/v2/devices` (Home Assistant surface) — `online "0"`
- `GET /api/bluiotdata/ha/v1/deviceStates` — zeros
- `findBySN` — skeleton record: `batSOC null`, powers 0, `netStatus 0`
- `homeDevices` — empty list
- `POST /api/bluiotdata/realtime/v1/getDeviceLastAlive` — `allFieldIsNull: true`

The owner's app shows live data because the app never uses REST for live
state. It subscribes to an MQTT broker and the device pushes its full
register dump there. Shared accounts are allowed on that channel — the
REST layer is the only place that shuts members out.

## What you need

- A Bluetti account of your own, with the device shared to it (owner's
  app → share → QR code), and the device online.
- Python 3, `pip install -r requirements.txt`, and `curl` on PATH
  (curl is load-bearing — see the pitfalls).
- Your device's model and serial: e.g. model `EL300`, serial
  `EL3001234567890123`. The part after the model prefix (`1234567890123`)
  is the *subSn* used in topic names.

## Step 1 — get the device onto your account

In the owner's app, share the device; in your app, scan the QR. Done.

Programmatic equivalent (what the app's scanner actually does with a
`SHARE:` QR): the entire scanned string, prefix included, is sent as the
serial in a plain bind call:

```
POST https://gwpry.bluettipower.com/api/blusmartprod/device/basic/v2/bind
Authorization: <OAuth access token, raw, no "Bearer">
{"sn": "SHARE:<the full scanned payload, unchanged>"}
```

An OAuth token for this can be minted with the public Home Assistant
client profile from the `bluetti-home-assistant` project
(`POST https://ssous.bluettipower.com/oauth2/token`, authorization-code
grant). Note the two failure codes that prove you're on the right path:
a plain serial returns `20100026` ("bound by …" — that's the owner-claim
path), while an *expired* share string returns `20100088` ("Invalid QR
code" — the share path, rejected only for expiry). Share QRs live about
10 minutes; work fast.

## Step 2 — log in like the app (`login.py`)

The OAuth/HA token from step 1 is **not** accepted by the live channel.
You need the app login token:

```
POST https://gw.bluettipower.com/accessToken     (note: gw, not ssous)
header: x-app-key: 1783AF460D4D0615365940C9D3A   (the Android app's key)
password field = SHA256(plaintext), uppercase hex
passOpen field = AES-256/ECB/PKCS7(plaintext), key =
                 MD5(SHA256-upper-hex(plaintext)) uppercase hex
```

`login.py` does this and saves the response to `app-token.json`
(`data.token`, plus a refresh token; TTL ≈ 31 days). Don't hammer the
login endpoint — one login lasts a month.

## Step 3 — pull live state (`mqtt_client.py`)

```bash
export BLUETTI_SUBSN=1234567890123        # your device's subSn
export BLUETTI_MODEL=EL300                # optional, default EL300
python3 mqtt_client.py                    # writes mqtt-state.json
```

```json
{"soc_pct": 72, "pv_w": 0, "grid_w": 0, "ac_load_w": 21, "dc_load_w": 17,
 "raw_topic": "PUB/EL300/1234567890123", "captured_at_utc": "…"}
```

Run it on whatever timer you like; each run performs the full chain
below in ~25 seconds. Wrap it if you want a JSON feed for a dashboard —
that's exactly how this was used in production (2-minute poll into a
status page, plus a low-battery alert at 20%).

## How it works

1. **Server time + broker + signature.**
   `GET /api/midppkic/cert/app/v2/now/utc-time` with the app token in
   `Authorization:` returns the server UTC (ms), an `X-Signature` header,
   and `x-iot-server` — the MQTT broker for your account
   (e.g. `iotus.bluettipower.com:18760`).
2. **Certificate password.** Requests are signed with
   `getRequestSign` = uppercase MD5 hex of the `k=v&…` string over the
   sorted params `{currentUtcTime (lowercase hex), url, x-app-key,
   x-app-ver, x-os, x-sid}` where `x-sid` is segment 1 of the app token.
   AES/ECB-decrypting the hex `X-Signature` under the utc-time signature
   yields the PKCS#12 password.
3. **Client certificate.** A second signature, this time keyed with a
   TOTP (below) of your account `uid` and a per-install device id, is
   AES-encrypted with the cert password and sent as `x-app-resource` to
   `POST /api/midppkic/cert/app/v1/pfx`. The returned PKCS#12 (signed by
   PowerOak's own CA) is **required** — the broker aborts the TLS
   handshake without a client certificate. Verify the broker against
   the CA bundled in the app (`bluetti-ca.crt` in this repo) and use
   OpenSSL `SECLEVEL=1`; the key is small.
4. **MQTT login.** Username: `tid:` + token segment 1. Password: the
   app's custom OTP — `TotpUtils.generateTotp(seg1, seg0, serverUtcMs)`:
   an 8-digit code built by interleaving the uppercase MD5 hex of the
   time counter (30 s step, T0 = 1371517200) with the MD5 hex of a key
   assembled from the token segments and a shared constant baked into
   the app. Client id: MD5 hex of `BLUETTI_ANDROID&<uuid4>&<epoch ms>`.
5. **Subscribe** to `PUB/<model>/<subSn>`. No request publish is needed:
   the device cyclically pushes its full register dump (~15 frames per
   burst). In each frame, bytes [12:14] are the block address and values
   start at offset 17. The home/realtime block is address **100**:
   SOC = u16be @4 (clamp 100); total DC/AC/PV/grid power = u32 @80/84/88/92
   with the two 16-bit halves swapped. Sanity anchors in the same block:
   model ASCII @20..31, rated voltage @138 (120), rated frequency @140
   (6000 = 60.00 Hz).

### Pitfalls that cost real time

- **Use curl for the cert chain.** The identical signature computation
  sent via Python urllib failed every time — urllib Title-Cases header
  names. curl with exactly the app's headers worked first try.
- **Send no `x-sid` header** on the utc-time call.
- The login endpoint is on `gw.bluettipower.com`; the same path on the
  SSO host drops the connection.
- The HA OAuth token and the app token are different beasts with
  different jobs: OAuth for REST/bind, app token for everything live.

## Caveats

- The app token lasts ~31 days; the login response includes a refresh
  token. When it dies, one careful login with `login.py` renews it.
- Regions differ: this was built on the US region (`gwpry` gateway,
  `iotus` broker). The broker hostname comes from the `x-iot-server`
  header, so the client follows whatever region your account is in.
- Bluetti can change any of this at any time; it is their cloud and
  their app protocol. Everything here was read out of the publicly
  distributed Android app.

## Credits

- The `bluetti-home-assistant` project, whose public client profile
  covers the OAuth step.
- Everyone who has picked apart consumer IoT clouds before; the pattern
  (REST for show, MQTT for real) is depressingly common.
