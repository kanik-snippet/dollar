# OPTIX Control Server

Dedicated Django control plane for OPTIX. It is intentionally separate from
the existing automation-control server: its database, encryption keys, release
storage, admin users and deployment domain must be separate.

The current installed OPTIX clients remain on the existing server until an
explicit cutover release points them at this server.

## Security and request flow

1. The desktop app calls `/api/v1/ip/` to learn the same public IPv4 the
   control server observes.
2. Before showing its main window, it POSTs that IPv4 to `/api/v1/bootstrap/`.
3. The app also sends a stable, non-secret device ID so systems behind the
   same office NAT can be distinguished.
4. The server independently reads the real source IPv4. On Render this is the
   first value in `X-Forwarded-For` when `TRUST_PROXY_HEADERS=1`.
5. Reported and observed IPv4 must match, and the IPv4 + device ID must have
   an active `ClientAccess` row. A blank device ID is an explicit IP-only row.
6. Only then is the encrypted configuration bundle decrypted and returned.
7. The response also includes provider/country metadata and a short-lived,
   IP-bound signed bearer token.
8. The app downloads the selected encrypted-at-rest country TXT through
   `/api/v1/proxies/<provider>/<country>/` using that bearer token.

Denied responses are intentionally generic. Configuration and proxy content
are never written to application logs. Successful responses send
`Cache-Control: no-store` and must be used only over HTTPS.

IP whitelisting is an access gate, not a replacement for transport security.
If multiple PCs share one office NAT IPv4, create one ClientAccess row per
stable device ID. The device ID distinguishes systems but is not a secret; a
future per-install activation credential can add stronger authentication.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:DEBUG='1'
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe manage.py runserver
```

Open `http://127.0.0.1:8000/admin/` and create records in this order:

1. Config bundle: paste a JSON object containing every former
   `tubelight_config.txt` value.
2. Client access: whitelist the public IPv4, choose bundle, office name, and
   system number.
3. Providers: use only public codes such as P1, P2, and so on.
4. Proxy country files: paste each country TXT into the encrypted content box.

Example configuration JSON keys:

```json
{
  "APP_API_KEY": "...",
  "APP_BASE_URL": "http://127.0.0.1:54032",
  "APP_START_URL": "...",
  "TUBELIGHT_API_KEY": "..."
}
```

`OFFICE_NAME` and `SYSTEM_NUMBER` are overwritten from the matching client row,
so they can differ by office/system while sharing one bundle.

## API contract

Observed public IPv4:

```http
GET /api/v1/ip/
```

Bootstrap request:

```http
POST /api/v1/bootstrap/
Content-Type: application/json

{"reported_ipv4":"203.0.113.10","device_id":"stable-device-hash","app_version":"1.6.1"}
```

Catalog download:

```http
GET /api/v1/proxies/P1/US/
Authorization: Bearer <bootstrap access_token>
X-Device-ID: stable-device-hash
```

No API secret or proxy credential belongs in a URL/query string.

## Import the former configuration

An existing key/value file can be encrypted into a bundle without printing any
values:

```powershell
python manage.py import_tubelight_config C:\secure\tubelight_config.txt --name Office --bundle-version 1
```

Verify the bundle in admin, then securely delete the plaintext source. Never
commit that file to Git.

## Bulk provider/country import

Use folders such as `catalog_seed/P1/US__United States.txt`, then run:

```powershell
python manage.py import_proxy_catalog catalog_seed --disable-missing
```

Do not commit real credential TXT files to a public repository. Render's normal
filesystem is ephemeral; persistent application data belongs in PostgreSQL.

## Render deployment

1. Put this folder in a private Git repository.
2. In Render, create a Blueprint from `render.yaml`.
3. After deployment, open Render Shell and run:
   `python manage.py createsuperuser`.
4. Open `https://<service>.onrender.com/admin/` and enter your data.
5. Test `/healthz/` and then provide the base URL for the desktop integration.

Never rotate `CONFIG_ENCRYPTION_SECRET` without first re-encrypting or exporting
the stored data: changing it makes existing encrypted bundles unreadable.

The Blueprint uses PostgreSQL because Render's default service filesystem is
ephemeral. Production secrets are generated as environment variables, `DEBUG`
is off, and Django secure-cookie/HSTS/HTTPS settings are enabled.

## Swagger and Postman

With the local server running, open `http://127.0.0.1:8000/docs/` for interactive
Swagger UI. The raw OpenAPI 3.1 schema is at `/openapi.json`. Import
`Warrior-Control-API.postman_collection.json` into Postman and run its four
requests in order. For local testing, create a ClientAccess row matching
`127.0.0.1` and the collection's `device_id`; on the deployed server use the
actual public IPv4 returned by `/api/v1/ip/`.

## Railway deployment with external MySQL

This repository includes `railway.toml` for static collection, pre-deploy
migrations, Gunicorn binding to Railway's `$PORT`, and `/healthz/` deployment
health checks. Python is pinned to the maintained 3.12.13 security release so
Railway does not use the old 3.12.8 standalone artifact that failed attestation.
Artifact verification remains enabled.

Set these variables in the Railway application service (never commit `.env`):

- `DEBUG=0`
- `DJANGO_SECRET_KEY=<long random value>`
- `CONFIG_ENCRYPTION_SECRET=<different long random value>`
- `DB_ENGINE=mysql`
- `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`
- `DB_SSL_MODE=REQUIRED` when required by the MySQL provider
- `DB_SSL_CA=<CA file path>` only when the provider supplies a mounted CA file
- `TRUST_PROXY_HEADERS=1`
- `REQUIRE_REPORTED_IP_MATCH=1`

Railway automatically supplies `RAILWAY_PUBLIC_DOMAIN` and `PORT`; the Django
settings add the public domain, CSRF origin, and Railway health-check hostname
automatically. Add custom domains explicitly to `ALLOWED_HOSTS` and
`CSRF_TRUSTED_ORIGINS`.

## Cloudflare real client IPv4 on Railway

`kanikdev.xyz` is Cloudflare-proxied, while Railway can expose an internal
`100.64.0.0/10` hop in its normal proxy headers. Configure one long random
value in both places:

1. Railway variable: `CLOUDFLARE_ORIGIN_SECRET=<random secret>`.
2. Cloudflare > Rules > Overview > Create rule > Request Header Transform Rule.
3. Apply it to hostname `kanikdev.xyz`.
4. Set static request header `X-Tubelight-Origin-Secret` to the same secret.

With the secret verified, Django reads the ISP-facing IPv4 from
`CF-Connecting-IP`. Requests that bypass Cloudflare or spoof the client-IP
header without the secret are rejected.

## Approved desktop-reported IPv4 mode

With `TRUST_APP_REPORTED_IPV4=1`, desktop v1.6.3 obtains its public IPv4 from
`https://ipv4.test-ipv6.com/ip/`. Bootstrap authorization and proxy-download
tokens bind that reported IPv4 to the exact `ClientAccess.device_id`. The app
sends the same value as `X-Client-IPv4` on token-protected catalog downloads.
The Railway `100.64.0.0/10` transport address remains available in audits but
is not used for the whitelist lookup in this explicitly approved mode.
# Mobile Quick Ops and YSBrowser bridge

Super-admins can open `/panel/mobile-ops/` from a phone to generate an office's
proxy inventory, add one IPv4 to every active office device, delete office
YSBrowser environments, and add/remove YSBrowser whitelist IPs.

The YSBrowser API listens on the office PC only. Provision its outbound HTTPS
bridge once on the server:

```bash
./.venv/bin/python manage.py provision_ys_bridge --name "Primary office PC"
```

Copy the one-time token, place `tools/Setup-YSBridge.ps1` and
`tools/YSBridgeAgent.ps1` together on that Windows PC, then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Setup-YSBridge.ps1
```

The setup prompts securely for the bridge token and YSBrowser API key, stores
both with Windows DPAPI, starts the bridge, and adds a per-user Startup shortcut.
No inbound firewall port or YSBrowser API key in the web browser is required.
