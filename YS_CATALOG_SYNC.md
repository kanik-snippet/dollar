# Dollar: scheduled YS catalog sync

This feature is source-ready; editing this repository does not itself start a
production schedule or update installed PCs. OPTIX/Warrior is unchanged.

## What is fetched

Four runs daily: **08:00, 12:00, 16:00 and 20:00 Asia/Kolkata**.
The original YS client requests these two read-only endpoints:

- `POST https://admin.ysbrowser.com/api/common/getWebConfigValue`: empty form,
  no account key; imports 19 allowlisted fingerprint catalogs including fonts,
  CPU, memory, screen and OS metadata.
- `POST https://admin.ysbrowser.com/api/aegisVersion/aegisCheck`: paginated form,
  original YS `X-API-Key`; imports browser-version discovery metadata only.

No profiles, account data or device details are uploaded. `SecureJson`, `ipList`,
routing settings, credentials, release HTML and download URLs are excluded.
TLS validation is mandatory and redirects are refused. Jobs have bounded size,
pagination and time limits. A DB lease prevents simultaneous syncs for a resource.
Each resource keeps its last valid snapshot on failure; current error and timestamps
are visible in Django admin → **YS browser catalog sync status**.

Host `osVersion=Windows` does not prove a desktop fingerprint runtime: an
Android-emulating browser can itself be a Windows executable. Therefore new
browser packages are marked `runtime_target=unverified`, `installable=false`.
The import never downloads or runs a binary and never changes the current curated
Android/desktop version policy. Browser binaries still require a validated signed
component release. Private release-signing keys remain outside the Django host.

## Production setup (deployment still required)

In this Dollar server's private `.env`, set:

```dotenv
YS_CATALOG_SYNC_ENABLED=true
YS_UPSTREAM_API_KEY=<original YS account API key, not a Dollar key>
```

After deploying this code and before restarting web/worker processes:

```bash
./.venv/bin/python manage.py migrate
./.venv/bin/python manage.py check
./.venv/bin/python manage.py sync_ys_catalogs
./.venv/bin/python manage.py sync_ys_catalogs --status
```

`--status` is read-only and never contacts YS. A manual sync explicitly runs even
when scheduled sync is disabled, exits nonzero on partial failure, and never prints
the upstream key or response body. A missing/wrong YS account key can prevent the
version list while the independently validated common catalogs remain available.

Use the deployment's process manager to run/restart one dedicated worker:

```bash
./.venv/bin/celery -A controlserver worker -Q catalog-sync --concurrency=1 --loglevel=INFO --hostname='dollar-catalog@%h'
```

Use **one** Celery beat scheduler for this Django deployment. Restart an existing
beat after deploying; do not start a second one. If there is no scheduler, configure
a process-manager service using `./.venv/bin/celery -A controlserver beat --loglevel=INFO`.
Redis must be configured and the worker must consume `catalog-sync`; starting only
the web server is not sufficient. The dedicated catalog worker does not enqueue
the proxy pool warmup on startup.

## Client delivery

Authorized Dollar bootstrap responses advertise a small `browser_catalog_sync`
descriptor. Updated Dollar clients fetch its revision from the same authenticated
control server at `/api/v1/browser-catalog/`. Legacy and OPTIX clients are not sent
the descriptor. The catalog endpoint requires the normal active, device/IP-bound
bootstrap token and a Dollar client identity.

One signed client/component update is needed to install the new consumer in
existing clients. After that, normal bootstrap/Reload picks up data changes without
a new installer. Catalog updates refresh only catalog records; intentional local
overrides remain intact. They do not restart the bridge, change active profiles,
change proxy routing or overwrite activation/B1 keys. Running profiles retain their
existing fingerprint; the new catalogs apply to subsequent profiles.

Glider engine changes are separate code changes. Switching a currently running
proxy-chain bridge waits until its profiles have been manually closed; no catalog
refresh kills profiles in order to activate the new relay.
