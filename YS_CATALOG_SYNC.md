# Dollar: scheduled YS catalog sync

This repository targets Dollar. Warrior/OPTIX has its own independent catalog
deployment. Editing either repository alone does not start a production schedule
or update installed PCs.

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
./.venv-optix/bin/python manage.py migrate
./.venv-optix/bin/python manage.py check
./.venv-optix/bin/python manage.py sync_ys_catalogs
./.venv-optix/bin/python manage.py sync_ys_catalogs --status
```

`--status` is read-only and never contacts YS. A manual sync explicitly runs even
when scheduled sync is disabled, exits nonzero on partial failure, and never prints
the upstream key or response body. A missing/wrong YS account key can prevent the
version list while the independently validated common catalogs remain available.

## Standalone scheduling on the current Dollar deployment

No Redis URL, Celery worker or beat is required. Do not start a full beat merely
for this feature: it would also schedule unrelated proxy maintenance. The
standalone unit runs as the existing unprivileged application user **dolla5434**
with `.venv-optix/bin/python`; root is needed only to install/manage its two units.

Before installation, inspect any existing units of these exact names and
privately back them up. Do not overwrite another service's configuration.
Then, as root:

```bash
cd /home/dollar.alessarsolutions.in/optix-control-server
systemd-analyze verify deploy/dollar-ys-catalog-sync.service deploy/dollar-ys-catalog-sync.timer
systemd-analyze calendar '*-*-* 08,12,16,20:00:00 Asia/Kolkata'
install -o root -g root -m 0644 deploy/dollar-ys-catalog-sync.service /etc/systemd/system/dollar-ys-catalog-sync.service
install -o root -g root -m 0644 deploy/dollar-ys-catalog-sync.timer /etc/systemd/system/dollar-ys-catalog-sync.timer
systemctl daemon-reload
systemctl enable --now dollar-ys-catalog-sync.timer
systemctl list-timers --all dollar-ys-catalog-sync.timer
```

The timer explicitly uses **Asia/Kolkata** (08/12/16/20), so the system timezone
does not affect the four slots. `Persistent=false` deliberately avoids an
unexpected immediate catch-up run when installing or after downtime. Confirm the
next trigger time after installation. No web/proxy-worker restart is needed just
to install these standalone scheduling units.

The explicit IANA timezone syntax follows the upstream
[systemd calendar documentation](https://www.freedesktop.org/software/systemd/man/systemd.time.html#Calendar%20Events).

The runner uses a per-repo `flock`, a 720-second timeout and
`sync_ys_catalogs --scheduled`. Scheduled mode respects
`YS_CATALOG_SYNC_ENABLED=false` without requests or DB writes; normal manual
mode retains its explicit force behavior. Only a static UTC
timestamp/result/exit-code line reaches the journal; raw Django stdout/stderr
is suppressed. Detailed sanitized resource status remains in Django admin or
`manage.py sync_ys_catalogs --status`. Failures/timeouts produce a failed service
exit code; a live lock skips safely. Service runtime is capped at 750 seconds.

```bash
systemctl show dollar-ys-catalog-sync.service -p User -p Result -p ExecMainStatus
journalctl -u dollar-ys-catalog-sync.service -n 20 --no-pager
```

Do not enable a second catalog schedule through cron or Celery. These units have
no Redis, cache, proxy-generation, browser or installer dependency. They never
start a Celery scheduler or restart any existing worker.

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
