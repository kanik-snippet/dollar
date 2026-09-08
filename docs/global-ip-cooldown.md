# Shared 25-hour IP check

The Proxy page on either panel has one master switch for authenticated OPTIX and Dollar sessions, across all offices/providers/browsers. Only a full administrator can change it; staff can inspect it.

Warrior stores ProxyCooldownPolicy(pk=1). Dollar reads/writes that same row using its existing private HMAC proxy bridge. There is no separate Dollar override or optimistic local success. The new panel endpoint is /panel/api/proxy-cooldown/. CSRF, staff/superuser permissions and revision conflict checks apply. Desktop proxy requests cannot change the policy.

Default is ON. OFF skips only historical 25-hour duplicate rejection, while recording successful claims and retaining IP rows. ON again uses the most recent successful claim time, including use while OFF. Same-reservation retries are idempotent. Tubelight, connectivity probes, per-RUN duplicate checks, authentication and reservation ownership are unchanged.

Explicit signed OPTIX bootstrap tokens and authenticated Dollar relay traffic use this policy. Legacy I am the best tokens remain enforced regardless of the master switch. Existing sessions without an explicit OPTIX token marker must bootstrap again before using an OFF policy; no new installer is required.

The next server check/claim reads current policy without a TTL cache. In-flight checks already evaluated can finish with their prior decision. Running profiles are never closed or restarted by a toggle. Open panels refresh the state every 15 seconds and on focus. Stale writes return 409 and re-read the authoritative state.

Only Warrior needs migration 0043_proxycooldownpolicy, which creates one new table and seeds ON; it does not delete/change cooldown history. Deploy Warrior first, migrate/check/collectstatic/gracefully reload, then deploy Dollar/check/collectstatic/reload. Keep production ON during verification. Dollar fails visibly if the shared service cannot confirm its state.

Verification uses isolated in-memory databases for ON/OFF/re-enable, legacy isolation, ownership/authentication, HMAC tampering, CSRF, strict input, conflict and relay failures. Row-lock concurrency tests require a transactional database with select_for_update support and are skipped on SQLite. JavaScript behavior tests live in control/tests_js/panel-cooldown.test.cjs.
