# OPTIX proxy bridge

OPTIX owns desktop access, activation, updates and activity records. Warrior
remains the private proxy-supply service: provider credentials, inventory,
generation workers, reservations and the global 25-hour exit-IP cooldown stay
there.

The desktop app never receives the Warrior URL or bridge secret.

## Required environment variables

Set the same long random value on both servers, through their deployment
environment manager rather than a committed `.env` file.

Warrior:

```text
OPTIX_PROXY_BRIDGE_ENABLED=true
OPTIX_PROXY_BRIDGE_SECRET=<long-random-secret>
```

OPTIX:

```text
WARRIOR_PROXY_BRIDGE_URL=https://<warrior-domain>/api/v1/internal/optix-proxy/
WARRIOR_PROXY_BRIDGE_SECRET=<the-same-long-random-secret>
WARRIOR_PROXY_BRIDGE_TIMEOUT_SECONDS=30
```

## Identity mapping

For OPTIX-backed offices that use Warrior as the proxy supplier, Warrior must
already have one active Client Access row with the same Office Name, System
Number and, when present, Device ID. This maps the OPTIX request to the
correct existing Warrior bundle without copying provider credentials into
OPTIX. Office-to-backend selection belongs to the OPTIX desktop router, not
to this proxy bridge.

## What is relayed

- proxy create/reserve and job status;
- P2/P3 city lists;
- exit-IP check/claim, including the 25-hour global cooldown.

HTTP requests are signed with HMAC-SHA256 over timestamp + request body. The
Warrior endpoint rejects missing/incorrect signatures and timestamps older
than two minutes.
