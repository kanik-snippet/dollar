# OPTIX desktop routing

One OPTIX desktop installer can use either backend on a per-PC basis.

## Routing flow

1. The desktop calls Warrior's `/api/v1/desktop-route/` first.
2. Warrior validates the current IPv4 and Device ID against its existing `Client Access` row.
3. The row's **OPTIX backend** setting decides the target:
   - **Warrior backend**: the desktop continues using Warrior, exactly as today.
   - **OPTIX backend**: the desktop repeats its normal bootstrap against the HTTPS URL in **OPTIX backend URL**.
4. The selected backend supplies its own runtime configuration, providers, UI configuration, browser/security settings, updates, and audit records.

The desktop never accepts a backend URL from the local machine.  Warrior returns it only after the device is authorized.

## Admin setup

On the Warrior server, open **Client Access** for the required office PCs:

- Keep **OPTIX backend** = `Warrior backend` for PCs that should stay on the existing system.
- Set **OPTIX backend** = `OPTIX backend` for PCs that should use the new server.
- Enter the deployed HTTPS OPTIX base URL in **OPTIX backend URL**.

For every PC routed to OPTIX, create a matching active Client Access row and Config Bundle in the OPTIX server.  The OPTIX server then performs the real bootstrap and authorization.

## Proxy source

When OPTIX should use Warrior-generated proxy pools, configure the private bridge values in the OPTIX server environment:

```text
WARRIOR_PROXY_BRIDGE_URL=https://<warrior-domain>/api/v1/internal/optix-proxy/
WARRIOR_PROXY_BRIDGE_SECRET=<same-long-random-secret-on-both-servers>
WARRIOR_PROXY_BRIDGE_TIMEOUT_SECONDS=30
```

Also set the same `OPTIX_PROXY_BRIDGE_SECRET` on Warrior and deploy the Warrior private bridge endpoint.  This is server-to-server only; no secret is present in the desktop installer.

## Deployment order

1. Deploy the Warrior migration and route endpoint.
2. Deploy OPTIX with its own database and HTTPS domain.
3. Configure the private Warrior-to-OPTIX proxy bridge.
4. Install OPTIX 1.5.2 or later on PCs that need dynamic routing.
5. Change a PC's **OPTIX backend** value only after its matching OPTIX Client Access row is ready.

Changing a row back to `Warrior backend` routes the PC back on its next reload/bootstrap; no separate desktop build is required.
