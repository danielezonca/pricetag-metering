# Deployment modes

`DEPLOYMENT_MODE` selects the product behavior. It defaults to `cluster` and
accepts `cluster` or `standalone`.

- `cluster` preserves the existing routes, authentication, entitlement,
  dashboard, database, and MaaS transport behavior. Management routes are not
  registered in this mode.
- `standalone` enables standalone account-directory enforcement, login CSRF and
  session-confirmation dialogs, read-only impersonation, the fixed personal-key
  group, and the `/account` landing page. Standalone mode requires
  `MANAGEMENT_API_SECRET` and `MANAGEMENT_PUBLIC_ORIGIN` at startup: it refuses
  to boot without them, and cluster mode in turn rejects `MANAGEMENT_API_SECRET`
  so a deployment that forgot `DEPLOYMENT_MODE=standalone` fails loudly instead
  of serving a management API that 404s.

## MaaS API TLS

Cluster mode retains the legacy MaaS transport defaults: TLS certificate
verification is skipped, redirects are followed, and an over-large key list is
truncated rather than rejected. Standalone mode verifies TLS with system roots,
does not follow redirects, and rejects a truncated key list. For an internal
CA, mount the CA bundle and set `MAAS_API_CA_FILE`. Set
`MAAS_API_INSECURE_SKIP_VERIFY=true` only for a reviewed self-signed deployment;
it is mutually exclusive with `MAAS_API_CA_FILE`.

## Standalone-only changes

These changes apply only in standalone mode:

- Self-service key revocation verifies ownership through a MaaS key list before
  revoking. A MaaS outage therefore returns a gateway error instead of revoking
  without verification.
- `/api/v1/admin/models` is GET-only.
- Login forms are limited to 16 KiB and malformed bodies return HTTP 400.
- Manager directory views show real quota and budget data. Budget overrides are
  resolved through any retained login, not only the user's current login.
- Dashboard, account, administrator, and manager pages are single templates
  shared by both modes. Mode-specific line ranges are marked in the template
  and resolved at serve time; cluster mode serves byte-identical output to the
  templates before standalone support, and standalone mode serves exactly the
  former standalone variants.

## Management API contracts

`GET /api/v1/management/users` and `GET /api/v1/management/budgets` both
return `{data, has_more}` envelopes so clients page them the same way; budgets
add `default_monthly_usd`. The users endpoint accepts `limit` (50, 100, 250,
or 500; default 100) and `offset` query parameters.

In standalone mode, entitlement-directory outages return HTTP 503. The gateway's
`external_metering` `fail_open` setting determines whether those errors allow or
deny inference. Deployments that require suspension to hold during a directory
outage must configure the gateway to fail closed for managed accounts.

On startup, each `SeedPricing` call freezes legacy `usage_events` rows whose
`cost_usd` is still NULL before changing the rates their fallback reads — one
`UPDATE … FROM` per model, in both modes. It is correct under READ COMMITTED
(the outer `cost_usd IS NULL` recheck keeps a concurrent repricing from being
overwritten), but on very large legacy tables it is a single transaction that
can contend with the batched id-window backfill that starts after seeding.
Pricing (including the discount policy) must be seeded before that backfill
freezes `cost_usd`, so the startup order is the supported one — there is no
entry point that runs the backfill first.

## Running standalone with podman

`docker-compose.standalone.yaml` runs the standalone stack — PostgreSQL,
a MaaS key service, and the metering service built from the repository
Dockerfile, the same image the OpenShift BuildConfig builds. Its environment
mirrors the full single-server deployment that `redhat-et/enmaas-mini`
generates for its quadlet services, so what you exercise here is the same
contract that deployment consumes:

```
podman compose -f docker-compose.standalone.yaml up --build
```

The metering service listens on `127.0.0.1:8080` only; remote access belongs
behind a TLS gateway (the full deployment fronts it with praxis-ai at
`:8443`). PostgreSQL and the key service stay on the compose network,
mirroring the OpenShift deployment where those are cluster-internal.

Administration is driven through the management API, which requires the
bearer secret from `MANAGEMENT_API_SECRET`. Provision an account before its
user signs in — roles live in `partner_users`, and unprovisioned sign-ins
land on the welcome page:

```
curl -X PUT -H 'Authorization: Bearer local-only-management-secret' \
  -H 'Content-Type: application/json' \
  -d '{"subject":"local-admin@example.com","name":"Local Admin","role":"super_admin"}' \
  http://localhost:8080/api/v1/management/users
```

Then open `http://localhost:8080/login` and sign in with the development
stub's key `local-admin-key` (that key maps to
`local-admin@example.com`). The provisioned `super_admin` role unlocks the
administrator console; `user` and `admin` scope the dashboard and manager
views accordingly.

The compose file's MaaS service is the local development stub with
in-memory state — point `KEY_SERVICE_URL` and `MAAS_VALIDATE_URL` at a real
key service (for example `redhat-et/maas-api` in standalone mode) and override
the placeholder secrets — `MANAGEMENT_API_SECRET`, `M2M_SHARED_SECRET`,
`SESSION_SECRET`, and `POSTGRES_PASSWORD` are interpolated from the
environment — for any shared environment. Stop with
`down`, wipe the database with `down -v`.

For development of the cluster mode itself, `docker-compose.yaml` remains
the harness: it runs the service in cluster mode against the same stub.
