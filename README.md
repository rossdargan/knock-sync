# knock-sync

Keeps UniFi **traffic matching lists** in sync with:

1. the dynamic allowlist served by the Cloudflare knock Worker (`GET $KNOCK_URL/list`, behind Cloudflare Access), and
2. a **static allowlist** of IPs/CIDRs/hostnames that are always whitelisted.

It's outbound-only: it polls the Worker and pushes changes to the UniFi Network Integration API. Images are built by GitHub Actions and published to GHCR.

## How often does it poll, and is that safe?

| Call | Default frequency | Notes |
|---|---|---|
| Worker `GET /list` | every `SYNC_INTERVAL` = **15s** (5,760/day) | The Workers free tier allows 100,000 requests/day, so the 5s minimum (17,280/day) also fits. Sends `If-None-Match` so the Worker can reply `304` if it sets an `ETag`. |
| UniFi `GET` list | only when the desired set changes, plus every `RECONCILE_INTERVAL` = **300s** | The periodic check reverts manual edits/drift. |
| UniFi `PUT` list | only when the list really differs | Values are compared canonically (e.g. `1.2.3.4` == `1.2.3.4/32`), so it never rewrites the same list. |
| DNS for `STATIC_HOSTS` | every `STATIC_REFRESH` = **300s** | The last good answer is kept if DNS fails. |
| DoH lookup for the Worker host | honours the record TTL (min 60s) | |

After a failure it backs off exponentially (up to `MAX_BACKOFF`) and honours `Retry-After` on `429`/`503`. If the Worker can't be reached, **UniFi is left as-is**. It never guesses.

## Static allowlist

You can combine either or both:

- **Env vars:** `STATIC_IPS=Anthropic API=160.79.104.0/21, Office=203.0.113.10` and `STATIC_HOSTS=Mum=mum.ddns.net`. The `Label=` prefix is optional.
- **File:** `./config/static.txt`, mounted at `/config/static.txt`. It's re-read automatically when it changes, so no restart is needed. Label entries with a trailing `# comment` or `Label = entry`. See [static.txt.example](static.txt.example).

Labels are only shown in the logs, because UniFi list entries have no description field. The static list is printed at startup and whenever it changes, and every change to UniFi shows why each address is there:

```
static (env): 160.79.104.0/21 (Anthropic API), 203.0.113.10 (Office)
allow-v4: +['160.79.104.0/21 (Anthropic API)', '198.51.100.23 (knock)'] -['192.0.2.1 (placeholder)']
```

Over-broad entries are refused (IPv4 shorter than `/8`, IPv6 shorter than `/64`). IPv6 hosts are widened to their `/64`.

## Deploy

1. Push this repo to GitHub. The [build workflow](.github/workflows/build.yml) runs the tests, then builds `linux/amd64` + `linux/arm64` images and pushes them to `ghcr.io/rossdargan/knock-sync`:
   - `latest` + `sha-xxxxxxx` on pushes to `main`
   - `1.2.3` / `1.2` for `v1.2.3` tags
   - a weekly rebuild that picks up base-image security fixes
2. The GHCR package is public, so no `docker login` is needed to pull it.
3. On the host:

   ```sh
   cp .env.example .env      # fill in secrets
   mkdir -p config && cp static.txt.example config/static.txt
   docker compose pull && docker compose up -d
   docker compose logs -f knock-sync
   ```

   **Dockhand / Portainer:** paste [docker-compose.yml](docker-compose.yml) as the stack and the contents of `.env.example` (filled in) as the stack's environment variables. You can mark the tokens/keys as secrets. The compose file maps every variable into the container explicitly, which these tools require.

4. Before the first run, check the API key and list IDs work:

   ```sh
   docker compose run --rm knock-sync --dump
   ```

   UniFi won't save an empty list, so seed each list in the UI with the placeholder (`192.0.2.1` / `2001:db8::/64`). The sync writes single addresses as `IP_ADDRESS` items and CIDR ranges (e.g. `160.79.104.0/21`) as `SUBNET` items.

The container runs as non-root on a read-only filesystem. It has a Docker `HEALTHCHECK`: it's unhealthy if no sync has succeeded in `HEALTH_MAX_AGE`, which defaults to max(120s, 4×interval).

## Configuration

See [.env.example](.env.example) for every variable. If you add a new variable, also map it under `environment:` in [docker-compose.yml](docker-compose.yml). Required ones:
`KNOCK_URL`, `KNOCK_SYNC_TOKEN`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`, `UNIFI_HOST`, `UNIFI_API_KEY`, `UNIFI_SITE_ID`, `UNIFI_LIST_V4_ID`.

## CLI

```
knock_sync.py                 run forever (container default)
knock_sync.py --once          single sync, exit code 0/1
knock_sync.py --dump          print the UniFi lists and exit
knock_sync.py --healthcheck   used by Docker HEALTHCHECK
```

## Development

```sh
python -m unittest discover -s tests -v
docker build -t knock-sync:dev .
```
