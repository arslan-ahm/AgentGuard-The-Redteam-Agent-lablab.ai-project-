# Deploying AgentGuard on Vultr

Owner: Arslan · Reviewer: Sohaib · Brief 6.10

One Vultr Cloud Compute VM runs the whole stack with Docker Compose. Vultr Serverless Inference runs the planner's LLM calls. Nothing else is needed.

```
Internet ──443/80──> web (Caddy: HTTPS, SPA, reverse proxy)
                       └─/api, /healthz──> backend (FastAPI) ──> postgres, redis
                                            worker (RQ) ──> docker-proxy ──> Docker engine
                                              │                              │
                                              └── Vultr Serverless Inference │ one fresh container per task
                                                  (planner, summaries)       v
                                                                   sandbox (Playwright)
                                                                   on agentguard-sandbox network
                                                                   (egress firewall: public internet only)
```

## How Vultr is used

| Vultr product | What runs there | Why |
|---|---|---|
| **Cloud Compute VM** (Ubuntu 24.04) | All containers: web, API, worker, Postgres, Redis, and every disposable sandbox | Full control of the Docker engine and the host firewall (iptables), which is what sandbox containment needs. Managed container platforms don't allow per-container network filtering like this |
| **Vultr Firewall** (group attached to the VM) | Inbound allow-list: 22 (your IP only), 80, 443 | A second layer outside the VM, in front of ufw |
| **Serverless Inference** (OpenAI-compatible API) | `plan(target_url, profile)` and the executive summary | No GPU to manage. The app sends redacted, truncated page text only; without a key it falls back to deterministic plans, so the demo never depends on the LLM |
| **Snapshots** (optional) | Whole-VM restore point before a demo | One-click rollback |

## 1. Create the VM

1. Vultr console → Deploy → **Cloud Compute**, Ubuntu 24.04 LTS x64. Size: **4 vCPU / 8 GB** or more. Each sandbox is limited to 1 CPU and 1 GB (`SANDBOX_CPU_LIMIT`, `SANDBOX_MEM_LIMIT`), and the rest of the stack needs about 2 GB.
2. Add your SSH key. Turn on automatic backups if you want them (they're separate from the DB dumps below).
3. **Firewall group:** inbound TCP 22 from your IP only, TCP 80 and TCP 443 from anywhere. Attach it to the VM.
4. DNS: create an `A` record (e.g. `agentguard.example.com`) pointing at the VM's IPv4. Caddy can only get a certificate once this record resolves.

## 2. Bootstrap the VM (once)

```bash
ssh root@<vm-ip>
git clone https://github.com/arslan-ahm/AgentGuard-The-Redteam-Agent-lablab.ai-project-.git /opt/agentguard-src
cd /opt/agentguard-src
bash scripts/deploy/bootstrap-vm.sh --ssh-from <your-ip>/32
```

`bootstrap-vm.sh` is idempotent. It does the following:

- Installs Docker Engine from Docker's apt repo.
- Sets up ufw: deny inbound except 22/80/443.
- Creates the work dir `/var/lib/agentguard/work`, owned by the worker's uid 10001.
- Installs and starts `agentguard-egress.service`, the sandbox network plus its iptables rules from `scripts/sandbox-egress.sh`.
- Enables the daily DB backup timer.

**Do not run scans if it reports the egress script missing.**

## 3. Configure

```bash
cp deploy/dotenv.example .env && chmod 600 .env
openssl rand -hex 32   # use one for SECRET_KEY, another for POSTGRES_PASSWORD
nano .env
```

| Variable | Production value |
|---|---|
| `SITE_ADDRESS` | `agentguard.example.com` (the domain only: Caddy turns on HTTPS) |
| `PUBLIC_BASE_URL`, `ALLOWED_ORIGINS` | `https://agentguard.example.com` |
| `SECRET_KEY`, `POSTGRES_PASSWORD` | fresh random values, never reused |
| `VULTR_INFERENCE_API_KEY` | Vultr console → Serverless Inference → API key. Check the base URL and pick `VULTR_INFERENCE_MODEL` from the model list there |
| `GITHUB_TOKEN` | optional; fine-grained, Issues: write on the demo repo only |
| `AGENTGUARD_WORK_ROOT` | keep `/var/lib/agentguard/work` (must be the same path on host and in the worker) |

`.env` is gitignored and never leaves the VM. To update a secret: edit `.env`, then `docker compose up -d`.

## 4. Build and start

```bash
docker compose --profile build-only build sandbox   # the per-task sandbox image
docker compose up -d --build
bash scripts/deploy/healthcheck.sh https://agentguard.example.com
```

`healthcheck.sh` must print `HEALTHY`. It checks the following:

- the public `/healthz` over verified HTTPS
- that every service is running and healthy
- that the sandbox image exists
- that the egress firewall is active
- that nothing except `web` publishes a port

## 5. Containment smoke test (before any demo)

Run the containment demo task: `security.exposed_endpoints` with `params: {"containment_demo": true}` (see `sandbox-worker/README.md`). Expected:

- The task ends `blocked`.
- The audit log has `navigate / blocked` for `http://169.254.169.254/latest/meta-data/`, then `sandbox_destroyed`.
- `docker ps -a --filter label=agentguard.scan_id` shows nothing left behind.

Independently, the egress firewall must stop a sandbox even when the in-browser policy is bypassed:

```bash
docker run --rm --network agentguard-sandbox --entrypoint /opt/venv/bin/python agentguard-sandbox:local \
  -c "import urllib.request as u; u.urlopen('http://169.254.169.254/', timeout=5)"
# expected: timeout / connection error, never a response
```

## 6. Docker access for the worker (security model)

The worker launches sandboxes with the `docker` CLI through `docker-proxy` (`tecnativa/docker-socket-proxy`). That proxy is the only container with the Docker socket, mounted read-only, and it sits on the `docker-api` network, which is `internal` and shared only with the worker. It allows the container endpoints and ping/version. It refuses the rest:

- image pulls
- `exec`
- builds
- networks and volumes
- swarm, system and events

The sandbox containers have no Docker access at all.

**Residual risk.** The container API can still create a privileged container, so the worker must only ever run our code. Never mount the socket elsewhere, never publish the proxy, never point `DOCKER_HOST` at it from another service. `backend/tests/test_deploy_config.py` fails the backend tests if any of these change.

## 7. Backups

- **Schedule:** daily at 03:15 UTC (systemd timer) to `/var/backups/agentguard/agentguard-<timestamp>.sql.gz`. Files are root-only, kept 14 days, and an empty or corrupt dump is rejected.
- **Manual backup:** `bash scripts/deploy/backup-db.sh`
- **Restore:** `bash scripts/deploy/backup-db.sh --restore <file>`. It asks you to type `RESTORE`, stops the API and worker, restores, then starts them again.
- **Copy off the VM:** `scp root@<vm-ip>:/var/backups/agentguard/*.sql.gz .` (or Vultr Object Storage). A backup that only lives on the VM is lost with the VM.

## 8. Updates and rollback

```bash
cd /opt/agentguard-src && git pull --ff-only
docker compose --profile build-only build sandbox
docker compose up -d --build
bash scripts/deploy/healthcheck.sh https://agentguard.example.com
```

To roll back, run `git checkout <previous tag or commit>` and the same build commands. If a migration ran, restore the backup taken before the update.

## 9. Uptime during judging

- Point an external monitor (UptimeRobot, Better Stack…) at `https://<domain>/healthz` every 1–5 minutes.
- `restart: unless-stopped` on every service, plus Docker enabled at boot, brings everything back after a reboot. `agentguard-egress.service` is enabled at boot too. After any reboot, run `healthcheck.sh` to confirm the egress rules are active again before running scans.
- Before the demo: take a Vultr snapshot, run `healthcheck.sh`, then run the containment smoke test.

## Troubleshooting

| Symptom | Check |
|---|---|
| HTTPS certificate not issued | `docker compose logs web`. The DNS A record must resolve to the VM, and ports 80/443 must be open in both the Vultr firewall and ufw |
| Every task ends `error`, stderr mentions docker | `docker compose logs docker-proxy worker`. The sandbox image must exist (`IMAGES=0` means it is never pulled) |
| Sandbox can't write `out/` | ownership of `AGENTGUARD_WORK_ROOT` (uid 10001), and the same path on both sides of the worker mount |
| Sandbox can't reach a public target | `scripts/sandbox-egress.sh status`. DNS must go to the host's upstream resolvers |
