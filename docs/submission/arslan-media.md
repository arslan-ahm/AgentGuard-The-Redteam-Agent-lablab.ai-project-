# Arslan's submission media

Brief section 17 / `SUBMISSION_PACK.md`. Items: #3 architecture diagram, #4 SECURITY.md + containment policy, #5 Vultr write-up, #6 live demo uptime, #14 Q&A prep (with Sarah), deck slides 6–8, video segment 2:30–3:05.

| # | Item | Where | Status |
|---|---|---|---|
| 3 | Architecture diagram | [`docs/architecture-diagram.png`](../architecture-diagram.png) (source: [`.svg`](../architecture-diagram.svg)) | Done. To re-render the PNG, open the SVG in Chromium at 2x and screenshot it |
| 4 | Security policy + containment | [`SECURITY.md`](../../SECURITY.md), [`docs/containment-policy.md`](../containment-policy.md) | Done |
| 5 | Vultr write-up | README "How Vultr powers AgentGuard", and the form text below | Done, except region and model, which get filled in after deploy |
| 6 | Live demo uptime | [`docs/deploy-vultr.md`](../deploy-vultr.md) §9, `scripts/deploy/healthcheck.sh` | **Blocked until the VM exists** |
| 14 | Q&A prep | below | Draft, for Sarah to merge with hers |
| — | Slides 6–8 | below | Content and speaker notes, for Ayesha to design |
| — | Video 2:30–3:05 | below | Script and shot list |

Only claim what works in the deployed demo. Anything marked _(after deploy)_ is confirmed on the VM before recording.

---

## Deck: slides 6–8

### Slide 6: Architecture

**Title:** One VM, one sandbox per test

**Visual:** `docs/architecture-diagram.png`, full width.

**Bullets (max 3):**
- Web app + API + queue + Postgres on a Vultr Cloud Compute VM
- Vultr Serverless Inference plans each scan
- Every test runs in a fresh Playwright container, deleted afterwards

**Speaker notes (about 18 s):** A user submits a URL to our web app on a Vultr VM. The planner on Vultr Serverless Inference turns it into a test plan, and the worker runs each test in its own throwaway Playwright container. Results come back as evidence, and the container is deleted.

### Slide 7: Why Vultr

**Title:** Built on Vultr

**Visual:** three tiles: Cloud Compute VM · Serverless Inference · Firewall.

| Tile | Text |
|---|---|
| Cloud Compute VM | Hosts the app, API, database, queue and every sandbox. We control Docker and the host firewall |
| Serverless Inference | Test planning and summaries over an OpenAI-compatible API. No GPUs to manage |
| Firewall | Only 80/443 (plus SSH from us) can reach the VM |

**Footer (fill after deploy):** Region: _…_ · VM: _… vCPU / … GB_ · Model: _…_

**Speaker notes (about 18 s):** We run everything on one Vultr Cloud Compute VM, because owning the Docker engine and the firewall is what lets us lock each sandbox down at the network level. Planning runs on Vultr Serverless Inference, so we never manage GPUs. If the model is down, fallback plans keep scans working.

### Slide 8: Containment first

**Title:** Containment first

**Visual:** screenshot of the red "Blocked by policy" event + "sandbox destroyed" _(after deploy)_.

**Bullets:**
- One container per task, always destroyed
- CPU, memory, process and time limits · non-root · read-only
- No Docker socket, no host files, no secrets inside
- Private IPs, localhost and cloud metadata blocked: by policy, in the browser and at the firewall
- Credentials never reach the LLM · secrets redacted
- Tamper-evident (hash-chained) audit log

**Speaker notes (about 20 s):** We assume the target site is hostile. Every test gets its own locked-down container with hard limits and no way into the host, and network access to private addresses and the cloud metadata service is blocked in three separate layers. Every allowed and blocked action lands in an audit log that detects tampering, and you'll see it live in the demo.

---

## Video segment 2:30–3:05: the containment moment (Arslan)

**Setup before recording:**
1. `healthcheck.sh` prints HEALTHY.
2. A finished demo scan is on screen.
3. The containment task is ready: `security.exposed_endpoints` with `params: {"containment_demo": true}` (how it's triggered in the UI depends on the orchestrator; Sohaib/Ayesha).

| Time | On screen | Voice-over |
|---|---|---|
| 2:30–2:37 | Live progress view; the containment task starts ("sandbox launched") | "Now let's make the agent do something unsafe: reach the cloud metadata service at 169.254.169.254, which holds a server's credentials." |
| 2:37–2:47 | The red **Blocked by policy** event appears, showing the target `http://169.254.169.254/latest/meta-data/` and the reason | "The policy engine blocks it before a single packet is sent." |
| 2:47–2:55 | The **sandbox destroyed** indicator; the task status is `blocked` | "The sandbox is destroyed straight away. Any blocked action ends the task." |
| 2:55–3:05 | Audit log view: `navigate / blocked`, then `sandbox_destroyed`, with timestamps | "And it's all in a tamper-evident audit log. Even if the browser were tricked, the host firewall drops private and metadata traffic as a second wall." |

**Captions:** "Blocked by policy", "Sandbox destroyed", "Tamper-evident audit log".
**Fallback if the UI isn't ready:** record a terminal running the task through the sandbox worker. It shows `blocked`, exit code 3, and the blocked event in `policy_events`.

---

## Submission form: "How we use Vultr"

> AgentGuard runs entirely on Vultr. A Vultr Cloud Compute VM (Ubuntu 24.04, _region_, _size_ (after deploy)) hosts the whole stack with Docker Compose: the React web app behind Caddy (automatic HTTPS), the FastAPI API, an RQ worker, PostgreSQL and Redis. The same VM runs the security sandboxes. For every test, the worker starts a fresh, non-root, resource-limited Playwright container on a dedicated Docker network whose host firewall rules drop traffic to private, loopback and cloud-metadata addresses, and destroys it afterwards. Vultr Serverless Inference (_model_ (after deploy)), through its OpenAI-compatible API, generates the structured test plan for each scan and the executive summary; it only receives redacted, truncated page text, and deterministic fallback plans keep scans working if it's unavailable. A Vultr Firewall group allows only HTTPS/HTTP and our SSH.

---

## Q&A prep (Arslan's answers; Sarah adds the AI ones)

**How is the sandbox contained?**
One container per test, deleted on every outcome. It runs:
- with CPU, memory (no swap), process and wall-clock limits
- as non-root, with all Linux capabilities dropped and a read-only filesystem
- with no Docker socket, no host folders except its own in/out, and no secrets

Network access is restricted three times: the URL policy (with DNS pinning), an in-browser guard on every request and redirect, and host iptables rules on the sandbox network. See `docs/containment-policy.md`.

**What stops someone pointing AgentGuard at an internal system, like 10.0.0.5 or localhost?**
- The URL policy resolves DNS and rejects any private, loopback, link-local, CGNAT or metadata address, including tricks like `127.1`, `0x7f000001` and IPv4 inside IPv6.
- It re-checks before each sandbox launch and at every redirect hop.
- If all that failed, the firewall still drops the packets.

**What about DNS rebinding?**
The launcher pins the target hostname to the IPs the policy approved (`--add-host`), so a second DNS answer pointing at 127.0.0.1 is never used. Every redirect hop is re-validated, and the firewall is the backstop.

**Could the target page escape the browser or the container?**
The page runs in Chromium inside a container with no capabilities, no privileges, a read-only root, and no host access. A full browser-plus-kernel escape would land in an empty, unprivileged, network-filtered box that is deleted within the time limit.

**How do you avoid attacking the sites you scan?**
- Authorization attestation, plus per-user and per-target rate limits.
- Inert, marked probe values (`agentguard-probe-…`); redirect probes point at the reserved `.invalid` domain.
- `GET` only for endpoint checks.
- At most 3 login attempts with a fake account.
- No exploitation, data changes or brute force.

**Can the audit log be tampered with?**
It's append-only and hash-chained, like a mini blockchain: each entry includes the previous entry's hash. Editing, deleting or reordering any entry breaks the chain, and verification reports the first bad entry. Secrets are redacted before anything is written.

**What does the LLM see? What about credentials?**
Only redacted, truncated page text. Credentials for a target are injected as short-lived environment variables and never appear in prompts, task files or logs. Redaction covers tokens, cookies, Authorization headers, passwords and well-known API key formats.

**Why Vultr, and why a VM rather than a managed container service?**
Containment needs control of the Docker engine and the host firewall, so we can filter each sandbox's network. Serverless Inference gives us the LLM without running GPUs.

**What happens if the LLM is down or produces a bad plan?**
Plans are schema-validated and limited to whitelisted check IDs, and there's a deterministic fallback plan per profile. (Sarah has more detail.)

**Who can start containers on the VM?**
Only the worker, through a Docker API proxy that allows the container endpoints alone (no image pulls, exec or builds). The proxy sits on an internal network the sandboxes can't reach. The remaining risk is that the worker itself is trusted, and we say so.

**Limitations?**
- Scans need a public target.
- Login checks touch the real site, within the safe limits above.
- 3 login attempts can't prove a rate limit is missing, so that finding is medium with confidence 0.6.
- Single VM: no horizontal scaling yet.
