# Security policy

AgentGuard runs browser tests against websites, so it is built to be safe to point at a target and hard to turn into an attack tool. This page covers how to report a problem, what AgentGuard will and won't do, and where the controls live.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem in AgentGuard itself.

- Use GitHub's private reporting: **Security → Report a vulnerability** on this repository.
- Include what you found, how to reproduce it, and the impact you expect.
- We aim to reply within 3 days and to fix confirmed issues before disclosing them. We'll credit you unless you'd rather we didn't.

**In scope:** sandbox escape or egress past the firewall, policy bypass (reaching private, loopback, link-local or metadata addresses), audit-log tampering, secret leakage into logs, evidence or LLM prompts, authentication and authorization flaws in the API, and access to the Docker API from anywhere but the worker.

**Out of scope:** findings that AgentGuard reports about *other* sites, denial of service against the demo VM, and social engineering.

## Using AgentGuard responsibly

- **Authorized targets only.** Scan only sites you own or have written permission to test. Each scan requires an authorization attestation, which is kept as an audit record (brief 13).
- **Safe checks only.** No exploitation, no data modification, no brute force, no scanning of private networks. The probes are clearly marked (`agentguard-probe-<id>`), inert and bounded:
  - Login rate checks stop at 3 attempts.
  - Endpoint checks only `GET` four fixed paths.
  - Redirect checks never follow the redirect.
- **Rate-limited.** The policy module caps scans at 10 per user and 6 per target host per hour (`backend/app/policy/rate_limit.py`, applied by the API).
- **Human in the loop.** Nothing leaves the system (GitHub issues, reports) without explicit approval.

## How AgentGuard is contained

Each check runs in its own disposable Docker container on a Vultr VM. The container:

- runs as non-root with a read-only filesystem and no Linux capabilities
- is limited in CPU, memory, processes and wall-clock time
- has no Docker socket, no host filesystem and no secrets
- sits on a network whose firewall only allows the public internet

Every allowed and blocked action goes into a hash-chained, append-only audit log, and secrets are redacted before anything is stored or sent to the LLM.

The full control list, with where each control is enforced and how it's tested, is in [docs/containment-policy.md](docs/containment-policy.md).

## Secrets

- Real secrets live only in `.env` on the server. `.env` is gitignored, and [`deploy/dotenv.example`](deploy/dotenv.example) holds names only.
- There is no automatic secret scan: check your diff before every push, and never commit `.env` or keys.
- Credentials for a target, if any, are injected as short-lived environment variables and never appear in task files, logs or LLM prompts.
- If a secret is ever committed: rotate it first, then remove it from history.
