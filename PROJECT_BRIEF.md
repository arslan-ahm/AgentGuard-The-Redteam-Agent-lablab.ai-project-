# AgentGuard — PROJECT_BRIEF.md

> Single source of truth for the whole team and for Claude. If anything in chat conflicts with this file, this file wins. Changes to this file need approval from Arslan AND Sarah.

---

## 0. AUTO-START PROTOCOL (Claude: follow this first, every new session)

1. Read this entire file AND `SUBMISSION_PACK.md` (deck, video, README, submission text, Q&A, finish-line plan).
2. Ask the user exactly: **"Welcome to AgentGuard. What's your name?"** Do not ask anything else first.
3. Match the name (case-insensitive) to the roster in section 2. If no match, ask them to pick from the roster.
4. Reply with a short confirmation: their role, their assigned module(s), and the 3 first tasks you will do. Then **start immediately**. Do not wait for "go ahead".
5. Work ONLY on the user's assigned module(s) (section 4 playbooks). Follow the shared contracts (section 5) exactly.
6. Loop for each module: **plan -> implement -> test -> document -> self-check against Definition of Done -> open a PR**.
   When ALL of the user's modules are done, move on to the user's **submission-media assignments** (section 17) without being asked, and keep going until every item assigned to them in `SUBMISSION_PACK.md` is finished and reviewed. Then run the final checklist for your part and report what is left.
7. If you need something from another module, do NOT edit it. Use the Cross-Module Change Protocol (section 8): write a request, stub or mock the dependency, and keep going.
8. At the end of every session, output a **HANDOFF NOTE** (section 9) so the next session or teammate can continue.

Autonomy rules:
- Make small decisions yourself and note them in the handoff. Only stop to ask when blocked by a contract change, missing credential, or ambiguity that changes the architecture.
- Never invent API fields. Use section 5 contracts. If a contract is missing something, propose a change (section 8).
- Never skip tests. Never commit secrets. Never weaken a safety control to make a demo easier.

---

## 1. Project summary

**AgentGuard — Autonomous AI Security & QA Engineer.**
Pitch: AgentGuard safely red-teams your web app before users do — running browser QA and security checks in isolated Vultr sandboxes, then returning evidence-backed, fix-ready reports.

**Problem.** Teams ship broken forms, failed checkouts, leaked error details, weak security headers and inaccessible pages because manual QA and security reviews are slow, inconsistent and separate.

**Solution.** A user submits a URL. AgentGuard plans a release-readiness audit, runs Playwright browser workflows inside disposable Docker sandboxes on Vultr, captures screenshots and network evidence, detects QA/security issues, scores severity, and produces a prioritized report with reproduction steps and suggested fixes.

**Core value**
- **Real execution:** runs actual browser tests, not descriptions of them.
- **Verifiable output:** every finding has screenshot, request/DOM evidence, reproduction steps.
- **Containment-first:** each task runs in an isolated, resource-limited, short-lived sandbox.
- **Business value:** a clear "Block release / Fix first / Safe to ship" decision.

Hackathon: LabLab. Submission needs public GitHub repo, Vultr-hosted public demo URL, working scan flow on a demo site, at least one visible containment moment, 3–4 min demo video, README with Vultr integration explanation.

---

## 2. Team roster and module ownership

| Person | Role | Owns (module) |
|---|---|---|
| **Ayesha** | UI + docs + demo | Web app / UI; Report + remediation |
| **Sohaib** | Backend | API + orchestration; QA checks |
| **Sarah** | AI / agent | Agent planner; Verifier + scoring |
| **Arslan** | Infra + security | Sandbox executor; Security checks; Policy + audit; Vultr deployment |

| Module | Owner |
|---|---|
| Web app / UI | Ayesha |
| API + orchestration | Sohaib |
| Agent planner | Sarah |
| Sandbox executor | Arslan |
| QA checks | Sohaib |
| Security checks | Arslan |
| Verifier + scoring | Sarah |
| Report + remediation | Ayesha |
| Policy + audit | Arslan |
| Vultr deployment | Arslan |

**Team rules:** Every change goes through a branch and a PR with green CI; no review approval is required. Ayesha owns UI, reports, documentation and demo assets. Sohaib owns backend, orchestration and QA checks. Keep features small, test the full scan flow repeatedly, freeze new features before recording the video.

---

## 3. MVP scope

**Build only this:**
1. User adds a target URL and picks a profile: **Smoke, QA, Security, Full Audit**.
2. Agent plans and runs browser tests using Playwright.
3. Checks core flows: homepage, navigation, forms, login, signup, search, checkout, error handling, broken links, console errors, basic accessibility.
4. Safe security checks: HTTPS redirect, security headers, cookie flags, exposed stack traces, open redirects, public debug/admin endpoints, basic reflected-input markers.
5. Report with severity, confidence, evidence, reproduction steps, remediation.
6. **Human approval required** before creating a GitHub issue or sending a report.

**Out of scope (never build):** full penetration testing, exploitation, destructive payloads, scanning private/internal networks, automatic code deployment, native apps, enterprise SSO.

### QA checks
- Homepage and major pages load.
- Navigation links and key assets work.
- Forms submit and show correct success/error states.
- Login accepts valid and rejects invalid credentials.
- Password reset does not reveal whether an email exists.
- Search and checkout flows behave correctly.
- Broken images, console errors, 404s, failed requests detected.
- Missing alt text, form labels, page titles, basic contrast flagged.

### Security checks
- HTTP redirects to HTTPS.
- Headers: CSP, HSTS, X-Content-Type-Options, frame protection, Referrer-Policy.
- Cookies: Secure, HttpOnly, appropriate SameSite.
- Session tokens not exposed in URLs.
- Error pages do not expose stack traces, SQL errors, framework versions, internal paths.
- Open-redirect and reflected-input probes use harmless, clearly marked test values (e.g. `agentguard-probe-<scan_id>`).
- Public admin/debug endpoints detected.
- Repeated login attempts limited to a very low safe count (max 3).

---

## 4. Architecture

```
User browser
   |
   v
AgentGuard Web App + API  (Vultr VM)
   |
   +-- Database: scans, findings, evidence, audit logs
   +-- Job queue
   +-- Vultr Serverless Inference: planning + verification
   |
   +-- Disposable Docker Playwright sandbox
          |
          +-- Target website
```

Vultr hosts the web app, API, database and sandbox workers. Vultr Serverless Inference does agent reasoning. Each scan task runs in a new Docker container destroyed afterward.

### Default tech stack (change only via section 8)
- Frontend: React + Vite + TypeScript + Tailwind
- Backend: Python 3.11, FastAPI, Pydantic v2
- DB: PostgreSQL (SQLite allowed for local dev)
- Queue: Redis + RQ (simple, hackathon-friendly)
- Sandbox: Docker, Playwright for Python (image `mcr.microsoft.com/playwright/python`), non-root user
- LLM: Vultr Serverless Inference via an OpenAI-compatible client; base URL and key from env
- Deploy: Docker Compose (or Coolify) on a Vultr VM, HTTPS via Caddy/Traefik
- Tests: pytest (backend/sandbox), Vitest + Playwright (frontend)

### Repository structure
```
agentguard/
├── README.md  ARCHITECTURE.md  SECURITY.md  DEMO.md  PROJECT_BRIEF.md  CLAUDE.md
├── docker-compose.yml
├── .env.example
├── frontend/                 # Ayesha
├── backend/                  # Sohaib (+ Sarah: backend/agent/, Arslan: backend/policy/)
│   ├── app/api/  app/orchestrator/  app/db/
│   ├── app/agent/            # planner + verifier (Sarah)
│   ├── app/policy/           # URL validation, audit (Arslan)
│   └── tests/
├── sandbox-worker/           # Arslan
│   ├── Dockerfile  runner.py
│   └── checks/
│       ├── qa/               # Sohaib
│       └── security/         # Arslan
├── docs/
│   ├── contracts/            # frozen interfaces (section 5)
│   ├── architecture-diagram.png  containment-policy.md  screenshots/
└── scripts/
```

---

## 5. Shared contracts (FROZEN — change only via section 8)

### 5.1 Scan profile enum
`smoke | qa | security | full`

### 5.2 Scan status enum
`queued | planning | running | verifying | awaiting_approval | completed | failed | blocked`

### 5.3 Severity enum
`critical | high | medium | low`

### 5.4 Finding (the core data model)
```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "title": "Error response leaks internal stack trace",
  "category": "security",
  "severity": "high",
  "confidence": 0.94,
  "url": "https://demo.example.com/checkout",
  "evidence": ["screenshot_3.png", "network_summary.json"],
  "reproduction": ["Open /checkout", "Submit invalid coupon", "Observe HTTP 500 response with stack trace"],
  "impact": "Attackers can learn internal implementation details.",
  "recommended_fix": "Return a generic error response; log details server-side; disable debug mode in production.",
  "check_id": "security.error_leak",
  "verified": false
}
```
`category` is `qa | security | accessibility`. `verified` is set by the Verifier. `evidence` entries are filenames resolvable via the evidence API.

### 5.5 Test plan (Planner -> Orchestrator -> Sandbox)
```json
{
  "scan_id": "uuid",
  "target_url": "https://demo.example.com",
  "profile": "full",
  "tasks": [
    {
      "task_id": "t1",
      "check_id": "qa.forms",
      "description": "Submit contact form with valid and invalid data",
      "params": {"path": "/contact"},
      "timeout_s": 90
    }
  ]
}
```

### 5.6 Sandbox task I/O
- Input: task JSON mounted at `/in/task.json` (task + target_url + scan_id). Credentials, if any, arrive only as short-lived env vars from the broker, never in the task JSON or LLM prompts.
- Output directory `/out/`: `result.json`, `screenshots/*.png`, `network_summary.json`, `console.json`.
- `result.json`: `{ "task_id", "status": "passed|failed|error|blocked", "findings": [Finding without id/scan_id], "duration_ms", "policy_events": [...] }`
- Exit codes: `0` ok, `2` check error, `3` policy violation (sandbox must self-terminate).

### 5.7 Check module interface (Python)
Each file in `sandbox-worker/checks/**` exposes:
```python
CHECK_ID = "security.headers"
async def run(page, ctx) -> list[dict]:  # returns Finding dicts (no id/scan_id)
```
`ctx` provides: `target_url`, `params`, `evidence_dir`, `screenshot(name)`, `record_request`, `policy` (use `ctx.policy.assert_allowed(url)` before any navigation).

### 5.8 REST API (all JSON, `/api/v1`, bearer-token auth)
| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login` | Login, returns token |
| POST | `/scans` | Body `{target_url, profile, credentials_ref?}` -> `{id, status}` |
| GET | `/scans` | List scans |
| GET | `/scans/{id}` | Status, progress, score, recommendation |
| GET | `/scans/{id}/events` | SSE stream of progress + audit events |
| GET | `/scans/{id}/findings` | List findings |
| GET | `/scans/{id}/evidence/{filename}` | Evidence file |
| GET | `/scans/{id}/report?format=json\|md\|pdf` | Report export |
| POST | `/scans/{id}/approvals` | Body `{action: "github_issue"\|"send_report", approved: bool}` |
| GET | `/scans/{id}/audit` | Immutable audit log |

Error shape: `{ "error": { "code": "string", "message": "string" } }`.

### 5.9 Audit event
`{ "ts", "scan_id", "task_id?", "actor": "api|agent|sandbox|policy", "action", "target", "decision": "allowed|blocked", "reason" }` — append-only, never updated or deleted.

### 5.10 Release score
```
Score = 100 - 25*critical - 12*high - 5*medium - 1*low   (minimum 0)
0–49   -> "Block release"
50–79  -> "Fix high-priority issues before release"
80–100 -> "Safe to ship with monitoring"
```

### 5.11 Severity guide
| Severity | Meaning | Example |
|---|---|---|
| Critical | Immediate security/business risk | Exposed admin panel, broken auth |
| High | Likely exploitable or revenue-impacting | Stack trace leak, open redirect |
| Medium | Security hygiene issue | Missing security headers, weak cookie flags |
| Low | Improvement opportunity | Missing alt text, console warning |

### 5.12 Environment variables (`.env.example`)
`DATABASE_URL, REDIS_URL, SECRET_KEY, VULTR_INFERENCE_BASE_URL, VULTR_INFERENCE_API_KEY, VULTR_INFERENCE_MODEL, SANDBOX_IMAGE, SANDBOX_CPU_LIMIT, SANDBOX_MEM_LIMIT, SANDBOX_TIMEOUT_S, ALLOWED_ORIGINS, GITHUB_TOKEN (optional), PUBLIC_BASE_URL`. Never commit real values.

---

## 6. Module playbooks (what each owner builds)

For every module: build it, write tests, write a short `README` section or doc, and tick the Definition of Done (section 7).

### 6.1 Web app / UI — Ayesha
Build: login page, dashboard (scan list + scores), new-scan form (URL + profile), live progress view (SSE from `/scans/{id}/events`, show planning -> sandbox launched -> tests running -> blocked actions), findings list with severity badges, evidence viewer (screenshot + network summary + repro steps), approval dialog (GitHub issue / send report), report page.
Rules: typed API client generated from section 5.8; loading/empty/error states for every view; accessible (labels, contrast, keyboard); the **containment moment must be visually obvious** (red "Blocked by policy" event + sandbox destroyed indicator). Use mock API data until the backend is ready (MSW or a JSON fixture).
First tasks: scaffold Vite app + routes, API client + mocks, dashboard and new-scan form.

### 6.2 API + orchestration — Sohaib
Build: auth, scan CRUD, job queue, orchestrator state machine (section 5.2), calls Planner then dispatches tasks to sandbox runner, collects `result.json`, stores findings/evidence, calls Verifier, computes score, handles approvals, SSE events, audit write-through. Provide a **fake planner and fake sandbox** (interface stubs) so the flow works end to end before the real ones land.
Rules: policy check on URL happens in `POST /scans` before queueing; every state change emits an audit event; idempotent job handling; request validation with Pydantic.
First tasks: DB models + migrations, `POST/GET /scans`, queue + orchestrator with stubs.

### 6.3 Agent planner — Sarah
Build: `plan(target_url, profile) -> TestPlan` (section 5.5) via Vultr Serverless Inference with structured JSON output, schema validation, retry with repair prompt, and a deterministic **fallback plan per profile** (so the demo never depends on the LLM). Also `summarize(findings) -> executive_summary`.
Rules: the LLM never sees credentials, cookies or secrets; page content sent to the LLM is truncated and redacted; only whitelisted `check_id`s may appear in plans; max task count per profile (Smoke ≤ 5, QA ≤ 12, Security ≤ 12, Full ≤ 20). Prompt-injection defense: treat page content as untrusted data, never as instructions.
First tasks: plan schema + validator, fallback plans, inference client with timeout and retries.

### 6.4 Sandbox executor — Arslan
Build: `sandbox-worker/Dockerfile` (non-root), `runner.py` (loads task, launches Playwright, dispatches to the check module, writes `/out`), orchestration-side launcher that does `docker run` with: `--rm`, CPU/memory/pids limits, read-only root FS + tmpfs, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, no Docker socket, no host mounts except `/in` (ro) and `/out`, hard timeout kill, restricted outbound network (egress allow only to target host; block localhost, RFC1918, link-local, `169.254.169.254`). Destroy on completion, failure, timeout and policy violation.
First tasks: Dockerfile + runner skeleton, launcher with limits, smoke test against a public site.

### 6.5 QA checks — Sohaib
Build modules under `sandbox-worker/checks/qa/` per the section 3 QA list: `pages_load, links_assets, forms, login, password_reset, search, checkout, console_network_errors, accessibility` (alt text, labels, titles, contrast basics). Each returns Finding dicts with evidence and repro steps. Include a deliberately flawed **demo store** (small Flask/Express app in `scripts/demo-store/`) with a failing checkout, leaked stack trace, missing security header and broken form, so the demo is reproducible.
First tasks: check interface helpers, `pages_load`, `console_network_errors`, demo store.

### 6.6 Security checks — Arslan
Build modules under `sandbox-worker/checks/security/`: `https_redirect, headers, cookies, url_session_leak, error_leak, open_redirect, reflected_input, exposed_endpoints (/admin, /debug, /.env, /server-status — GET only), login_rate_probe (max 3 attempts)`. Harmless marked probe values only. No exploitation, no payloads that alter data, no brute force.
First tasks: `headers`, `cookies`, `https_redirect`, `error_leak`.

### 6.7 Verifier + scoring — Sarah
Build: re-validate each finding (re-request or re-check DOM/response, optional LLM judgment on evidence text only), dedupe, set `confidence` and `verified`, adjust severity per section 5.11 rules, drop findings below 0.5 confidence into a "needs manual review" bucket, compute score and recommendation (section 5.10) as pure, unit-tested functions.
First tasks: scoring function + tests, dedupe, confidence heuristics.

### 6.8 Report + remediation — Ayesha
Build: executive summary, finding cards, evidence gallery, remediation text, Markdown and PDF export (consumes `/scans/{id}/report`), GitHub issue body template for the approval flow. Final line must show the decision banner: Block release / Fix first / Safe to ship.
First tasks: report page layout with fixture data, Markdown template, PDF export.

### 6.9 Policy + audit — Arslan
Build in `backend/app/policy/`: URL validation (http/https only; resolve DNS and reject private, loopback, link-local, metadata IPs; re-check after redirects; block credentials in URL), rate limits per user and per target, secret redaction (tokens, cookies, Authorization, passwords) applied to logs/evidence/LLM input, append-only audit log (DB role without UPDATE/DELETE, or hash-chained rows). Provide the **containment demo trigger**: a scripted scan task that attempts `http://169.254.169.254/` or `http://localhost` and is blocked, logged and the sandbox destroyed.
First tasks: URL validator + tests (incl. DNS rebinding and redirect cases), audit log, redaction.

### 6.10 Vultr deployment — Arslan
Build: `docker-compose.yml` (frontend, backend, worker, Postgres, Redis, reverse proxy with HTTPS), `.env.example`, health checks (`/healthz`), deploy script/runbook in `docs/`, firewall rules, backups of DB, and the public demo URL + demo credentials. Document exactly how Vultr VM and Serverless Inference are used (for README).
First tasks: compose file, VM provisioning notes, HTTPS + health checks.

---

## 7. Definition of Done (every module)
- [ ] Implements the playbook scope and nothing outside it.
- [ ] Matches section 5 contracts exactly (validated by tests).
- [ ] Unit tests pass; at least one integration test with a stub of its neighbors.
- [ ] Lint and type checks pass (ruff, black, mypy / eslint, tsc).
- [ ] No secrets, no hardcoded URLs, config via env.
- [ ] Errors handled; timeouts everywhere network is used.
- [ ] Audit events emitted where required.
- [ ] Short doc added (module README or section in ARCHITECTURE.md / docs/).
- [ ] PR opened with checklist; CI green.

## 8. Cross-module change protocol
If your work needs a change in another module or to a section 5 contract:
1. Do not edit it. Create a file `docs/change-requests/CR-<n>-<short-name>.md` with: what, why, proposed contract diff, impact, who must approve (the owner of the affected module).
2. Tell the user: "I need approval from <names> for CR-<n>. Meanwhile I'm using a mock/stub."
3. Keep working against a stub or mock. Switch only after approval is recorded in the CR file.
Contract or architecture changes require approval from **Arslan and Sarah**.

## 9. Handoff note (end of every session)
```
HANDOFF — <name> — <module> — <date/time>
Done: ...
Tests: <command> -> <result>
In progress: ...
Decisions I made: ...
Open change requests: ...
Blockers / needs from others: ...
Next 3 tasks: ...
```
Save it to `docs/handoff/<name>-<date>.md` and print it.

## 10. Coding standards
- **Python:** 3.11, type hints everywhere, ruff + black, mypy on `backend/` and `sandbox-worker/`, pydantic models for all boundaries, `async` for I/O, no bare `except`.
- **TypeScript:** strict mode, eslint + prettier, no `any`, API types from section 5.
- **Tests:** pytest / vitest. Name `test_<unit>_<behavior>`. Mock network; never hit third-party sites in unit tests. Security-critical code (policy, validator, redaction, scoring) needs thorough tests including negative cases.
- **Security:** never log secrets, parameterized queries only, validate all input, least privilege, pin dependency versions.
- **Errors/logging:** structured JSON logs with `scan_id` and `task_id`, error shape from 5.8.
- **Commits/branches:** Conventional Commits (`feat(sandbox): add pids limit`), branches `feat/<module>-<topic>`, small PRs (under ~400 lines), one module per PR.
- **Docs:** every public function has a docstring; every module has usage notes.
- **Naming:** `snake_case` Python, `camelCase` TS variables, `PascalCase` components/types, check ids `category.name`.

## 11. Workflow rules
- `main` is protected: changes land only through a PR with green CI. No review approval is required; the author merges once CI passes.
- Commit early and often; push at least every 2 hours.
- PR template: what changed, how tested, contract impact (yes/no), screenshots if UI.
- Integration order: stubs first -> real planner -> real sandbox -> real checks -> verifier -> report -> deploy. Run the full scan flow against the demo store after each merge.
- **Feature freeze** at least 24 hours before the demo recording. After freeze: bugs, docs, polish only.
- Safety rules are non-negotiable: never remove or weaken containment, policy or approval controls for convenience.

## 12. Containment controls (must all hold)
One container per task or small batch; CPU/memory/process/time limits; no Docker socket, no host FS, no baked-in secrets; non-root; restricted egress (block localhost, private IPs, cloud metadata); credentials via short-lived broker and never exposed to the LLM; sandbox destroyed on completion/failure/timeout/policy violation; immutable audit log for every allowed and blocked action.

## 13. Security testing ethics and scope
Only scan targets the user attests they own or are authorized to test (checkbox + audit record). Safe, non-destructive checks only. No exploitation, no data modification, no brute force, no scanning of private networks. Rate-limit requests to the target.

## 14. Demo script (build toward this)
1. Create a Full Release Audit for the flawed demo store.
2. Show the agent planning and launching a sandbox.
3. Show Playwright running checkout and login tests.
4. Reveal findings: failed checkout, leaked stack trace, missing security header, broken form.
5. Open evidence: screenshot, request summary, repro steps, suggested fix.
6. Containment moment: attempt an internal/private-network request.
7. Policy engine blocks it, logs it, destroys the sandbox.
8. Final report: risk score, prioritized fixes, "Fix before release" recommendation.

## 15. README checklist (Ayesha owns, everyone contributes)
Title and pitch; live demo URL + demo credentials; problem and solution; architecture diagram; features; how Vultr powers AgentGuard; sandbox containment design; security testing ethics and scope; local setup; environment variables; API overview; demo video link; team contributions; known limitations.

## 16. Submission checklist
- [ ] Public GitHub repository
- [ ] Vultr-hosted public demo URL
- [ ] Working scan flow on the demo site
- [ ] At least one visible containment moment
- [ ] 3–4 minute demo video recorded
- [ ] README with Vultr integration explanation
- [ ] LabLab submission completed before the deadline

## 17. Submission-media assignments by expertise (do these after your modules work)

Full details, templates and drafts are in `SUBMISSION_PACK.md`.

| Person | Code modules | Submission-media items (SUBMISSION_PACK section 1 numbers) |
|---|---|---|
| **Ayesha** | Web app / UI; Report + remediation | #1 repo polish, #2 README assembly, #10 pitch deck, #11 video lead + editing, #12 screenshots, #13 LabLab text, #15 launch post, #16 team contributions |
| **Sohaib** | API + orchestration; QA checks | #7 demo store + seed data, #8 API overview + curl examples, input to deck slide 10 and video segment 1:20–1:55 |
| **Sarah** | Agent planner; Verifier + scoring | #9 AI section + false-positive results table, #14 Q&A prep (with Arslan), deck slides 5 and 9, video segments 0:45–1:20 and 1:55–2:30 |
| **Arslan** | Sandbox executor; Security checks; Policy + audit; Vultr deployment | #3 architecture diagram, #4 SECURITY.md + containment policy, #5 Vultr write-up, #6 live demo uptime, #14 Q&A prep, deck slides 6, 7, 8, video segment 2:30–3:05 (containment moment) |

Rules for media work:
- Only describe what actually works in the deployed demo; unfinished ideas go under Roadmap.
- Use real screenshots and real numbers from the demo store.
- Pull content from the brief and the actual code, not from memory of the spec.
- When a deliverable is finished, update its status box in `SUBMISSION_PACK.md` section 1 and list it in your handoff note.

**Project finished means:** all modules merged, full scan flow works on the Vultr-deployed demo, all SUBMISSION_PACK deliverables ticked, the final checklist in `SUBMISSION_PACK.md` section 9 is fully checked, and the LabLab form is submitted.
