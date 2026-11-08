# Sohaib: submission media (DRAFT)

Draft written before the API is finished. Only publish a line in the README, deck or video once it works in the deployed demo (CLAUDE.md hard rule). Verify every endpoint and example against the live API first.

## 1. API overview (README section, SUBMISSION_PACK item 8)

Base path `/api/v1`, JSON, bearer-token auth. Errors always look like `{"error": {"code": "...", "message": "..."}}`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login` | Log in, returns a bearer token |
| POST | `/scans` | Create a scan: `{target_url, profile, authorized: true, credentials_ref?}` returns `{id, status}` |
| GET | `/scans` | List scans |
| GET | `/scans/{id}` | Status, progress, score, recommendation |
| GET | `/scans/{id}/events` | Server-sent events: progress and audit events |
| GET | `/scans/{id}/findings` | List findings |
| GET | `/scans/{id}/evidence/{filename}` | One evidence file (screenshot, network summary) |
| GET | `/scans/{id}/report?format=json\|md\|pdf` | Report export |
| POST | `/scans/{id}/approvals` | Human approval: `{action: "github_issue"\|"send_report", approved: bool}` |
| GET | `/scans/{id}/audit` | Immutable audit log |

Profiles: `smoke`, `qa`, `security`, `full`. Statuses: `queued`, `planning`, `running`, `verifying`, `awaiting_approval`, `completed`, `failed`, `blocked`.

### curl example 0: log in (shape proposed in CR-2)

```bash
TOKEN=$(curl -s -X POST "$AGENTGUARD_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "<demo password>"}' | jq -r .access_token)
# response: {"access_token": "...", "token_type": "bearer", "expires_in": 28800}
```

Rate limits: scans per user and per target host return `429` with `Retry-After`; a blocked target returns `403 target_blocked` and is recorded as a `blocked` scan. Scans are private to the user who created them.

### curl example 1: start a scan

```bash
curl -s -X POST "$AGENTGUARD_URL/api/v1/scans" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"target_url": "https://demo.example.com", "profile": "full", "authorized": true}'
# {"id": "3f0c...", "status": "queued"}
```

### curl example 2: read the findings

```bash
curl -s "$AGENTGUARD_URL/api/v1/scans/$SCAN_ID/findings" \
  -H "Authorization: Bearer $TOKEN"
# [{"title": "Error response leaks an internal stack trace", "severity": "high", ...}]
```

Before publishing: the login and scan-detail bodies are proposed in `docs/change-requests/CR-2-api-response-shapes.md` and need Arslan and Sarah to approve. The examples above were checked against the test suite only, not against the deployed API.

## 2. Slide 10 data: the demo store's deliberate flaws

Source: `scripts/demo-store/README.md`. 15 flaws, 14 distinct checks.

| Flaw | Check |
|---|---|
| Broken link, 404 asset | `qa.links_assets` |
| Console error, failed asset request | `qa.console_network_errors` |
| Missing alt text, unlabeled inputs | `qa.accessibility` |
| Contact form returns HTTP 500 | `qa.forms` |
| Checkout returns HTTP 500 | `qa.checkout` |
| Stack trace shown to visitors | `security.error_leak` |
| No CSP, HSTS or X-Frame-Options | `security.headers` |
| Cookie without Secure, HttpOnly, SameSite | `security.cookies` |
| Session id in the URL | `security.url_session_leak` |
| Open redirect | `security.open_redirect` |
| Reflected unescaped input | `security.reflected_input` |
| Unauthenticated `/admin` | `security.exposed_endpoints` |
| No login rate limit | `security.login_rate_probe` |
| No HTTP to HTTPS redirect | `security.https_redirect` |

## 3. Video segment 1:20 to 1:55 (real execution, voice: Sohaib)

On screen: the live progress view while the sandbox runs the QA and security tasks against the demo store.

| Time | Screen | Voice-over |
|---|---|---|
| 1:20 | Progress view, first tasks turn to "running" | "These are real browser tests, not a chatbot guessing. Playwright opens the store and uses it like a customer." |
| 1:30 | Checkout task fails, red HTTP 500 appears | "Checkout fails with a server error. AgentGuard captures a screenshot and the network trace as evidence." |
| 1:40 | Findings list fills in: stack trace, missing headers, open redirect | "Forms, login, links, console errors, headers, cookies. Each finding has a severity, evidence and steps to reproduce." |
| 1:50 | Counter: tasks done, findings found | "One scan, every check, and nothing leaves the sandbox except evidence." |

Hand-off at 1:55 to the next segment (Arslan, containment).
