# CR-2: Response shapes the brief does not spell out (login, scan detail, approvals, report)

- Requested by: Sohaib (API + orchestration)
- Date: 2026-11-06
- Status: proposed

## What

Brief 5.8 fixes the routes and the request bodies but leaves several response bodies open. The API needs concrete shapes to be built and consumed (Ayesha's UI, Arslan's deploy checks). They are implemented in `backend/app/api/schemas.py`, not in the frozen `agentguard_contracts`, until approved. Nothing in section 5 changes.

| Route | Request | Response |
|---|---|---|
| `POST /auth/login` | `{email, password}` | `{access_token, token_type: "bearer", expires_in}` (seconds) |
| `GET /scans`, `GET /scans/{id}` | n/a | `ScanDetail`: `{id, target_url, profile, status, progress: {tasks_total, tasks_done}, score?, recommendation?, summary?, error?, created_at, updated_at}` |
| `POST /scans/{id}/approvals` | brief 5.8 | `{scan_id, action, approved, scan_status, executed}`. `executed` is always `false`: the API records the decision only; filing the issue or sending the report is a separate step |
| `GET /scans/{id}/report?format=json` | n/a | `{scan: ScanDetail, findings: [Finding], needs_review: [Finding]}` |
| `GET /scans/{id}/report?format=md` | n/a | Markdown text. `format=pdf` answers `501 not_implemented` |
| `GET /scans/{id}/events` | n/a | SSE. Event `audit`: an `AuditEvent` (5.9), with `id` = audit sequence number so `Last-Event-ID` resumes. Event `progress`: a `ScanDetail`. The stream closes at a final state |

Behaviours this implies (no contract change, listed so reviewers can object):

- Every route except login needs `Authorization: Bearer <token>`. Scans belong to their creator; other users get `404`.
- `SSE` needs the header, so a browser `EventSource` cannot connect; the web app should use `fetch` streaming.
- `POST /scans` order: URL policy (`403 target_blocked`, scan stored as `blocked`), then rate limit (`429` + `Retry-After`), then queue.
- Containment demo: header `X-AgentGuard-Demo: containment` on `POST /scans` appends the `security.exposed_endpoints` task with `containment_demo: true`. No body field is added.
- Evidence file names in `Finding.evidence` become `<task_id>__<filename>` so they are unique per scan.
- Findings with confidence below 0.5 are excluded from `/findings` and the score and appear in the report's `needs_review` list (brief 6.7).
- Interim pieces until Sarah's modules land: `FakePlanner`, and a local copy of the 5.10 score formula (`backend/app/orchestrator/scoring.py`). The Verifier call signature is still open (see `app/interfaces.py`): the orchestrator uses a local `Verifier` protocol returning `(confirmed, needs_review)`.

## Why

The UI and deploy checks cannot be built against undefined bodies, and inventing them silently inside a module is what section 8 forbids.

## Approval

- [ ] Arslan
- [ ] Sarah
