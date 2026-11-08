# AgentGuard web app

Owner: Ayesha (Web app / UI, Report + remediation). React 19 + Vite + TypeScript (strict) + Tailwind v4.

## Run

```bash
bun install
bun run dev        # real API, proxied to http://localhost:8000 (AGENTGUARD_API_URL to change)
bun run dev:mock   # no backend: in-memory mock API with fixture scans
```

In mock mode any email and password sign in (the password `wrong` shows the error state), and a
"Mock data" tag is shown in the header. Fixture data is **not** real scan output: never use it
for screenshots or numbers in the deck, video or README.

## Checks

```bash
bun run test && bun run lint && bun run format:check && bun run build
```

## Layout

| Path | What |
|---|---|
| `src/api/contracts.ts` | Frozen brief section 5 types (change only through a change request) |
| `src/api/schemas.ts` | Response shapes proposed in CR-2 (login, scan detail, approvals, report), mirrored from `backend/app/api/schemas.py` |
| `src/api/client.ts` | `ApiClient` interface + real client (`fetch`, bearer token, 5.8 error shape, timeouts) |
| `src/api/sse.ts` | SSE parser: the events stream needs the `Authorization` header, so it is read with `fetch`, not `EventSource` |
| `src/api/mock/` | Mock client + fixtures implementing the same `ApiClient` |
| `src/auth/` | Session storage (sessionStorage, with an in-memory fallback), `AuthProvider`, `useAuth`, `useApi` |
| `src/app/` | Routes, signed-in layout, route guard |
| `src/components/ui/` | Shared primitives: `Button`, `TextField`, `Alert`, `Spinner` / `LoadingState` |
| `src/components/` | `SeverityLabel`, `StatusLabel`, `DecisionLabel`, empty/error states, page header |
| `src/lib/` | Display helpers (`format.ts`), URL validation, `useAsync`, `useScanEvents` (SSE with resume) |
| `src/features/scan/` | Live progress, activity feed, containment alert, findings list, approval dialog |
| `src/features/evidence/` | Evidence viewer (screenshots, `network_summary.json` table) |
| `src/features/report/` | Decision banner, GitHub issue template, file downloads |
| `src/pages/` | Screens |

## Screens

| Route | Screen |
|---|---|
| `/login` | Sign in |
| `/` | Scans: status, score and decision; refreshes while scans run |
| `/scans/new` | URL, profile, authorization checkbox, optional containment demo |
| `/scans/:id` | Live progress (stages, tasks), red "Blocked by policy" + sandbox destroyed, findings, activity (audit log), human approval |
| `/scans/:id/findings/:findingId` | Finding detail: impact, reproduction steps, suggested fix, evidence |
| `/scans/:id/report` | Decision banner, executive summary, prioritized fixes; Markdown, JSON and PDF (print) export |

## Design tokens ("Sandbox Console")

There is no `DESIGN.md`; the tokens in `src/index.css` (`@theme`) are the spec, based on the
team's Stitch reference. Dark is the default theme; `<html data-theme="light">` switches to light
(set before paint by `public/theme-init.js`, toggled in the top bar). Use the token utilities
(`bg-canvas`, `bg-panel`, `bg-raised`, `border-line`, `text-fg`, `text-fg-muted`, `text-accent`,
`rounded-sm|md|lg`), not raw hex values.

- Cyan (`accent`) is the brand. Amber (`tertiary`) is a rare highlight such as "Recommended".
- Fonts: Space Grotesk (UI) and JetBrains Mono (labels, URLs, logs), bundled from
  `@fontsource-variable/*`, so the production CSP allows them. Small uppercase labels use
  `label-mono` plus a text colour.
- Severity (`critical|high|medium|low` + `-soft`) always shows shape + word + colour
  (`SeverityLabel`). Verdicts use `bad|warn|success` (`components/decisionStyle.ts`).
- Every text/background pair meets WCAG AA in both themes. Controls are at least 44px tall. Icons
  come from `lucide-react` only. Motion respects `prefers-reduced-motion`.
- Phones get a bottom tab bar (Dashboard, New scan).

## Notes for API consumers

- Evidence files need the bearer token, so use `api.fetchEvidence()` and an object URL instead of
  a plain `<img src>`.
- `createScan(body, { containmentDemo: true })` sends `X-AgentGuard-Demo: containment` (CR-2) to
  add the blocked-request task for the containment demo.
- A 401 from any route except login clears the session and returns the user to the login page.
- PDF export uses the browser's print dialog with a light print stylesheet, because the API
  answers `format=pdf` with `501 not_implemented`.
- Approvals only record the decision (`executed: false`); the UI says so after approving.
- The authorization checkbox is required in the form but not yet sent to the API (CR-3).
- Screenshots are shown through `blob:` URLs, so the Caddy CSP allows `img-src blob:`.
