# AgentGuard — CLAUDE.md (auto-loaded by Claude Code at the repo root)

## First reply of every new session (mandatory)
Whatever the user's first message says, your first reply is exactly:

> Welcome to AgentGuard. What's your name?

Skip this only when the first message already names a roster member (e.g. `/start Sarah` or "I'm Sohaib"). Don't act on any other request until you know who the user is.

## Then
1. Read `@PROJECT_BRIEF.md` and `@SUBMISSION_PACK.md` in full. They are the single source of truth; if anything conflicts, the brief wins.
2. Match the name (case-insensitive) to the roster in brief section 2. If there's no match, ask them to pick one:

   | Name | Modules | Reviewer(s) |
   |---|---|---|
   | Sarah | Web app / UI; Report + remediation | Ayesha |
   | Sohaib | API + orchestration; QA checks | Arslan (API), Ayesha (QA) |
   | Ayesha | Agent planner; Verifier + scoring | Arslan |
   | Arslan | Sandbox executor; Security checks; Policy + audit; Vultr deployment | Ayesha (Sohaib for deployment) |

3. Check `docs/handoff/` for that person's latest note and continue from its "Next 3 tasks".
4. Confirm their module(s), reviewer(s), submission-media items (brief section 17) and first 3 tasks, then start immediately, following brief section 0 (AUTO-START PROTOCOL).
5. When their modules are done, continue into their submission-media items (brief section 17, `SUBMISSION_PACK.md`) until everything assigned to them is finished.
6. End every session with a handoff note in `docs/handoff/<name>-<date>.md` (brief section 9). `/handoff` writes it.

## Hard rules
- Work only on the user's assigned module(s) and media items. Other modules are read-only to you.
- Follow the frozen contracts in brief section 5 exactly. Cross-module or contract changes go through brief section 8: a file in `docs/change-requests/` (template there), approved by Arslan and Ayesha. Use stubs meanwhile.
- Tests, docs, and a handoff note (section 9) are part of every task.
- Only describe features in the deck, video and README that actually work in the deployed demo.
- Never commit secrets (`.env` is gitignored; only `.env.example` is committed). Never weaken containment, policy, or approval controls.
- Use branch `feat/<module>-<topic>`, Conventional Commits, small PRs (the template is in `.github/`). Never merge your own PR.
- Commit as the person running the session, with their own git identity.

## Code layout and commands
- Ownership map and local setup: `README.md`. Frozen contracts in code: `shared/contracts-py` (Python) and `frontend/src/api/contracts.ts` (TS). Never redefine them inside a module.
- Python uses **uv** (`uv sync`, `uv add`, `uv run ...`); the frontend uses **Bun** (`bun install`, `bun add`, `bun run ...`). Don't use pip, npm or npx.
- Before handing off, run your area's checks from `README.md` ("Checks") and paste the real output into the handoff note.
- Day-to-day work needs neither Docker nor Vultr: code against `backend/app/interfaces.py` with fakes. Docker is only for the full stack and the sandbox image.

## Repo tooling for Claude
- `.claude/settings.json`: a SessionStart hook that reminds Claude of the protocol above, and denies reading `.env` files.
- `/start [name]`: begin a session. `/handoff`: write the end-of-session note.
