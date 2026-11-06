# AgentGuard — CLAUDE.md (auto-loaded by Claude Code at the repo root)

## First reply of every new session (mandatory)
Whatever the user's first message says, your first reply is exactly:

> Welcome to AgentGuard. What's your name?

Skip this only when the first message already names a roster member (e.g. `/start Ayesha` or "I'm Sohaib"). Don't act on any other request until you know who the user is.

## Then
1. Read `@PROJECT_BRIEF.md` and `@SUBMISSION_PACK.md` in full. They are the single source of truth; if anything conflicts, the brief wins.
2. Match the name (case-insensitive) to the roster in brief section 2. If there's no match, ask them to pick one:

   | Name | Modules |
   |---|---|
   | Ayesha | Web app / UI; Report + remediation |
   | Sohaib | API + orchestration; QA checks |
   | Sarah | Agent planner; Verifier + scoring |
   | Arslan | Sandbox executor; Security checks; Policy + audit; Vultr deployment |

3. Check `docs/handoff/` for that person's latest note and continue from its "Next 3 tasks".
4. Confirm their module(s), submission-media items (brief section 17) and first 3 tasks, then start immediately, following brief section 0 (AUTO-START PROTOCOL).
5. When their modules are done, continue into their submission-media items (brief section 17, `SUBMISSION_PACK.md`) until everything assigned to them is finished.
6. End every session with a handoff note in `docs/handoff/<name>-<date>.md` (brief section 9). `/handoff` writes it.

## Hard rules
- Work only on the user's assigned module(s) and media items. Other modules are read-only to you.
- Follow the frozen contracts in brief section 5 exactly. Cross-module or contract changes go through brief section 8: a file in `docs/change-requests/` (template there), approved by Arslan and Sarah. Use stubs meanwhile.
- Tests, docs, and a handoff note (section 9) are part of every task.
- Only describe features in the deck, video and README that actually work in the deployed demo.
- Never commit secrets (`.env` is gitignored; only `.env.example` is committed). Never weaken containment, policy, or approval controls.
- Follow the Git workflow above: branch → checks → push → PR → green CI → merge on GitHub. Small PRs (under ~400 lines).
- Commit as the person running the session, with their own git identity.

## Git workflow (mandatory: nothing is ever committed or pushed to `main`)
1. At session start, run `git config core.hooksPath .githooks` (enables the hooks that block commits and pushes to `main`), then `git fetch origin`.
2. Before writing any code, branch from the latest main: `git switch -c feat/<module>-<topic> origin/main` (types: feat, fix, docs, chore, test, refactor, ci, perf; lowercase). One module per branch. If the branch already exists, switch to it and `git rebase origin/main`.
3. Commit with Conventional Commits (`feat(sandbox): add pids limit`), using the user's own git identity. Never use `--no-verify`, and never bypass or edit the hooks.
4. Run your area's checks (README "Checks") until green, then `git push -u origin <branch>`.
5. Open a PR into `main` with `gh pr create --base main --fill`, filling in the PR template; the title is a Conventional Commit.
6. CI must be green ("CI passed"). Fix failures on the same branch and push again. No review approval is required: once CI is green, the author merges the PR on GitHub. **Never push to `main`, never force-push to someone else's branch.**

## Code layout and commands
- Ownership map and local setup: `README.md`. Frozen contracts in code: `shared/contracts-py` (Python) and `frontend/src/api/contracts.ts` (TS). Never redefine them inside a module.
- Python uses **uv** (`uv sync`, `uv add`, `uv run ...`); the frontend uses **Bun** (`bun install`, `bun add`, `bun run ...`). Don't use pip, npm or npx.
- Before handing off, run your area's checks from `README.md` ("Checks") and paste the real output into the handoff note.
- Day-to-day work needs neither Docker nor Vultr: code against `backend/app/interfaces.py` with fakes. Docker is only for the full stack and the sandbox image.

## Repo tooling for Claude
- `.claude/settings.json`: a SessionStart hook that reminds Claude of the protocol above, and denies reading `.env` files.
- `/start [name]`: begin a session. `/handoff`: write the end-of-session note.
