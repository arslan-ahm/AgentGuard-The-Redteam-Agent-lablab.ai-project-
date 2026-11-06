# AgentGuard — Team Setup Guide (5 minutes)

The pack has five core files (plus the Claude Code tooling listed under Option B):
- `PROJECT_BRIEF.md` — full spec, roster, contracts, module playbooks, standards, workflow, media assignments
- `SUBMISSION_PACK.md` — pitch deck, demo video script, README template, LabLab text, Q&A prep, finish-line plan
- `PROJECT_INSTRUCTIONS.md` — the one paragraph to paste into the Claude Project
- `CLAUDE.md` — auto-start file for Claude Code in the repo
- `SETUP_GUIDE.md` — this file

## Option A — Claude Project (shared, easiest)

1. In Claude, go to **Projects -> Create project**. Name it `AgentGuard`.
2. **Add `PROJECT_BRIEF.md` and `SUBMISSION_PACK.md` to the project's knowledge/files.**
3. Open **Project instructions** and paste the paragraph from `PROJECT_INSTRUCTIONS.md`.
4. **Share the project with the team** if your plan supports sharing. Otherwise each teammate creates their own project and repeats steps 1–3 (about two minutes, same files).
5. Each teammate opens a **new chat inside the project**, types `start` (or just their name), and answers the name question. Claude identifies their modules and starts, then moves on to their deck/video/README items when the code is done.

Tips:
- One chat per module task keeps context clean. When a chat gets long, ask "Write the handoff note", then start a new chat.
- In a Project chat Claude gives you code and files to copy into the repo. To have it write directly into the repo, use Option B.
- When either brief file changes, re-upload it to everyone's project. Only Arslan and Sarah approve changes.

## Option B — Claude Code (writes directly into the repo)

1. Commit the whole repo root, including the `.claude/`, `.github/` and `docs/` folders, and push it to the shared GitHub repo.
2. Each teammate clones the repo and runs `claude` in it (or opens it in the VS Code Claude extension).
3. The first time, Claude Code asks whether to trust the folder and run its project hook. Accept: the `SessionStart` hook in `.claude/settings.json` is what makes Claude ask for your name.
4. Type anything (e.g. `hi`) and Claude replies "Welcome to AgentGuard. What's your name?". Or skip the question with `/start <your name>`.
5. Claude reads the brief and your latest note in `docs/handoff/`, confirms your modules and starts. At the end, type `/handoff` to save your handoff note.

What's in the repo for this:
- `CLAUDE.md`: auto-loaded instructions (the name question, roster, hard rules)
- `.claude/settings.json` + `.claude/session-start.txt`: the session-start hook; also blocks Claude from reading `.env`
- `.claude/commands/start.md`, `handoff.md`: the `/start` and `/handoff` commands
- `.github/pull_request_template.md`: PR checklist (brief sections 7 and 11)
- `docs/change-requests/`: CR template (brief section 8)
- `docs/handoff/`: handoff notes (brief section 9)

Personal overrides go in `.claude/settings.local.json` or `CLAUDE.local.md`. Both are gitignored.

## Roster -> work

| Name | Code modules | Submission media |
|---|---|---|
| Ayesha | Web app / UI, Report + remediation | README, pitch deck, video lead, screenshots, LabLab text, launch post |
| Sohaib | API + orchestration, QA checks | Demo store + seed data, API docs, curl examples |
| Sarah | Agent planner, Verifier + scoring | AI section + eval table, Q&A prep, deck slides 5 and 9 |
| Arslan | Sandbox executor, Security checks, Policy + audit, Vultr deployment | Architecture diagram, SECURITY.md, Vultr write-up, live demo uptime, containment segment |

## Schedule (D = LabLab deadline)

D-4 end-to-end stub flow works · D-3 real components merged and deployed · D-2 feature freeze · D-2 to D-1 three clean full runs, record video, finalize deck · D-1 README clean-clone test and submission text · D-0 submit at least 3 hours early. Details and the final checklist are in `SUBMISSION_PACK.md` section 9.

## Merge flow

Author opens a PR; once CI is green the author merges it. No review approval is required. Contract changes use the change-request process in brief section 8.
