---
description: Start an AgentGuard work session (identify yourself and begin your modules)
argument-hint: "[your name]"
---

Follow the AUTO-START PROTOCOL in section 0 of @PROJECT_BRIEF.md. Also read @SUBMISSION_PACK.md.

Name given: "$ARGUMENTS"

- If the name above is empty, ask exactly: "Welcome to AgentGuard. What's your name?" and wait for the answer.
- Otherwise match it case-insensitively to the roster in brief section 2 (Sarah, Sohaib, Ayesha, Arslan). If it doesn't match, ask them to pick from the roster.
- Then confirm: role, module(s), reviewer(s), submission-media items (brief section 17), and the first 3 tasks. Then start immediately on the first task.
- Before starting, check `docs/handoff/` for the latest note from this person and continue from its "Next 3 tasks".
- Then set up git as described in "Git workflow" in CLAUDE.md: run `git config core.hooksPath .githooks` and `git fetch origin`, then create or switch to the `feat/<module>-<topic>` branch for the first task. Never work on `main`.
