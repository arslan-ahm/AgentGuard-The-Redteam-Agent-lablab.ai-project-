# CR-1: Swap Sarah's and Ayesha's assignments

- Requested by: Arslan (team lead, Infra + security)
- Date: 2026-11-06
- Status: proposed

## What

Swap everything assigned to Sarah with everything assigned to Ayesha. Sohaib and Arslan are unchanged.

| | Before | After |
|---|---|---|
| **Sarah** | UI + docs + demo: Web app / UI; Report + remediation | AI / agent: Agent planner; Verifier + scoring |
| **Ayesha** | AI / agent: Agent planner; Verifier + scoring | UI + docs + demo: Web app / UI; Report + remediation |

The swap is complete, so it carries everything tied to each seat:

- **Reviewer seat.** "Arslan and Ayesha review every PR" becomes "Arslan and Sarah". Every module Ayesha reviewed (Web app, Sandbox, QA checks, Security checks, Report, Policy) is now reviewed by Sarah. Arslan still reviews the agent modules, now owned by Sarah.
- **Approval rights.** Contract, architecture and brief changes need Arslan AND Sarah.
- **Submission media (brief 17).**
  - Ayesha: repo polish, README assembly, pitch deck, video lead and editing, screenshots, LabLab text, launch post, team contributions.
  - Sarah: AI section and eval table, Q&A prep with Arslan, deck slides 5 and 9, video segments 0:45–1:20 and 1:55–2:30.
- **Ownership comments in code** (`backend/app/agent`, `frontend/src`, module docstrings).

## Why

Team decision by the lead, to match each person's strengths. Nothing has been built yet in either swapped module (only scaffold), so no work changes hands mid-flight.

## Proposed contract diff

None. Section 5 contracts are untouched. Only brief sections 2, 4 (repo tree comments), 6 (playbook headings), 8, 11, 15 and 17 change, plus the same names in `CLAUDE.md`, `README.md`, `SETUP_GUIDE.md`, `SUBMISSION_PACK.md`, `.claude/`, the PR template and owner comments in code.

## Impact (modules, tests, demo)

- No code behaviour changes. Comments and docstrings only.
- Claude sessions route by name: after merge, "Sarah" gets the agent modules and "Ayesha" gets the UI modules.
- Open PRs from before the swap should request Sarah where they would have requested Ayesha.

## Stub/mock used meanwhile

Not applicable.

## Approvals (required under the current brief: Arslan AND Ayesha; both swapped members should agree)
- [x] Arslan, 2026-11-06 (requested)
- [ ] Ayesha, <date>
- [ ] Sarah (agrees to the swap), <date>
