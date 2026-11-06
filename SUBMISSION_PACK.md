# AgentGuard — SUBMISSION_PACK.md

Everything needed for the LabLab hackathon submission beyond the code: deck, demo video, README, submission text, screenshots, Q&A prep, and the final freeze checklist. Each owner's Claude produces their own items after their module works (see PROJECT_BRIEF.md section 17).

Rule: **every claim in the deck, video and README must be true of the deployed demo.** Do not describe features that are not working. Put unfinished items under "Roadmap".

---

## 1. Deliverables, owners, status

| # | Deliverable | Owner (does the work) | Reviewer | Status |
|---|---|---|---|---|
| 1 | Public GitHub repo, clean history, MIT/Apache license | Ayesha | Arslan | [ ] |
| 2 | README (template in section 5) | Ayesha | Sarah | [ ] |
| 3 | Architecture diagram (`docs/architecture-diagram.png`) | Arslan | Sohaib | [ ] |
| 4 | `SECURITY.md` + `docs/containment-policy.md` | Arslan | Sarah | [ ] |
| 5 | Vultr integration write-up (README section) | Arslan | Sohaib | [ ] |
| 6 | Live demo URL + demo credentials, uptime-checked | Arslan | Sohaib | [ ] |
| 7 | Flawed demo store, reproducible (`scripts/demo-store/`) + seed data | Sohaib | Sarah | [ ] |
| 8 | API overview + curl examples (README section) | Sohaib | Arslan | [ ] |
| 9 | AI section: planner/verifier explanation, prompts, fallback, false-positive results table | Sarah | Arslan | [ ] |
| 10 | Pitch deck (section 2) | Ayesha (content from all) | Sarah | [ ] |
| 11 | Demo video 3–4 min (section 3) | Ayesha (lead), all record their segments | Arslan, Sarah | [ ] |
| 12 | Screenshots set (section 6) | Ayesha | Sarah | [ ] |
| 13 | LabLab submission text (section 4) | Ayesha | all | [ ] |
| 14 | Q&A prep (section 7) | Sarah + Arslan | Ayesha | [ ] |
| 15 | Social/launch post (section 8) | Ayesha | Sarah | [ ] |
| 16 | Team contributions + known limitations | everyone adds own lines | Ayesha | [ ] |

---

## 2. Pitch deck (12 slides, 16:9)

Format: build as a Slides artifact if available in the session; otherwise a .pptx (pptx skill) and export a PDF copy into `docs/`. Style: dark security theme, one message per slide, real screenshots over stock images, large text.

| # | Slide | Content | Visual |
|---|---|---|---|
| 1 | Title | AgentGuard: Autonomous AI Security & QA Engineer. Pitch line. Team names. | Logo + hero screenshot of report |
| 2 | Problem | Teams ship broken checkouts, leaked stack traces, weak headers, inaccessible pages. QA and security are slow, inconsistent, separate. | 3–4 pain icons |
| 3 | Solution | Submit a URL, get a release decision backed by real browser execution and evidence. | Input URL -> Report flow |
| 4 | Live demo moment | "Block release / Fix first / Safe to ship" with score. | Screenshot of report banner |
| 5 | How it works | Plan -> Sandbox -> Playwright run -> Verify -> Score -> Report -> Human approval. | 6-step pipeline |
| 6 | Architecture | Web app + API, DB, queue, Vultr Serverless Inference, disposable Docker Playwright sandboxes. | `architecture-diagram.png` |
| 7 | Why Vultr | VM hosts app, API, DB and workers; Serverless Inference does planning and verification; fast disposable compute for sandboxes. State exactly what is used. | Vultr components diagram |
| 8 | Containment-first | One container per task; CPU/mem/pid/time limits; non-root; no Docker socket; egress blocked to private IPs and metadata; credentials never reach the LLM; immutable audit log. | Screenshot of "Blocked by policy" event |
| 9 | AI agents | Planner (structured plans, deterministic fallback), Verifier (re-check, dedupe, confidence). Prompt-injection defense. Results table from Sarah's eval. | Before/after false-positive numbers |
| 10 | Evidence-backed findings | One finding card: screenshot, network summary, repro steps, fix. | Finding card screenshot |
| 11 | Business value + roadmap | Who buys: product/QA/security teams, agencies, startups pre-launch. Roadmap: CI/CD integration, more profiles, auth flows, scheduled scans. Mark clearly as future work. | Simple 3-column roadmap |
| 12 | Team + links | Ayesha, Sohaib, Sarah, Arslan with roles; repo URL; live demo URL; video link; QR code. | QR codes |

Speaker notes: 2–3 sentences per slide, max 20 seconds each. Sarah's Claude drafts slides 5, 9; Arslan's slides 6, 7, 8; Sohaib's slide 10 data and demo store; Ayesha assembles and designs.

---

## 3. Demo video (target 3:30, hard max 4:00)

Record at 1080p, clean browser profile, zoom 125%, hide bookmarks and notifications, audio recorded separately or with a good mic. Do a dry run twice. Keep a pre-run scan result ready as a fallback, but show a real live scan.

| Time | Scene | On screen | Narration (draft) | Who |
|---|---|---|---|---|
| 0:00–0:20 | Hook | Title + broken checkout clip | "Every release ships with bugs and security holes nobody caught. AgentGuard red-teams your web app before your users do." | Ayesha |
| 0:20–0:45 | Start scan | New Scan form: demo store URL, Full Audit, authorization checkbox | "I give AgentGuard a URL and choose a Full Audit. It will only run safe, non-destructive checks on sites I'm authorized to test." | Ayesha |
| 0:45–1:20 | Planning + sandbox | Live progress: planning, sandbox launched | "The planner, running on Vultr Serverless Inference, builds a test plan. Each task launches in a fresh Docker sandbox on a Vultr VM." | Sarah |
| 1:20–1:55 | Real execution | Playwright running checkout and login, events streaming | "These are real browser tests: checkout, login, forms, links, console errors." | Sohaib |
| 1:55–2:30 | Findings + evidence | Findings list; open leaked stack trace: screenshot, network summary, repro steps, fix | "Every finding comes with a screenshot, request evidence, reproduction steps and a suggested fix. The verifier re-checks each one to cut false positives." | Sarah |
| 2:30–3:05 | Containment moment | Trigger private-network request; red "Blocked by policy"; sandbox destroyed; audit log entry | "Now an unsafe action: a request to an internal address. The policy engine blocks it, logs it immutably, and destroys the sandbox." | Arslan |
| 3:05–3:30 | Report + decision | Report page: score, prioritized fixes, "Fix before release"; approval dialog for GitHub issue | "The result is a clear release decision. Nothing is sent or filed without human approval." | Ayesha |
| 3:30–3:50 | Close | Slide 12 with links | "AgentGuard: real execution, verifiable evidence, containment first. Built on Vultr." | Ayesha |

Shot list extras: 5 seconds of architecture diagram over the planning scene; captions on for key terms; background music low or none; export MP4 H.264; upload to YouTube (unlisted is fine unless the form needs public) and keep a local backup copy.

---

## 4. LabLab submission text (trim to the form's limits)

**Project title:** AgentGuard — Autonomous AI Security & QA Engineer

**Short description:** AgentGuard safely red-teams your web app before users do: it runs real Playwright QA and security checks in disposable Vultr sandboxes and returns evidence-backed, fix-ready reports with a clear release decision.

**Long description (draft, edit to match what ships):**
Teams ship broken forms, failed checkouts, leaked error details and weak security headers because manual QA and security reviews are slow, inconsistent and separate. AgentGuard lets a user submit a URL and pick a profile (Smoke, QA, Security, Full Audit). An AI planner running on Vultr Serverless Inference creates a structured test plan. Each task runs in a fresh, resource-limited Docker sandbox on a Vultr VM using Playwright, capturing screenshots, console logs and network evidence. A verifier re-checks findings to reduce false positives, assigns confidence and severity, and calculates a release score that maps to "Block release", "Fix first" or "Safe to ship". Every finding includes reproduction steps and a suggested fix. Containment comes first: non-root containers, CPU/memory/time limits, blocked private-network and metadata access, credentials never exposed to the LLM, an immutable audit log, and human approval before any GitHub issue or report is sent. Scope is deliberately limited to safe, non-destructive checks on targets the user is authorized to test.

**How we use Vultr:** (Arslan fills with exact facts) VM size and region, Docker Compose deployment, Serverless Inference model used for planning and verification, how sandbox workers run on the VM.

**Tech stack tags:** Vultr, Vultr Serverless Inference, Docker, Playwright, Python, FastAPI, React, PostgreSQL, Redis, AI agents, security, QA automation.

**Links:** GitHub repo, live demo URL, demo credentials, video URL, slides PDF.

**Cover image:** 16:9 screenshot of the report page with the decision banner (Ayesha).

---

## 5. README template (Ayesha fills; each owner supplies own section)

```
# AgentGuard
<pitch line> | badges: license, build

[Live demo](URL) · [Demo video](URL) · [Slides](URL)
Demo login: <user> / <password>   (demo store target: <URL>)

## Problem / Solution
## Demo (GIF or screenshot of report)
## Features (QA, Security, Containment, Human approval)
## Architecture (diagram + 5-line explanation)
## How Vultr powers AgentGuard   <- Arslan: VM, Serverless Inference, sandbox workers, region
## Sandbox containment design    <- Arslan: controls table + link to docs/containment-policy.md
## AI agents                     <- Sarah: planner, verifier, fallback, prompt-injection defense, eval results
## Security testing ethics and scope  (authorized targets only, safe checks, out of scope list)
## Local setup (prereqs, clone, cp .env.example .env, docker compose up, open URL, run demo scan)
## Environment variables (table from .env.example)
## API overview (endpoint table + 2 curl examples)  <- Sohaib
## Running tests
## Project structure
## Team contributions (one line each)
## Known limitations (honest list)
## License
```
README must work from a clean clone: Ayesha (or a teammate who didn't write the code) follows it verbatim on a fresh machine before submission.

---

## 6. Screenshots and assets (store in `docs/screenshots/`)

1. Dashboard with several completed scans and scores.
2. New Scan form (URL, profile, authorization checkbox).
3. Live progress view mid-scan.
4. Findings list with severity badges.
5. One finding detail with evidence, repro steps, fix.
6. Containment moment: "Blocked by policy" + audit log entry.
7. Final report with decision banner.
8. Approval dialog.
9. Architecture diagram (PNG + source file).
10. Logo/wordmark (simple, SVG) and 16:9 cover image.

---

## 7. Judge Q&A prep (Sarah + Arslan draft answers, everyone reads)

- **Is this just a vulnerability scanner?** No: it executes real browser workflows (checkout, login, forms) and combines QA and safe security checks with evidence and verification.
- **How do you prevent it being used to attack sites?** Authorization attestation recorded in the audit log, safe non-destructive checks only, rate limits, no exploitation or brute force, private networks blocked.
- **What if the LLM hallucinates findings?** Findings come from deterministic checks with captured evidence; the verifier re-checks them; low-confidence items go to manual review.
- **What if the target page contains prompt injection?** Page content is treated as untrusted data, truncated and redacted; plans may only use whitelisted check IDs.
- **How is the sandbox contained?** List of controls (section 12 of the brief) plus the live containment demo.
- **How is Vultr used and why?** Exact components; fast disposable compute for sandboxes; Serverless Inference for planning and verification.
- **What happens to credentials?** Short-lived broker injection, never in prompts, redacted from logs.
- **What does it cost to run a scan?** (Sarah measures: tokens per scan and sandbox time on the demo store.)
- **What's next?** CI/CD integration, scheduled scans, richer auth flows, more profiles.
- **Limitations?** Honest list from README.

---

## 8. Launch post (draft)

"We built AgentGuard for the LabLab x Vultr hackathon: an autonomous AI QA and security engineer that runs real Playwright tests in disposable Vultr sandboxes and returns evidence-backed, fix-ready release reports. Containment-first, human-approved. Demo + code: <links> #LabLab #Vultr #AI #Security"

---

## 9. Finish-line plan (work backwards from the deadline D)

| When | Goal |
|---|---|
| D-4 days | Stubs integrated: full scan flow runs end to end on the demo store |
| D-3 days | Real planner, sandbox, checks, verifier all merged; deployed on Vultr with HTTPS |
| D-2 days | **Feature freeze.** Bug fixes, docs, screenshots, deck draft |
| D-2 to D-1 | Run the full flow 3 times on the deployed site from a clean state; record video (2 takes); finalize deck |
| D-1 | README clean-clone test, links check, submission text final, buffer for fixes |
| D-0 morning | Submit on LabLab at least 3 hours before the deadline; verify every link logged out |

Final checklist (all must be true):
- [ ] Demo URL loads over HTTPS from a different network, login works, a scan completes in under about 3 minutes
- [ ] Containment moment triggers reliably
- [ ] Repo public, no secrets in history (run a secret scan), license present
- [ ] README works from a clean clone
- [ ] Video 3–4 minutes, audio clear, uploaded, link tested logged out
- [ ] Deck PDF in repo and linked
- [ ] All submission form fields filled, links tested
- [ ] Backup: local copies of video, deck, a recorded full scan run, and a seeded DB snapshot
- [ ] Demo VM has a restart policy and monitoring so it stays up through judging

Fallbacks: if the LLM is slow, use the deterministic fallback plan; if the live scan is flaky on camera, show a pre-run scan and say so plainly; if deployment breaks, revert to the last tagged release (`git tag demo-ok`).
