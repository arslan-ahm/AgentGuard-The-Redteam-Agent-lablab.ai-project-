# Ayesha's submission media

Brief section 17 / `SUBMISSION_PACK.md`. Items: #1 repo polish, #2 README, #10 pitch deck, #11 demo
video (lead + edit), #12 screenshots, #13 LabLab text, #15 launch post, #16 team contributions +
known limitations, and reviewing #14 Q&A prep.

Only claim what works in the deployed demo. Anything marked _(after deploy)_ gets confirmed on the
live site before it is published.

| # | Item | Where | Status |
|---|---|---|---|
| 1 | Repo polish | [`LICENSE`](../../LICENSE) (MIT), license badge in README | License done. Before submission: make the repo public and run a secret scan of the history |
| 2 | README | [`README.md`](../../README.md) | Ethics and scope, team contributions, known limitations, license added. Still to come: live demo URL + demo login, video link, slides link _(after deploy)_, clean-clone run-through |
| 10 | Pitch deck | below (outline) | Outline and design rules ready. Slides 5–9 content from Sarah and Arslan is in their media docs. Build once real screenshots exist |
| 11 | Demo video | below (my segments) | Script ready. **Blocked:** needs the live demo and the merged web app |
| 12 | Screenshots | below (shot list) | Shot list ready. **Blocked:** needs a real scan on the live demo |
| 13 | LabLab text | below | Draft ready; fill the links _(after deploy)_ |
| 15 | Launch post | below | Draft ready; fill the links _(after deploy)_ |
| 16 | Team contributions + known limitations | README sections | Done; teammates check their own line |
| 14 | Review Q&A prep | `docs/submission/arslan-media.md`, `sarah-media.md` | To review |

---

## LabLab submission text (#13)

**Project title:** AgentGuard: Autonomous AI Security & QA Engineer

**Short description (one line):**
AgentGuard tests your web app before your users do: real browser QA and safe security checks in
disposable sandboxes, with evidence for every finding and a clear release decision.

**Long description:**
Teams ship broken checkouts, leaked error details and weak security headers because QA and
security reviews are slow, manual and separate. With AgentGuard you enter a URL, confirm you are
authorized to test it, and pick a profile (Smoke, QA, Security or Full audit). An AI planner on
Vultr Serverless Inference builds a test plan from a fixed list of safe checks. Each check runs in
its own locked-down Playwright container on a Vultr VM and is deleted afterwards. A verifier
re-checks findings, removes duplicates and sets a confidence; low-confidence items go to a manual
review list instead of the score. The result is a release score with a decision (Block release,
Fix first or Safe to ship), and every finding comes with a screenshot, request evidence,
reproduction steps and a suggested fix. Containment comes first: non-root containers with CPU,
memory and time limits, private-network and cloud-metadata access blocked, secrets redacted before
anything reaches the model, a hash-chained audit log, and human approval before any report or
GitHub issue leaves the system. You can watch it happen: when a test tries to reach an internal
address, the scan shows a red "Blocked by policy" alert and the sandbox is destroyed.

**How we use Vultr:** see Arslan's form text in `docs/submission/arslan-media.md` (region, VM size
and model filled in _(after deploy)_).

**Tech tags:** Vultr, Vultr Serverless Inference, Docker, Playwright, Python, FastAPI, React,
TypeScript, PostgreSQL, Redis, AI agents, security, QA automation.

**Links:** repo · live demo _(after deploy)_ · demo login _(after deploy)_ · video · slides PDF.

**Cover image:** 16:9 report page with the decision banner (shot 7 below).

> Before submitting, check every sentence above against the live demo. If something doesn't work
> there, cut it (for example, drop "GitHub issue" from the approval sentence if approvals still
> only record the decision, and say so).

---

## Launch post (#15)

> We built **AgentGuard** for the LabLab × Vultr hackathon: an AI QA and security engineer that
> runs real browser tests in disposable Vultr sandboxes and gives you a release decision backed by
> evidence. Every finding has a screenshot, repro steps and a fix. Unsafe actions get blocked and
> the sandbox destroyed, live on screen. Nothing is sent without human approval.
>
> 🎥 Demo: <video link> · 💻 Code: <repo link> · 🌐 Try it: <demo link>
>
> #LabLab #Vultr #AI #Security #QA

Short version (X / 280 chars):

> AgentGuard: an AI QA + security engineer that tests your web app in disposable @Vultr sandboxes
> and returns a release decision with proof. Containment first, human approved. Built for
> #LabLab. Demo: <link>

---

## Pitch deck (#10): outline and design

Format: a Slides artifact (fallback: .pptx) plus a PDF copy in `docs/`. 16:9, 12 slides, one message
per slide, real screenshots only.

Look (same as the web app): dark canvas `#0b0e14`, cyan accent `#2dd4e8` for the brand and one
highlight per slide, verdict colours only for verdicts (red Block release, amber Fix first, green
Safe to ship), Space Grotesk for text, JetBrains Mono for URLs and code. No stock photos, no
emoji, Lucide-style line icons only.

| # | Slide | Content source | Visual |
|---|---|---|---|
| 1 | Title | Pitch line + team | Report page screenshot (shot 7) |
| 2 | Problem | SUBMISSION_PACK §2 | 4 line icons: broken checkout, stack trace, missing header, inaccessible form |
| 3 | Solution | URL in, decision out | New scan form (shot 2) → report banner (shot 7) |
| 4 | Live demo moment | Score + decision | Decision banner crop |
| 5 | How it works | Sarah (`sarah-media.md`) | 6-step pipeline |
| 6 | Architecture | Arslan (`arslan-media.md`) | `docs/architecture-diagram.png` |
| 7 | Why Vultr | Arslan | Three tiles |
| 8 | Containment first | Arslan | Containment alert screenshot (shot 6) |
| 9 | AI agents | Sarah | False-positive eval table |
| 10 | Evidence-backed findings | Sohaib data + my screenshot | Finding page (shot 5) |
| 11 | Business value + roadmap | SUBMISSION_PACK §2 | 3 columns, roadmap clearly marked "future" |
| 12 | Team + links | README team table | QR codes for repo, demo, video |

---

## Demo video (#11): my segments

Record at 1080p in the **dark theme**, browser zoom 125%, clean profile, no bookmarks bar, never in
mock mode.

| Time | On screen | Narration |
|---|---|---|
| 0:00–0:20 | Title card, then the demo store's checkout failing | "Every release ships with bugs and security holes nobody caught. AgentGuard tests your web app before your users do." |
| 0:20–0:45 | New scan: type the demo store URL, pick Full audit, tick the authorization box, Start scan | "I give AgentGuard a URL and choose a Full audit. It only runs safe, non-destructive checks, on sites I'm authorized to test." |
| 3:05–3:30 | Report page: decision banner, score, prioritized fixes; open the approval dialog | "The result is a clear release decision with proof. Nothing is sent or filed without a human approving it." |
| 3:30–3:50 | Slide 12 with links | "AgentGuard: real execution, verifiable evidence, containment first. Built on Vultr." |

Editing: captions for key terms, the architecture diagram for ~5 s over the planning scene, music
low or none, export MP4 H.264, keep a local backup.

---

## Screenshot set (#12)

Store in `docs/screenshots/`, PNG. Desktop at 1440×900, dark theme, real scan of the demo store on
the live demo (never mock mode: no "Mock data" tag in the header).

| # | File | Screen | What must be visible |
|---|---|---|---|
| 1 | `01-dashboard.png` | Dashboard | Several scans with scores and decisions, KPI tiles |
| 2 | `02-new-scan.png` | New scan | URL filled, Full audit selected, authorization ticked |
| 3 | `03-live-progress.png` | Scan page mid-run | Stage stepper, task bar, activity feed streaming |
| 4 | `04-findings.png` | Scan page findings | Severity tags, category filter |
| 5 | `05-finding-evidence.png` | Finding page | Screenshot evidence, repro steps, suggested fix |
| 6 | `06-containment.png` | Scan page | Red "Blocked by policy" alert + "Sandbox destroyed" + blocked feed row |
| 7 | `07-report.png` | Report page | Decision banner and score (also the 16:9 cover, 1920×1080) |
| 8 | `08-approval.png` | Approval dialog | GitHub issue preview |
| 9 | `09-mobile-scan.png` | Scan page at 375 px | Optional, shows responsiveness |
