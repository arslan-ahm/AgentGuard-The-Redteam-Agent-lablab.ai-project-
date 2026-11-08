# Sarah's submission media

Brief section 17 / `SUBMISSION_PACK.md` (seat swapped by CR-1). Items:
- #9 AI section with the false-positive results table
- #14 Q&A prep (AI answers, merged with Arslan's)
- deck slides 5 and 9
- video segments 0:45–1:20 and 1:55–2:30

| # | Item | Where | Status |
|---|---|---|---|
| 9 | AI section + eval table | README "The AI agents", [`docs/agent.md`](../agent.md), [`docs/agent-eval.md`](../agent-eval.md) | Done |
| 14 | Q&A prep (AI) | below, next to Arslan's in [`arslan-media.md`](arslan-media.md) | Done |
| — | Slides 5 and 9 | below | Content and speaker notes, for Ayesha to design |
| — | Video 0:45–1:20 and 1:55–2:30 | below | Script and shot list; recording needs the deployed demo and the UI |

Only claim what works in the deployed demo. Lines marked _(after deploy)_ are true only once `VULTR_INFERENCE_*` is set on the VM. Check the worker log says nothing about "fallback plans only" before recording them.

---

## Deck

### Slide 5: How it works

**Title:** Plan, run, verify, decide

**Visual:** a 6-step pipeline:

URL → AI plan → sandboxed browser tests → verifier → score → human approval

Highlight the two AI steps.

**Bullets (max 3):**
- The AI planner picks checks from a whitelist of 18; it can't invent new ones
- Every test runs in a real browser inside a throwaway sandbox
- The verifier re-checks each finding against saved evidence before it counts

**Speaker notes (about 18 s):** You give AgentGuard a URL and a profile. The planner, on Vultr Serverless Inference, turns it into a test plan, but only from our whitelist of 18 safe checks, with a fallback plan if the model is down. Each test runs in a real browser in its own sandbox. The verifier then checks every finding against the evidence before it reaches your score.

### Slide 9: AI agents you can trust

**Title:** The AI decides what to test, not what is true

**Visual:** a two-column table (the README's eval table):

| | Before the verifier | With the verifier |
|---|:-:|:-:|
| Real findings re-checked against evidence | 0 of 13 | **13 of 13** |
| Real findings lost | 0 | **0** |
| False alarms that reached the score | 6 of 6 | **0 of 6** |

**Bullets (max 3):**
- Planner: whitelisted checks, task caps, one repair round, deterministic fallback
- Verifier: evidence re-check, dedupe, severity guide; unbacked claims never count
- Prompt-injection defence: site text is redacted, fenced data, and every answer is validated

**Speaker notes (about 20 s):** Findings come from real checks in a real browser, never from the model. The verifier checks every one against the screenshots and network records the sandbox saved. We ran all 18 checks against our demo store and added six realistic false alarms. Before the verifier all six counted; after it none did, and no real finding was lost.

**Footnote on the slide:** "Real check output from our demo store plus 6 injected faults. Method: docs/agent-eval.md"

---

## Video segment 0:45–1:20: planning + sandbox (Sarah)

**Setup:** the deployed demo, logged in, the New Scan form submitted for the demo store with Full Audit. The architecture diagram is ready for a 5-second overlay.

| Time | On screen | Voice-over |
|---|---|---|
| 0:45–0:55 | Live progress: **planning** | "First the planner builds a test plan. It runs on Vultr Serverless Inference _(after deploy)_, but it can only choose from our 18 whitelisted checks." |
| 0:55–1:05 | Overlay: architecture diagram (5 s), then the plan's task list | "Each task is one check, with a hard cap per profile. If the model is slow or gives a bad answer, a built-in plan takes over, so the scan always runs." |
| 1:05–1:20 | Progress: **sandbox launched**, the first tasks running | "Every task launches in a fresh Docker sandbox on our Vultr VM, with no access to anything but the site under test." |

**Captions:** "18 whitelisted checks", "Fallback plan if the AI is down", "One sandbox per task".

## Video segment 1:55–2:30: findings + evidence (Sarah)

**Setup:** the same scan, finished. The findings list is open. The checkout stack-trace or failed-checkout finding is the one to open.

| Time | On screen | Voice-over |
|---|---|---|
| 1:55–2:05 | Findings list with severity badges and the **verified** marker | "Here's what it found. Every finding was re-checked by the verifier before it counts." |
| 2:05–2:20 | Open one finding: screenshot, network summary, reproduction steps, fix | "Each one comes with a screenshot, the recorded request, steps to reproduce it and a suggested fix." |
| 2:20–2:30 | Scroll to the "needs manual review" list, or show the confidence value | "If the evidence doesn't back a claim, it never touches your score. It goes to a human for review instead." |

**Captions:** "Verified against evidence", "Repro steps + fix", "No evidence, no score".

**Fallback if the UI isn't ready:** show `GET /api/v1/scans/{id}/findings` in the browser's JSON viewer (`verified: true`, `confidence`), then the evidence file from `GET /api/v1/scans/{id}/evidence/{name}`.

---

## Q&A prep (AI answers)

**What if the LLM hallucinates findings?**
It can't create findings. Findings come only from deterministic checks running in a real browser. The model chooses which checks to run (and can write the summary). The verifier then re-checks every finding against the evidence the sandbox saved, and a claim the evidence doesn't back is capped below the threshold, so it can't affect the score. In our eval, 0 of 6 injected false alarms reached the score.

**What if the target page contains prompt injection?**
Page text is treated as data:
- It's redacted with the same rules as our logs.
- Hidden and bidi characters are stripped.
- It's cut to a fixed size and fenced in tags the page can't close.

More importantly, the model's answer is validated. A plan may only contain whitelisted check ids for that profile, allowlisted params (relative paths, at most 3 login attempts) and no flags like the containment trigger. So an obeyed injection gets rejected, and the fallback plan runs. Summaries with links are thrown away.

**What does the model actually see?**
- **Planning:** the target's scheme, host and path (no credentials, query or fragment), the profile, and the check catalog.
- **Summaries:** each finding's title, severity, category, check and page.
- **Verifier opinions:** one finding's claim and its redacted evidence records.

Never cookies, tokens, passwords or credentials.

**What if the model is down, slow or wrong?**
- Each call has a 20-second timeout and 2 retries, only on connection, timeout, rate-limit or server errors.
- An invalid plan gets one repair round with the exact validation errors.
- After that, the deterministic fallback plan for the profile runs, and the summary falls back to one built from the findings.

A scan never fails because of the model.

**How do you measure false positives?**
We ran all 18 real checks against our demo store. Every finding was labelled against its list of planted flaws, plus 4 real extras confirmed by hand with curl. We then added 6 realistic faults: a crashed task, a claim about a page that was never recorded, a page the check skipped, a duplicate from a retry, a finding with no evidence, and an unbacked endpoint claim. Results: 13 of 13 real findings verified, 0 lost, 0 of 6 faults scored. `docs/agent-eval.md` has the method and the limits (one target, synthetic faults, LLM not in the eval).

**Does the verifier re-request the site?**
No, on purpose. Only the sandbox may talk to a scanned site (containment). The verifier re-checks the responses the sandbox recorded, so a re-check can't become a way out of the sandbox.

**How is severity decided?**
Each check sets a severity. The verifier then clamps it to the range the brief's severity guide gives that kind of issue: an open redirect is high, missing headers are never critical, a failed checkout is at least high. Every range contains every severity the checks themselves emit, so only clear violations change. In the eval, one did: an open redirect went from medium to high.

**What does a scan cost in tokens?** (estimate from prompt sizes, not a billing measurement)
- Plan: about 700 input tokens for a full audit, with output capped at 1,200 tokens.
- Summary: at most about 1,700 input tokens.
- Verifier opinions: only for borderline findings, at most 8 per scan, each at most about 1,300 input tokens.

A typical full audit uses about 2.5k input and 0.6k output tokens. The worst case is about 13k input. Sandbox time is the bigger cost.

**Why not let the LLM find vulnerabilities itself?**
Judges, users and we need to trust the result. Deterministic checks with captured evidence are reproducible and explainable. The model adds judgement where it's safe: what to test, what matters most, and a second opinion on borderline evidence.

**Limitations (AI)**
- The LLM path was tested with a scripted model, not yet against the live Vultr endpoint _(after deploy)_.
- The fallback plans have no page paths, so on the demo store `qa.forms` and `qa.console_network_errors` test only the home page and miss the flaws on `/contact` and `/about`. The LLM planner can pass those paths.
- The eval covers one target.
