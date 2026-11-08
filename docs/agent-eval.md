# Verifier eval: false positives before and after

Owner: Sarah (brief 6.7, SUBMISSION_PACK item 9). Run on 2026-11-08.

## Method

1. **Real check output.** All 18 real check modules ran in real Chromium against the local demo store (`scripts/agent-eval/run_checks.py`). The harness uses the sandbox runner's own `execute()`, but leaves out the network guard, because that guard rightly refuses `127.0.0.1`. For that reason the harness refuses any other target.
2. **Labels.** Every finding is labelled against the demo store's planted-flaw table (`scripts/demo-store/README.md`). Four real issues the table doesn't list were confirmed by hand with `curl`: the `sid` value reflected raw into links, `Server: Werkzeug/3.1.9`, missing `X-Content-Type-Options`, and missing `Referrer-Policy`. Labels live in `scripts/agent-eval/ground_truth.json`.
3. **Before vs after**, on the same input:
   - **Before** is the old default: confidence ≥ 0.5, nothing re-checked.
   - **After** is `EvidenceVerifier` (evidence re-check, severity guide, dedupe), with no LLM.
4. **Injected faults.** Six realistic false positives or duplicates, built from the real run, are added to the real findings, then both runs are repeated.

```bash
cd scripts/demo-store && uv run python app.py                                   # terminal 1
uv run --project sandbox-worker python scripts/agent-eval/run_checks.py --work .agent-eval
cd backend && PYTHONPATH=. uv run python ../scripts/agent-eval/eval_verifier.py --work ../.agent-eval
```

## Results

### Real run

- Findings produced by the checks: **13**: 9 match a planted flaw, 4 are real but unlisted, **0 false positives**.
- Planted flaws found: **9 of 16**. Missed: console_error, contact_500, missing_script, no_https, no_login_limit, reflected_search, stack_trace (see "What the eval found" below).

| | Before (confidence rule only) | After (EvidenceVerifier) |
|---|---|---|
| Findings that count toward the score | 13 | 13 |
| Marked `verified` (evidence re-checked) | 0 | **13** |
| True findings lost | 0 | **0** |
| Severity corrected to the brief 5.11 guide | 0 | 1 (open redirect: medium → high) |
| Release score | 19 (Block release) | 12 (Block release) |

### With 6 injected faults

| Fault | Before | After |
|---|---|---|
| Evidence never written (task 99 never ran) | counted | needs manual review (not scored) |
| Stack-trace claim on a page the check never recorded | counted | needs manual review |
| Claim on a page the check recorded as skipped | counted | needs manual review |
| Duplicate from a retried task | counted | merged into the original |
| No evidence and no reproduction steps | counted | needs manual review |
| `/backup.zip` exposure the evidence doesn't show | counted | needs manual review |

- **Faults that reached the score: 6 of 6 before, 0 of 6 after.**
- Real findings lost to review or merging: **0**.
- Release score: 0 before (the faults drag it down), 12 after. 12 is exactly the score of the real findings alone.

## What the eval changed in the verifier

The first version used small penalties. The eval showed that 4 of the 6 faults still reached the score: a check reporting 0.95 confidence minus 0.25 is still 0.7. The rule is now: **a claim the evidence does not back is capped at 0.45**, below the 0.5 threshold, so it can only go to manual review. The optional LLM opinion applies only to findings the evidence already backs, so it can't rescue an unbacked claim.

The eval also showed that checks record a page load *and then* a "skipped" record when there was nothing to test (no form, no search box). A skip record now outweighs the page-load record.

## What the eval found in the checks (for Sohaib and Arslan)

| Missed flaw | Likely cause | Fix |
|---|---|---|
| contact_500 | `qa.forms` tested only `/` and recorded "no testable POST form found" | The planner should pass `{"path": "/contact"}`. The LLM planner can; the fallback plan has no paths |
| console_error, missing_script | `qa.console_network_errors` only loaded `/`; the flaws are on `/about` | Same: a `path` param, or let the check follow nav links |
| stack_trace | `security.error_leak` doesn't trigger the POST to `/checkout` that leaks | Check owner (Arslan) |
| reflected_search | Found the `sid` reflection on `/` first and stopped; `/search?q=` wasn't probed | Check owner (Arslan) |
| no_login_limit | `login_rate_probe` passed although the store has no lockout | Check owner (Arslan) |
| no_https | Local run on plain HTTP and a non-default port, which the check skips by design | Expected; re-run on the deployed demo |

## Limits

- One target (the demo store), 13 real findings. Small, but every label was checked by hand.
- The faults are synthetic. They model failures we expect (crashed tasks, retries, skipped pages, hallucinated claims), not ones observed in production.
- The LLM part of the planner and verifier is not in this eval: no Vultr Serverless Inference key was available. Its behaviour is covered by unit tests with a scripted model.
