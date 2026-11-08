# Agent: planner, verifier and scoring

Owner: Sarah (brief 6.3, 6.7). Code: `backend/app/agent/`.

## Planner (`AgentPlanner`, implements `app.interfaces.Planner`)

```
target URL + profile (+ optional page text)
        │
        ▼
Vultr Serverless Inference (OpenAI-compatible chat API)
        │  answer: {"tasks": [{"check_id", "description", "params"}]}
        ▼
validate_plan_payload ── invalid ──► one repair round with the exact errors
        │                                   │ still invalid / model down
        ▼                                   ▼
contract TestPlan (5.5)            deterministic fallback plan
```

| Rule (brief 6.3) | How it's enforced |
|---|---|
| Only whitelisted check ids | `validate_plan_payload` accepts only `ALLOWED_CHECK_IDS`, and only those of the scan's profile (`catalog.PROFILE_CHECKS`) |
| Max tasks per profile | Smoke 5, QA 12, Security 12, Full 20 (`MAX_TASKS_PER_PROFILE`). The orchestrator checks again |
| Demo never depends on the LLM | `fallback.py`: a fixed plan per profile, used when inference is not configured, errors, times out, or answers invalidly twice |
| Timeouts and retries | `VultrInferenceClient`: 20 s per call, 2 retries with backoff, only on connection, timeout, 429 and 5xx errors. Auth and bad-request errors fail at once |
| LLM never sees credentials | The prompt carries only `scheme://host[:port]/path` of the target (no userinfo, query or fragment), the profile and the catalog |
| Page content is redacted and truncated | `untrusted.py`: Arslan's `redact_text`, control and bidi characters removed, 3,000-char budget |
| Prompt-injection defence | Site text is fenced in `<untrusted_data>` tags the page cannot close. The system prompt says it is data only. Above all, the **output** is validated: a model that obeys an injection still cannot add a check, a param outside the allowlist, a non-relative path, `containment_demo`, a probe marker or more than 3 login attempts |

Task ids (`t1..tN`), timeouts (15–180 s) and the target URL are set by the validator, never by the model.

Allowed params: `path` (relative, same origin) for every check. `paths` (1–10 relative paths) only for `security.exposed_endpoints`, and `attempts` (capped at 3) only for `security.login_rate_probe`.

### Fallback plans

| Profile | Checks |
|---|---|
| Smoke | pages_load, console_network_errors, https_redirect, headers, error_leak |
| QA | all 9 QA checks |
| Security | all 9 security checks |
| Full | all 18 checks |

### Executive summary (`summarize`)

A deterministic summary (counts per severity plus the top 3 issues) is always computed. With inference configured, the model writes 3–5 plain sentences from the findings' title, severity, category, check and page. Each page URL is reduced to scheme, host and path, and the findings are fenced as untrusted data. The answer is rejected in favour of the deterministic summary if it is empty, too long, contains a link or echoes the fence tags.

## Verifier (`EvidenceVerifier`, CR-3)

The verifier never contacts the target. Containment (brief 12) means only the sandbox talks to scanned sites, so each finding is re-validated against the evidence the sandbox saved in `<work_root>/<scan_id>/<task_id>/out/`:

| Step | Rule |
|---|---|
| Evidence check | Every cited file must exist in that task's `out/` (path traversal, symlinks and other scans' files are refused) |
| Response re-check | `network_summary.json` must hold a record for the finding's page that supports it: `leak` for error_leak, `exposed` for exposed_endpoints, `set_cookie` for cookies, `headers`/`status` for headers and https_redirect, any page record for the other checks. A `skipped` record for that page contradicts the finding |
| Unbacked claims | Missing files, no supporting record, a skipped page or no evidence at all cap confidence at **0.45**. Such findings go to "needs manual review" and are never scored |
| LLM judgement (optional) | Only for findings the evidence already backs, with confidence 0.35–0.7, at most 8 per scan. The model sees the claim and the redacted, fenced evidence records and answers `{"supported": true\|false}`, which moves confidence by ±0.15. Anything else changes nothing |
| Severity | Clamped to the brief 5.11 range for each check. Each range contains every severity the check itself emits, so only clear violations change (e.g. open redirect = high, missing headers ≤ medium, checkout failure ≥ high) |
| Dedupe | Same check, same page (or same site for headers and https_redirect), same normalised title. A verified finding represents the group (then the most severe, then the most confident), with the union of the evidence and an "Also seen on" line |
| Verified | `True` only when the evidence exists and backs the claim, and confidence is ≥ 0.5 |

The orchestrator stores all of it on the finding rows, deletes merged duplicates and audits `verify.done` (CR-3).

Measured on real check output from the demo store: 13 of 13 real findings verified, none lost, and 0 of 6 injected false positives reached the score (6 of 6 before). See [agent-eval.md](agent-eval.md).

## Scoring (`app/agent/scoring.py`)

Pure functions of brief 5.10: `compute_score`, `recommend` (0–49 Block, 50–79 Fix first, 80–100 Safe to ship) and `score_breakdown` for the report. Only confirmed findings count. `app/orchestrator/scoring.py` re-exports these, so there is one formula.

## Configuration

`VULTR_INFERENCE_BASE_URL`, `VULTR_INFERENCE_API_KEY`, `VULTR_INFERENCE_MODEL` (brief 5.12). Without all three, the planner logs a warning and uses the fallback plans. `AGENTGUARD_USE_FAKES=1` still selects the fake planner for local development.

## Tests

```bash
cd backend && uv run pytest tests/test_agent_planner.py tests/test_agent_verifier.py tests/test_agent_integration.py
```

The model is a scripted fake, so no test calls the network.
