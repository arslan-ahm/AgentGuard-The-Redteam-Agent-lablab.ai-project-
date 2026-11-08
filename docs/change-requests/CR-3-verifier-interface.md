# CR-3: Verifier interface and how the orchestrator stores its results

- Requested by: Sarah (Verifier + scoring), work done in the session run by Arslan
- Date: 2026-11-08
- Status: proposed

## What

`app/interfaces.py` says the Verifier's signature is to be agreed through a change request. This CR fixes it as the protocol the orchestrator already uses (`app/orchestrator/verify.py`), unchanged:

```python
class Verifier(Protocol):
    async def verify(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """(confirmed, needs_review). Same ids as the input; may update severity,
        confidence, verified, evidence and reproduction; may merge duplicates by leaving
        them out of both lists; never invents findings."""
```

It also records the orchestrator change needed to use it (`Orchestrator._persist_verification`, Sohaib's module):

- The verifier's decisions are written back to each `FindingRow`: severity, confidence, `verified`, evidence, reproduction and `needs_review`. Before this, only `needs_review` was stored, so the verifier's work was lost.
- A finding missing from both lists was merged into a duplicate. Its row is deleted; the survivor keeps the union of the evidence, so nothing is lost.
- Ids the scan did not produce are ignored.
- One audit event, `verify.done` (actor `agent`), records the counts.

`build_services` wires `EvidenceVerifier(work_root, model)`. `ConfidenceVerifier` stays the default for fakes and tests.

## Why

Brief 6.7: the verifier sets `confidence` and `verified`, adjusts severity and dedupes. Those results must reach the API and the report, not just the score.

## Proposed contract diff

None to brief section 5. `Finding` is unchanged. The verifier protocol moves from "to be agreed" to the shape above.

## Impact (modules, tests, demo)

- Orchestrator: one new method, plus the call that replaces the old `needs_review` loop. Every existing orchestrator test passes unchanged, and there is a new integration test (`test_verifier_results_are_persisted_and_scored`).
- API: `GET /scans/{id}/findings` now returns verified, severity-adjusted, deduplicated findings.
- Score: computed from confirmed findings only, as before.

## Stub/mock used meanwhile

`ConfidenceVerifier` (confidence rule only).

## Approvals (Arslan AND Sarah)
- [x] Arslan, 2026-11-08 (asked for Sarah's modules to be completed)
- [ ] Sarah, <date>
- [ ] Sohaib (orchestrator owner, informed), <date>
