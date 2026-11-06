# Contracts

The frozen interfaces are defined in `PROJECT_BRIEF.md` section 5 and implemented in exactly two places:

- Python: `shared/contracts-py/src/agentguard_contracts/__init__.py` (used by `backend/` and `sandbox-worker/`)
- TypeScript: `frontend/src/api/contracts.ts`

`backend/tests/test_contracts.py` checks the Python models against the brief's own examples.

Change them only through a change request (`docs/change-requests/`), approved by Arslan and Ayesha, and update both files in the same PR. After a change, run `uv sync --reinstall-package agentguard-contracts` in `backend/` and `sandbox-worker/`.

Open gaps (the brief doesn't fix these shapes yet; each needs a CR before it's used):
- Response of `POST /auth/login` (token field name)
- Responses of `GET /scans` and `GET /scans/{id}` (progress, score, recommendation fields)
- The Verifier's call signature in `backend/app/interfaces.py`
- The shape of entries in `result.json` `policy_events` (the sandbox placeholder uses audit-event-like dicts)
