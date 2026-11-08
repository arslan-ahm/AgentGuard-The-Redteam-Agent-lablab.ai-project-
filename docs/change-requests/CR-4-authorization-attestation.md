# CR-4: Record the "authorized to test" attestation on scan creation

- Requested by: Ayesha (Web app / UI)
- Date: 2026-11-07
- Status: implemented on branch `feat/api-attestation` (Arslan's session, 2026-11-08)

## What

Add a required boolean `authorized` to the `POST /scans` body, and record it in the audit log when a scan is created.

## Why

Brief section 13: "Only scan targets the user attests they own or are authorized to test (checkbox + audit record)." The new-scan form has the checkbox, but the frozen `ScanCreate` contract (brief 5.8: `{target_url, profile, credentials_ref?}`) has no field for it, and the API rejects unknown fields (`extra="forbid"`). So today the attestation is enforced only in the browser and never reaches the audit log. That's the record judges will ask about (SUBMISSION_PACK Q&A: "Authorization attestation recorded in the audit log").

## Proposed contract diff

Brief 5.8, `POST /scans` body:

```diff
- {target_url, profile, credentials_ref?}
+ {target_url, profile, credentials_ref?, authorized: true}
```

- `shared/contracts-py`: `ScanCreate.authorized: Literal[True]` (any other value or a missing field is a `422 validation_error`).
- `frontend/src/api/contracts.ts`: `ScanCreate.authorized: true`.
- API (Sohaib): include it in the `scan.create` / first `scan.status` audit event, e.g. `reason: "created by <user>; authorization attested"`.

## Impact (modules, tests, demo)

- API + orchestration (Sohaib): one field, one audit reason change, one test.
- Contracts (Arslan + Sarah approve): both mirrors updated in the same PR.
- Web app (Ayesha): sends `authorized: true` from the checkbox (already required in the form).
- curl examples in `docs/submission/sohaib-media.md` gain the field.
- No change to the sandbox, checks, planner or verifier.

## Stub/mock used meanwhile

The form requires the checkbox before it submits, but sends the current contract body without the field. The UI doesn't claim the attestation is logged.

## Approvals (required: owner of affected module; contract/architecture changes: Arslan AND Sarah)
- [ ] Sohaib (API), <date>
- [x] Arslan, 2026-11-08
- [ ] Sarah, <date>
