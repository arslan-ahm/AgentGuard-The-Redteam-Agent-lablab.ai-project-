## What changed
<!-- One module per PR, under ~400 lines. Branch: feat/<module>-<topic>. -->

Module:
Owner:

## How tested
<!-- Exact commands and their real results. -->

## Contract impact
- [ ] No change to PROJECT_BRIEF.md section 5 contracts
- [ ] Yes. Change request: `docs/change-requests/CR-<n>-<name>.md` (approved by Arslan and Sarah)

## Screenshots (UI changes)

## Definition of Done (brief section 7)
- [ ] Implements the playbook scope and nothing outside it
- [ ] Matches section 5 contracts exactly (validated by tests)
- [ ] Unit tests pass; at least one integration test with a stub of its neighbours
- [ ] Lint and type checks pass (ruff, black, mypy / eslint, tsc)
- [ ] No secrets, no hardcoded URLs, config via env
- [ ] Errors handled; timeouts everywhere network is used
- [ ] Audit events emitted where required
- [ ] Short doc added (module README or ARCHITECTURE.md / docs/)
- [ ] No containment, policy or approval control weakened
- [ ] Reviewer(s) from the brief section 2 table assigned; author does not merge
