# AgentGuard pitch deck: speaker notes

About 20 seconds per slide. Sources: `ayesha-media.md`, `sarah-media.md` (slides 5, 9),
`arslan-media.md` (slides 6 to 8), `sohaib-media.md` (slide 10), README "Known limitations".
Screenshots on slides 1, 3, 4, 8 and 10 come from the web app's mock mode and are captioned
"UI shown with demo data". Replace them with shots from the live demo once it is deployed.

## 1. Title
AgentGuard tests your web app before your users do. It runs real browser QA and safe security
checks in disposable sandboxes, attaches evidence to every finding, and ends with a clear release
decision. We are Ayesha, Sohaib, Sarah and Arslan.

## 2. Problem
Teams ship broken checkouts, error pages that leak stack traces, weak security headers and
inaccessible forms. QA and security reviews are slow, manual and done by different people, so
these problems slip through right before a release.

## 3. Solution
You give AgentGuard a URL, choose a profile and confirm you are authorized to test the site. It
only runs safe, non-destructive checks, and you get back a score, a verdict and the fixes, each
backed by evidence.

## 4. One clear decision
Every scan ends in one of three decisions: Block release, Fix first or Safe to ship. The score
starts at 100 and drops for each finding by severity, so the verdict is easy to explain: this demo
report has two high, three medium and one low finding, which gives 60, Fix first.

## 5. How it works
You give AgentGuard a URL and a profile. The planner turns it into a test plan, but only from our
whitelist of 18 safe checks, with a fallback plan if the model is down. Each test runs in a real
browser in its own sandbox, and the verifier checks every finding against the evidence before it
reaches your score.

## 6. Architecture
A user submits a URL to the web app. The planner turns it into a test plan, and the worker runs
each test in its own throwaway Playwright container; results come back as evidence and the
container is deleted. The stack is designed for one Vultr VM; it runs locally today and the
deployment is in progress. Approvals are recorded only for now: nothing is sent to GitHub.

## 7. Designed for Vultr
The design puts everything on one Vultr Cloud Compute VM, because owning the Docker engine and the
firewall is what lets us lock each sandbox down at the network level. Planning is built for Vultr
Serverless Inference, so there are no GPUs to manage. Honest status: the deployment is in
progress, the inference client has only been tested with a scripted model, and if the model fails
the built-in fallback plan keeps scans working.

## 8. Containment first
We assume the target site is hostile. Every test gets its own locked-down container with hard
limits and no way into the host, and access to private addresses and the cloud metadata service is
blocked in three separate layers. Every allowed and blocked action lands in an audit log that
detects tampering.

## 9. AI agents you can trust
Findings come from real checks in a real browser, never from the model. The verifier checks every
one against the screenshots and network records the sandbox saved. We ran all 18 checks against
our demo store and added six realistic false alarms: before the verifier all six counted, after it
none did, and no real finding was lost. The LLM was not part of that eval.

## 10. Evidence-backed findings
Each finding has a severity and confidence, exact reproduction steps, the evidence the sandbox
captured and a suggested fix. This example is a stack trace leaked by the checkout error page, one
of the deliberate flaws in our demo store. If the evidence doesn't back a claim, it never touches
the score and goes to manual review instead.

## 11. Who needs it, and what comes next
AgentGuard is for product, QA and security teams before a release, agencies handing sites to
clients, and startups before launch. Everything on the right is future work and not in the demo:
CI/CD integration, authenticated flows, scheduled scans and more profiles, and actually sending
approved GitHub issues and PDF reports.

## 12. Team and links
AgentGuard: real execution, verifiable evidence, containment first. The code is on GitHub; scan
the QR code to open it. The demo video and the live demo link follow once the Vultr deployment is
done.
