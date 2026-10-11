# Exercise

**Practise response until it becomes muscle memory.**

The final stage is cultural. You don't want your team's first incident response to be the real thing. Exercise means tabletop drills, hands-on simulations and testing your undo buttons, so developers and leaders know what to do when the alarms go off.

## Why Exercising Matters

- **For developers**: Run short tabletop scenarios. Test your kill switches. Rotate a token for real and time it. Find out where the runbook breaks.
- **For leaders**: Exercises give you confidence that the organisation can respond under pressure, beyond being compliant on paper.

**Key insight:** Exercising builds resilience into people as well as systems. It is also where incident response stops being someone else's job.

## Incident Response Basics

Exercise is where your incident response lives. Before you drill, make sure you have:

- **Named roles**: who leads, who investigates, who communicates, and who has the rights to revoke tokens or unpublish packages
- **Runbooks** for your likeliest scenarios, written by the people who will follow them
- **A communication channel** that still works if your main tools are compromised
- **A reporting path**: who decides whether something is reportable, and how you meet deadlines such as the CRA's 24-hour early warning
- **An evidence habit**: save logs, workflow runs and artefacts before you clean up

NIST SP 800-61 Revision 3 (2025) aligns incident response with the NIST Cybersecurity Framework 2.0 and is a sensible reference.

## Exercise Types

### Tabletop Exercises

Talk through a scenario as a team. No systems are touched.

- **Supply chain compromise**: a dependency you use ships a malicious release
- **Stolen publish token**: someone publishes a version of *your* package
- **Poisoned workflow**: a pull request modifies CI to exfiltrate secrets
- **Leaked cloud or AI API key**: the bill starts climbing
- **The CVE nobody will fix**: a high-severity CVE lands in an end-of-life component you depend on, and there will be no upstream patch. Who notices? Can you upgrade, replace, isolate or buy extended support, and how long does each take? What do you tell customers in the meantime? See [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md).

Good tabletops escalate in stages, ask people to make decisions with incomplete information, and end with an after-action review.

### Developer-Focused Drills

Hands-on drills that test real controls in safe conditions.

- **Secret rotation drill**: revoke and replace a real CI or registry token, and time how long it takes to find every place it was used
- **Canary token drill**: plant a canary credential in a test pipeline, trigger it, and check the alert reaches someone who acts
- **Dependency drill**: publish a benign look-alike or canary package to a **local** registry such as Verdaccio, devpi or a private Nexus. Check whether your tooling, reviewers and alerts catch it.
- **Rollback drill**: redeploy the last known-good artefact by digest
- **Kill switch drill**: flip a feature flag off in production and confirm the effect
- **AI assistant drill**: in a sandbox, see whether an assistant suggests a non-existent package, and whether your checks stop it being installed
- **Scanner disagreement drill**: scan one project with two scanners, such as `osv-scanner` and Trivy. Then scan it again using an application SBOM and an SBOM that includes build tooling. Explain every difference: scope, package identification, database coverage or a genuine miss. Read-only, and safe to run on any project you own. See [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md).

### Safety Rules

- **Never publish test packages to public registries.**
- **Never run real malware.** Use benign canaries and look-alikes in isolated environments.
- **Never use real secrets** as bait. Use canary tokens built for the purpose.
- **Tell the people who need to know**, so a drill isn't mistaken for a real incident.

### Chaos Engineering

- **Dependency outages**: what happens when a registry or mirror is unavailable?
- **Credential loss**: what breaks when a token is revoked mid-deploy?
- **Partial compromise**: can a degraded service keep working safely?

## Running Exercises

### Design

- **Set a learning goal** for each exercise
- **Base scenarios on real incidents**, such as those in the battlecards
- **Include decision points** that force trade-offs
- **Keep the scope small** enough to finish in the time available

### Rhythm

- **Monthly**: 30-minute micro-drills on one procedure, such as token rotation
- **Quarterly**: 90-minute tabletop on a full scenario, with leadership joining for the decisions that need them
- **After every real incident**: rerun the scenario with the fixes in place

### Measure What Matters

- **Time to detect**: from the injected event to someone noticing
- **Time to contain**: from noticing to credentials revoked or artefact pulled
- **Runbook gaps**: steps that were missing, wrong or needed rights nobody had
- **Alert quality**: did the right alert fire, and did it reach the right person?

Feed what you learn back into [Fortify](#stages-03-fortify-md), [Limit](#stages-04-limit-md) and [Expose](#stages-05-expose-md).

## Exercise Checklist

### Getting Started

- [ ] **Name incident roles** and who holds revoke and unpublish rights
- [ ] **Write a runbook** for a stolen publish token
- [ ] **Run a 30-minute token rotation drill**
- [ ] **Set up a local registry** for safe dependency drills

### Building Maturity

- [ ] **Run a quarterly tabletop** based on a recent real incident
- [ ] **Plant canary tokens** and test that alerts reach people
- [ ] **Practise rollback** by artefact digest
- [ ] **Run the scanner disagreement drill** and record what each tool missed
- [ ] **Record lessons learned** and track the fixes to completion

### Advanced Programmes

- [ ] **Include suppliers or downstream users** in a joint exercise
- [ ] **Exercise your CRA reporting path** against the 24-hour deadline
- [ ] **Build scenarios** around your own stack and threat model
- [ ] **Run chaos experiments** on registry and credential failures

## Goal

**Build team muscle memory for security incidents through realistic, safe practice and continuous improvement.**

## Core Activities

- **Tabletop exercises**: practise decisions and coordination
- **Developer drills**: test rotation, rollback, kill switches and alerts for real
- **Incident response readiness**: roles, runbooks and reporting paths
- **Continuous improvement**: measure, learn and feed fixes back into the other stages

## Related Battlecards

Practise your response to specific scenarios:

- [Maintainer Account Takeover](#battlecards-maintainer-account-takeover-md)
- [Jenkins CI/CD Compromise](#battlecards-jenkins-ci-cd-compromise-md)
- [Malicious IDE Extensions](#battlecards-malicious-ide-extensions-md)
- [Developer Review Fatigue and Social Engineering](#battlecards-developer-review-fatigue-and-social-engineering-md)

---

**Previous Stage:** [← Expose](#stages-05-expose-md)

**Framework complete.** You've now worked through all six REFLEX stages.

Return to the [REFLEX overview](#index-md) to see how the stages work together, or explore the [Battlecards](#battlecards-md) to apply the framework to real-world attack scenarios.
