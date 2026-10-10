# Expose 👁️

**Make attacks visible through monitoring and detection.**

Undetected attacks are the most expensive kind. Expose is about building observability and alerts into your systems and your development workflow, so you know when something abnormal happens. Early detection limits damage and speeds recovery.

## Why Detection Matters

- **For developers**: Ship structured logs. Alert on suspicious events in your own workflow, such as an unexpected package publish or a surprise lockfile change. Link every alert to a runbook.
- **For leaders**: Expose provides the evidence regulators and auditors will ask for. What did you see, when did you see it, and what did you do about it? Under the EU Cyber Resilience Act, the clock on a 24-hour early warning starts when you become aware.

**Key insight:** Detection buys time. Teams that notice quickly recover faster, and can show customers they take security seriously.

## Developer-Level Signals

Many supply chain attacks show up first in places developers already look. Make these signals loud.

### Source Control

- **Changes to workflow files** (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`), especially from new contributors or bots
- **New deploy keys, webhooks or GitHub Apps** on a repository or organisation
- **Branch protection or ruleset changes**, and force pushes to protected branches
- **New repositories created** under a user or organisation account. Some worms publish stolen secrets this way.
- **AI-generated pull requests** that add dependencies or touch build configuration

### Dependencies

- **Unexpected lockfile churn**: many packages changing in a PR that claims to do something small
- **New install scripts** (`preinstall`, `postinstall`) appearing in an updated dependency
- **New maintainers** added to a package you depend on, or an ownership transfer
- **Releases without provenance** from a project that normally publishes it
- **Dependencies reaching end of life**, so you know when "no more fixes" begins
- **New dependencies introduced by AI-generated changes**, from assistants, agents or automated fix PRs
- **Attempts to resolve versions that don't exist**: repository manager logs show these failures, and they can be the first sign of a hallucinated AI suggestion
- **Avoidable exposure**: vulnerable versions still in use when a fixed release exists. Sonatype's research found around 95% of vulnerable downloads had a fix available.

### Consumption

- **Downloads that bypass the repository manager**: direct registry traffic from CI or developer machines, and models, wheels or scripts fetched from GitHub, Hugging Face or vendor sites
- **End-of-life footprint** tracked as a metric over time: how many EOL components, in which services, and whether the number is falling

### Registries and Publishing

- **New publish tokens** created on your registry accounts
- **Publishes you didn't plan**: versions released outside your normal release workflow
- **Changes to trusted publishing configuration** or package access settings

### CI/CD Runtime

- **New outbound domains** contacted from CI jobs
- **Secrets accessed by jobs** that don't normally use them
- **Unusual job duration or CPU use**, a common sign of cryptomining
- **Cloud API calls from CI identities** outside their usual pattern

### Cloud and AI Services

- **New IAM users, keys or role trust policies**
- **Resources created in regions** you don't use
- **AI API usage or spend** jumping above its baseline

## Building the Plumbing

### Logging

- **Structured JSON logs** with consistent field names
- **Correlation IDs** across services
- **Security events logged deliberately**: authentication, authorisation decisions and configuration changes
- **Audit logs switched on** for GitHub or GitLab, your registries and your cloud accounts, and kept long enough to investigate

### Alerting

- **Route alerts to where developers already work**, such as the team channel or the on-call rota
- **Every alert has an owner and a runbook**
- **Tune ruthlessly.** An alert nobody acts on is noise, and noise hides attacks.
- **Start with a handful of high-signal alerts** and grow from there

### Tools That Help

- **Dependency monitoring**: Dependabot alerts, Renovate and `osv-scanner` in CI
- **Package behaviour analysis**: tools that flag new install scripts, network calls or obfuscated code in updated dependencies
- **Secret scanning** across repositories and history
- **Canary tokens** planted in CI and developer environments, which alert when someone uses them
- **CI egress monitoring**, such as StepSecurity Harden-Runner for GitHub Actions
- **Cloud audit trails** such as AWS CloudTrail, Azure Activity Log or Google Cloud Audit Logs

If your organisation runs a central security monitoring platform, send these signals there too. Developers still need to see the ones that concern their own code.

## Exposure Checklist

### Immediate Actions

- [ ] **Turn on audit logging** for your source control organisation, registries and cloud accounts
- [ ] **Alert on workflow file changes** and new publish tokens
- [ ] **Enable dependency and secret scanning** alerts
- [ ] **Add structured logging** with correlation IDs

### Medium-term Goals

- [ ] **Flag lockfile churn and new install scripts** in pull requests
- [ ] **Monitor CI egress** for new outbound domains
- [ ] **Plant canary tokens** in CI and developer environments
- [ ] **Watch for new maintainers** and ownership changes on key dependencies
- [ ] **Alert on traffic that bypasses your repository manager**
- [ ] **Report EOL footprint and avoidable exposure** alongside other engineering metrics

### Advanced Detection

- [ ] **Baseline normal CI behaviour** and alert on deviations
- [ ] **Alert on publishes** that didn't come from your release workflow
- [ ] **Track spend anomalies** on cloud and AI services
- [ ] **Write custom detections** for your own threat model

## Goal

**Build visibility into your systems and workflows, so attacks become detectable events instead of silent compromises.**

## Core Activities

- **Developer-level signals**: watch workflows, lockfiles, publishes and maintainers
- **Audit logging**: switch it on everywhere that matters, and keep it
- **Alerting**: route a small set of high-signal alerts to the people who can act
- **Feedback**: tune alerts after every incident and every exercise

## Related Battlecards

Apply detection techniques to specific scenarios:

- [Shai-Hulud npm Worm](#battlecards-npm-worm-shai-hulud-md)
- [Abandoned Package Hijack](#battlecards-abandoned-package-hijack-md)
- [Build Cache and Artifact Poisoning](#battlecards-build-cache-and-artifact-poisoning-md)
- [Cloud Metadata and SSRF in Builds](#battlecards-cloud-metadata-and-ssrf-in-builds-md)
- [Shadow Downloads](#battlecards-shadow-downloads-md)
- [AI Dependency Recommendations](#battlecards-ai-dependency-recommendations-md)

---

**Previous Stage:** [← Limit](#stages-04-limit-md)
**Next Stage:** [Exercise →](#stages-06-exercise-md)

Once you can detect attacks, practise your response until it becomes muscle memory.
