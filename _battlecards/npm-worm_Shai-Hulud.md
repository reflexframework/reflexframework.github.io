---
permalink: /battlecards/shai_hulud
title: Shai-Hulud (@ctrl/tinycolor) npm compromise
 
battlecard:
 title: Shai-Hulud (@ctrl/tinycolor) npm compromise
 category: Software supply-chain/security
 scenario: Trojanized npm packages that steal credentials, inject malicious CI workflows, and self-propagate via forced publishing
 focus: 
   - Harvesting high-value credentials
   - Automated propagation via package publishing
   - Persistence and lateral expansion via CI workflows
---

A popular npm package (`@ctrl/tinycolor`) and ~40 related packages were trojanized with a large `bundle.js` payload that executed during `npm install` (postinstall). The payload hunted for environment and filesystem secrets, exfiltrated them to attacker-controlled endpoints, created public repos named `Shai-Hulud`, and injected malicious GitHub Actions workflows into reachable repositories. 

**Immediate impact:** developer workstations and CI runners that installed the compromised versions likely leaked tokens (GitHub PATs, npm tokens, cloud keys), possible forced-publishes of other packages, and new malicious CI workflows that persist and expand access.

---

{% block type='battlecard' text='reconnaissance' %}

### Explanation
Attackers publish a malicious package version or compromise a maintainer account. A `postinstall` script executes `bundle.js` that scans for secrets (env vars, `.npmrc`, cloud SDK files), queries filesystem contents (TruffleHog-style), calls attacker webhooks, and abuses recovered npm/GitHub creds to publish further trojanized packages and inject workflows.

### Insight
This is a supply-chain worm: once one maintainer’s credentials are obtained, the malware uses them to propagate automatically. Key attacker methods: postinstall hooks, filesystem scanning, outbound webhooks, GitHub Actions injection, and forced npm publishing using stolen tokens.

### Practical 
- `npm ls @ctrl/tinycolor || true` — detect direct deps.
- `grep -E "ctrl/tinycolor|Shai-Hulud" -R package-lock.json yarn.lock || true` — search lockfiles.
- `find . -type f -name "bundle.js" -print` and `grep -R "shai-hulud" . || true`.
- `git log --all --grep="shai-hulud" || true` — search repo history for mentions.
- Check recent GitHub repos created under your org for suspicious names.

### Tools/Techniques
- TruffleHog — secret-scanning: https://github.com/trufflesecurity/trufflehog
- `npm` / `yarn` tooling — audit and `npm ls`: https://docs.npmjs.com/
- GitHub CLI — repo and workflow inspection: https://cli.github.com/
- Semgrep supply-chain rules — detection: https://semgrep.dev/
- Socket.dev / StepSecurity advisories for known IOCs.

### Metrics/Signal
- Alert if `npm ls` finds any compromised package ⇒ immediate critical signal.
- File presence: `bundle.js` or known SHA-256 appears in `node_modules` (presence → alert).
- New workflows added to repos: count of `.github/workflows/*.yml` created in last 24h > baseline.
- Public repo creations matching regex `(?i)shai-?hulud` within org → immediate alert.
- Outbound connections from CI to unknown webhook domains (e.g. `webhook.site`) — network allowlist violations.

{% endblock %}

{% block type='battlecard' text='evaluation' %}

### Explanation
Susceptibility depends on: (a) using affected package versions (direct or transitive), (b) installing on systems with secrets exposed to the environment, and (c) CI runners that allow outbound network and repo write permissions.

### Insight
Even a single engineer installing a compromised package on a machine with long-lived tokens can seed the organization: harvested tokens can be used to publish more packages and plant workflows on repos that CI or the user can access.

### Practical 
- Run fleet-wide scans: `npm ls @ctrl/tinycolor --all` across repos.
- Search CI logs for installs of suspect versions (`grep -R "@ctrl/tinycolor@4.1" /var/log/ci || true`).
- Check runner environments for secrets: `env | egrep 'AWS|GITHUB|NPM|TOKEN|SECRET' || true`.
- Inspect GitHub audit logs for repo-creation and workflow additions in the last 48h.
- Use TruffleHog or similar to scan build agents and developer machines.

### Tools/Techniques
- `npm ls`, `yarn why` — dependency inspection.
- TruffleHog — secrets discovery.
- GitHub Audit Log / Enterprise audit tools — https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-audit-logs
- Sysdig Falco / OSSEC — detect unexpected install-time behaviors.
- Grep/RIPE for lockfiles across mono-repos or monorepo hosts.

### Metrics/Signal
- Percentage of repos with an affected dependency (e.g., >0.1% → escalate).
- Count of CI runners that had `npm install` while an `AWS_*` or `GITHUB_*` env var existed (non-zero → high risk).
- Number of repos with newly added workflows in last 24h compared to baseline (delta > 200% → urgent).
- TruffleHog secret hits on build agents > 0 → treat as compromised.


{% endblock %}
{% block type='battlecard' text='fortify' %}


### Explanation
Prevent by reducing attack surface (no long-lived creds on build/install surface), blocking or sandboxing `postinstall` execution, pinning vetted package versions, and adding provenance/verification for packages.

### Insight
Mitigations combine process (review/cooldown for new releases), platform (CI network restrictions, limited permissions), and tooling (SCA, SBOM, provenance). Disabling install scripts and using internal registries significantly lowers risk.

### Practical 
- Add lock-step pinning: set `package-lock.json` in source and run `npm ci` in CI.
- In CI, run install in a network-isolated container: `docker run --network=none -v $(pwd):/src node:18 bash -c "npm ci"`.
- Temporarily set `npm config set ignore-scripts true` for non-development installs: `npm ci --ignore-scripts` (test first).
- Add an SBOM generator step: `syft packages.json -o json > sbom.json` or use `npm audit` nightly.
- Enforce a 24–48h cooldown for new dependency versions before automatic upgrades.

### Tools/Techniques
- Sigstore / Cosign for artifact provenance: https://sigstore.dev/
- Syft (Anchore) for SBOM generation: https://github.com/anchore/syft
- Dependabot / Snyk for monitoring and alerts: https://snyk.io/ & https://github.com/dependabot
- Container sandboxing: Docker `--network=none` or buildkite isolated agents.
- Private npm registry / proxy (Verdaccio): https://verdaccio.org/

### Metrics/Signal
- Percent of builds using `--ignore-scripts` or running in network-isolated mode (target: 100% for sensitive builds).
- Time between package publish and org adoption (median > 24h desired).
- Number of packages consumed from internal registry (increase → healthier posture).
- SBOM coverage rate (repos with SBOM / total repos) target > 90%.

{% endblock %}
{% block type='battlecard' text='limit' %}

### Explanation
Assume secrets present during affected installs are leaked. Rapidly identify, revoke, rotate credentials, remove malicious artifacts, and rebuild from trusted environments.

### Insight
Containment is triage + credential rotation + artifact removal. Attackers may have planted GitHub Actions; these workflows can re-exfiltrate new secrets if not removed. Treat token rotation and workflow removal as urgent containment.

### Practical 
- Revoke suspected tokens immediately: npm tokens, GitHub PATs, CI tokens. For npm: go to [npm website](https://docs.npmjs.com/creating-and-viewing-access-tokens?utm_source=chatgpt.com#viewing-access-tokens) and revoke; for GitHub revoke PAT in Settings → Developer settings → Personal access tokens.
- Clean installs: `rm -rf node_modules && npm cache clean --force && npm ci --ignore-scripts` on a quarantined host.
- Search and remove workflows: `gh repo list ORG --limit 200 | xargs -I{} gh api repos/{}/actions/workflows --paginate` then inspect and remove suspicious `.github/workflows/*.yml`.
- Rotate cloud credentials: create new keys (`aws iam create-access-key`) and delete old keys (`aws iam delete-access-key`). Update CI secrets and deploy agents with new creds.

### Tools/Techniques
- GitHub CLI (`gh`) for repo/workflow automation: [github cli](https://cli.github.com/)
- AWS CLI for key rotation: [aws cli](https://aws.amazon.com/cli/) (`aws iam create-access-key`, `aws iam delete-access-key`)
- Vault for short-lived credentials and secrets management: [Vault](https://www.vaultproject.io/)
- Incident response scripts (custom) to scan `node_modules` for known bundle hash and remove.

### Metrics/Signal
- Number of rotated secrets vs. total suspected secrets (target: rotate 100% of suspected).
- Time-to-rotation median (target: < 60 minutes for critical tokens).
- Number of runners rebuilt from clean images (target: traceable 100% rebuild for affected runners).
- Count of malicious workflows removed (aim: 0 remaining).

{% endblock %}
{% block type='battlecard' text='expose' %}

### Explanation
Rapid, clear disclosure and coordination reduces lateral spread. Share IOCs, impacted package versions, and remediation steps internally and with upstream/registry providers.

### Insight
Timely internal messaging + registry reports (npm), security advisories, and coordination with maintainers and downstream consumers curtails propagation and informs detection in other orgs.

### Practical 
- Create an internal incident channel & post: affected package names/versions, install timestamps, rotated secrets, and remediation actions taken. Use templated message.
- File abuse reports to npm: https://www.npmjs.com/support and open issues on affected package repos tagging maintainers.
- Publish indicators to internal SIEM and add blocking rules (IOC file hashes, webhook domains).
- Notify platform teams to watch for suspicious activity (new repo creations, workflow changes, unexpected npm publishes).

### Tools/Techniques
- Slack/Teams incident channel for developer ops coordination.
- npm Support / Registry abuse reporting: https://www.npmjs.com/support
- Abuse reporting to GitHub and creation of security advisories: https://docs.github.com/en/code-security/secure-your-code/reporting-security-vulnerabilities
- SIEM ingestion: Elastic / Splunk for alerts on outbound network patterns and repo events.

### Metrics/Signal
- Time from detection to internal notification (target: < 30 minutes).
- Number of org teams notified (target: 100% of engineering teams).
- Number of external reports filed to npm/GitHub within 1 hour.
- Number of hits on published IOCs by other org services (signal of propagation).

{% endblock %}
{% block type='battlecard' text='exercise' %}

### Explanation
Use the incident as a source to harden developer workflows: enforce least-privilege secrets, tighten publish processes, automate detection, and practice incident response.

### Insight
Exercises should be blameless, aim to close detection and response gaps, and convert tactical fixes into permanent guardrails (SBOMs, trusted registries, CI hardening).

### Practical
- Run a blameless post-mortem; produce a short action list with owners for lockfile policy, CI sandboxing, and secret management.
- Add `postinstall` and large-bundle checks into PR gates: fail PRs if `postinstall` present or package size increases > X%.
- Implement a short-lived token policy in CI: moves to Vault or OIDC (GitHub Actions `id-token`) to reduce leaked credential value.
- Schedule tabletop IR run on this scenario within 30 days.

### Tools/Techniques
- OIDC-based workflows (GitHub Actions `id-token`) to issue short-lived credentials: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- Policy-as-code for dependency checks (Open Policy Agent / Sentinel).
- CI sandboxing + egress controls (buildkite, GitHub Actions self-hosted runners with network policies).
- Continuous SBOM and SCA integration (Syft + Snyk/Dependabot).

### Metrics/Signal
- Reduction in number of secrets available in build envs (target: 0 long-lived secrets in CI).
- Time between new package publish and internal adoption (target: ≥24 hours).
- Percentage of repos with enforced lockfile and SBOM generation (target: >95%).
- Tabletop exercise frequency and time-to-closure on action items (target: exercise quarterly; 80% actions closed in 90 days).

{% endblock %}