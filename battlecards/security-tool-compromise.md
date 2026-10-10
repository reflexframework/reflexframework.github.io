---
title: Compromised Security Scanners and Cascading Credential Theft
category: CI/CD & Build
scenario: A trojanised scanner steals CI secrets and spreads downstream
focus:
  - security tools running with broad CI secrets
  - mutable action tags and unpinned scanner binaries
  - incomplete credential rotation
  - one stolen token compromising the next project
---

## Scenario

A team adds a vulnerability scanner to its release workflow. It is the responsible thing to do. The scanner's GitHub Action runs in the same job that builds and publishes the package, so the job holds the registry token, cloud credentials and a write-capable `GITHUB_TOKEN`.

The scanner's own project is then compromised:

1. Attackers steal a privileged token from the scanner project's CI. The maintainers notice, disclose and rotate credentials. One token is missed.
2. Weeks later, the attackers use that token to force-push most of the action's version tags to a malicious commit, and publish a trojanised scanner binary.
3. Every workflow that references the action by tag, or downloads the "latest" binary, now runs the attacker's code. It reads secrets from the runner's memory and filesystem and sends them away encrypted.
4. One victim is a popular library. Its stolen registry token lets the attackers publish malicious releases of that library directly to the registry.
5. Everyone who installs the library unpinned is now compromised too, including the CI pipelines of other projects. The cycle repeats.

The scanner did exactly what it was trusted to do: run with access to everything. That is why it was chosen.

**Real-world precedent:** On 19 March 2026 the TeamPCP group used credentials left over from an incompletely rotated February breach to publish a malicious Trivy v0.69.4 and force-push 76 of 77 `aquasecurity/trivy-action` tags ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23), CVE-2026-33634, now in CISA's KEV catalogue). LiteLLM ran Trivy in its CI. On 24 March, malicious `litellm` 1.82.7 and 1.82.8 appeared on PyPI ([LiteLLM](https://docs.litellm.ai/blog/security-update-march-2026)). The same group hijacked Checkmarx's `kics-github-action` tags on 23 March ([Wiz](https://www.wiz.io/blog/teampcp-attack-kics-github-action)). A year earlier, a compromised `reviewdog/action-setup` (CVE-2025-30154) led to the `tj-actions/changed-files` compromise (CVE-2025-30066).

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers pick tools that run everywhere and are trusted by default. Security scanners, linters and SBOM generators qualify. They are added to release pipelines, often by tag, and rarely questioned.

The attackers then study the tool's own project: how it releases, which workflows hold tokens, whether tags are protected. After the first theft, they collect secrets from every pipeline the tool runs in, and look for publish tokens to popular packages.

### Insight

From an attacker's view, a widely used scanner is a key to thousands of CI environments at once. Each stolen publish token is a key to the next project's users.

### Practical

- List every security tool in your pipelines: scanners, SAST, secret scanners, SBOM tools, licence checkers.
- For each, record how it is referenced (tag, SHA or digest) and how its binary or database is fetched.
- Note which jobs run these tools alongside publish, deploy or cloud credentials.

### Tools/Techniques

- `grep -rn 'uses:' .github/workflows/` across your repositories, filtered for scanner actions.
- GitHub code search for `trivy-action`, `kics-github-action`, `setup-trivy` and similar across your organisation.

### Metrics/Signal

- Security tool steps running in jobs that hold publish or deploy credentials.
- Security actions referenced by mutable tag.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For each scanner step, ask what it could steal if it turned hostile. Remember that step-level `env:` is a weak boundary. The Trivy and `tj-actions` payloads read the runner process's memory, which holds every secret the job uses.

Then ask how you would recover. If you had to rotate every credential those jobs could reach, do you know what they all are?

### Insight

Pinning the action is necessary and not sufficient. A SHA pin freezes the action's code, not what that code downloads. The Trivy advisory lists runs that used `version: latest` as affected, and some old SHA pins too. The scanner binary and its database need pinning as well.

### Practical

- Map each scanner job to the secrets, `permissions:` and OIDC roles it has.
- Check whether the action installs a binary, and whether that version is pinned or "latest".
- Check whether the scanner needs any secret at all. Most need read access to the code or image, nothing more.
- Write down the full credential set for each release job. You will need that list on the worst day.

### Tools/Techniques

- [zizmor](https://docs.zizmor.sh/) for unpinned actions and excessive permissions.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) `Pinned-Dependencies` and `Token-Permissions` checks.
- GitHub's [allowed actions and SHA-pinning policy](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/).

### Metrics/Signal

- Scanner jobs with publish, deploy or cloud credentials in reach.
- Release jobs with a documented credential inventory.
:::

::: {! stage fortify}
## Fortify

### Explanation

Run scanners in jobs that have nothing worth stealing. Pin the action by full commit SHA and the tool by exact version. Publish with short-lived, identity-based credentials, so there is no long-lived token to take.

### Insight

LiteLLM's attackers bypassed CI and uploaded straight to PyPI with a stolen credential. Trusted publishing removes the stored token from the pipeline. A stolen OIDC token expires in minutes and only works for that workflow.

### Practical

Split scanning from publishing. The scan job gets read-only permissions and no secrets:

```yaml
permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>  # v7
        with:
          persist-credentials: false
      - uses: aquasecurity/trivy-action@<full-commit-sha>  # v0.36.0
        with:
          scan-type: fs
          version: v0.75.0  # pin the scanner binary too

  publish:
    needs: scan
    runs-on: ubuntu-latest
    environment: release
    permissions:
      contents: read
      id-token: write  # PyPI trusted publishing, no stored token
    steps:
      - uses: actions/checkout@<full-commit-sha>  # v7
        with:
          persist-credentials: false
      - run: pipx run build
      - uses: pypa/gh-action-pypi-publish@<full-commit-sha>  # release/v1
```

- Replace each `<full-commit-sha>` with the real commit. Write the tag, then let `pinact run` swap it for the SHA and keep the tag as a comment.
- Turn on GitHub's SHA-pinning enforcement for the organisation.
- Prefer actions published as [immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases). Trivy-action 0.35.0 was an immutable release and was the one tag the attackers could not move.
- Verify scanner binaries with their Sigstore signatures where the project provides them.
- If you publish anything, use trusted publishing (PyPI, npm, crates.io) and gate the publish job behind a protected environment.

### Tools/Techniques

- [pinact](https://github.com/suzuki-shunsuke/pinact) and Renovate or Dependabot to keep SHA pins current.
- PyPI and npm trusted publishing.
- [GitHub Actions Workflow Poisoning](#battlecards-github-actions-workflow-poisoning-md) covers wider workflow hardening.

### Metrics/Signal

- Security actions pinned by SHA, with the tool version pinned too.
- Publish jobs using trusted publishing, and long-lived publish tokens remaining.
:::

::: {! stage limit}
## Limit

### Explanation

When a tool you depend on is compromised, the clock is running. Rotate everything the affected jobs could reach, all at once. Then look downstream: did you publish anything during the window?

### Insight

Trivy's February rotation was not atomic. One credential survived, and the attackers used it to come back. Rotating in stages lets an attacker who holds one valid secret read the new ones as you issue them.

### Practical

- Keep a credential inventory per pipeline, so "rotate everything" is a checklist, not an investigation.
- Revoke first, then reissue. Cut off every credential in scope before trusting any new one.
- Freeze releases from affected pipelines until rotation is complete.
- Check whether any release was built or published during the exposure window. If so, yank it and tell your users.
- Pin downstream dependencies by version and hash. LiteLLM's official Docker image pinned its dependencies and was not affected.
- Use a release-age gate, such as Renovate's `minimumReleaseAge`, so a malicious release has time to be caught before you install it.

### Tools/Techniques

- Your secrets manager's audit log and revocation API.
- Registry controls to yank or delete compromised releases.
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) in block mode, so exfiltration to unknown hosts fails.

### Metrics/Signal

- Time from advisory to full revocation of in-scope credentials.
- Credentials still valid after a declared rotation (the target is zero).
:::

::: {! stage expose}
## Expose

### Explanation

Detect three things: a tool behaving differently, a tag moving under you, and your own credentials being used where they should not be.

### Insight

A scanner has no business opening connections to new domains or creating repositories. Both happened here. The Trivy payload fell back to creating a public `tpcp-docs-` repository on the victim's account when exfiltration failed.

### Practical

- Baseline egress from scanner jobs and alert on new destinations.
- Alert on unexpected repositories, releases or deploy keys created in your organisation.
- Alert when a referenced action's tag moves to a new commit. Renovate and Dependabot show this as a digest change if you pin by SHA.
- Watch registry publish events for your packages that did not come from your trusted publisher.
- Subscribe to advisories for every security tool you run. You need to know within hours.

### Tools/Techniques

- Harden-Runner in audit mode to baseline egress.
- GitHub organisation audit log streaming.
- Registry publish notifications and provenance checks for your own packages.

### Metrics/Signal

- New egress destinations from scanner jobs.
- Publishes of your packages without matching provenance.
:::

::: {! stage exercise}
## Exercise

### Explanation

Rehearse a scanner compromise in a sandbox repository. Use a fake scanner action and canary credentials, never a real secret or real malware.

### Insight

The drill is mostly about the rotation list. Teams usually find a credential nobody remembered.

### Practical

1. In a private sandbox repository, create a local "scanner" action that only sends the names of the job's environment variables to a canary endpoint you control.
2. Put canary tokens in the scan job's secrets, as an attacker would hope to find.
3. Run your real workflow layout against it. Record which canaries were reachable from the scan job.
4. Move the action's tag to a new commit and see whether anything alerts.
5. Run your rotation checklist against the canaries. Time it, and note anything missing from the inventory.
6. Fix the workflow so the scan job holds no secrets, and run the drill again.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org/) for fake AWS keys and URLs.
- A private sandbox repository and runner with no production access.
- Harden-Runner and zizmor configured as in production.

### Metrics/Signal

- Canaries reachable from the scan job, before and after the fix.
- Time to complete the rotation checklist.
:::

## Further Reading

- [Trivy advisory GHSA-69fq-xp46-6x23 (CVE-2026-33634)](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- [Aqua Security: Trivy supply chain attack, what you need to know](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know)
- [LiteLLM: Security update, suspected supply chain incident](https://docs.litellm.ai/blog/security-update-march-2026)
- [Wiz: KICS GitHub Action compromised](https://www.wiz.io/blog/teampcp-attack-kics-github-action)
- [Wiz: reviewdog/action-setup supply chain attack](https://www.wiz.io/blog/new-github-action-supply-chain-attack-reviewdog-action-setup)
- Related cards: [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md), [GitHub OIDC Misconfiguration](#battlecards-github-oidc-misconfiguration-md), [Maintainer Account Takeover](#battlecards-maintainer-account-takeover-md)
