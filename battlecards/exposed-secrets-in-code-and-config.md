---
title: Exposed Secrets in Code and Config
category: Secrets & Credentials
ref: RFX-SEC-01
precedent: "2022"
scenario: Credentials committed to repositories, config files and logs
focus:
  - committed .env files and API keys
  - push protection and secret scanning
  - leaked tokens in CI logs
  - rotation after exposure
---

## Scenario

A developer is racing to ship an AI feature. The project's `.gitignore` excludes `.env`, but a deploy script fails, so they run `git add -f .env` to "just get it working" and push to a public repository.

The file contains an AWS access key with broad permissions, a production database URL with a password, and an LLM provider API key.

Within minutes, automated scanners watching GitHub's public event stream pick up the `AKIA...` key. Someone starts GPU instances in a region the company never uses. Another uses the LLM key until it hits its spending limit. A third tries the database URL, which only fails because the database is not internet-reachable.

The developer deletes the file in the next commit. That changes nothing. The key is still in the history, and it has already been copied.

::: {! precedent}
**Real-world precedent:** In October 2022 [Toyota disclosed](https://blog.gitguardian.com/toyota-accidently-exposed-a-secret-key-publicly-on-github-for-five-years/) that a contractor had published T-Connect source code to a public GitHub repository in December 2017, including an access key to a server holding data on almost 300,000 customers. It stayed public for nearly five years. Uber's 2016 breach also began with cloud credentials found in a GitHub repository.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Most secret theft is automated and untargeted. Bots watch public commits on GitHub, GitLab and package registries, and match known token formats such as AWS `AKIA` keys, GitHub `ghp_` and `github_pat_` tokens, Slack `xox` tokens and LLM provider keys. Others search code, Docker image layers, npm and PyPI packages, and CI logs.

Targeted attackers go further: they search old commits, forks, gists and public CI logs for a specific organisation.

### Insight

The time from exposure to first use is measured in minutes. Once a secret is pushed somewhere public, treat it as stolen, whether or not you delete it.

### Practical

Search your own public footprint with GitHub code search. Use the `path:` qualifier (the older `filename:` qualifier belongs to the legacy search):

```text
org:your-org path:.env
org:your-org path:*.tfvars
org:your-org "BEGIN OPENSSH PRIVATE KEY"
org:your-org "AKIA"
```

Also scan full history, not just the current tree, and include forks and gists.

### Tools/Techniques

- GitHub code search with `path:` and `org:` qualifiers.
- [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) for history scans; TruffleHog can verify whether a found credential is still live.
- GitHub's free secret risk assessment in the organisation's Security tab.

### Metrics/Signal

- Number of verified live secrets found in history.
- Repositories and container images never scanned.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Find out where secrets live in your codebase today and how they get there.

### Insight

Secrets leak in a few predictable ways:

- `.env` and config files committed, often with `git add -f`, which overrides `.gitignore`.
- Hardcoded keys in tests, notebooks and example code.
- Secrets printed to CI logs by `set -x`, debug output or error messages.
- Secrets baked into container image layers or published package tarballs.

Rewriting history with `git filter-repo` and then `git push --force` removes the file from your branch. It does not remove it from clones, forks, caches or anyone who already copied it. Rotation is the fix; history cleaning is tidying up.

### Practical

1. Run a full-history scan of your main repositories.
2. Check CI logs for secrets that masking missed, especially values transformed by base64 or JSON encoding.
3. Inspect image layers: `docker history --no-trunc <image>` and a scanner over the layers.
4. Run `npm pack --dry-run` or build the wheel locally to see what you are about to publish.

```bash
gitleaks git --redact --report-path gitleaks.json .
trufflehog git file://. --results=verified
```

### Tools/Techniques

- gitleaks, TruffleHog, detect-secrets.
- [Trivy](https://github.com/aquasecurity/trivy) `--scanners secret` for images and file systems.
- `npm pack --dry-run`, `python -m build` plus `unzip -l`.

### Metrics/Signal

- Secrets found per repository, split by source (code, history, logs, images).
- Percentage of found secrets that were still valid.
:::

::: {! stage fortify}
## Fortify

### Explanation

Stop secrets entering repositories, and stop applications needing long-lived secrets in files.

### Insight

GitHub turned on secret scanning and [push protection by default for new public repositories](https://github.blog/changelog/2024-03-11-secret-scanning-and-push-protection-are-enabled-by-default-on-new-public-repositories/) in 2024. Since April 2025, [GitHub Secret Protection](https://github.blog/changelog/2025-03-04-introducing-github-secret-protection-and-github-code-security/) is sold on its own, so Team-plan organisations can buy push protection for private repositories without full GitHub Advanced Security.

### Practical

- Enable push protection for every repository, public and private, and for your user account.
- Add a pre-commit hook so developers catch secrets before they push:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
```

- Keep `.env` out of the repository and commit a `.env.example` with placeholder values instead.
- Load secrets at runtime from a secrets manager or your platform's secret store, never from committed files.
- Replace static cloud keys with OIDC federation in CI and workload identity in production.
- Mask secrets in CI and avoid `set -x` in steps that handle them.

### Tools/Techniques

- GitHub push protection, GitLab secret push protection.
- pre-commit with gitleaks or detect-secrets.
- HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, 1Password or Doppler.

### Metrics/Signal

- Percentage of repositories with push protection enabled.
- Push protection bypasses per month, and the reasons given.
:::

::: {! stage limit}
## Limit

### Explanation

Assume a secret will leak eventually. Make each one narrow, short-lived and quick to revoke.

### Insight

GitHub's [secret scanning partner programme](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program) sends tokens found in public repositories to the issuing provider. Many providers then act automatically: GitHub revokes its own tokens, and AWS attaches a quarantine policy (such as `AWSCompromisedKeyQuarantineV3`) to exposed access keys. That buys time. Do not rely on it as your plan.

### Practical

- Scope every credential to one service and the least privilege it needs.
- Set spending limits and usage alerts on LLM provider keys and cloud accounts.
- Keep databases off the public internet, so a leaked connection string is not enough on its own.
- Write a rotation runbook for each secret type and test it, so rotating takes minutes.
- When a secret leaks: revoke and rotate first, then check the provider's logs for use, then clean history.

### Tools/Techniques

- Cloud IAM policies, service control policies and budgets.
- Provider usage dashboards and alerts for LLM APIs.
- AWS CloudTrail, GCP Cloud Audit Logs and Azure Activity Log to check what a leaked key did.

### Metrics/Signal

- Mean time to rotate a leaked secret.
- Credentials with no expiry or no owner.
:::

::: {! stage expose}
## Expose

### Explanation

Know quickly when a secret leaks and when one is used by someone else.

### Insight

The fastest alert often comes from outside: a secret scanning alert, a provider's "your key was found on GitHub" email, or a sudden bill. Make sure those reach someone who will act.

### Practical

- Route GitHub secret scanning alerts to the owning team's channel, not a shared inbox.
- Make sure provider security emails go to a monitored team address.
- Alert on cloud API calls from unfamiliar IPs or regions, and on new compute in unused regions.
- Plant canary tokens in places a leak would expose (a fake AWS key in an internal repository's config) so their use triggers an alert.

### Tools/Techniques

- GitHub secret scanning alerts and webhooks.
- AWS GuardDuty, GCP Security Command Center, Microsoft Defender for Cloud.
- [Canarytokens](https://canarytokens.org/) for fake AWS keys and other bait credentials.

### Metrics/Signal

- Time from push to alert.
- Time from alert to rotation.
:::

::: {! stage exercise}
## Exercise

### Explanation

Practise the full leak-and-rotate cycle with a credential that cannot do any harm.

### Insight

Teams that have never rotated a production secret under pressure find out what breaks at the worst moment.

### Practical

1. Create a Canarytokens AWS key. Commit it to a private test repository and push. Check that push protection or your pre-commit hook blocks it.
2. Bypass the block deliberately (in the test repository only) and time how long until an alert reaches the right person.
3. Pick one real, low-risk secret and rotate it using your runbook. Time it and note every system that broke.
4. Update the runbook with what you learned. Follow [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (2025) if you need a reference for incident handling.

### Tools/Techniques

- Canarytokens for a fake but detectable AWS key.
- A private test repository.

### Metrics/Signal

- Whether the canary was blocked, and how fast its use was reported.
- Rotation time for the real secret, before and after improving the runbook.
:::

## Further Reading

- [GitHub: about push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)
- [GitHub: secret scanning partner programme](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program)
- [GitGuardian: Toyota exposed a secret key on GitHub for five years](https://blog.gitguardian.com/toyota-accidently-exposed-a-secret-key-publicly-on-github-for-five-years/)
- [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [NIST SP 800-61 Rev. 3: incident response recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
