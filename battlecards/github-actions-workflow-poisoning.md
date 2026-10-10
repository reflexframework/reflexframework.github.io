---
title: GitHub Actions Workflow Poisoning
category: CI/CD & Build
scenario: Pwn request and mutable action tags
focus:
  - pull_request_target running fork code
  - unpinned third-party actions
  - secrets and tokens exposed to workflows
---

## Scenario

An attacker targets a popular open-source Python library. The goal is its PyPI publishing credential, so they can ship a malicious release to every downstream user.

The project has a workflow that runs on `pull_request_target`. That trigger runs in the context of the base repository, with its secrets and a write-capable `GITHUB_TOKEN`. It always uses the workflow file from the base branch, so a fork cannot simply edit the YAML. The flaw is in what the workflow does next:

```yaml
on: pull_request_target

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pip install -e . && pytest
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
```

1. The attacker forks the repository and opens a pull request that "fixes a flaky test".
2. The PR also edits `setup.py` and `conftest.py`. Both run during `pip install` and `pytest`.
3. The trusted workflow checks out the attacker's head commit and runs it with the secret in the environment.
4. The attacker's code reads `PYPI_TOKEN`, plus the token that `actions/checkout` persisted in `.git/config`, and sends both to a server they control.

The same project also uses `some-org/lint-action@v2`. Tags are mutable. Anyone who compromises that action's repository can move `v2` to a malicious commit, and every workflow that references the tag runs it on the next build.

**Real-world precedent:** In December 2024 a `pull_request_target` injection in Ultralytics' workflows led to poisoned builds and two malicious `ultralytics` releases on PyPI ([PyPI analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)). In March 2025 attackers repointed the tags of `tj-actions/changed-files` to a commit that dumped runner secrets into build logs ([CVE-2025-30066](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)). That compromise was itself reached through `reviewdog/action-setup` (CVE-2025-30154).

::: {! stage recon}
## Reconnaissance

### Explanation

Workflow files are public in every public repository. Attackers search them at scale for two patterns: `pull_request_target` or `workflow_run` jobs that check out PR code, and third-party actions referenced by tag or branch. They also look for {% verbatim %}`${{ github.event.* }}`{% endverbatim %} expressions dropped straight into `run:` scripts, which allow shell injection through a PR title or branch name.

Popular actions are targets in their own right. Compromising one action's release process reaches thousands of repositories at once.

### Insight

Your workflows are part of your attack surface, and they are published for anyone to read. Doing the same search yourself takes minutes and shows you what an attacker sees.

### Practical

- Search your organisation's workflows for risky triggers and checkouts:
    - `pull_request_target` or `workflow_run` combined with `github.event.pull_request.head.sha` or `head.ref`.
    - {% verbatim %}`${{ github.event.pull_request.title }}`{% endverbatim %}, `head_ref` or `body` used inside `run:`.
- List every third-party action you use and how it is referenced (tag, branch or full SHA).
- Note which workflows have access to publish credentials, cloud roles or deploy keys.

### Tools/Techniques

- GitHub code search, for example `org:your-org path:.github/workflows pull_request_target`.
- [zizmor](https://github.com/zizmorcore/zizmor) to scan your own workflows the way an attacker would.
- [poutine](https://github.com/boostsecurityio/poutine) from BoostSecurity, which can scan a whole organisation for build pipeline weaknesses.

### Metrics/Signal

- Number of workflows using `pull_request_target` or `workflow_run`.
- Number of third-party action references not pinned to a full commit SHA.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

A "pwn request" needs three things together: a privileged trigger, a checkout of untrusted PR code, and a step that executes that code. Building, testing, installing dependencies and running linters all count as execution. Evaluate each workflow against those three conditions.

For actions, the question is simple. Is every `uses:` pinned to a 40-character commit SHA, and do you know who maintains each one?

### Insight

Most teams use `pull_request_target` to label PRs or post comments. Those jobs rarely need the PR's code at all. The danger appears when someone later adds a checkout to "run the tests properly".

### Practical

- Run the linters below against every repository and triage the high-severity findings first.
- For each `pull_request_target` workflow, confirm whether it checks out the head commit and what it then runs.
- Check top-level and job-level `permissions:`. A missing block means the token gets the repository default, which may be write-all on older repositories.
- Check whether `actions/checkout` persists credentials into `.git/config`.

### Tools/Techniques

- [zizmor](https://docs.zizmor.sh/): flags `dangerous-triggers`, template injection, `unpinned-uses`, `artipacked` (persisted credentials) and excessive permissions.
- [actionlint](https://github.com/rhysd/actionlint): catches syntax errors and script injection through untrusted inputs.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard): its `Dangerous-Workflow`, `Pinned-Dependencies` and `Token-Permissions` checks map directly to this attack.

```bash
pip install zizmor
zizmor --min-severity medium .github/workflows/
```

### Metrics/Signal

- zizmor high-severity findings per repository, trending to zero.
- Percentage of workflows with an explicit top-level `permissions:` block.
:::

::: {! stage fortify}
## Fortify

### Explanation

The fix for pwn requests is structural. Run untrusted code only under the `pull_request` trigger, which gets a read-only token and no secrets for forks. If you need privileged follow-up, such as posting results, split it into a second job or workflow that never executes PR code and treats any artifacts from the first as untrusted data.

For actions, pin to full commit SHAs and let a bot keep them up to date.

### Insight

A SHA pin is immutable. A tag is a pointer that someone else controls. The `tj-actions` compromise hit tag users and missed anyone pinned to a known-good SHA.

### Practical

- Replace `pull_request_target` with `pull_request` wherever the job needs PR code.
- Set least-privilege permissions at the top of every workflow and widen per job only where needed.
- Pin actions to full SHAs, with the version in a comment for humans and Dependabot.
- Never interpolate {% verbatim %}`${{ github.event.* }}`{% endverbatim %} into `run:`. Pass it through an environment variable instead.

```yaml
on: pull_request

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - name: Echo title safely
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "Testing: $PR_TITLE"
      - run: pip install -e . && pytest
```

- Turn on the organisation or repository Actions policy that requires actions to be pinned to a full SHA. Since August 2025 GitHub can enforce this and can block named actions outright.
- Publish your own actions with [immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases) so their tags and assets cannot be changed after release.
- Require approval before workflows run for PRs from outside contributors (Settings > Actions > General).

### Tools/Techniques

- [GitHub allowed actions and SHA-pinning policy](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/).
- [pinact](https://github.com/suzuki-shunsuke/pinact) or `zizmor --fix` to convert tag references to SHAs.
- Dependabot or Renovate with the `github-actions` ecosystem to update pinned SHAs through reviewed PRs.
- [CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) entry for `.github/workflows/` so workflow changes need a platform owner's review.

### Metrics/Signal

- 100% of third-party actions pinned to SHAs, enforced by policy.
- Zero workflows that combine `pull_request_target` with a head checkout.
:::

::: {! stage limit}
## Limit

### Explanation

Assume one workflow will eventually run hostile code. Limit what that code can reach. Keep publish credentials out of test jobs entirely, and replace long-lived tokens with short-lived, identity-based ones.

### Insight

Ultralytics' second wave of releases used an old PyPI API token still sitting in the repository's secrets. Trusted publishing was already set up, but the leftover token gave the attacker another way in.

### Practical

- Use [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) (or npm and crates.io equivalents). Delete stored registry tokens once it works.
- Put the release job behind a GitHub [environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) with required reviewers and a deployment branch rule for `main` or release tags.
- Give each job only the `permissions:` it needs. Only the publish job gets `id-token: write`.
- Do not share caches between untrusted PR builds and release builds.

### Tools/Techniques

- GitHub environments with required reviewers and branch restrictions.
- Registry trusted publishing (PyPI, npm, crates.io) bound to a specific workflow file and environment.
- `actions/checkout` with `persist-credentials: false`.

### Metrics/Signal

- Number of long-lived registry or cloud tokens stored as repository secrets, trending to zero.
- Release jobs that run outside a protected environment.
:::

::: {! stage expose}
## Expose

### Explanation

Detect this attack at two points: when a risky workflow change is proposed, and when a workflow does something unexpected at runtime. Unexpected outbound connections from a test job are the clearest runtime signal.

### Insight

The `tj-actions` payload printed secrets into public build logs. It was spotted because a runtime egress monitor flagged a call to an unexpected endpoint.

### Practical

- Run zizmor or actionlint as a required status check on any PR that touches `.github/workflows/`.
- Monitor runner egress and alert on destinations outside a known allow-list.
- Watch the audit log for changes to Actions policy, secrets and environments.
- Subscribe to GitHub security advisories for the actions you use.

### Tools/Techniques

- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) in `audit` mode to baseline network calls, then `block` mode.
- [zizmor](https://github.com/zizmorcore/zizmor) as a CI check with SARIF upload to code scanning.
- GitHub organisation audit log events for `workflows`, `environment` and `org.update_actions_secret`.

### Metrics/Signal

- Alerts for new egress destinations from CI jobs.
- PRs that add or edit workflows without passing the workflow linter.
:::

::: {! stage exercise}
## Exercise

### Explanation

Prove that your workflows resist a pwn request and that you would notice an attempt. Use a private sandbox repository and a canary token in place of any real secret.

### Insight

Teams often fix the workflow they know about and miss the copy in another repository. A live drill in a sandbox finds the gaps that a document review misses.

### Practical

1. Create a private sandbox repository with a deliberately vulnerable `pull_request_target` workflow.
2. Store a [canary token](https://canarytokens.org/) (an AWS key canary works well) as the secret.
3. From a second account, open a PR whose `conftest.py` tries to use the canary key.
4. Record whether the canary fires, whether zizmor flagged the workflow, and whether egress monitoring alerted.
5. Apply the Fortify changes and repeat. The canary should stay silent.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org/) for fake AWS credentials.
- A private sandbox repository and a throwaway test account.
- zizmor and Harden-Runner configured as in production.

### Metrics/Signal

- Time from PR open to alert.
- Whether the second run, after hardening, produces no canary trigger.
:::

## Further Reading

- [GitHub Security Lab: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [GitHub Docs: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [PyPI: Ultralytics attack analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [GitHub Advisory: tj-actions/changed-files (CVE-2025-30066)](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
- [zizmor documentation](https://docs.zizmor.sh/)
