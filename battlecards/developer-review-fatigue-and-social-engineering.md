---
title: Developer Review Fatigue and Social Engineering
category: Social Engineering
scenario: A trusted contributor slips in a malicious "urgent fix"
focus:
  - long-game trust building
  - pressure and urgency in reviews
  - CI changes hidden in routine PRs
---

## Scenario

An attacker, calling themselves "Alex", targets a popular open-source project run by a few overworked maintainers.

Alex starts slowly. Over several months they send small, genuinely useful PRs: documentation fixes, a missing unit test, a tidy refactor. The maintainers merge them gladly. Alex becomes a familiar, helpful name. Meanwhile, other accounts start posting in issues, complaining that the project is slow and asking why Alex has not been given more responsibility.

One Friday afternoon, the CI build on `main` starts failing because of a flaky upstream tool. Within the hour Alex opens a PR titled "URGENT: fix CI pipeline failure". It changes `ci.yml` to download a "patched" build tool with `curl | bash`.

The script looks for secrets in the runner environment, such as `NPM_TOKEN` and cloud credentials, and sends them out before letting the build pass. A tired maintainer sees a trusted name, a green build and a weekend approaching. They merge it.

**Real-world precedent:** The xz-utils backdoor ([CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)), found in March 2024, followed this playbook: a contributor known as "Jia Tan" built trust over about two years while sock-puppet accounts pressured the lone maintainer to hand over control. In 2018 the [event-stream](https://github.com/dominictarr/event-stream/issues/116) npm package was handed to a helpful volunteer, who added a dependency that targeted a cryptocurrency wallet.

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker studies people as much as code. They look for projects with few maintainers, a long PR backlog and a clear sign of strain, such as an issue titled "Looking for help maintaining this". They watch when maintainers are active, who merges quickly, and which parts of the repository get little review.

### Insight

Maintainer burnout is visible in public. Long response times, apologetic comments and a single merger all tell an attacker where pressure will work.

### Practical

- Look at your own project as an outsider would:
    - How many people can merge?
    - How long do PRs wait?
    - Have you posted about being short of time?
- Check whether changes to CI files, build scripts and release tooling get the same review as application code.

### Tools/Techniques

- GitHub Insights (contributors, pulse) for your own repositories.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) `Maintained` and `Code-Review` checks for your critical dependencies.

### Metrics/Signal

- Number of people with merge rights on each critical repository.
- Median time to first review.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Assess how your process behaves under pressure. Could one person merge a CI change alone? Would a workflow from a recent contributor run without approval? Does an "urgent" label change how carefully people review?

### Insight

Process that only works on a calm Tuesday is not a control. The attacker will pick Friday evening.

### Practical

- Review the last few months of merges to `.github/workflows/`, build scripts and dependency manifests. Who approved them, and how fast?
- Check whether new contributors' workflow runs need approval.
- Check whether approvals survive later pushes to the same PR.
- Note any PRs merged with a single approval during an incident.

### Tools/Techniques

- `git log --since="6 months ago" --format='%h %an %ad %s' -- .github/workflows/` to list recent CI changes, then check each PR's reviews with `gh pr view`.
- GitHub Actions settings for fork pull request workflow approval.

### Metrics/Signal

- Percentage of CI or build changes merged with two or more approvals.
- Number of merges by a single person without any second reviewer.
:::

::: {! stage fortify}
## Fortify

### Explanation

Build controls that hold when people are tired. Require more than one reviewer for sensitive paths, block known-dangerous patterns automatically, and make sure approvals apply to the final code.

### Insight

Automation does not get tired. Let it reject the obviously risky change so humans can spend their attention on the subtle ones.

### Practical

- Add CODEOWNERS entries for `.github/workflows/`, build scripts and release tooling, owned by a small platform or security group.
- Use a ruleset on `main` that requires:
    - Code-owner review.
    - Dismissal of stale approvals.
    - Approval of the most recent reviewable push, so a change pushed after review needs fresh approval.
- Require approval before workflows run for outside contributors.
- Lint workflows in CI, and fail on `curl | bash` style downloads, unpinned actions and template injection.
- Agree a team rule: "urgent" changes to CI get a second reviewer, however small.

### Tools/Techniques

- [GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).
- [zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint) as required checks.
- Semgrep or a short `grep` in CI to block `curl ... | bash` in workflow files.

### Metrics/Signal

- Coverage of CI and build paths by CODEOWNERS.
- Workflow lint findings blocked before merge.
:::

::: {! stage limit}
## Limit

### Explanation

If a malicious CI change does merge, it should find little worth stealing. Keep publishing and deploy credentials out of ordinary build jobs, and prefer short-lived tokens.

### Insight

The attacker in this scenario only wins because long-lived secrets were in the runner's environment. Remove them and the "urgent fix" steals nothing useful.

### Practical

- Publish with trusted publishing (npm, PyPI, crates.io) instead of stored tokens.
- Put release and deploy jobs behind a GitHub environment with required reviewers.
- Set `permissions: contents: read` by default in every workflow.
- Use separate maintainer accounts with hardware-key 2FA for registry ownership.

### Tools/Techniques

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) and [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/).
- GitHub environments with required reviewers.

### Metrics/Signal

- Long-lived registry or cloud tokens stored as CI secrets.
- Workflows without an explicit `permissions:` block.
:::

::: {! stage expose}
## Expose

### Explanation

Look for the behaviour that gives this attack away: unexpected network calls from CI, changes to workflows by new contributors, and new maintainers or owners on packages you depend on.

### Insight

The xz backdoor was found because one engineer noticed SSH logins were half a second slower. Small anomalies are worth chasing.

### Practical

- Monitor runner egress and alert on unknown destinations.
- Alert when a workflow file changes in a PR from someone outside the maintainer group.
- Track maintainer and ownership changes on your critical dependencies.

### Tools/Techniques

- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) to log and restrict CI egress.
- GitHub audit log events for repository role changes.
- [Socket](https://socket.dev/) or similar tools that flag new maintainers and install scripts in dependencies.

### Metrics/Signal

- New egress destinations from CI per week.
- Workflow changes by contributors with fewer than a set number of merged PRs.
:::

::: {! stage exercise}
## Exercise

### Explanation

Run a friendly, announced-to-leadership drill. A colleague plays "Alex" and submits an "urgent" CI fix to a sandbox copy of your repository. Use a canary token as the only secret, so nothing real can leak.

### Insight

People who have been fooled once in a safe drill spot the real thing faster. Keep the debrief blameless and focus on the process gaps.

### Practical

1. Create a private sandbox repository with your normal rulesets and CI.
2. Store a [canary token](https://canarytokens.org/) (a fake AWS key) as a repository secret.
3. On a Friday afternoon, a colleague opens an "URGENT" PR whose script calls `aws sts get-caller-identity` with that secret. Using the canary key triggers its alert.
4. Record:
    - Whether the PR was merged.
    - Whether linting or code-owner rules stopped it.
    - Whether the canary fired and who saw the alert.
5. Fix the gaps and repeat next quarter.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org/) for fake AWS credentials.
- A private sandbox repository mirroring production rules.

### Metrics/Signal

- Whether the drill PR was blocked, and by which control.
- Time from merge (if it happened) to canary alert.
:::

## Further Reading

- [CISA: Reported supply chain compromise affecting XZ Utils (CVE-2024-3094)](https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094)
- [event-stream incident discussion](https://github.com/dominictarr/event-stream/issues/116)
- [GitHub Docs: About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub Docs: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
