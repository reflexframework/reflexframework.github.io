---
title: Branch Protection and CODEOWNERS Gaps
category: Source Control & Review
ref: RFX-SRC-01
precedent: "2024"
scenario: Merging a backdoor through review gaps
focus:
  - paths with no code owner
  - approvals that survive new pushes
  - bypass lists and admin overrides
---

## Scenario

An attacker has phished a developer's GitHub session at a fintech company. They want to plant a backdoor in the authentication service without attracting attention.

The `main` branch requires one approval. CODEOWNERS covers most of the repository, but a new directory, `src/main/java/com/mycorp/auth/mfa/`, was added last month and nobody updated the file. It also has no entry for `.github/workflows/` or for CODEOWNERS itself.

1. The attacker opens a PR with a genuine, harmless refactor of the MFA module.
2. A colleague on another team approves it quickly.
3. After approval, the attacker pushes one more commit. It adds a hard-coded bypass code to the MFA check.
4. The branch rule does not dismiss stale approvals, and no code owner is required for that path. The PR merges with the original approval still attached.

::: {! precedent}
**Real-world precedent:** GitHub's "Require approval of the most recent reviewable push" setting exists to close exactly this post-approval gap ([GitHub Docs](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-reviews-before-merging)). The xz-utils backdoor (CVE-2024-3094, March 2024) showed how much damage a trusted account with merge rights can do; see [Developer Review Fatigue and Social Engineering](#battlecards-developer-review-fatigue-and-social-engineering-md).
:::

::: {! stage recon}
## Reconnaissance

### Explanation

An attacker with read access can learn a lot about your review rules. CODEOWNERS is a plain file in the repository. Merged PRs show how many approvals were needed and who usually gives them. The attacker looks for paths without owners, reviewers who approve fast, and whether approvals survive later pushes.

### Insight

Your review rules are only as strong as their least-covered path. Attackers look for that path deliberately.

### Practical

- Read your own CODEOWNERS as an attacker would. List sensitive paths with no owner.
- Remember that the last matching pattern wins. A later, broader line without owners can remove ownership from an earlier one.
- Look at recent merges: who approved, how fast, and whether commits landed after approval.

### Tools/Techniques

- GitHub's CODEOWNERS error check: `gh api repos/OWNER/REPO/codeowners/errors`.
- The PR timeline (commits after the approval event) in the GitHub UI or `gh pr view --json reviews,commits`.

### Metrics/Signal

- Sensitive directories with no CODEOWNERS match.
- PRs merged with commits pushed after the last approval.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check the rules that actually apply to `main`, from both classic branch protection and rulesets. Then check who can bypass them.

### Insight

Many organisations have good rules with a long bypass list. Every person and app on that list is a way around review.

### Practical

- Fetch the effective rules for a branch:

```bash
gh api repos/OWNER/REPO/rules/branches/main
gh api repos/OWNER/REPO/branches/main/protection
```

- Confirm these settings are on:
    - Require a pull request, with at least one approval (two for high-risk repositories).
    - Require review from Code Owners.
    - Dismiss stale pull request approvals when new commits are pushed.
    - Require approval of the most recent reviewable push.
    - Require status checks to pass.
    - Do not allow bypassing the above settings (classic protection), or an empty or minimal bypass list (rulesets).
- Check that CODEOWNERS has no syntax errors and that every listed owner has write access.

### Tools/Techniques

- [OpenSSF Scorecard](https://github.com/ossf/scorecard) `Branch-Protection` and `Code-Review` checks.
- [OpenSSF Allstar](https://github.com/ossf/allstar) to check branch protection across an organisation continuously.
- GitHub's ruleset insights page, which shows rule evaluations and bypasses.

### Metrics/Signal

- Repositories where `main` lacks code-owner review or stale-approval dismissal.
- Number of actors on each ruleset bypass list.
:::

::: {! stage fortify}
## Fortify

### Explanation

Use organisation-level rulesets so every repository gets the same baseline, and keep bypass lists short. Give CODEOWNERS a default owner, then add specific owners for sensitive paths, workflows and the CODEOWNERS file itself.

### Insight

Protecting `.github/workflows/` and `CODEOWNERS` matters most. Without that, an attacker can quietly change who reviews, or what CI runs.

### Practical

A CODEOWNERS file with a fallback owner and protected sensitive paths:

```text
# Default owner for everything
*                         @mycorp/maintainers

# Sensitive code
/src/main/java/com/mycorp/auth/   @mycorp/identity-team

# Pipeline and ownership rules
/.github/workflows/       @mycorp/platform-security
/.github/CODEOWNERS       @mycorp/platform-security
```

- Create an organisation ruleset targeting the default branch of every repository, with:
    - Require a pull request with code-owner review.
    - Dismiss stale approvals and require approval of the most recent reviewable push.
    - Required status checks, including your security scanners.
    - Block force pushes and deletions.
- Keep the bypass list empty for `main`, or limit it to a break-glass team with audit logging.
- Manage rulesets as code so changes themselves get reviewed.

### Tools/Techniques

- [GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).
- [CODEOWNERS reference](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).
- [Terraform GitHub provider](https://registry.terraform.io/providers/integrations/github/latest/docs) for rulesets and repository settings.

### Metrics/Signal

- Percentage of repositories covered by the organisation ruleset.
- CODEOWNERS coverage of sensitive paths, `.github/workflows/` and CODEOWNERS itself.
:::

::: {! stage limit}
## Limit

### Explanation

If a malicious change does merge, limit how far it travels before a human sees it. Separate merge from deploy, and protect production deployments with their own approval.

### Insight

Commit signing tells you which key signed a commit. It does not prove which person or machine made the change. A stolen session or key still produces "verified" commits.

### Practical

- Deploy to production through a GitHub environment with required reviewers.
- Keep production credentials scoped to that environment, so a merged change cannot reach them from a PR build.
- Use short-lived sessions and enforce SSO and 2FA for the organisation, to limit what a stolen session can do.
- Keep the ability to edit rulesets with a small group, separate from day-to-day maintainers.

### Tools/Techniques

- [GitHub environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) with required reviewers.
- Organisation SSO and 2FA enforcement.

### Metrics/Signal

- Time between merge to `main` and production deployment.
- Number of people who can change rulesets or bypass them.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for the events this attack produces: rules being weakened, bypasses being used, and merges where the approved code differs from the merged code.

### Insight

Ruleset bypasses and protection changes are rare in a healthy organisation. Each one deserves a look.

### Practical

- Alert on audit log events for ruleset and branch protection changes.
- Alert on ruleset bypasses.
- Alert on changes to CODEOWNERS or `.github/workflows/` merged without a platform security review.
- Periodically report PRs merged with commits after the final approval.

### Tools/Techniques

- [GitHub audit log streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise) for `repository_ruleset` and `protected_branch` events.
- Ruleset insights for bypass history.
- OpenSSF Allstar issues when a repository drifts from policy.

### Metrics/Signal

- Number of ruleset bypasses per month.
- Changes to protection on default branches.
:::

::: {! stage exercise}
## Exercise

### Explanation

Try the attack yourself in a sandbox repository that copies your production rules.

### Insight

Most teams find at least one path without an owner, or one person who can bypass everything.

### Practical

1. Copy your production ruleset and CODEOWNERS to a sandbox repository.
2. Open a PR touching an unowned path. Get it approved, then push a further commit.
3. Try to merge. Record whether the approval was dismissed and whether a code owner was required.
4. Try editing CODEOWNERS in a PR. Record who was asked to review.
5. Fix the gaps and repeat.

### Tools/Techniques

- A sandbox repository and two test accounts.
- `gh api repos/OWNER/REPO/rules/branches/main` before and after.

### Metrics/Signal

- Number of gaps found per exercise.
- Whether the post-approval push was blocked after fixes.
:::

## Further Reading

- [GitHub Docs: About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub Docs: About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub Docs: About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [OpenSSF Allstar](https://github.com/ossf/allstar)
