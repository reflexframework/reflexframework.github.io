---
title: GitHub OIDC Misconfiguration
category: Infrastructure & Cloud
ref: RFX-INF-03
precedent: "2023"
scenario: Over-trusting cloud roles federated to GitHub Actions
focus:
  - broad sub conditions in trust policies
  - pull_request_target inheriting the base ref
  - unpinned reusable workflows
---

## Scenario

A company deploys to AWS from GitHub Actions using OpenID Connect (OIDC). There are no stored AWS keys. Each job requests a short-lived token from GitHub and exchanges it for a role. That part is good. The trust policy behind the role is where it goes wrong.

The production deploy role trusts this:

```json
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
  },
  "StringLike": {
    "token.actions.githubusercontent.com:sub": "repo:my-cool-org/*:*"
  }
}
```

That matches any workflow, in any repository, on any branch or pull request in the organisation.

1. An attacker phishes a contractor who has write access to `my-cool-org/docs-site`, a low-value repository with no branch protection.
2. They push a workflow to a feature branch that requests an OIDC token and assumes the production role. The `sub` is `repo:my-cool-org/docs-site:ref:refs/heads/feature-x`, which the wildcard accepts.
3. They now hold production AWS credentials.

The application repository has a second problem. Its deploy job calls `my-cool-org/reusable-workflows/.github/workflows/deploy.yml@main`. That repository has weaker protection than the app. Anyone who can push to its `main` branch changes what every production deploy runs, and the trust policy cannot tell the difference.

::: {! precedent}
**Real-world precedent:** In 2023 several research teams found AWS roles trusting GitHub's OIDC provider with no `sub` condition, so any GitHub repository could assume them ([Wiz research](https://www.wiz.io/blog/avoiding-mistakes-with-aws-oidc-integration-conditions)). AWS IAM now rejects GitHub OIDC trust policies that omit `sub` or set it to a bare wildcard ([AWS IAM guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html#idp_oidc_Create_GitHub)).
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Role ARNs are not secret. They sit in public workflow files, Terraform modules and build logs. An attacker who finds one can test it from their own GitHub repository. If the trust policy is loose, the role assumption simply succeeds.

Inside an organisation, the attacker looks for the weakest repository that a trust policy will accept. Sandbox repositories, docs sites and abandoned projects are typical.

### Insight

The `sub` claim is the only thing standing between "our workflow" and "any workflow". Everything in this attack comes down to what that string matches.

### Practical

- Search your organisation for `role-to-assume:` and `aws-actions/configure-aws-credentials` to list every role used from Actions.
- Search for reusable workflow calls (`uses: .../.github/workflows/...@`) and note their refs.
- List every workflow with `permissions: id-token: write`.

### Tools/Techniques

- GitHub code search: `org:my-cool-org path:.github/workflows role-to-assume`.
- `aws iam list-roles` filtered for trust policies naming `token.actions.githubusercontent.com`.

### Metrics/Signal

- Number of IAM roles that trust GitHub's OIDC provider.
- Number of workflows that can mint OIDC tokens.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Read each trust policy and ask which token would satisfy it. GitHub's default `sub` formats differ by context:

- `repo:ORG/REPO:ref:refs/heads/main` for a branch push or manual run.
- `repo:ORG/REPO:environment:production` when the job uses an environment.
- `repo:ORG/REPO:pull_request` for `pull_request` events.

The trap is `pull_request_target`. It runs in the context of the base branch, so its token carries the base ref, such as `ref:refs/heads/main`. A policy that only trusts `main` will accept it. If that workflow checks out and runs fork code, the fork gets your production role.

### Insight

A trust policy scoped to a branch is only as strong as every workflow that can run on that branch. An environment-scoped `sub`, guarded by environment protection rules, is much harder to reach.

### Practical

- Flag any `sub` with `*` in the repository or context position.
- Flag `StringEquals` used with wildcards. It treats `*` literally, so the policy either fails or someone "fixes" it by widening it.
- Find `pull_request_target` workflows that have `id-token: write`.
- Check whether reusable workflows are called by branch, and whether that repository is as well protected as the caller.
- Decode a token in a test run to confirm the exact claims your jobs produce. Repositories created after 15 July 2026 use an immutable `sub` that includes numeric IDs, for example `repo:my-cool-org@123/app@456:ref:refs/heads/main`. Existing repositories keep the old format unless they opt in.

### Tools/Techniques

- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html) policy validation.
- [zizmor](https://github.com/zizmorcore/zizmor) to find `pull_request_target` workflows and unpinned reusable workflows.
- [GitHub OIDC claims reference](https://docs.github.com/en/actions/reference/security/oidc).

### Metrics/Signal

- Roles whose `sub` contains a repository or context wildcard.
- `pull_request_target` workflows with `id-token: write`.
:::

::: {! stage fortify}
## Fortify

### Explanation

Scope every role to one repository and one trusted context. For production, use a GitHub environment so the `sub` names it, and protect that environment with required reviewers and a deployment branch rule. Pin reusable workflows by commit SHA, and when a role should only be reachable through a central deploy workflow, require it with the `job_workflow_ref` claim.

### Insight

Environment protection rules are enforced by GitHub before the job gets a token. That makes them a much stronger gate than a branch name in a policy.

### Practical

A production trust policy scoped to one repository and environment:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:my-cool-org/app:environment:production"
        }
      }
    }
  ]
}
```

- Use `StringLike` only when you genuinely need a pattern, and keep the wildcard out of the organisation and repository parts.
- Call reusable workflows by SHA: `uses: my-cool-org/reusable-workflows/.github/workflows/deploy.yml@<full-sha>`.
- To trust only a central deploy workflow, [customise the `sub` claim](https://docs.github.com/en/actions/reference/security/oidc) to include `job_workflow_ref` and match it in the policy.
- Never grant `id-token: write` to a `pull_request_target` job.
- Plan for the immutable `sub` format: new and renamed repositories will not match name-only policies.

### Tools/Techniques

- [GitHub environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) with required reviewers and deployment branch rules.
- [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials).
- Terraform or CloudFormation for trust policies, so changes go through review.

### Metrics/Signal

- Production roles scoped to an environment `sub`.
- Reusable workflow calls pinned to SHAs.
:::

::: {! stage limit}
## Limit

### Explanation

If an attacker does assume a role, its permissions and session decide the damage. Separate roles per repository and per stage, so a docs pipeline can never reach production.

### Insight

One shared "GitHubActions" role for the whole organisation turns the weakest repository into the strongest credential.

### Practical

- Create one role per repository and environment, each with only the actions it needs.
- Keep `MaxSessionDuration` short, for example one hour.
- Put production in its own AWS account and apply service control policies.
- Add permissions boundaries to roles created by pipelines.

### Tools/Techniques

- AWS Organizations service control policies.
- [IAM Access Analyzer unused access findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html) to trim permissions.

### Metrics/Signal

- Number of repositories that can reach each production role (target: one).
- Roles with administrator-level permissions used from CI.
:::

::: {! stage expose}
## Expose

### Explanation

Every successful role assumption is logged in CloudTrail as `AssumeRoleWithWebIdentity`, including the token's subject. Alert when the subject is one you did not expect for that role.

### Insight

You know exactly which repositories and environments should use each role. Anything else is a strong signal.

### Practical

- Alert on `AssumeRoleWithWebIdentity` where the subject does not match the expected repository and environment.
- Alert on role assumptions outside your normal deploy windows.
- Watch the GitHub audit log for new workflows that request `id-token: write`, and for environment protection rule changes.

### Tools/Techniques

- AWS CloudTrail with CloudWatch metric filters or EventBridge rules.
- Amazon GuardDuty for anomalous use of the issued credentials.
- GitHub audit log streaming for environment and workflow changes.

### Metrics/Signal

- Role assumptions from unexpected subjects.
- Changes to environment protection rules on production environments.
:::

::: {! stage exercise}
## Exercise

### Explanation

Test your trust policies from the attacker's position. Use a sandbox AWS account and roles with no real permissions.

### Insight

Teams tend to trust the policy they wrote. Watching an unexpected repository get credentials is persuasive.

### Practical

1. In a sandbox account, create a role with no permissions and copy your production trust policy onto it.
2. From a different repository in your organisation, run a workflow that tries to assume it.
3. From the app repository, run a `pull_request_target` job that tries the same.
4. Record which attempts succeed and whether your CloudTrail alert fired.
5. Tighten the policy to an environment `sub` and repeat. Both attempts should fail.

### Tools/Techniques

- A sandbox AWS account.
- [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials) in a test workflow.
- `aws sts get-caller-identity` as the only call made with the assumed role.

### Metrics/Signal

- Number of unintended repositories or triggers that could assume the role.
- Time from test assumption to alert.
:::

## Further Reading

- [GitHub Docs: OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub Docs: Configuring OpenID Connect in AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [AWS IAM: Configuring a role for GitHub OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html#idp_oidc_Create_GitHub)
- [GitHub changelog: Immutable subject claims for OIDC tokens](https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens)
- [Wiz: Avoiding mistakes with AWS OIDC integration conditions](https://www.wiz.io/blog/avoiding-mistakes-with-aws-oidc-integration-conditions)
