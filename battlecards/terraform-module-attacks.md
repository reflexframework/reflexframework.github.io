---
title: Terraform Module Attacks
category: Infrastructure & Cloud
scenario: Hijacked third-party Terraform module with a repointed version tag
focus:
  - mutable git tags on module sources
  - plan-time code execution
  - backdoor resources and secrets in state
---

## Scenario

A platform team manages its EKS clusters with Terraform. It uses a popular community module straight from GitHub, pinned to a tag:

```hcl
module "eks_addons" {
  source = "git::https://github.com/eks-helpers/terraform-aws-eks-addons.git?ref=v3.2.0"
  # ...
}
```

The module maintainer's GitHub account is compromised. The attacker pushes a malicious commit and force-moves the existing `v3.2.0` tag, and every other release tag, to point at it. Nobody bumps a version. The next CI run does a fresh `terraform init`, downloads the module, and gets the new code.

The malicious commit does three things:

1. Adds a `data "external"` block. External data sources run their program during `terraform plan`, so the payload executes on the first pull request plan, with whatever cloud credentials the plan job holds.
2. Flips the cluster's `endpoint_public_access` to `true` with `public_access_cidrs = ["0.0.0.0/0"]`, buried among routine add-on changes in a long plan.
3. Creates an IAM user with an access key and an admin policy attachment. The key lands in the state file in plain text, and a `local-exec` provisioner posts it to the attacker during apply.

The plan output shows all of this. It is also 400 lines long, and the reviewer approves it on a Friday afternoon.

**Real-world precedent:** In March 2025 attackers repointed the version tags of the [tj-actions/changed-files](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066) GitHub Action (CVE-2025-30066) to a malicious commit, so every workflow pinned to a tag ran the attacker's code. A Terraform module pinned with `?ref=<tag>` has exactly the same exposure.

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers look for widely used modules sourced straight from git, maintained by one person, with weak account security. Public Terraform code on GitHub shows them which modules your organisation uses, how they are pinned, and often which CI system runs plans on pull requests.

### Insight

Terraform modules run with your most powerful credentials: the ones that can create IAM users and change network boundaries. A module compromise is an infrastructure compromise.

### Practical

- List every module source in your code and classify it: local path, private registry, public registry, or git.
- For git sources, note whether `ref` is a tag, a branch or a commit SHA.
- For each third-party module, note the maintainer count and whether the repository enforces branch and tag protection.

### Tools/Techniques

- `rg -n 'source\s*=' --glob '*.tf'` to enumerate module sources.
- `terraform modules` (Terraform 1.10+) or `.terraform/modules/modules.json` after `init` to see resolved module versions.
- [OpenSSF Scorecard](https://scorecard.dev/) on the module's repository.

### Metrics/Signal

- Percentage of third-party module sources pinned to a commit SHA.
- Number of third-party modules with a single maintainer.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check how module versions are pinned, where `plan` runs and with which credentials, and what ends up in state.

### Insight

`.terraform.lock.hcl` records provider versions and checksums. It does not cover modules at all. A git tag is a mutable pointer, so `?ref=v3.2.0` can change under you without any change to your code. Registry module versions also come from git tags in the source repository, so pin them exactly and review the diff on every upgrade.

### Practical

- Check whether CI runs `terraform plan` automatically on pull requests, including from forks, and with what role.
- Search your code and third-party modules for `data "external"`, `local-exec`, `remote-exec` and the `http` data source. Each one needs a reason.
- Check what secrets live in state: database passwords, generated keys, IAM access keys.
- Check your S3 backend configuration. In Terraform 1.11 and later, `dynamodb_table` locking is deprecated in favour of `use_lockfile = true`.

### Tools/Techniques

- [Trivy](https://trivy.dev/) (which absorbed tfsec) and [Checkov](https://www.checkov.io/) for static IaC misconfiguration checks.
- `terraform show -json` to inspect plans and state as data.

### Metrics/Signal

- Plan jobs that run with write-capable credentials.
- Secrets found in state files.
:::

::: {! stage fortify}
## Fortify

### Explanation

Pin modules immutably, mirror the ones you depend on, keep secrets out of state, and put policy between plan and apply.

### Insight

A commit SHA cannot be moved. Pinning to one turns "the maintainer was hacked" into "we ignore their new commits until we review them".

### Practical

- Pin git module sources to a full commit SHA, with the release tag in a comment:

    ```hcl
    module "eks_addons" {
      # v3.2.0
      source = "git::https://github.com/eks-helpers/terraform-aws-eks-addons.git?ref=8f3c2a1d9b7e4f60a5c1d2e3f4a5b6c7d8e9f012"
    }
    ```

- Better still, fork or mirror third-party modules into your own organisation or private registry (HCP Terraform, or an OpenTofu-compatible registry), and update them through reviewed pull requests.
- Pin registry modules to an exact version (`version = "20.8.4"`), never a range.
- Keep generated secrets out of state with ephemeral resources (Terraform 1.10+) and write-only arguments (1.11+):

    ```hcl
    ephemeral "random_password" "db" {
      length = 32
    }

    resource "aws_db_instance" "app" {
      # ...
      password_wo         = ephemeral.random_password.db.result
      password_wo_version = 1
    }
    ```

- Use native S3 locking and encryption for state:

    ```hcl
    terraform {
      backend "s3" {
        bucket       = "acme-tf-state"
        key          = "platform/eks.tfstate"
        region       = "eu-west-2"
        encrypt      = true
        use_lockfile = true
      }
    }
    ```

    OpenTofu users can also enable client-side state encryption (OpenTofu 1.7+).

- Gate apply on policy checks against the plan:

    ```rego
    package main

    import rego.v1

    deny contains msg if {
        rc := input.resource_changes[_]
        rc.type == "aws_iam_access_key"
        "create" in rc.change.actions
        msg := sprintf("%s creates an IAM access key", [rc.address])
    }

    deny contains msg if {
        rc := input.resource_changes[_]
        rc.type == "aws_eks_cluster"
        rc.change.after.vpc_config[_].endpoint_public_access == true
        msg := sprintf("%s exposes the EKS API endpoint publicly", [rc.address])
    }
    ```

    ```bash
    terraform plan -out tfplan
    terraform show -json tfplan > plan.json
    conftest test plan.json
    ```

### Tools/Techniques

- [Conftest](https://www.conftest.dev/) or OPA for plan policies; Sentinel or OPA policies in HCP Terraform.
- Renovate's Terraform manager, which raises reviewable pull requests when tagged module sources (`?ref=v1.2.0`) have new releases.

### Metrics/Signal

- Third-party modules pinned to SHAs or mirrored internally.
- Applies blocked by policy, and why.
:::

::: {! stage limit}
## Limit

### Explanation

Make a malicious module run with as little power as possible, and make its most damaging changes impossible.

### Insight

Plan only needs to read. Apply needs to write. Giving them the same role hands plan-time payloads full write access.

### Practical

- Use separate cloud roles for plan (read-only) and apply (write), both via OIDC federation with no static keys.
- Do not run plans automatically on pull requests from forks. Require a maintainer to approve the run first.
- Run apply only from the main branch, behind an environment with required reviewers.
- Use AWS Organizations SCPs to deny `iam:CreateUser` and `iam:CreateAccessKey` to everything except a break-glass role.
- Keep the EKS API private by default and allow public access only through an explicit, reviewed exception.
- Restrict read access to the state bucket to the apply role and a small admin group.

### Tools/Techniques

- AWS IAM roles for GitHub Actions or HCP Terraform dynamic provider credentials.
- Service control policies for organisation-wide guardrails.

### Metrics/Signal

- Plan jobs running with write roles (should be zero).
- Accounts without an SCP blocking IAM user creation.
:::

::: {! stage expose}
## Expose

### Explanation

Detect a module that has changed under you, and detect the resources it creates.

### Insight

If a tag you depend on now points at a different commit, that is a near-certain sign of tampering. It is cheap to check.

### Practical

- In CI, compare each tag-pinned module's current commit against the one you recorded:

    ```bash
    expected=8f3c2a1d9b7e4f60a5c1d2e3f4a5b6c7d8e9f012
    actual=$(git ls-remote https://github.com/eks-helpers/terraform-aws-eks-addons.git 'refs/tags/v3.2.0^{}' | cut -f1)
    [ -z "$actual" ] && actual=$(git ls-remote https://github.com/eks-helpers/terraform-aws-eks-addons.git refs/tags/v3.2.0 | cut -f1)
    [ "$actual" = "$expected" ] || { echo "Tag v3.2.0 moved to $actual"; exit 1; }
    ```

- Alert on CloudTrail `CreateUser`, `CreateAccessKey` and `AttachUserPolicy` events from Terraform roles.
- Alert when an EKS cluster's `endpointPublicAccess` changes to true.
- Turn on drift detection (HCP Terraform health assessments, or a scheduled `terraform plan -detailed-exitcode`).

### Tools/Techniques

- AWS CloudTrail with EventBridge rules, or GuardDuty.
- AWS Config rules for EKS endpoint public access.

### Metrics/Signal

- Module tag mismatches detected.
- IAM user creations by automation roles.
:::

::: {! stage exercise}
## Exercise

### Explanation

Rehearse a moved tag against a module you control, in a sandbox account.

### Insight

You learn more from watching your pipeline consume a moved tag than from reading about tj-actions.

### Practical

1. Create a small module in a private sandbox repository and tag `v1.0.0`. Reference it by tag from a sandbox Terraform project.
2. Add a commit that creates an `aws_iam_access_key` and a `data "external"` that calls a [Canarytokens](https://canarytokens.org) URL. Force-move `v1.0.0` to it.
3. Open a pull request in the sandbox project. Check whether the tag-mismatch check fails, whether the canary fires during plan, and whether conftest blocks the apply.
4. Switch the reference to a SHA and repeat. Confirm nothing changes until someone updates the SHA.

### Tools/Techniques

- A sandbox cloud account with SCPs matching production.
- Canarytokens for a harmless callback.

### Metrics/Signal

- Which control stopped the attack first.
- Whether the canary fired during plan, which tells you plan-time execution is reachable.
:::

## Further Reading

- [CISA: Supply chain compromise of third-party GitHub Action tj-actions/changed-files (March 2025)](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066)
- [Terraform: module sources](https://developer.hashicorp.com/terraform/language/modules/sources)
- [Terraform: dependency lock file](https://developer.hashicorp.com/terraform/language/files/dependency-lock)
- [Terraform 1.11: ephemeral values and write-only arguments](https://www.hashicorp.com/blog/terraform-1-11-ephemeral-values-managed-resources-write-only-arguments)
- [Terraform S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)
