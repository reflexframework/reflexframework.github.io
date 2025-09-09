---
 permalink: /battlecards/terraform
battlecard:
 title: Terraform Module Attacks
 category: Infra-as-Code
 scenario: Terraform
 focus: 
   - poisoned modules 
   - state file leakage 
---
{% block type='battlecard' text='Scenario' %}
**Infrastructure as Code (IaC) / Terraform: Poisoned Modules & State File Leakage**

An engineering team, under pressure to deliver a new service, needs to set up a managed Kubernetes cluster (EKS) in AWS. A developer finds a public Terraform module on the Terraform Registry named `eks-quickstart-cluster` that promises a "one-line" setup. The module is a typosquatted version of a popular, legitimate module.

The developer adds this module to their project. When they run `terraform apply`, the malicious module performs two actions:
1.  **Poisoned Module:** It provisions the EKS cluster as advertised, but it also silently adds a `NodePort` service to the cluster that exposes the Kubernetes API server publicly. It also creates a new, hard-to-notice IAM user named `ec2-instance-metadata-svc` with broad administrative privileges.
2.  **State File Leakage:** The module uses a `local-exec` provisioner to `curl` the `terraform.tfstate` file to an attacker-controlled server. Because the team is still prototyping, they are using the default local state file, which now contains the EKS cluster details, VPC configuration, and the access keys for the newly created backdoor IAM user.

The attacker now has both a compromised state file full of secrets and persistent, high-privilege access to the team's AWS account.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. Their goal is to create a convincing trap for developers. They aren't targeting your company specifically yet; they are building a tool to exploit the common developer practice of using open-source components to move faster. They know that IaC modules often have privileged access to create infrastructure, making them a high-value target.

The attacker's tactics include:
*   **Typosquatting & Impersonation:** They search public registries for popular modules and publish their own with very similar names (e.g., `eks-quickstart-cluster` instead of `eks-cluster-quickstart`). They copy the original module's README and documentation to appear legitimate.
*   **Trojan Horse:** They create a genuinely useful module that solves a common problem but hide malicious code within it. The malicious code is often obfuscated or uses subtle misconfigurations that look like mistakes, not malice.
*   **Public Scanning:** In parallel, they run automated scanners across public code repositories like GitHub, looking for accidentally committed sensitive files, specifically `terraform.tfstate`, `*.tfvars` files containing passwords, or hardcoded credentials.

### Insight
Attackers weaponize convenience. They understand that developers are rewarded for shipping features quickly and may not have the time or expertise to perform deep security validation on every third-party code snippet or module they use. They exploit the implicit trust developers place in public package and module registries.

### Practical
*   Understand that when you search for a module, you are being targeted by attackers who have set traps.
*   Think about the "blast radius" of the credentials on your developer machine. If you run `terraform apply` from your laptop with your admin-level user, any module you use inherits those god-like permissions.
*   Check your own public GitHub repositories. Have you or a team member ever accidentally committed a `.tfstate` file or a file with secrets?

### Tools/Techniques
*   **GitHub Code Search:** Attackers use advanced search queries (dorks) like `filename:terraform.tfstate` or `path:*.tfvars "password ="`.
*   **Automated Scanners:** Tools like [truffleHog](https://github.com/trufflesecurity/truffleHog) or [Gitleaks](https://github.com/gitleaks/gitleaks) are used by attackers (and defenders) to scan repositories for secrets.
*   **Terraform Registry:** Attackers browse the [Terraform Registry](https://registry.terraform.io/) to identify popular modules to impersonate.

### Metrics/Signal
*   This stage is performed by the attacker, so there are no direct signals for a developer. The key takeaway is awareness of these tactics.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking in the mirror. How vulnerable are you *right now* to this attack? It involves auditing your team's current practices, codebases, and infrastructure to find the weak spots an attacker would exploit. The goal is to identify risks before they are exploited.

### Insight
Your team's culture around security and speed is a key indicator of vulnerability. A culture that prioritizes shipping code over reviewing dependencies is at high risk. The most common and dangerous practice is using local state files and un-versioned, unvetted modules from public sources.

### Practical
1.  **Audit Your Module Sources:** Open your Terraform projects and look at the `source` attribute in your `module` blocks. Where do they come from? Are they from the official HashiCorp, AWS, or Google authors, or from unverified individual publishers?
2.  **Check for Local State Files:** Run the command `find . -name "*.tfstate"` in your code repositories. If this returns any results, you are using local state, which is a major security risk for teams.
3.  **Review your `.gitignore`:** Ensure that `*.tfstate`, `*.tfstate.*`, `.terraform/`, and `*.tfvars` are present in your project's `.gitignore` file to prevent accidental commits.
4.  **Assess CI/CD Permissions:** What IAM role or user does your CI/CD pipeline (e.g., GitHub Actions, Jenkins) use to run `terraform apply`? Does it have admin access, or is it scoped to only the resources it needs to manage?

### Tools/Techniques
*   **IaC Scanners:** Use static analysis tools to scan your code for misconfigurations and bad practices.
*   [tfsec](https://github.com/aquasecurity/tfsec)
*   [Checkov](https://www.checkov.io/)
*   [Terrascan](https://github.com/tenable/terrascan)
*   **Supply Chain Security:** Tools that can analyze your dependencies.
*   [Snyk IaC](https://snyk.io/product/infrastructure-as-code-security/)
*   [Bridgecrew (by Prisma Cloud)](https://www.paloaltonetworks.com/prisma/cloud/infrastructure-as-code-security)

### Metrics/Signal
*   **Module Source Ratio:** Percentage of modules sourced from a private, internal registry vs. public registries. A higher ratio of internal modules is better.
*   **State File Exposure:** Number of `terraform.tfstate` files found in your version control system. This should be zero.
*   **Use of Remote State:** Percentage of projects configured to use a remote state backend. This should be 100%.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is the proactive hardening phase. Based on your evaluation, you'll implement changes to your development practices, pipelines, and infrastructure to make the attack scenario much more difficult for an attacker to pull off.

### Insight
Treat your infrastructure code with the same supply-chain rigor as your application code. You wouldn't use an unknown, unvetted library in your production application, and you shouldn't use an unvetted module to build your production infrastructure. Your Terraform state is one of your most sensitive assets; protect it accordingly.

### Practical
*   **Use a Remote Backend for State:** This is non-negotiable for teams. Store your state file in a centralized, access-controlled, and encrypted location.
*   **Action:** Configure a backend like [AWS S3](https://www.terraform.io/language/settings/backends/s3) (with a DynamoDB table for state locking), [Azure Blob Storage](https://www.terraform.io/language/settings/backends/azurerm), or [Google Cloud Storage](https://www.terraform.io/language/settings/backends/gcs).
*   **Example S3 Backend Config:**
```hcl
terraform {
backend "s3" {
bucket         = "my-tf-state-bucket-unique-name"
key            = "global/s3/terraform.tfstate"
region         = "us-east-1"
dynamodb_table = "my-tf-state-lock-table"
encrypt        = true
}
}
```
*   **Vet and Vendor Your Modules:** Don't source modules directly from public registries in production code.
*   **Action:** Fork the public module into your own private Git organization. This allows you to review the code for backdoors or vulnerabilities. Then, in your Terraform code, source the module from your own Git repository, pinning it to a specific commit hash or tag. This prevents malicious upstream changes from affecting you.
*   **Example Module Sourcing:**
```hcl
module "my_vpc" {
# Pinning to a specific tag/release in your forked repo
source = "git@github.com:my-org/terraform-aws-vpc.git?ref=v3.2.0"
}
```
*   **Use a Private Module Registry:** For mature teams, a private registry provides a central, trusted source for all shared modules.

### Tools/Techniques
*   **Remote Backends:** [AWS S3](https://www.terraform.io/language/settings/backends/s3), [AzureRM](https://www.terraform.io/language/settings/backends/azurerm), [GCS](https://www.terraform.io/language/settings/backends/gcs).
*   **Private Registries:** [Terraform Cloud](https://www.hashicorp.com/products/terraform/private-registry), [JFrog Artifactory](https://jfrog.com/community/devops-tools/terraform-registry/).
*   **Pull Request Automation:** Use tools like [Atlantis](https://www.runatlantis.io/) to automatically run `terraform plan` and post the output in pull requests, making peer review of infrastructure changes easier and more consistent.

### Metrics/Signal
*   **Remote State Adoption:** 100% of projects are using a configured remote backend.
*   **Immutable Module Sources:** 100% of module sources are pinned to a specific commit hash or tag (e.g., contains `?ref=...`).
*   **Private Source Percentage:** An increasing percentage of modules are sourced from internal, private repositories.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and a malicious module was applied. This stage is about damage control. How could you have designed your system to contain the "blast radius" of the compromise, ensuring the attacker can do as little damage as possible?

### Insight
The principle of least privilege is your most powerful defense. A malicious module can only perform actions that the credentials used to run Terraform allow. If Terraform is run with god-mode administrator privileges, the blast radius is your entire cloud account. If it's run with a tightly scoped role, the damage is contained to a small set of resources.

### Practical
*   **Scope Down CI/CD Permissions:** Don't use a single, all-powerful IAM role for all of your Terraform pipelines. Create specific roles for specific projects. A pipeline for a static website only needs S3 and CloudFront permissions, not permission to create IAM users or modify VPCs.
*   **Use Short-Lived Credentials:** Use OpenID Connect (OIDC) to generate short-lived, role-based credentials for each CI/CD job. This eliminates the need to store long-lived secrets in your CI/CD platform.
*   **Don't Store Secrets in State:** This is critical. If your state file is stolen, the impact is much lower if it doesn't contain database passwords, API keys, or other secrets.
*   **Action:** Instead of passing secrets as variables, store them in a dedicated secrets manager (like AWS Secrets Manager or HashiCorp Vault). In your Terraform code, pass a *reference* to the secret. The application code then fetches the secret at runtime.
*   **Implement Policy-as-Code:** Automatically check the `terraform plan` output in your CI/CD pipeline *before* applying. If the plan includes a change you want to forbid (like creating a new IAM user or a security group open to the world), the pipeline should fail.

### Tools/Techniques
*   **Short-Lived Credentials:** [GitHub Actions OIDC Connect with AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services), [HashiCorp Vault Dynamic Secrets](https://www.vaultproject.io/docs/secrets/databases).
*   **Secrets Management:** [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/), [Google Secret Manager](https://cloud.google.com/secret-manager).
*   **Policy-as-Code:** [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) with [Conftest](https://www.conftest.dev/) to write policies against the Terraform plan JSON output.

### Metrics/Signal
*   **CI/CD Credential TTL:** The average Time-to-Live (TTL) of credentials used in CI/CD should be measured in minutes, not days or months.
*   **Secrets in State:** Number of plaintext secrets found in state files (run scans to ensure this is 0).
*   **Policy Block Rate:** The number of CI/CD runs blocked by your OPA policies. A non-zero number shows the system is working.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
How do you detect an attack in progress or one that has already occurred? This stage focuses on the monitoring, logging, and alerting required to gain visibility into suspicious activity related to your infrastructure and IaC pipelines.

### Insight
You need to be able to "see" what's happening at two key points: during the code review/CI process and in the cloud environment after deployment. Detecting a malicious change *before* it's applied is infinitely cheaper and safer than trying to find a backdoor in a complex cloud environment.

### Practical
*   **Enforce `plan` Reviews:** Make reviewing the `terraform plan` output a mandatory and rigorous part of your pull request process. Train developers to look for unexpected or suspicious resource creations/changes, such as:
*   New IAM users, roles, or policies.
*   Security group rules that open ports to `0.0.0.0/0`.
*   Unexpected `local-exec` or `remote-exec` provisioners.
*   **Monitor Your State Backend:** Enable server access logging on your S3 bucket (or equivalent) that holds your state files. Ingest these logs into your security monitoring tool and create alerts for any access from unexpected IP ranges, countries, or IAM principals. A `GetObject` call on your state file from anything other than your CI/CD role or authorized developers is a major red flag.
*   **Monitor Cloud Audit Logs:** Use services like AWS CloudTrail to monitor API activity. An alert should be triggered if the new IAM user (`ec2-instance-metadata-svc` from our scenario) created by Terraform immediately starts making API calls from a non-AWS IP address.
*   **Use Cloud Security Posture Management (CSPM):** A CSPM tool constantly scans your cloud environment for misconfigurations. It would immediately flag the new, overly permissive IAM user and the publicly exposed Kubernetes API created by the malicious module.

### Tools/Techniques
*   **Cloud Audit Logs:** [AWS CloudTrail](https://aws.amazon.com/cloudtrail/), [Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/overview), [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit).
*   **Threat Detection:** [AWS GuardDuty](https://aws.amazon.com/guardduty/) can automatically detect anomalous API behavior, such as credentials created by Terraform being used in a suspicious way.
*   **CSPM Tools:** [AWS Security Hub](https://aws.amazon.com/security-hub/), [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction), [Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud).
*   **SIEM/Log Analysis:** [Splunk](https://www.splunk.com/), [Datadog Cloud SIEM](https://www.datadoghq.com/product/cloud-siem/), [Elastic Security](https://www.elastic.co/security).

### Metrics/Signal
*   **State File Access Alerts:** Number of alerts triggered by unexpected access to your Terraform state files. This should be zero.
*   **Mean Time to Detect (MTTD):** How long does it take for your CSPM or threat detection tool to flag a malicious resource after it has been created by Terraform?
*   **PR Review Signal:** Alert on pull requests where the `terraform plan` contains high-risk resource types (e.g., `aws_iam_access_key`) to draw extra scrutiny from reviewers.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is about building muscle memory. You can have the best tools and processes in the world, but if your developers don't know how to use them under pressure, they will fail. This stage is about practicing your response to this attack scenario in a safe environment.

### Insight
Security is a team sport. Running exercises democratizes security knowledge, moving it from a specialized team to every developer who writes infrastructure code. It turns abstract security policies into tangible skills and helps identify gaps in your defenses that only become apparent through practice.

### Practical
*   **Tabletop Exercise:**
*   **Scenario:** Gather the team and present them with a pull request containing a `terraform plan` that uses a new, unvetted module. The plan output clearly shows the creation of an unexpected IAM user.
*   **Goal:** Ask the team: "What do you do?" Walk through the process. Who should review this? What questions should they ask? Where do they look for information about the module? What is the process for rejecting the PR and explaining the risk?
*   **Live Fire Exercise (in a Sandbox Account):**
*   **Scenario:** Have a "red team" (or a developer playing the role) create a pull request that uses a benign-but-suspicious Terraform module they wrote. This module could create a security group that opens port 22 to the internet.
*   **Goal:** Test the entire defense stack. Does the Policy-as-Code check in the CI/CD pipeline block the `apply`? If not, do the reviewers spot it? If it gets deployed, how quickly does the CSPM tool detect and alert on it?
*   **Capture the Flag (CTF):**
*   **Scenario:** Create a sample `terraform.tfstate` file that contains fake secrets (e.g., a database password, an API key).
*   **Goal:** Challenge developers to find the secrets. This exercise provides a powerful, hands-on lesson in *why* state file security is so critical and why secrets should never be stored in them.

### Tools/Techniques
*   **Internal Documentation:** Create and maintain a simple, clear wiki page titled "Our Rules for Using Terraform" that covers module sourcing, state management, and PR review expectations.
*   **Sandbox Environments:** Use dedicated, isolated AWS/Azure/GCP accounts for security exercises to ensure no impact on production.
*   **Red Teaming / Penetration Testing:** For mature organizations, hire external or use internal teams to formally test your IaC security posture.

### Metrics/Signal
*   **Exercise Success Rate:** Percentage of developers who correctly identify and block the suspicious change during a simulated exercise.
*   **Time to Remediate:** In a live fire exercise, measure the time from deployment of the misconfiguration to its detection and removal.
*   **Improved Developer Awareness:** Track whether developers start asking more security-focused questions during regular pull request reviews after conducting an exercise.
{% endblock %}