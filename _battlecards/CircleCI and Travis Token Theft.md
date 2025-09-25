---
 permalink: /battlecards/cicd
battlecard:
 title: CircleCI and Travis Token Theft
 category: CI/CD
 scenario: CircleCI/TravisCI
 focus: 
   - stolen tokens 
   - exposed secrets in logs 
---

An attacker uses an automated scanner on public GitHub repositories to find projects using CircleCI or TravisCI. The scanner identifies a repository where a developer, while debugging a build script, temporarily added `set -x` to their `.circleci/config.yml`. This command prints every executed command to the build logs. A subsequent command uses an environment variable, `export AWS_SESSION_TOKEN=...`, which is now exposed in the publicly accessible build logs on Circleci.com.

The attacker finds this token in the logs. Although it's a short-lived session token, it's still active. They use the token to gain read-only access to an S3 bucket. Inside the bucket, they find unencrypted Terraform state files. By parsing these files, the attacker discovers more valuable, long-lived credentials, including a `GITHUB_TOKEN` with write access to the organization's private repositories and a `DOCKER_HUB_PASSWORD`.

With these new credentials, the attacker pushes a malicious change to a widely used base Docker image stored in the organization's Docker Hub, adding a cryptominer. The next time the CI/CD pipeline runs to build the main application, it pulls the compromised base image, embedding the malware, which is then deployed to production.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's discovery phase. They aren't targeting you specifically but are running automated scans across public platforms like GitHub, looking for common patterns of misconfiguration. They search for CI/CD configuration files (`.circleci/config.yml`, `.travis.yml`), hardcoded API keys, or, in this case, publicly accessible build logs that might contain sensitive data. Their goal is to find one small foothold—a single leaked key—that they can use to start exploring your internal systems.

### Insight
Attackers operate at scale. They play a numbers game, knowing that among thousands of repositories, someone will have made a mistake. Your public repository and its associated CI logs are part of their attack surface. The ease and low cost of automated scanning mean that any public mistake is likely to be found quickly.

### Practical
- **Audit your visibility:** Identify all your public repositories that use CircleCI/TravisCI. Check if their build logs are public.
- **Self-scan:** Use secret-scanning tools to search your own code history for accidentally committed credentials.
- **Google Dorking:** Search for potentially exposed information using queries like `site:circleci.com "your_company_name" "password"` or `inurl:travis-ci.org/your_org "SECRET_KEY"`.

### Tools/Techniques
-   [**TruffleHog**](https://github.com/trufflesecurity/truffleHog): Scans your git repository history for secrets, including checking entropy to find keys that don't match simple regexes.
-   [**gitleaks**](https://github.com/gitleaks/gitleaks): A static analysis tool for detecting hardcoded secrets like passwords, API keys, and tokens in git repos.
-   [**GitHub Code Scanning**](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning): Natively integrated into GitHub, it can find secrets and other vulnerabilities in your code.

### Metrics/Signal
-   Number of secrets found by automated scanners in your codebase.
-   Number of projects with publicly visible CI/CD build logs.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you turn the attacker's lens on yourself. You need to assess your CI/CD environment, configurations, and logs to determine how vulnerable you are to this scenario. The goal is to find weaknesses before an attacker does. This involves not just scanning for secrets in code, but reviewing the logic in your build scripts and the permissions granted to your CI/CD jobs.

### Insight
A common blind spot for developers is the runtime environment of the CI/CD pipeline itself. We focus on the code, but the environment where that code is built and tested is a treasure trove of secrets. A single `env` or `printenv` command in a build script can expose every secret available to that job.

### Practical
- **Review Build configurations:** Manually inspect your `.circleci/config.yml` or `.travis.yml` files. Look for commands that could print environment variables, such as `set -x`, `env`, `printenv`, or `echo "$SENSITIVE_VAR"`.
- **Audit Secret Scopes:** In CircleCI, check which [Contexts](https://circleci.com/docs/contexts/) are used in each workflow and who has access. In TravisCI, review who has permission to view or change environment variable settings. Are production secrets available in PR builds?
- **Log Review:** Download and programmatically scan the last month of build logs for high-entropy strings or keywords like `token`, `key`, `password`, `AKIA` (AWS Access Key ID prefix).

### Tools/Techniques
-   [**CircleCI CLI**](https://circleci.com/docs/local-cli/): Use the `circleci config validate` command to check for syntax errors, but this requires manual inspection for security flaws.
-   **Custom Scripts:** Use `grep`, `awk`, or scripts written in Python to download logs via the CircleCI/TravisCI API and scan for patterns indicating secret leakage.
-   [**Datadog's Sensitive Data Scanner**](https://docs.datadoghq.com/security/sensitive_data_scanner/): If you already forward logs to Datadog, you can configure it to find and alert on sensitive data patterns in your CI logs.

### Metrics/Signal
-   Percentage of CI/CD jobs that have been manually audited for potential secret leakage.
-   Number of build configurations that use commands known to expose environment variables (`set -x`, `env`).

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This stage is about proactively hardening your CI/CD pipeline to prevent secrets from being exposed in the first place. The focus is on robust secret management, secure configuration, and leveraging modern authentication methods that reduce the reliance on static, long-lived keys.

### Insight
The most effective defense is to make secrets as short-lived and inaccessible as possible. The "best" secret is one you never have to see or manage directly. Moving from long-lived API keys stored in CI environment variables to dynamic, short-lived credentials generated on-the-fly for each job is a massive security improvement.

### Practical
- **Use a Dedicated Secrets Manager:** Instead of storing secrets directly in CircleCI/TravisCI environment variables, store them in a dedicated tool like HashiCorp Vault or AWS Secrets Manager. Fetch them dynamically during the build.
- **Embrace OIDC:** Use [OpenID Connect (OIDC)](https://circleci.com/docs/openid-connect-tokens/) to establish a trust relationship between your CI provider and your cloud provider (AWS, GCP, Azure). This allows your jobs to authenticate and receive short-lived credentials without needing any long-lived keys stored in the CI system.
- **Mask Secrets in Scripts:** In shell scripts, wrap sensitive commands with `set +x` and `set -x` to prevent them from being printed to the log. For example:
```bash
set +x
docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"
set -x
```
- **Restrict Secret Access:** Use CircleCI Contexts or TravisCI's environment settings to ensure that secrets are only available to the specific jobs that need them (e.g., deployment jobs), not to pull request validation or testing jobs.

### Tools/Techniques
-   [**HashiCorp Vault**](https://www.vaultproject.io/): An industry-standard tool for managing secrets, with integrations for most CI/CD platforms.
-   [**AWS Secrets Manager**](https://aws.amazon.com/secrets-manager/) and [**GCP Secret Manager**](https://cloud.google.com/secret-manager): Managed cloud services for secret storage.
-   [**SOPS (Secrets OPerationS)**](https://github.com/mozilla/sops): An open-source editor of encrypted files that you can safely commit to Git, decrypting them at build time.

### Metrics/Signal
-   Percentage of secrets managed via a dedicated secrets store vs. native CI environment variables.
-   Number of CI/CD jobs using short-lived OIDC tokens vs. static, long-lived keys.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume a breach will happen. This stage is about damage control. If an attacker successfully steals a token from a CI job, how do you limit what they can do with it? This is achieved by applying the principle of least privilege, ensuring that any stolen credential has a minimal "blast radius."

### Insight
An attacker's goal after getting a foothold is to move laterally and escalate their privileges. Your goal is to build dead ends. A stolen token should only grant access to a single, non-critical resource for a few minutes. This turns a potential disaster into a minor, contained incident.

### Practical
- **Scoped, Single-Purpose Credentials:** Create a unique IAM role or service account for each distinct CI/CD task. A job that builds a Docker image should have credentials that *only* allow it to push to a specific image repository, not access production databases.
- **Short Token Lifespan:** When using OIDC or dynamically generating tokens, configure them with the shortest possible time-to-live (TTL) that still allows the job to complete (e.g., 15 minutes).
- **Environment-Specific Permissions:** Use different cloud accounts or IAM roles for `dev`, `staging`, and `prod`. A token stolen from a pull request build on a feature branch should have zero access to production resources.
- **Network Segmentation:** If your CI jobs run on self-hosted runners, use network policies (e.g., Kubernetes NetworkPolicies, VPC security groups) to restrict their outbound access to only the specific services they need to reach.

### Tools/Techniques
-   [**AWS IAM**](https://aws.amazon.com/iam/): The primary tool for creating and managing fine-grained access control policies in AWS.
-   [**GitHub's token permissions setting**](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token): A great model for defining what a CI job's token can do on a per-job basis (e.g., `contents: read`, `packages: write`).
-   [**CircleCI Orbs for Vault/AWS**](https://circleci.com/developer/orbs): Pre-packaged configurations that can simplify the process of fetching scoped, short-lived secrets.

### Metrics/Signal
-   Average lifespan of credentials used in CI/CD jobs.
-   Number of "god-mode" roles with overly permissive policies (e.g., `*:*`).
-   Number of distinct, single-purpose IAM roles used by CI/CD, versus a single monolithic role.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about detection. How do you know if a secret has been stolen and is being used maliciously? This requires monitoring and alerting on anomalous activity in your CI/CD platform, cloud environments, and source control systems. The goal is to get a signal as quickly as possible that something is wrong.

### Insight
Detection is about finding the unexpected. An attacker using your stolen AWS key from a server in a different country is a strong signal. Your CI/CD system authenticating to AWS at 3 AM when no jobs are scheduled is another. You need to establish a baseline of normal activity so you can spot the deviations that indicate a compromise.

### Practical
- **Centralize Logs:** Ship all CircleCI/TravisCI audit logs, build logs, and cloud provider logs (e.g., AWS CloudTrail) to a centralized security information and event management (SIEM) platform like Splunk, Datadog, or an ELK stack.
- **Create Alerts:** Set up specific alerts for suspicious activities:
- An AWS API key from your CI system used from an IP address that isn't a known CircleCI/TravisCI IP range.
- A `GITHUB_TOKEN` being used to create a new user or change repository permissions.
- A spike in resource usage in a CI job, which could indicate cryptojacking.
- **Use Honeypots:** Create "canary" tokens—fake credentials that are not used anywhere. Plant them in your CI/CD environment variables or in code. If you ever receive an alert that one was used, you know you have an intruder.

### Tools/Techniques
-   [**AWS CloudTrail**](https://aws.amazon.com/cloudtrail/): Logs every API call made in your AWS account. It's essential for investigating what an attacker did with stolen credentials.
-   [**Canarytokens**](https://canarytokens.org/generate): A free service from Thinkst Canary to create and manage honeypot tokens of various types (AWS keys, Slack tokens, etc.).
-   [**Falco**](https://falco.org/): A cloud-native runtime security tool that can detect unexpected application behavior, such as a build container making a suspicious outbound network connection.

### Metrics/Signal
-   Number of alerts generated for suspicious API calls originating from CI/CD credentials.
-   Time-to-detect for a triggered canary token.
-   Log data retention period (you need enough history to investigate an incident).

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice. Security is not just about tools; it's about people and processes. By simulating an attack, you can test your defenses, validate your response plans, and build "muscle memory" within the team so that everyone knows what to do when a real incident occurs.

### Insight
You don't want the first time you execute your incident response plan to be during a real, high-stress attack. Regular, low-stakes exercises build confidence and reveal gaps in your tooling, monitoring, and documentation that you can fix before they become critical.

### Practical
- **Tabletop Exercise:** Gather the development team and walk through the scenario verbally. "A developer alerts us that they think they leaked an AWS key in a CircleCI log. What's the first thing we do? Who do we notify? How do we revoke the key? How do we determine what the attacker accessed?"
- **Controlled Live Fire Exercise:**
1. Create a dedicated, sandboxed AWS account.
2. Intentionally "leak" a key for this account into a CI build log of a test application.
3. See if your monitoring and alerting systems (`Expose` stage) fire.
4. Have a developer follow the documented incident response plan to revoke the key and investigate the activity.
- **Security Education:** Use the findings from these exercises to educate developers. Show them a real (but sanitized) example of a leaked key and the alerts it generated. This is far more impactful than a generic security presentation.

### Tools/Techniques
-   [**Incident Response Playbooks**](https://www.atlassian.com/incident-management/handbook/playbooks): Create simple, clear, and accessible documentation for common security incidents like a leaked key.
-   [**CloudGoat**](https://github.com/RhinoSecurityLabs/cloudgoat): A "Vulnerable by Design" AWS environment that lets you practice exploiting and defending against common cloud security misconfigurations.
-   **Internal CTFs (Capture The Flag):** Create a fun challenge where developers have to find a "flag" (a piece of text) by finding a secret in old build logs or a misconfigured S3 bucket.

### Metrics/Signal
-   Time-to-detect and Time-to-remediate a simulated leaked credential.
-   Number of gaps in tooling or process identified during an exercise.
-   Percentage of developers who have participated in a security exercise in the last six months.
{% endblock %}