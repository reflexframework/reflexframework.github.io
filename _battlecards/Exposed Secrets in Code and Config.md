---
 permalink: /battlecards/secrets
battlecard:
 title: Exposed Secrets in Code and Config
 category: Secrets Management
 scenario: Exposed Secrets
 focus: 
   - API keys in .env 
   - credentials in code 
   - leaked tokens in logs 
---

A developer, racing to deploy a new AI-powered feature, accidentally commits a `.env` file to a public GitHub repository. This file contains a high-privilege AWS access key, a production database connection string, and a powerful third-party API key for an LLM service like OpenAI. Within minutes, an automated bot scanning GitHub for patterns like `AKIA...` discovers the AWS key. 

The attacker immediately uses it to spin up a fleet of expensive GPU instances for crypto-mining, racking up thousands of dollars in charges. Simultaneously, they use the database credentials to exfiltrate a table of user PII and leverage the OpenAI key for their own purposes, leading to a massive, unexpected bill and a serious data breach.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Reconnaissance is the attacker's first step: finding your secrets. This isn't usually a targeted, sophisticated attack against your company. More often, it's automated bots or low-level attackers running continuous, wide-net scans across public internet assets like GitHub, GitLab, and Pastebin. They search for common key patterns, filenames like `.env`, or keywords like `api_key` and `password`. The goal is to find low-hanging fruit—credentials that are easy to find and use immediately.

### Insight
The time from exposure to compromise is measured in seconds, not days. Automated scanners are incredibly fast and efficient. The moment a secret hits a public repository, you should assume it's been compromised. This isn't a "maybe someone will find it" situation; it's a "when will the first bot use it" certainty.

### Practical
*   **Map Your Footprint:** As a team, identify all your public code repositories, public S3 buckets, and any other public-facing assets where code or configuration might exist.
*   **Think Like an Attacker:** Use GitHub's advanced search to look for sensitive strings within your own organization's public repositories. Search for things like `filename:.env org:your-org` or `"internal-api-key" org:your-org`.
*   **Review Your History:** Remember that Git history is a treasure trove. A secret removed in a recent commit can still be found by cloning the repository and checking out an older commit.

### Tools/Techniques
*   **Code Scanning Tools:**
*   [Gitleaks](https://github.com/gitleaks/gitleaks): An open-source tool that scans git repository history for secrets.
*   [TruffleHog](https://github.com/trufflesecurity/trufflehog): Scans for secrets by digging deep into commit history and checking for high-entropy strings.
*   [Git-secrets](https://github.com/awslabs/git-secrets): An AWS tool to prevent you from committing passwords and other sensitive information to a git repository.
*   **Search Engines:**
*   [Shodan](https://www.shodan.io/): A search engine for internet-connected devices; can be used to find misconfigured servers exposing `.env` files over HTTP.

### Metrics/Signal
*   Number of public repositories owned by your organization.
*   Findings from a manual or automated scan of your public assets for exposed secrets.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward to find out how vulnerable you are to the scenario. It involves auditing your code, your CI/CD pipelines, and your team's day-to-day practices. Where are secrets stored? How are they shared between developers? Are they visible in logs or build artifacts? You are essentially performing reconnaissance on yourself to find weaknesses before an attacker does.

### Insight
A perfect `.gitignore` file is only a starting point. A developer can still accidentally force-push a sensitive file with `git add -f .env`. Vulnerability often lies in process gaps and developer habits, not just missing lines of configuration. For example, a common blind spot is secrets being printed in CI/CD logs during a failed test run.

### Practical
*   **Code Review:** Systematically search your entire codebase for hardcoded credentials. Look for common patterns like `password =`, `api_key:`, or IP addresses of internal services.
*   **Configuration Audit:** Check your `.gitignore` files in every repository. Ensure they include `.env`, `*.pem`, `credentials.json`, and other common sensitive file types.
*   **Pipeline Inspection:** Review your CI/CD pipeline configurations (e.g., `Jenkinsfile`, `.github/workflows/`). Are secrets being passed as plain text? Are they being masked in the logs? Run a build and inspect the raw log output.
*   **Log Analysis:** Check the logging configuration in your applications. Are you logging entire HTTP request/response objects, which might contain session tokens or API keys in headers or bodies?

### Tools/Techniques
*   **Static Analysis (SAST):**
*   [Semgrep](https://semgrep.dev/): An open-source, fast static analysis tool with rules to detect hardcoded secrets.
*   [Snyk Code](https://snyk.io/product/snyk-code/): Scans your code for security vulnerabilities, including hardcoded secrets.
*   **Pre-commit Hooks:**
*   [pre-commit](https://pre-commit.com/): A framework for managing and maintaining multi-language pre-commit hooks. You can integrate tools like `TruffleHog` or `Gitleaks` to run on every `git commit`.

### Metrics/Signal
*   Number of hardcoded secrets found by SAST scans per week.
*   Percentage of repositories in your organization that have a secret-scanning pre-commit hook configured.
*   Time-to-remediate for a critical hardcoded secret vulnerability after it's discovered.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about proactively building strong defenses to prevent secrets from being exposed in the first place. The core principle is to treat secrets as toxic waste: handle them as little as possible, store them in a secure and centralized location, and provide them to an application only when it needs them.

### Insight
The most effective strategy is to remove the developer from the equation of handling raw production secrets. If a developer never sees or manages a production credential, they can't accidentally leak it. Secrets should be injected into the application environment at runtime by an automated, trusted system.

### Practical
*   **Centralize Secrets:** Adopt a dedicated secret management tool. Stop using `.env` files, shared documents, or private chat messages for anything other than local, non-sensitive development.
*   **Inject, Don't Store:** Configure your deployment process (e.g., in Kubernetes, AWS ECS, or your CI/CD pipeline) to fetch secrets from the central store and inject them as environment variables into the running application container. The secret never touches the codebase or the developer's machine.
*   **Enforce `.gitignore`:** Use a global or template-based `.gitignore` for all new projects to ensure consistency.
*   **Filter Logs:** Implement log filtering or redaction at the application level to automatically strip out data that looks like a credential, token, or PII before it's sent to your logging provider.

### Tools/Techniques
*   **Secret Management Systems:**
*   [HashiCorp Vault](https://www.vaultproject.io/): A powerful open-source tool for managing secrets and protecting sensitive data.
*   [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/): A managed service for storing and rotating secrets on AWS.
*   [Google Secret Manager](https://cloud.google.com/secret-manager): Google Cloud's managed secrets store.
*   [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/): Managed secrets, keys, and certificates for Azure.
*   **Developer-focused Secret Management:**
*   [Doppler](https://www.doppler.com/): A platform focused on making secret management easy for developers across different environments.

### Metrics/Signal
*   Percentage of applications integrated with a central secret manager.
*   Number of build failures caused by CI/CD secret scanning checks (a good sign that the system is catching mistakes).
*   Zero hardcoded secrets detected in new code contributions over a 30-day period.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume a breach will happen. Limiting is about minimizing the damage when a secret is inevitably exposed. If an attacker gets a key, what's the worst they can do? A well-architected system ensures the answer is "not much." This is achieved by strictly adhering to the principle of least privilege and reducing the lifetime of every credential.

### Insight
A static, long-lived credential with administrator-level permissions is a ticking time bomb. The goal is to make any single compromised secret far less valuable. An attacker who steals a key that can only read from one specific S3 bucket and expires in 5 minutes has a much smaller window of opportunity than one who steals a permanent key that can control your entire cloud account.

### Practical
*   **Scope Down Permissions:** For every API key or service account, grant it the absolute minimum set of permissions required to do its job. If an application only needs to read objects from an S3 bucket, give it an `s3:GetObject` permission, not `s3:*`.
*   **Automate Key Rotation:** Never create "permanent" keys. Use your secret manager or cloud provider's features to automatically rotate keys every 30, 60, or 90 days.
*   **Use Dynamic, Short-Lived Credentials:** Instead of giving an application a static database password, use a tool like Vault to generate a unique database credential with a short time-to-live (TTL) of a few minutes or hours. The application fetches a new credential upon startup.
*   **Isolate Environments:** Use completely separate credentials, or even separate cloud accounts, for your development, staging, and production environments. A compromised `dev` key should never grant access to `prod`.

### Tools/Techniques
*   **Identity and Access Management (IAM):**
*   [AWS IAM](https://aws.amazon.com/iam/): The core service for managing permissions in AWS.
*   [Google Cloud IAM](https://cloud.google.com/iam): Manages permissions for Google Cloud resources.
*   **Short-Lived Credential Generation:**
*   [HashiCorp Vault's Dynamic Secrets](https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql): Vault can connect to a database and generate temporary credentials on the fly.
*   [AWS STS (Security Token Service)](https://aws.amazon.com/iam/features/mfa-and-temporary-credentials/): Allows you to grant temporary, limited-privilege credentials.

### Metrics/Signal
*   Maximum credential age for any static secret (e.g., target <= 90 days).
*   Percentage of IAM roles that have wildcard (`*`) permissions.
*   Average TTL for dynamically generated secrets.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about detection and response. How do you know a secret has been compromised and is being used by an attacker? This requires robust monitoring, logging, and alerting on the activity associated with your credentials. You need to establish a baseline of "normal" behavior so you can quickly identify anomalies that signal an attack.

### Insight
Attackers often reveal themselves through their actions. A developer in North America using an AWS key during business hours to access EC2 is normal. That same key being used at 3 AM from an IP address in an unfamiliar country to access a service that has never been used before (like a data warehousing service) is a major red flag. The faster you can detect this anomaly, the faster you can respond.

### Practical
*   **Enable Audit Logs:** Turn on audit logging for your cloud provider (e.g., AWS CloudTrail, Google Cloud Audit Logs) and critical third-party services. These logs record every single API call made with your credentials.
*   **Set Up Billing Alerts:** The most obvious sign of a compromised cloud key is a sudden, massive spike in your bill. Set up automated billing alerts that notify you when costs exceed a certain threshold.
*   **Monitor for Anomalies:** Create alerts for suspicious API call patterns:
*   Activity from unusual geographic locations.
*   A key being used to access services or regions it never has before.
*   A high rate of "permission denied" errors, which could indicate an attacker probing the limits of a key.
*   **Leverage Provider Protections:** Enable services like GitHub's secret scanning, which automatically detects committed secrets for many common services (like AWS, Stripe, and Twilio) and notifies the provider to take protective action, often by automatically revoking the key.

### Tools/Techniques
*   **Cloud Monitoring:**
*   [AWS CloudTrail](https://aws.amazon.com/cloudtrail/): Logs all API activity in your AWS account.
*   [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit): Provides a trail of activity in Google Cloud.
*   **Automated Scanning:**
*   [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning): Scans public (and private, with a license) repositories for known secret formats.
*   **Log Analysis and SIEM:**
*   [Datadog Cloud SIEM](https://www.datadoghq.com/product/cloud-siem/): Correlates logs from different sources to detect threats.
*   [Splunk](https://www.splunk.com/): A powerful platform for searching, monitoring, and analyzing machine-generated data.

### Metrics/Signal
*   Alerts triggered for API calls from a geo-location outside of your team's normal operating countries.
*   A sudden spike in the daily cloud bill by more than 20%.
*   Number of notifications received from GitHub Secret Scanning per month.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about practicing your defense and response. You wouldn't send a firefighter into a building without training; you shouldn't wait for a real incident to test your security processes. By running drills and simulated attacks, developers and operations teams build the "muscle memory" needed to respond quickly and effectively under pressure.

### Insight
A security playbook sitting on a shared drive is useless if no one has ever read it. The goal of an exercise isn't to pass or fail, but to find the flaws in your plan. You might discover that the person with the authority to revoke a key is on vacation with no backup, or that your monitoring tools produce so much noise that the real alert gets missed. These are invaluable lessons to learn in a drill, not during a real crisis.

### Practical
*   **Tabletop Exercise:** Gather the team and walk through the attack scenario verbally. "A developer just messaged on Slack that they accidentally committed an AWS key. What is the first thing we do? Who is responsible for revoking the key? How do we communicate with the team?"
*   **Live Fire Drill (Controlled):** Create a *fake* but realistic-looking credential (e.g., `FAKE_AWS_KEY_...`) and have a team member commit it to a test repository. See how long it takes for your automated scanning and monitoring tools to fire an alert. Then, practice the full revocation and post-mortem process.
*   **Create an Incident Response Playbook:** Document the step-by-step process for handling a leaked secret. This should include:
1.  **Identification:** How the leak was found.
2.  **Containment:** The immediate steps to revoke the secret and block the attacker.
3.  **Eradication:** How to ensure the attacker is out of the system.
4.  **Recovery:** How to restore services safely.
5.  **Lessons Learned:** The post-mortem process.

### Tools/Techniques
*   **Playbook Development:** Use templates and frameworks like those from [NIST](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) (Computer Security Incident Handling Guide) as a starting point.
*   **Internal Training:** Use platforms like [Secure Code Warrior](https://www.securecodewarrior.com/) or internal "Capture The Flag" (CTF) events to train developers on how to spot and avoid secret management anti-patterns.

### Metrics/Signal
*   **Time to Detect (TTD):** In a drill, the time from when the fake secret is committed to when the first alert is triggered.
*   **Time to Remediate (TTR):** The time from the initial alert to the secret being successfully revoked and confirmed.
*   Percentage of the engineering team that has participated in a security drill in the last 6 months.
{% endblock %}