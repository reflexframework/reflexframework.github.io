---
 permalink: /battlecards/metadata
battlecard:
 title: Model Supply Chain Metadata Leaks
 category: AI/ML Supply Chain
 scenario: Model Metadata Exposure
 focus: 
   - sensitive info in model cards 
   - leaked environment variables in training logs 
   - debug artifacts bundled with models 
---
{% block type='battlecard' text='Scenario' %}
An attacker, browsing a public model repository like Hugging Face, discovers a new sentiment analysis model uploaded by a startup. Curious, they download the model artifacts. While inspecting the package, they find a `.zip` file containing not just the model weights, but also the full training logs from a few months ago.

By running a simple `grep` command for keywords like "key", "secret", and "token" on the log files, the attacker finds a set of AWS credentials (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`) that were accidentally printed to the console during a debugging session. The developer who ran the training job had their credentials configured as local environment variables, which were then captured by the logging framework.

The attacker tests the credentials and finds they are still active. The IAM permissions are overly permissive, granting them `s3:ListAllMyBuckets` and `s3:GetObject` access to the company's entire S3 environment. The attacker proceeds to exfiltrate proprietary training datasets, other pre-production models, and sensitive business documents, causing significant data loss and a major security breach.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
In this stage, the attacker is hunting for exposed information without actively trying to break in. They operate like a digital scavenger, sifting through publicly available data associated with your ML projects. They will scan public model hubs (Hugging Face, TensorFlow Hub), code repositories (GitHub, GitLab), and even public Docker images. Their goal is to find any metadata that gives them a foothold: credentials, internal server names, dataset paths, software versions, or even developer email addresses that could be used for phishing. Think of it as them looking at the "making of" documentary for your model to find mistakes.

### Insight
Attackers don't just look for obvious things like `PASSWORD=...`. They piece together small, seemingly harmless bits of information. A username in a file path (`/home/asmith/project/train.py`), the version of a library (`torch==1.9.0`), or an internal API endpoint (`http://model-builder.internal.corp:8080`) are all valuable clues. This information helps them build a map of your internal infrastructure, understand your tech stack, and tailor their next move.

### Practical
- **Search like an attacker:** Periodically search for your company or project name on GitHub and Hugging Face. Look for public forks of your repos or models uploaded by employees to personal accounts.
- **Audit your artifacts:** Before uploading a model, unpack it and inspect every file. Check log files, model card descriptions, and any supplementary code. Ask yourself: "If a competitor saw this, what could they learn?"
- **Review commit history:** Use tools to scan your entire Git history, not just the latest commit. A secret committed a year ago and removed five minutes later is still permanently stored in the Git history unless it's deliberately purged.

### Tools/Techniques
*   **[truffleHog](https://github.com/trufflesecurity/trufflehog):** Scans repositories for secrets, digging deep into commit history and branches.
*   **[gitleaks](https://github.com/gitleaks/gitleaks):** A SAST tool for detecting hardcoded secrets in git repositories.
*   **GitHub Search:** Use advanced search queries like `"org:your-org filename:.env"` or `"your-company-name AWS_SECRET_ACCESS_KEY"`.
*   **[Hugging Face Hub Scanners](https://huggingface.co/docs/hub/security-scanners):** The Hugging Face Hub automatically scans repositories for secrets, but you should not rely on it as your only line of defense.

### Metrics/Signal
*   **Signal:** An alert from a tool like `gitleaks` in your CI/CD pipeline.
*   **Metric:** Number of public repositories associated with your organization containing sensitive keywords. The goal is zero.
*   **Metric:** Time-to-discovery for a "honeypot" secret intentionally planted in a public-facing asset.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is your chance to look inward and assess your team's practices before an attacker does. How do you handle secrets during development and training? Are your logs overly verbose? Do you have a process for sanitizing model artifacts before publication? An honest evaluation means asking tough questions about your current workflow, from local development machines to the CI/CD pipeline that trains and deploys your models. For a developer, this is like code review, but for your security practices.

### Insight
The most common vulnerability is the "it's just a dev environment" mindset. Developers often use real, long-lived credentials in development for convenience. These credentials, even if they have limited permissions, can provide an attacker with a crucial entry point to pivot from. The line between "dev" and "prod" blurs in a CI/CD world, and a secret in a dev branch can easily end up in a public artifact.

### Practical
- **Checklist Review:** Create a simple checklist for publishing a model. Does it include steps like "Sanitize training logs," "Inspect model card for sensitive info," and "Verify no debug artifacts are included"?
- **Pipeline Audit:** Review your CI/CD pipeline configuration (`.gitlab-ci.yml`, `Jenkinsfile`, GitHub Actions). Are secrets being passed as masked environment variables, or are they being printed to logs? Check the verbosity levels of your build and training scripts.
- **Dependency Check:** Your code might be clean, but a dependency could be logging sensitive information from its environment. Be aware of the logging behavior of the libraries you use, especially MLOps tools.

### Tools/Techniques
*   **[Bandit](https://github.com/PyCQA/bandit):** A tool designed to find common security issues in Python code, including hardcoded passwords.
*   **[Checkov](https://github.com/bridgecrewio/checkov):** Scans infrastructure as code (Terraform, CloudFormation) to find misconfigurations, such as overly permissive IAM roles used in training jobs.
*   **IDE Plugins:** Use plugins like [SonarLint](https://www.sonarsource.com/products/sonarlint/) or [GitGuardian's ggshield](https://www.gitguardian.com/ggshield) directly in your IDE (e.g., VS Code) to catch secrets before they are even committed.

### Metrics/Signal
*   **Metric:** Percentage of projects that have passed a security checklist review before their first release.
*   **Signal:** A failed CI build due to a secrets detection tool.
*   **Metric:** The number of hardcoded secrets found during a full codebase scan.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about building proactive defenses to prevent metadata exposure from happening in the first place. This means adopting a "secure by default" posture. Instead of relying on developers to remember to remove secrets, the systems they use should make it difficult to leak them. This involves using proper secrets management tools, automatically sanitizing logs, and building lean, production-ready artifacts.

### Insight
The best way to prevent secrets from leaking is to never have them in a developer's hands directly. Instead of giving a developer (or a CI/CD job) a static, long-lived key, use a system that injects temporary, short-lived credentials just-in-time for the task at hand. If a temporary credential leaks, its value to an attacker is drastically reduced because it will expire in minutes or hours.

### Practical
- **Centralize Secrets:** Use a dedicated secrets manager. Instead of `.env` files, your application should fetch secrets from a secure vault at runtime.
- **Sanitize Logs:** Configure your logging framework to automatically filter or redact sensitive patterns. For example, create a custom log filter that replaces anything looking like an `AWS_SECRET_ACCESS_KEY` with `[REDACTED]`.
- **Use Multi-Stage Builds:** When containerizing your models, use [multi-stage Docker builds](https://docs.docker.com/develop/develop-images/multistage-build/). The first stage can contain all the build tools, debug libraries, and training data, but the final stage copies only the essential, sanitized model artifacts, leaving all the sensitive build-time metadata behind.

### Tools/Techniques
*   **Secrets Management:**
*   **[HashiCorp Vault](https://www.vaultproject.io/):** A powerful open-source tool for managing secrets and providing dynamic, short-lived credentials.
*   **[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/):** A managed service for storing and rotating secrets on AWS.
*   **[Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault):** Microsoft's equivalent for the Azure ecosystem.
*   **Pre-commit Hooks:**
*   **[pre-commit](https://pre-commit.com/):** A framework for managing pre-commit hooks. You can integrate tools like `truffleHog` or `gitleaks` to scan for secrets on every `git commit` command, preventing them from ever entering the repository.

### Metrics/Signal
*   **Metric:** Percentage of services and CI/CD jobs that fetch credentials from a central secrets manager vs. using static environment variables.
*   **Signal:** A pre-commit hook blocking a commit due to a detected secret.
*   **Metric:** Number of active long-lived static credentials in your organization.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Despite your best efforts, a breach might still occur. The "Limit" stage is about containing the blast radius. If an attacker gets a key, what can they actually do with it? The goal is to ensure that a compromised credential doesn't give them the "keys to the kingdom." This is achieved by strictly adhering to the Principle of Least Privilege: every process, job, and user should only have the absolute minimum permissions required to perform its function.

### Insight
Developers often request broad permissions (like S3 read/write access to all buckets) during development to avoid frustrating permissions errors. This is convenient but dangerous. Security should be treated like any other functional requirement. The permissions needed for a training job should be defined and scoped as carefully as the model's hyperparameters. Think of it as putting bulkheads in a ship; a single hole shouldn't sink the entire vessel.

### Practical
- **Scope Down IAM Roles:** For a model training job, create a specific IAM role that only has `s3:GetObject` permission on the specific bucket/prefix where the training data resides (`s3://my-training-data/raw-images/*`) and `s3:PutObject` permission on the specific prefix for model artifacts (`s3://my-model-artifacts/sentiment-v2/*`). It should not have permission to list all buckets or access user data.
- **Use Short-Lived Credentials:** Use services that provide temporary, auto-expiring credentials. For example, use [AWS STS](https://aws.amazon.com/iam/features/orgs-sts/) to assume a role that grants temporary credentials for a CI/CD job. Even if these leak, they become useless after their short TTL (e.g., 1 hour).
- **Network Segmentation:** Place your training infrastructure in a separate VPC or network segment with strict ingress/egress rules. A leaked key used from an EC2 instance in that VPC shouldn't be able to access your production database server in another VPC.

### Tools/Techniques
*   **Cloud IAM:**
*   **[AWS IAM](https://aws.amazon.com/iam/):** Use IAM Roles and fine-grained policies.
*   **[Azure RBAC](https://docs.microsoft.com/en-us/azure/role-based-access-control/overview):** Azure's Role-Based Access Control.
*   **[Google Cloud IAM](https://cloud.google.com/iam):** GCP's access control service.
*   **OpenID Connect (OIDC):** Configure your CI/CD provider (e.g., GitHub Actions, GitLab) to use [OIDC to authenticate with your cloud provider](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services). This allows your jobs to securely obtain short-lived credentials without ever handling a static secret.

### Metrics/Signal
*   **Metric:** Number of IAM roles using wildcard (`*`) permissions in their policies.
*   **Metric:** Average Time-To-Live (TTL) for credentials used in CI/CD pipelines.
*   **Signal:** A CI/CD job failing due to insufficient permissions (this can be a good sign that least privilege is being enforced, though it may require tuning).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This stage is about detection and response. How do you know when a leaked secret is being used by an attacker? You need visibility into who is accessing your resources, from where, and for what purpose. This means setting up robust logging, monitoring, and alerting on your infrastructure and applications. The goal is to quickly detect anomalous activity that indicates a compromised credential is in use, so you can respond before significant damage is done.

### Insight
The first sign of an attack won't be an alarm bell in your application code. It will be a faint signal in your cloud provider's audit logs. For example, an `s3:ListBuckets` API call from an IP address in a country you don't operate in, or a user accessing a dataset at 3 AM on a Saturday. Your job as a developer is to ensure the systems you build produce the right logs so that these signals can be detected.

### Practical
- **Enable Audit Logs:** Ensure services like AWS CloudTrail, Azure Monitor, or Google Cloud's operations suite are enabled and configured to log all data access and management events.
- **Set Up Alerts:** Create specific alerts for suspicious behavior. For example, trigger a high-priority alert if an access key that has been inactive for 90 days is suddenly used, or if a key is used to access data from multiple geographic regions in a short period.
- **Use Canaries:** Intentionally plant "canary tokens" or honeypot credentials in places an attacker might look (e.g., in a config file in a public code repo). A canary token is a fake credential that, when used, does nothing but trigger a high-fidelity alert that notifies you immediately of a breach.

### Tools/Techniques
*   **Cloud Monitoring:**
*   **[AWS CloudTrail](https://aws.amazon.com/cloudtrail/) & [Amazon GuardDuty](https://aws.amazon.com/guardduty/):** CloudTrail logs all API activity, while GuardDuty uses ML to detect threats and anomalies, such as credential compromise.
*   **[Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/overview):** Collects and analyzes telemetry from your Azure and on-premises environments.
*   **SIEM and Log Analysis:**
*   **[Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), [Elastic Stack](https://www.elastic.co/elastic-stack):** These tools aggregate logs from all your systems, allowing you to search for, analyze, and create alerts on suspicious patterns.
*   **Canary Tokens:**
*   **[CanaryTokens.org](https://canarytokens.org/generate):** A free and easy-to-use tool from Thinkst Canary for creating and managing canary tokens.

### Metrics/Signal
*   **Signal:** An alert from AWS GuardDuty for "UnauthorizedAccess:IAMUser/AnomalousBehavior".
*   **Signal:** A triggered canary token alert.
*   **Metric:** Mean Time To Detect (MTTD) a compromised key, measured from the time of the anomalous activity to the time an alert is generated.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice. Security isn't just about having the right tools; it's about having the right reflexes. By running realistic drills, developers build muscle memory and learn how to react in a real incident. These exercises test your tools, processes, and people to find weaknesses before an attacker does. It turns security from a theoretical concept into a practical skill.

### Insight
Security exercises shouldn't be reserved for a specialized "red team." Developer-led exercises can be incredibly effective. A simple, low-stakes drill can reveal surprising gaps in your process. For example, you might discover that your on-call developer knows they should rotate a leaked key, but they don't have the necessary IAM permissions to do so, causing a critical delay.

### Practical
- **Tabletop Exercise:** Gather the team and walk through the attack scenario verbally. "A developer alerts us that they accidentally posted an AWS key in a public GitHub issue. What is the first thing we do? Who do we notify? What's the process for revoking the key and assessing the damage?" Use a tool like [Backstory](https://www.runbackstory.com/incident-response-scenarios/aws-credential-leak) to guide the session.
- **Live Fire Drill (Controlled):** Have a developer intentionally commit a *fake*, but valid-looking, secret to a feature branch.
-   Did the pre-commit hook stop them?
-   If not, did the CI pipeline's secret scanner catch it and fail the build?
-   Did it generate an alert to the security team or the project owner?
-   How long did it take from commit to alert?
- **Capture The Flag (CTF):** Create a small, sandboxed challenge for developers where they have to find a "flag" (a piece of text) hidden in the metadata of a model or a commit history. This makes learning about security fun and engaging.

### Tools/Techniques
*   **[Gameday/DiRT (Disaster Recovery Testing)](https://aws.amazon.com/gameday/):** A framework for running structured operational exercises to test systems and team responses.
*   **Incident Response Playbooks:** Maintain a simple, clear document in your team's wiki outlining the step-by-step procedure for handling a credential leak.
*   **Automated Attack Simulation:** Platforms like [AttackIQ](https://attackiq.com/) or [Stratus Red Team](https://github.com/DataDog/stratus-red-team) can be used to safely simulate specific attack techniques in your cloud environment.

### Metrics/Signal
*   **Metric:** Time To Remediate (TTR) for the simulated secret leak—from the moment the alert is fired to when the credential is revoked and confirmed.
*   **Metric:** Percentage of developers who have participated in a security exercise in the last 6 months.
*   **Signal:** Successful completion of a tabletop exercise resulting in actionable improvements to the incident response playbook.
{% endblock %}