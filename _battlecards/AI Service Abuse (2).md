---
 permalink: /battlecards/aiservice2
 keywords : [production AI API key, public GitHub repository fork]
 
battlecard:
 title: AI Service Abuse
 category: Cross-cutting
 scenario: Cloud AI API Exploits
 focus: 
   - leaked API keys 
   - quota exhaustion / DoS via AI endpoints 
   - cost-amplification attacks 
---

A FinTech startup, "FinBotics," integrates a powerful third-party generative AI model into its new customer support chatbot. A developer, working late on a feature, hardcodes the production AI API key into a utility script and accidentally commits it to a public GitHub repository fork.

Within hours, an automated scanner operated by an attacker discovers the key. The attacker first confirms the key is active by making a few small, legitimate-looking API calls. Seeing the key has high quota limits and no IP restrictions, they launch a cost-amplification attack. They use a script to bombard the AI endpoint with extremely long, complex, and computationally expensive prompts designed to maximize token usage. The goal is not just to disrupt service but to inflict massive financial damage. By Monday morning, FinBotics is facing a $50,000 bill from their AI provider, and their legitimate chatbot service is down due to rate-limiting.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's discovery phase. They aren't targeting you specifically; they are casting a wide net for a common, high-value mistake: leaked credentials. Like a driver checking for unlocked car doors in a parking lot, their methods are automated and opportunistic. They use tools to continuously scan public data sources for anything that looks like an API key. Their primary targets include public code repositories, developer forums like Stack Overflow, public cloud storage buckets, and even client-side JavaScript files served by websites.

### Insight
A secret is considered compromised the instant it touches a public or semi-public system, even if you delete it seconds later. Commit history in Git is a permanent record. Automated bots are incredibly fast and will likely find the key before you even realize the mistake. The attacker's goal is to find keys that are not just active, but also overly permissive, lacking the necessary controls to limit their potential for abuse.

### Practical
- **Audit your organization's public presence:** Manually check your organization's public GitHub/GitLab repositories, including the commit history of all branches.
- **Educate your team:** Make every developer aware that secrets should never be placed in code, config files that are checked into source control, or issue trackers.
- **Never hardcode anything:** Create a team-wide policy against hardcoding credentials, tokens, or keys, even for "testing in dev."

### Tools/Techniques
- **[gitleaks](https://github.com/gitleaks/gitleaks):** An open-source tool to scan git repositories for hardcoded secrets. You can run this on your local machine before pushing code.
- **[truffleHog](https://github.com/trufflesecurity/truffleHog):** Scans repositories for secrets, digging deep into commit history and branches.
- **[GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning):** An automated service from GitHub that scans public repositories (and private ones with an Advanced Security license) for known secret formats and notifies providers.

### Metrics/Signal
- **Secret Scanner Alerts:** A positive hit from a tool like `gitleaks` in a pre-commit hook or CI pipeline.
- **GitHub Notifications:** An email from GitHub titled "[repo-name] A secret has been detected in your repository".

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about turning the lens inward to assess your own vulnerabilities. It's a self-audit to determine how susceptible you are to the scenario. You need to ask critical questions: Where do we store our AI API keys? Are they hardcoded in our source code, `.env` files checked into git, or CI/CD pipeline variables? Who has access to them? Are we using one master key for all services, or unique, purpose-built keys for each application? Answering these honestly will reveal your security posture.

### Insight
Developers often think of security in terms of application logic flaws, but operational security—how you manage and deploy secrets—is just as critical. The biggest risk is often not a sophisticated hack, but a simple oversight. A single "god-mode" API key with no restrictions is a ticking time bomb. Evaluating your "secret sprawl" is the first step to defusing it.

### Practical
- **Conduct a Secret Sprawl Audit:** Systematically review your codebases, configuration files (`application.properties`, `settings.py`), and CI/CD job logs for anything resembling an API key. Use `grep` or your IDE's search function for patterns like `OPENAI_API_KEY`, `_KEY`, `_SECRET`.
- **Review Cloud IAM Policies:** Check which users, groups, or roles have permission to view or create API keys for your AI services. Is the list of people with access surprisingly large?
- **Map Your Keys:** Create a simple inventory of your active API keys, noting what service each key is for, its permissions, and where it is currently being used. If you can't build this map easily, your keys are not being managed effectively.

### Tools/Techniques
- **Manual Code Review:** The most straightforward method. Focus on configuration and initialization code where keys are often set.
- **Cloud Security Posture Management (CSPM):** Tools like [AWS Security Hub](https://aws.amazon.com/security-hub/) or [Google Security Command Center](https://cloud.google.com/security-command-center) can identify overly permissive IAM roles and other configuration risks.
- **[Semgrep](https://semgrep.dev/):** A fast, open-source static analysis tool that can be used with custom rules to find hardcoded secrets in your codebase.

### Metrics/Signal
- **Count of Hardcoded Secrets:** A simple count of secrets found outside a dedicated secrets manager. The goal is zero.
- **Key-to-Service Ratio:** The ratio of API keys to the number of services that use them. A 1:1 ratio is ideal; a 1:many ratio is a red flag.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about proactively building strong defenses to prevent secrets from leaking in the first place. The core principle is to never let a developer or a static file handle a production secret directly. Instead, secrets should be stored in a centralized, encrypted vault, and your applications should be granted temporary, programmatic access to retrieve them at runtime. This approach removes the human element and the risk of accidental commits.

### Insight
Treat secrets like passwords—don't write them down or store them in plain text. By using a secrets manager and IAM roles, you shift the security model from "who knows the secret" to "what is allowed to access the secret." This is a fundamentally more secure and scalable approach for cloud-native applications. A key stored in a vault is useless to an attacker who only has your source code.

### Practical
- **Adopt a Secrets Manager:** Store all API keys, database credentials, and other secrets in a dedicated secrets management tool.
- **Inject Secrets at Runtime:** Modify your application's startup logic to fetch secrets from the secrets manager instead of reading them from environment variables or config files. For example, in a Kubernetes environment, use a sidecar container or a CSI driver to mount secrets into your application pod.
- **Enforce Branch Protection Rules:** In your Git provider (GitHub, GitLab), protect your `main` or `production` branches. Require pull requests and status checks (like a successful secret scan) before any code can be merged.
- **Integrate Secret Scanning in CI/CD:** Add a step to your CI pipeline (e.g., in GitHub Actions, Jenkins) that runs a tool like `gitleaks`. Fail the build if any secrets are detected.

### Tools/Techniques
- **Secrets Managers:**
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [Google Cloud Secret Manager](https://cloud.google.com/secret-manager)
- [HashiCorp Vault](https://www.vaultproject.io/) (open source and enterprise versions available)
- **CI/CD Integration:**
- Use pre-built GitHub Actions like the [gitleaks-action](https://github.com/gitleaks/gitleaks-action) to automate scanning on every pull request.
- **[pre-commit framework](https://pre-commit.com/):** A framework for managing and maintaining multi-language pre-commit hooks. You can configure it to run a secrets scanner on your code before you're even allowed to create a commit.

### Metrics/Signal
- **Secrets Manager Adoption:** Percentage of your services that fetch secrets from a managed vault instead of configuration files.
- **Failed CI Builds:** An increase in CI/CD builds failing due to the "Secret Scan" step indicates the system is working, catching issues before they reach production.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Limitation assumes the worst has happened: an attacker has your key. The goal now is to contain the "blast radius" by making that key as useless as possible to them. This involves applying strict, server-side controls that limit what the key can do, how much it can be used, and from where it can be used. Even if an attacker has your key, they should hit a wall of restrictions that prevents them from causing significant damage.

### Insight
A compromised key is a security failure, but a massive cloud bill is a business failure. Financial controls are a surprisingly effective form of security control. Attackers in this scenario are often motivated by resource abuse, so by capping the resources they can abuse, you directly undermine their goal and turn a potential catastrophe into a manageable incident.

### Practical
- **Set Hard Billing and Quota Limits:** Go to your AI provider's dashboard *now* and configure the lowest possible usage quotas and spending limits that your service can tolerate. For example, set a hard monthly spend limit of $500. It's better for your service to be temporarily disabled by hitting a legitimate limit than to be bankrupted by an attacker.
- **Apply the Principle of Least Privilege:** Create API keys that have the absolute minimum set of permissions required. If a key is for a text-generation chatbot, it should *not* have permission to list or retrain models.
- **Use IP Address Restrictions:** If your backend services that call the AI API have static, predictable IP addresses, configure the API key to only accept requests from that specific IP range. This immediately invalidates the key for any attacker operating outside your network.
- **Rotate Keys Regularly:** Implement a policy for rotating API keys (e.g., every 90 days). This limits the window of opportunity for an attacker who has an old, leaked key.

### Tools/Techniques
- **[OpenAI API Usage Limits](https://platform.openai.com/docs/guides/rate-limits/usage-tiers):** Provides a dashboard to set hard and soft monthly spending limits for your organization.
- **[Google Cloud Quotas](https://cloud.google.com/docs/quota):** Allows you to view and manage quotas for all Google Cloud services, including Vertex AI. You can request lower limits.
- **[AWS Budgets](https://aws.amazon.com/aws-cost-management/aws-budgets/):** While not a hard limit, AWS Budgets can send you immediate alerts when your spending forecast or actual usage exceeds a threshold, acting as an early warning system.

### Metrics/Signal
- **Quota Exceeded Errors:** An increase in `429 Too Many Requests` or similar quota-related errors in your logs. This can indicate either an attack or that your legitimate usage is growing (a good problem to have).
- **Billing Alerts:** Receiving an alert from your cloud provider that you have exceeded 50% of your monthly budget in the first three days of the month is a massive red flag.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about achieving visibility. How do you know an attack is happening in real time? You need to have the right monitoring, logging, and alerting in place to detect anomalous activity. Relying on a surprise bill at the end of the month is not a detection strategy. You should be able to spot the signs of a compromised key within minutes, not weeks.

### Insight
Your application's operational data (logs, metrics) and financial data (billing dashboards) are also critical security data. A sudden spike in cost is a security signal. A sudden surge in API calls from a previously unseen country is a security signal. By treating this data as a source of truth for security, you can build a powerful and responsive warning system.

### Practical
- **Centralize Your Logs:** Ensure that logs from your application (which should include metadata about AI API calls) are shipped to a central logging platform for analysis.
- **Create Key Dashboards:** Build a monitoring dashboard with key metrics for your AI service usage:
- API call count over time.
- Average tokens per request.
- API error rate (especially 401s, 403s, 429s).
- Cost per day/hour.
- Map of requests by source IP/geography.
- **Configure Proactive Alerts:** Set up automated alerts based on anomalies in your dashboard metrics. Don't wait to check the dashboard; have the alerts pushed to your team's chat client (e.g., Slack, Microsoft Teams) or on-call system (e.g., PagerDuty).

### Tools/Techniques
- **Cloud Monitoring:**
- [Amazon CloudWatch](https://aws.amazon.com/cloudwatch/): Create alarms based on metrics and log filters.
- [Google Cloud's operations suite (formerly Stackdriver)](https://cloud.google.com/products/operations): Powerful for creating dashboards and alerts on GCP service usage.
- **Application Performance Monitoring (APM) & Log Aggregation:**
- [Datadog](https://www.datadoghq.com/): Can ingest logs and metrics to create sophisticated dashboards and anomaly detection alerts.
- [Splunk](https://www.splunk.com/): A powerful platform for searching, monitoring, and analyzing log data.
- **Billing Dashboards:** Regularly check the native cost management dashboards provided by AWS, GCP, and Azure. They are often the first place a cost-amplification attack becomes visible.

### Metrics/Signal
- **Alert on Cost Spike:** An alert fires because the cost attributed to your AI service has exceeded its daily forecast by 200%.
- **Alert on High Request Volume:** An alert fires because the number of API calls per minute has jumped from an average of 10 to 500.
- **Geographic Anomaly:** A new alert shows that 90% of your API requests in the last hour have come from an unexpected ASN or country.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice for fight night. It's not enough to have tools and plans; your team needs the "muscle memory" to act quickly and correctly under pressure. By simulating an attack scenario in a controlled way, you can test your defenses, identify gaps in your processes, and train your developers on the incident response playbook.

### Insight
In a real incident, communication and coordination are just as important as technical tools. An exercise will reveal the non-technical problems: Who has the authority to rotate the key? How do we notify stakeholders? Is the playbook clear and easy to follow at 3 AM? Practicing builds confidence and drastically reduces the time it takes to contain a real breach.

### Practical
- **Tabletop Exercise:**
1.  Gather the relevant team members (devs, SRE/Ops, security).
2.  Present the scenario: "GitHub just sent an email about a leaked AI key in our main repository. Simultaneously, a PagerDuty alert fires for a massive spike in AI service costs. What are our immediate actions, step-by-step?"
3.  Talk through the entire process: identification, communication, containment (key rotation), and post-mortem. Document gaps and action items.
- **Live Fire Exercise (Controlled):**
1.  **Preparation:** Create a *dedicated, non-production* AI project with a new API key that has a very low spending limit (e.g., $5).
2.  **Simulated Leak:** Intentionally commit this dummy key to a test repository.
3.  **Test Detection:** Does your automated secret scanner (e.g., `gitleaks` in the CI pipeline) catch it? Does GitHub Secret Scanning fire an alert?
4.  **Simulated Attack:** Use a simple script (e.g., a Python script using the `requests` library) to make rapid API calls with the dummy key until it hits its rate or spending limit.
5.  **Test Response:** Do your monitoring dashboards and alerts light up as expected? Can the on-call developer follow the playbook to identify the compromised key, revoke it in the provider's console, and confirm the "attack" has stopped?

### Tools/Techniques
- **Incident Response Playbook:** A document (e.g., in your company's wiki like [Confluence](https://www.atlassian.com/software/confluence)) that details the step-by-step procedure for handling a secret leak.
- **Attacker Simulation Script:** A simple script in a language like Python or Node.js to generate API traffic for the live fire exercise.
- **Chaos Engineering:** While more advanced, tools like the [Chaos Toolkit](https://chaostoolkit.org/) could be used to design more complex experiments, such as simulating the failure of a secrets manager to test your application's resilience.

### Metrics/Signal
- **Time to Detect (TTD):** The time from the simulated key commit to the first automated alert being generated.
- **Time to Remediate (TTR):** The time from the first alert to the compromised key being successfully revoked.
- **Playbook Gaps:** The number of "we don't know" or "we're not sure" answers that come up during a tabletop exercise. The goal is to drive this number to zero over time.
{% endblock %}