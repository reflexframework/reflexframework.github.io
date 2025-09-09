---
 permalink: /battlecards/aiservice1
 keywords : [hardcoded API key, cloud AI API,public GitHub repository]
 
battlecard:
 title: AI Service Abuse
 category: Cross-cutting
 scenario: Cloud AI API Exploits
 focus: 
   - leaked API keys 
   - quota exhaustion / DoS via AI endpoints 
   - cost-amplification attacks 
---
{% block type='battlecard' text='Scenario' %}
A developer working on a new feature that integrates with a commercial Large Language Model (LLM) via a cloud AI API (e.g., Google's Vertex AI, OpenAI's API) hardcodes the API key into a source file for a "quick test" on their local machine. Later, while cleaning up their workspace, they accidentally commit this file to a public GitHub repository for a related open-source utility.

Within hours, an attacker's automated scanner, which constantly scrapes public repositories for secrets matching common API key formats, discovers the key. The attacker immediately begins using the key to send a massive volume of complex, computationally expensive requests to the most powerful models available through the API. Their goal is twofold: cause a Denial of Service (DoS) by exhausting the service quota, and inflict maximum financial damage on the victim through a cost-amplification attack, potentially running up a bill of tens of thousands of dollars in a single day.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
In this scenario, reconnaissance is largely automated and opportunistic. Attackers don't target your company specifically; they cast a wide net looking for easy targets. They operate bots that continuously scan public data sources for credentials. Their primary tactics are:
- **Public Code Repository Scanning:** Using tools that search sites like GitHub, GitLab, and Bitbucket for code that matches predefined patterns for API keys (e.g., `sk-` for Stripe/OpenAI, or specific base64-encoded string patterns).
- **Pastebin and Public Gist Monitoring:** Scraping sites like Pastebin and GitHub Gists where developers might temporarily share code snippets or logs that inadvertently contain secrets.
- **Exposed Container Image Analysis:** Scanning public container registries like Docker Hub for images where secrets were mistakenly baked into a layer during the build process.
- **Misconfigured Cloud Storage:** Searching for publicly accessible S3 buckets or other cloud storage that might contain configuration files (`.env`, `credentials.json`) or backups.

### Insight
The "blast radius" for a leak is far wider than just your official company repositories. A key can be leaked from a developer's personal fork, a contractor's repository, a public Q&A forum post, or even a screenshot in a blog post. The speed is also critical; automated scanners can find and exploit a committed key in minutes, long before a human might notice.

### Practical
- **Audit Your Public Footprint:** Use GitHub's search functionality to look for your company's name, project names, or even unique internal strings in public code.
- **Think Like a Scanner:** Understand the specific format of the API keys you use. For example, an OpenAI key starts with `sk-`. Run a regex search for that pattern across your organization's public presence.

### Tools/Techniques
-   [**gitleaks**](https://github.com/gitleaks/gitleaks): An open-source tool to scan Git repositories for hardcoded secrets. You can run this against your own repos to find existing leaks.
-   [**truffleHog**](https://github.com/trufflesecurity/trufflehog): Scans repositories for secrets, digging deep into commit history to find secrets that were committed and then removed.
-   [**GitHub Secret Scanning**](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning): Natively built into GitHub, this service automatically looks for known secret patterns and can notify service providers (like AWS, Google, etc.) to automatically revoke them. Ensure this is enabled for your organization.

### Metrics/Signal
-   Number of active alerts from GitHub Secret Scanning.
-   Number of secrets found by running `gitleaks` or `truffleHog` on your existing codebases. A non-zero result indicates a problem.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. A developer or team can assess their vulnerability by reviewing their own environment and practices. The core question is: "How easy would it be for one of our secrets to end up in a public place?" You should evaluate:
- **Codebases:** Are there any API keys, passwords, or tokens hardcoded directly in the source code, configuration files, or test data?
- **Secret Management:** How are secrets handled? Are they stored in plaintext files like `.env`? Are those files correctly listed in `.gitignore`? Is there a formal process, or does each developer manage them independently?
- **CI/CD Pipelines:** How are secrets provided to your build and deployment jobs? Are they stored as plaintext variables? Are they masked in logs? It's common for a failed build script to dump all its environment variables, including secrets, to a log file.
- **Developer Onboarding:** How do you give a new developer access to the secrets they need? Is the process secure and auditable?

### Insight
Developer convenience is the enemy of security. The most common vulnerability is a developer taking a shortcut "just for a moment" to get something working. This evaluation isn't about placing blame; it's about identifying where your processes make it easy to do the wrong thing and hard to do the right thing.

### Practical
- **Conduct a Code Review Day:** Dedicate a few hours for the entire team to specifically scan your application code for hardcoded secrets. Don't look for logic bugs, just credentials.
- **Audit your `.gitignore` files:** Ensure that all common configuration and credential files (`.env`, `*.pem`, `credentials.json`, `id_rsa`) are explicitly ignored.
- **Review a recent CI/CD build log:** Look through the logs of a build job. Can you see any sensitive information? Try to make a build fail and see what the output looks like.

### Tools/Techniques
-   [**Static Application Security Testing (SAST)**](https://owasp.org/www-community/Source_Code_Analysis_Tools): Tools like SonarQube or Snyk Code can be configured with rules to detect hardcoded secrets during automated scans.
-   [**HashiCorp Vault**](https://www.vaultproject.io/): A widely used tool for managing secrets. Evaluate if you have such a tool. If not, consider it.
-   [**Cloud Provider Secret Managers**](https://cloud.google.com/secret-manager): Services like [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) or [Google Secret Manager](https://cloud.google.com/secret-manager) are excellent, managed alternatives to running your own Vault.

### Metrics/Signal
-   Percentage of repositories that have a documented and enforced secret management strategy.
-   Time required for a new developer to get access to necessary secrets. A very short time might indicate an insecure process (e.g., sending keys over Slack).

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about implementing preventative controls to stop secrets from ever being leaked. The goal is to make committing a secret by accident nearly impossible.
1.  **Never Hardcode Secrets:** This is the golden rule. Secrets should be loaded from the environment at runtime.
2.  **Use a Secrets Manager:** Centralize all secrets in a dedicated, encrypted, and access-controlled tool like Vault or a cloud provider's native offering. Applications should fetch credentials from this service at startup.
3.  **Implement Pre-Commit Hooks:** This is a powerful "shift-left" technique. A small script can be configured to run on every developer's machine *before* a `git commit` is finalized. This script scans the changes for anything that looks like a secret and will block the commit if one is found.
4.  **Enforce CI/CD Gating:** Your CI pipeline should run a secret-scanning check as one of its very first steps. If a secret is detected, the build should fail immediately, preventing the insecure code from being deployed or even merged.

### Insight
Focus on automation. A developer might forget to follow a manual process, but an automated pre-commit hook or a required CI check runs every single time. By building security into the tools developers already use (Git, CI/CD), you make the secure path the easiest path.

### Practical
- **Local Development:** Use `.env` files to store secrets for local development and ensure `.env` is in your global `.gitignore`. Use a library like `dotenv` for [Node.js](https://github.com/motdotla/dotenv) or [Python](https://pypi.org/project/python-dotenv/) to load these variables into your application's environment.
- **Production/Staging:** Configure your application to read secrets from the environment or directly from a secrets management service using its SDK.
- **Setup a pre-commit hook:** Use the [`pre-commit`](https://pre-commit.com/) framework to easily manage hooks and add a `gitleaks` or `truffleHog` check.

### Tools/Techniques
-   [**pre-commit**](https://pre-commit.com/): A framework for managing and maintaining multi-language pre-commit hooks. It's easy to add a hook that runs `gitleaks`.
-   **Example Python code (loading from environment):**
```python
import os
# Load API key from an environment variable, not from code
AI_API_KEY = os.getenv("AI_API_KEY")
if not AI_API_KEY:
raise ValueError("AI_API_KEY environment variable not set!")
```
-   [**Doppler**](https://www.doppler.com/): A developer-friendly secret management platform that simplifies syncing secrets across different environments.

### Metrics/Signal
-   Number of commits blocked by pre-commit hooks in a given week. (This is a good thing!)
-   100% of production services load secrets from a managed secrets store.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume a breach happens despite your best efforts. Limiting the blast radius is about ensuring that a successful attack causes minimal damage.
- **Principle of Least Privilege:** Create API keys that have the absolute minimum set of permissions needed. If a key is only for reading data from a specific AI model, it should not have permissions to re-train models or access other services.
- **Set Billing Alerts and Budgets:** This is your most critical defense against cost-amplification attacks. In your cloud provider's console, set a hard budget for your project. Then, configure alerts that send emails or trigger PagerDuty notifications when spending reaches 50%, 75%, and 90% of that budget. An unexpected alert is a massive red flag.
- **Enforce Quotas:** On top of billing, set usage quotas on your AI API endpoints. For example, limit usage to 1,000 requests per day if that's your expected traffic. This can stop a DoS attack cold.
- **Use Environment-Specific Keys:** Use different API keys for your `dev`, `staging`, and `prod` environments. A leaked `dev` key should have no access to production resources and should have a very low quota, limiting its potential for abuse.

### Insight
A billing alert is one of the most effective and underrated security signals you can have. Attackers can hide their network traffic or code changes, but they cannot hide the bill. For cost-amplification attacks, the money trail is the easiest one to follow.

### Practical
- **Action Item:** Go to your cloud provider's billing console right now. Find the project where you are using the AI API. Create a new budget for a reasonable monthly amount and set up at least one alert to email your team when it hits 50%.
- **Review Key Scopes:** Look at the permissions assigned to the API keys you are currently using. Are they overly permissive? Can you restrict them by IP address or to a specific API method?

### Tools/Techniques
-   [**Google Cloud Budgets and Alerts**](https://cloud.google.com/billing/docs/how-to/budgets)
-   [**AWS Budgets**](https://aws.amazon.com/aws-cost-management/aws-budgets/)
-   [**Azure Cost Management + Billing**](https://docs.microsoft.com/en-us/azure/cost-management-billing/costs/cost-mgt-alerts-monitor-usage-spending)
-   [**Terraform**](https://www.terraform.io/): Use Infrastructure as Code (IaC) to define and enforce quotas and permissions on API keys, making the configuration auditable and repeatable.

### Metrics/Signal
-   An unexpected billing alert is your primary signal of an attack in progress.
-   Mean Time to Revoke (MTTR): How long does it take from the moment a billing alert fires to the moment the compromised key is identified and disabled?

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about detection and observability. How do you know an attack is happening, and how can you investigate it?
- **Monitor API Usage Metrics:** Watch the key metrics provided by your cloud AI service. The most important one is the number of requests over time. A sudden, vertical spike in traffic that is not correlated with a new feature launch is a primary indicator of compromise.
- **Analyze API Logs:** Log every API request, including the source IP address, the endpoint being called, and the user agent. During an attack, you will likely see a high volume of requests coming from a small set of unusual IP addresses (e.g., from data centers, not residential ISPs).
- **Set Anomaly Detection Alerts:** Instead of static thresholds, use monitoring tools that can learn your application's normal traffic patterns. These tools can then alert you when there is a significant deviation from the baseline, which is a much more reliable signal than a simple "requests > 1000" alert.

### Insight
Your monitoring and logging data tells a story. The story of normal operation is a gentle, wave-like pattern of usage corresponding to business hours. The story of an attack is a sudden, flat, high-volume plateau that starts at a random time and doesn't stop. Learning to distinguish between these two stories is a critical developer skill.

### Practical
- **Create a Security Dashboard:** In your monitoring tool, create a dashboard dedicated to your AI API. It should have widgets for:
-   API requests per minute.
-   API error rate.
-   Estimated cost per hour.
-   Top 10 source IP addresses.
- **Review these dashboards regularly** as part of your team's operational rhythm, not just when there's an incident.

### Tools/Techniques
-   [**Amazon CloudWatch**](https://aws.amazon.com/cloudwatch/): Provides detailed monitoring of AWS resources, including API Gateway and Lambda, which might be fronting your AI service. Use CloudWatch Anomaly Detection.
-   [**Google Cloud Monitoring**](https://cloud.google.com/monitoring): The equivalent service for GCP, allows you to create dashboards and alerts on API usage and billing data.
-   [**Datadog**](https://www.datadoghq.com/) or [**Splunk**](https://www.splunk.com/): These are more advanced, third-party observability platforms that can ingest logs and metrics from your cloud provider and offer more powerful anomaly detection and alerting capabilities.

### Metrics/Signal
-   **API Request Rate:** A sudden, sustained spike is the clearest signal.
-   **Cost Velocity:** A sharp increase in the "cost per hour" metric.
-   **Geographic Distribution of Requests:** A sudden flood of traffic from a country you don't typically do business in.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is about building muscle memory. You don't want your first time dealing with a leaked key to be during a real, high-stakes incident. You need to practice. The goal is to simulate an attack in a controlled way to test your defenses, processes, and people.

A typical exercise would be a "Game Day" or "Red Team" scenario:
1.  **Preparation:** Create a new, temporary AI API key with a very strict quota and budget (e.g., $10).
2.  **Execution:** A designated "attacker" intentionally commits this key to a public GitHub Gist and sends the link to the "defenders" (the rest of the dev team).
3.  **Test:** The team must now race against the clock to execute the incident response plan.
-   Did the monitoring and billing alerts fire as expected?
-   Could they quickly identify which key was compromised?
-   Did they know the process for revoking the key in the cloud console?
-   How long did the entire process take?
4.  **Review:** After the exercise, conduct a post-mortem. What went well? What was slow or confusing? Update your documentation and runbooks based on what you learned.

### Insight
The goal of the exercise is not to "win" but to learn. It's perfectly fine if the first run-through is chaotic and slow. The purpose is to find the weak points in your process—a missing dashboard, a confusing alert, an outdated runbook—and fix them before a real attacker finds them for you.

### Practical
- **Schedule Your First Game Day:** Put 2 hours on the team calendar for next month. It doesn't need to be complex. The simple act of creating, leaking, and revoking one key is an incredibly valuable exercise.
- **Write a Simple Runbook:** Create a Markdown file in your team's wiki or repository named `INCIDENT_RESPONSE_LEAKED_KEY.md`. Write down the 3-4 basic steps: 1. Acknowledge alert. 2. Identify the key from logs/alerts. 3. Disable the key in the AWS/GCP/Azure console. 4. Communicate status.

### Tools/Techniques
-   [**Incident Response Plan Template**](https://www.atlassian.com/incident-management/handbook/templates): Use a simple template to build your runbook. Don't overcomplicate it.
-   [**PagerDuty**](https://www.pagerduty.com/) or [**Opsgenie**](https://www.atlassian.com/software/opsgenie): Use an incident management tool to practice the alerting and escalation part of the response. You can configure your billing/monitoring alerts to trigger a test incident in these tools.
-   **Chaos Engineering:** For more advanced teams, tools like the [**AWS Fault Injection Simulator**](https://aws.amazon.com/fis/) can be used to simulate different failure scenarios, though a manual game day is often best for this specific scenario.

### Metrics/Signal
-   **Mean Time to Remediate (MTTR):** Measure the time from the "leak" to the successful revocation of the key. Your goal should be to reduce this time with each subsequent exercise.
-   **Post-Mortem Action Items:** The number of concrete improvements made to your tooling, documentation, and processes as a result of the exercise.
{% endblock %}