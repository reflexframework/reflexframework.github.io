---
 permalink: /battlecards/aicd
 keywords : [hardcoded API key, public GitHub Actions, build log]
battlecard:
 title: AI in CI/CD Pipelines
 category: CI/CD + AI
 scenario: Model in the Build Pipeline
 focus: 
   - pulling unverified models in Dockerfiles 
   - using AI inference APIs without auth 
   - build logs exposing AI API keys 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets a company's public source code repositories, hunting for common developer mistakes. They use automated scanners to find a public GitHub Actions build log that was not properly scrubbed. Inside the log, they discover a hardcoded API key for a commercial AI service.

Simultaneously, they inspect the repository's `Dockerfile`. They notice it pulls a pre-trained sentiment analysis model from a public, non-official Hugging Face space using a simple `git clone` command. The attacker has previously uploaded a malicious version of this model to a similarly-named, typosquatted repository. They know it's a matter of time before a developer accidentally uses their malicious version.

The attacker uses the leaked API key to access the company's private models and data hosted on the AI service, exfiltrating proprietary information and racking up a massive bill. Weeks later, a developer, rushing to fix a bug, mistakenly points the build pipeline to the attacker's typosquatted model repository. During the next CI/CD run, the malicious model's setup script executes within the build container. It scans the build environment for all environment variables, finds AWS credentials for the build runner, and sends them to an attacker-controlled server, giving them a foothold into the company's cloud environment.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Reconnaissance is the attacker's discovery phase. They aren't targeting you specifically yet; they're scanning the internet for easy opportunities. They use automated tools to find low-hanging fruit like secrets accidentally committed to public repositories or exposed in build logs. They search for Dockerfiles pulling dependencies from unverified public registries, looking for a supply chain weakness they can exploit. It’s like a burglar walking down a street, checking every car door to see which one is unlocked.

### Insight
Your public code, documentation, and CI/CD logs are your organization's digital storefront. Attackers are constantly window-shopping for security flaws. They assume developers will make mistakes under pressure, and they build tools to find those mistakes at scale.

### Practical
As a developer, you can think like an attacker. Use GitHub's own search functionality to look for sensitive strings (e.g., `api_key`, `secret`, `password`) within your organization's public repositories. Review your build logs; are they publicly accessible? Do they print environment variables or secrets? Check your Dockerfiles: are you pulling images or models from sources you don't explicitly trust?

### Tools/Techniques
*   **Secret Scanning:** Use tools like [TruffleHog](https://trufflesecurity.com/), [gitleaks](https://github.com/gitleaks/gitleaks), or [GitHub's secret scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning) to find credentials in your codebases. Run these as pre-commit hooks to catch secrets before they are ever committed.
*   **Public Exposure:** Use search engines like [Shodan](https://www.shodan.io/) to see if any of your internal services or APIs are accidentally exposed to the internet.

### Metrics/Signal
*   Number of publicly accessible repositories and their rate of growth.
*   Count of active, high-entropy strings (potential secrets) detected by scanners in public code. A downward trend is a sign of improved hygiene.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
Evaluation is where you turn the lens inward to assess your own environment against the attacker's tactics. This involves a deliberate audit of your CI/CD pipelines, dependencies, and code. You are systematically checking your "car doors" to see if you've left any unlocked. How are secrets managed in your builds? What is the provenance of your base Docker images and AI models? Are your internal network services properly secured?

### Insight
Vulnerabilities are often born from convenience. A "temporary" hardcoded key becomes permanent. A "quick test" using a public model from an unknown author makes it into the `main` branch. The developer's goal is to ship features, and security practices can feel like they slow things down. A good evaluation process finds these shortcuts before an attacker does.

### Practical
Create a checklist for your team.
1.  **Secrets:** Review your CI/CD configuration files (e.g., `.github/workflows/main.yml`, `Jenkinsfile`). Is there any secret material stored in plaintext?
2.  **Dependencies:** For every `FROM` instruction in a `Dockerfile` and every model in a `requirements.txt` file, ask: "Do we trust the source of this artifact? Is the version pinned to a specific, immutable digest (e.g., `@sha256:...`) instead of a mutable tag like `:latest`?"
3.  **APIs:** Examine the code that calls internal AI inference services. Is there an authentication layer? Is it robust? Could a compromised build server access it?

### Tools/Techniques
*   **Software Composition Analysis (SCA):** Tools like [Snyk](https://snyk.io/), [Trivy](https://github.com/aquasecurity/trivy), and [Grype](https://github.com/anchore/grype) can scan `Dockerfile`s and other dependency manifests for known vulnerabilities and bad practices.
*   **Static Analysis (SAST):** Use linters and SAST tools that have rules for detecting hardcoded secrets in your codebase. Many IDEs have plugins for this.
*   **Manual Review:** Nothing beats a peer review. Add "Check for hardcoded secrets" and "Verify dependency sources" to your pull request templates.

### Metrics/Signal
*   Percentage of repositories that have automated secret scanning integrated into the CI pipeline.
*   Number of build dependencies using floating tags (e.g., `:latest`, `*`) versus pinned versions/digests.
*   A list of internal services and a corresponding check for whether they enforce authentication.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is the process of actively strengthening your defenses based on what you found during evaluation. It's about implementing best practices to make your build pipelines resilient to these attacks. This means moving secrets out of code, verifying the integrity of your dependencies, and securing your services.

### Insight
The goal is to make the secure path the easiest path for developers. If using the official secrets manager is simpler than hardcoding a key, developers will adopt it. If the official, vetted base image is readily available and well-documented, developers won't go searching for a random one on Docker Hub.

### Practical
*   **Manage Secrets Centrally:** Never store secrets in code or config files. Use your platform's built-in secret management (e.g., GitHub Actions Secrets, GitLab CI/CD variables) or a dedicated vault. These tools securely inject secrets into the build environment as environment variables at runtime.
*   **Harden the Supply Chain:**
*   **Base Images:** Use base images from trusted publishers (e.g., official language images, or minimal images like [Google's distroless](https://github.com/GoogleContainerTools/distroless)). Pin the image reference to its immutable digest (`.../image-name@sha256:abcd...`).
*   **AI Models:** Host vetted, approved models in a private registry (e.g., a private Hugging Face space, AWS S3 bucket, or Artifactory). Use model cards to document their origin and purpose.
*   **Secure APIs:** Enforce authentication on all internal APIs, even those you think are "safe" on an internal network. Use API keys, mTLS, or OAuth2. Implement rate limiting to prevent abuse.

### Tools/Techniques
*   **Secrets Management:** [HashiCorp Vault](https://www.vaultproject.io/), [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), [Google Secret Manager](https://cloud.google.com/secret-manager), or [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault).
*   **Artifact Integrity:** Use [Sigstore/Cosign](https://www.sigstore.dev/) to cryptographically sign and verify your container images and models, ensuring they haven't been tampered with.
*   **API Gateways:** Services like [Kong](https://konghq.com/) or cloud-native gateways can centralize authentication, rate limiting, and logging for your internal APIs.

### Metrics/Signal
*   100% of secrets required by CI/CD are sourced from a managed vault.
*   Automated CI check fails if a `Dockerfile` uses a `:latest` tag or an image from an untrusted registry.
*   0 hardcoded secrets found in the main branch across all repositories.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker gets past your defenses. Limitation is about containing the damage, also known as reducing the "blast radius." If an attacker compromises a single build container, what can they actually do? A well-architected system ensures the answer is "not much." This involves enforcing principles of least privilege and network segmentation.

### Insight
Perfect prevention is impossible. A determined attacker with enough time and resources may eventually find a way in. Your next line of defense is to ensure that a small breach doesn't turn into a catastrophic failure. The compromised build container should be a dead end for the attacker, not a doorway into your entire infrastructure.

### Practical
*   **Least Privilege for CI/CD:** Create dedicated IAM roles or service accounts for your CI/CD pipeline with the absolute minimum permissions required. If the build needs to upload a file to an S3 bucket, give it a role that *only* allows `s3:PutObject` to that specific bucket, nothing more. The AI API key used should be scoped to inference-only, if possible.
*   **Network Isolation:** Your build runners should operate in an isolated network environment. Use firewall rules (like VPC security groups) to block all outbound (egress) traffic except to necessary services (e.g., your package repository, artifact registry). A compromised container shouldn't be able to connect to your production database or random IPs on the internet.
*   **Ephemeral, Stateless Builders:** Each CI/CD job should run in a clean, new environment that is destroyed immediately after the job completes. This prevents an attacker from establishing a persistent foothold.

### Tools/Techniques
*   **Cloud IAM:** Use [AWS IAM](https://aws.amazon.com/iam/), [GCP IAM](https://cloud.google.com/iam), or [Azure RBAC](https://docs.microsoft.com/en-us/azure/role-based-access-control/overview) to create fine-grained, short-lived credentials for build jobs.
*   **Network Policies:** Use [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) or cloud firewalls to strictly control traffic flow in and out of your build environments.
*   **Ephemeral Runners:** Use the default runners provided by services like [GitHub Actions](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners) which are naturally ephemeral, or configure your self-hosted runners to be single-use.

### Metrics/Signal
*   Regular (e.g., quarterly) automated audits of permissions granted to CI/CD roles.
*   Number of allowed egress network destinations from the build network (should be a small, well-defined list).
*   Credentials used by the build job have a Time-To-Live (TTL) of less than the maximum build time (e.g., 1 hour).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about making the invisible visible. It's the process of implementing logging, monitoring, and alerting to detect suspicious activity in real-time. How would you know if a leaked AI API key was being used from an unexpected country? How would you know if a build container was trying to send data to a malicious server? Without good observability, you're flying blind.

### Insight
Attackers rely on stealth. They hope that their activity will be lost in the noise of everyday operations. Your job is to create signals out of that noise. An effective detection system doesn't just log data; it actively looks for anomalies and tells you when something is wrong.

### Practical
*   **Monitor API Key Usage:** For your AI services, monitor where and how your API keys are being used. Set up alerts for usage from IP addresses outside of your known CI/CD runners or corporate network ranges.
*   **Log and Audit Network Traffic:** Log all network connections originating from your build environment. An alert should be triggered if a build runner attempts to connect to an IP address that is not on an allowlist.
*   **Centralize Logs:** Funnel logs from your CI/CD system, cloud provider (e.g., AWS CloudTrail), and applications into a central location. This allows you to correlate events across different systems to spot an attack pattern.

### Tools/Techniques
*   **Cloud Monitoring:** Use services like [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) to log all API calls within your cloud account and [Amazon CloudWatch Alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html) to create alerts. Similar services exist for GCP (Cloud Audit Logs) and Azure (Monitor).
*   **Log Aggregation Platforms:** Tools like [Datadog](https://www.datadoghq.com/), [Splunk](https://www.splunk.com/), or the open-source [ELK Stack](https://www.elastic.co/what-is/elk-stack) are essential for collecting and analyzing logs from diverse sources.
*   **AI Observability:** Platforms like [Arize](https://arize.com/) and [WhyLabs](https://whylabs.ai/) can help you monitor the behavior of your models, which can be an indicator of compromise or data poisoning attacks.

### Metrics/Signal
*   An alert is generated any time an API key is used from an IP address not associated with a known environment.
*   A high-severity alert is triggered on any unexpected egress network traffic from a build runner.
*   The mean time to detect (MTTD) a simulated suspicious event is measured and tracked over time.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
Exercise is about building muscle memory for your team and validating your defenses. Security is not just about tools and processes; it's about people. By running realistic drills and simulations, you can train developers to respond correctly under pressure, identify weaknesses in your defenses, and foster a security-conscious culture.

### Insight
You don't want the first time you execute your incident response plan to be during a real incident. Regular practice, even in small ways, makes the team more confident and capable. It transforms security from a theoretical concept into a practical, shared responsibility.

### Practical
*   **Tabletop Exercise:** Get the team in a room (or a video call) and walk through this exact scenario. "We just got an alert that our OpenAI key is being used from a strange IP. What's the first thing we do? Who do we call? How do we rotate the key?" Document the answers.
*   **Controlled Red Teaming:** Have an internal security team or a trusted external partner attempt to find and exploit these very vulnerabilities in your staging environment. This is the ultimate test of your defenses.
*   **Fire Drills:**
*   **Secret Rotation Drill:** Deliberately trigger a "leak" of a non-critical API key and time how long it takes the team to revoke the old key, issue a new one, and deploy the fix.
*   **Dependency Poisoning Drill:** Create a private, "malicious" version of a common internal library. See if your CI/CD pipeline's vulnerability and integrity scanners catch it before it gets to production.

### Tools/Techniques
*   **Attack Simulation Frameworks:** Open-source tools like [MITRE Caldera](https://caldera.mitre.org/) can be used to simulate attacker behavior within your network in a controlled way.
*   **Vulnerable-by-Design Apps:** Set up a training application like [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) and hold a "Capture the Flag" event for developers to practice their security skills.
*   **Security Gamedays:** Formalize your drills into a recurring "gameday" event where you test a specific part of your security response.

### Metrics/Signal
*   Mean Time to Remediate (MTTR) for a simulated secret leak decreases over time.
*   Percentage of developers who have participated in a security exercise or training in the last year.
*   Number of security improvements or process changes generated from the findings of a security exercise.
{% endblock %}