---
 permalink: /battlecards/jenkins
battlecard:
 title: Jenkins CI/CD Compromise
 category: CI/CD
 scenario: Jenkins
 focus: 
   - plugin vulnerabilities 
   - insecure Groovy sandbox 
   - leaked secrets 
---

An attacker identifies a public-facing Jenkins instance belonging to your organization. By scanning the instance, they discover it's running an outdated version of a popular plugin with a known Remote Code Execution (RCE) vulnerability. The attacker uses a public exploit to gain a foothold on the Jenkins controller.

Once inside, their initial shell is limited. They discover a pipeline job that dynamically builds a Groovy script from user-submitted parameters without proper sanitization. By manipulating the build parameters, they bypass the Groovy sandbox, achieving full code execution on the controller.

With unrestricted access, the attacker scans the Jenkins controller's filesystem. They analyze build logs and workspace directories, eventually finding a file containing hardcoded, long-lived AWS credentials. Using these credentials, the attacker pivots from the CI/CD environment into your production cloud infrastructure, exfiltrates sensitive customer data from an S3 bucket, and deploys crypto-mining software on several EC2 instances.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They are looking for a way in by discovering and mapping your external-facing systems. For a Jenkins environment, they want to find your Jenkins servers, identify their versions, and list the plugins they use to find a known vulnerability. They will also search public code repositories for `Jenkinsfile`s to understand how your pipelines are structured, what tools they use, and what systems they connect to. This gives them a blueprint of your internal development and deployment processes before they even attempt an exploit.

### Insight
Developers often think of CI/CD systems as internal, "dev-only" tools, forgetting that they are powerful automation servers connected to the company's most valuable assets: source code and production infrastructure. To an attacker, compromising Jenkins is like finding the master key to your entire engineering kingdom. A `Jenkinsfile` in a public GitHub repository is a gift to an attacker, revealing your internal architecture and potential weak points.

### Practical
*   **Audit your digital footprint:** Use the same tools an attacker would to see what's visible. Search for your company's domains and IP ranges on public scanners.
*   **Review public code:** Systematically check all your organization's public code repositories (e.g., on GitHub, GitLab) for any `Jenkinsfile`s or other CI/CD configuration files. Assume anything public will be read by an adversary.
*   **Check DNS records:** Look for subdomains like `jenkins.yourcompany.com`, `ci.yourcompany.com`, or `build.yourcompany.com`.

### Tools/Techniques
*   [Shodan](https://www.shodan.io/): A search engine for internet-connected devices. Search for `X-Jenkins` on your organization's IP blocks.
*   [Google Dorks](https://www.exploit-db.com/google-hacking-database): Use specific search queries like `inurl:/login intitle:"Dashboard [Jenkins]"` combined with `site:yourcompany.com`.
*   [Wappalyzer](https://www.wappalyzer.com/): A browser extension that can identify the version of Jenkins running on a web server from its HTTP headers and HTML content.
*   [GitHub Code Search](https://github.com/search): Search for `Jenkinsfile org:your-company-name` to find exposed pipeline configurations.

### Metrics/Signal
*   Number of publicly accessible Jenkins instances discovered.
*   Time since the Jenkins version or plugins on a public instance were last updated.
*   Number of `Jenkinsfile`s or CI/CD configuration files found in public repositories.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. As a developer, you need to assess your own Jenkins environment and pipelines to see if they are vulnerable to the attack scenario. This involves checking for outdated software, insecurely configured pipelines that bypass security controls like the Groovy sandbox, and places where secrets might be accidentally exposed, such as in build logs or source code.

### Insight
The biggest threat is often convenience masquerading as efficiency. Disabling the Groovy sandbox because it's "easier," hardcoding a temporary secret into a script to "get it working," or letting plugins get stale because "updating might break something" are all common practices that create massive security holes. A working pipeline is not the same as a secure pipeline.

### Practical
*   **Plugin Audit:** In Jenkins, go to `Manage Jenkins` > `Manage Plugins` > `Advanced` and click `Check now` to see if any plugins have security warnings. Review the list of installed plugins and remove any that are not actively used.
*   **Sandbox & Script Approval:** Go to `Manage Jenkins` > `In-process Script Approval`. Review every approved script signature. Are there dangerous methods approved (e.g., `execute()`, `new File()`)? Question why they are needed and if there's a safer alternative.
*   **Secret Sprawl:** Use `grep` or other search tools to scan your `Jenkinsfile`s and build script repositories for common secret patterns (e.g., `AWS_ACCESS_KEY_ID`, `-----BEGIN RSA PRIVATE KEY-----`). Check recent build logs for any accidentally printed secrets.

### Tools/Techniques
*   [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/): Can be configured to scan your `JENKINS_HOME/plugins` directory to identify plugins with known CVEs.
*   [TruffleHog](https://github.com/trufflesecurity/trufflehog) or [Gitleaks](https://github.com/gitleaks/gitleaks): Open-source tools that can be run in pipelines to scan source code and build artifacts for hardcoded secrets.
*   **Manual Code Review:** Pay special attention to any `script { ... }` blocks in your `Jenkinsfile`s. This is where un-sandboxed Groovy code often lives.

### Metrics/Signal
*   Number of installed plugins with known, unpatched vulnerabilities.
*   Number of scripts and method signatures in the "In-process Script Approval" list.
*   Count of hardcoded secrets detected by automated scanners across all repositories.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about actively hardening your systems and practices to shut down the vulnerabilities identified in the evaluation phase. This means updating Jenkins and its plugins, enforcing the use of security features like the Groovy sandbox, implementing a robust secrets management strategy, and applying the principle of least privilege to your pipeline jobs.

### Insight
Treat your CI/CD infrastructure as a production application. Your `Jenkinsfile`s and Jenkins system configuration should be stored in version control (`Jenkinsfile`s in their respective app repos, system config via JCasC), peer-reviewed, and subjected to automated security testing just like your Java or Python code. This approach, known as Configuration-as-Code, makes your setup repeatable, auditable, and easier to secure.

### Practical
*   **Update Everything:** Establish a regular schedule (e.g., monthly) to update the Jenkins controller and all plugins. Prioritize updates that patch security vulnerabilities.
*   **Embrace the Sandbox:** Avoid approving dangerous scripts. Instead, move complex or privileged operations into a [Shared Library](https://www.jenkins.io/doc/book/pipeline/shared-libraries/). This centralizes sensitive code where it can be properly reviewed and maintained by a smaller group of trusted developers.
*   **Centralize Secrets:** Use the built-in [Jenkins Credentials Plugin](https://plugins.jenkins.io/credentials/) to manage all secrets. For a more robust solution, integrate Jenkins with an external secrets manager. This ensures secrets are never hardcoded, are injected at runtime, and can be automatically rotated.

### Tools/Techniques
*   [Jenkins Configuration as Code (JCasC)](https://plugins.jenkins.io/configuration-as-code/): Define your entire Jenkins configuration (security settings, plugins, jobs) in a YAML file stored in Git.
*   [HashiCorp Vault Plugin](https://plugins.jenkins.io/hashicorp-vault-plugin/): Allows Jenkins pipelines to dynamically fetch secrets from a HashiCorp Vault instance at runtime.
*   [Role-based Authorization Strategy plugin](https://plugins.jenkins.io/role-strategy/): Provides fine-grained access control, ensuring users and jobs only have the permissions they absolutely need to function.
*   [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/): A framework for establishing secure dependency management practices.

### Metrics/Signal
*   Average time-to-patch for critical Jenkins/plugin vulnerabilities is less than 7 days.
*   Percentage of secrets managed via a secrets management tool vs. hardcoded.
*   100% of pipeline jobs run with the Groovy sandbox enabled.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker will eventually get in. This stage is about damage control. The goal is to contain the "blast radius" so that a compromise of one part of the system doesn't lead to a total takeover. For Jenkins, this means isolating build environments from each other and from the controller, and ensuring that the credentials used by a pipeline are temporary and narrowly scoped.

### Insight
A long-running, static build agent is a huge liability. If compromised, it becomes a persistent base for an attacker to explore your network. Ephemeral, single-use build agents are the modern standard. They are created just-in-time for a build and destroyed immediately after, wiping out any foothold an attacker may have gained.

### Practical
*   **Use Ephemeral Build Agents:** Configure Jenkins to dynamically provision build agents on-demand using containers or temporary VMs. The agent should be torn down as soon as the build finishes.
*   **Network Segmentation:** Place your build agents in an isolated network segment. They should only be able to connect to the specific services they need (e.g., the Jenkins controller, your artifact repository, your source code repository) and nothing else. Block all other outbound traffic.
*   **Use Short-Lived, Scoped Credentials:** Instead of giving a pipeline a static, powerful AWS key, configure it to assume an IAM role that provides temporary credentials (e.g., valid for 1 hour) with the minimum required permissions (e.g., only `s3:PutObject` to a specific bucket).

### Tools/Techniques
*   [Jenkins Kubernetes Plugin](https://plugins.jenkins.io/kubernetes/): The standard for running ephemeral build agents as pods in a Kubernetes cluster.
*   [AWS IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html): Allows a Kubernetes pod (your build agent) to assume an IAM role without needing to manage static keys. Similar features exist for [Google Cloud](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) and [Azure](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview).
*   **Cloud Security Groups / Firewalls:** Use cloud-native firewalls (like AWS Security Groups or GCP Firewall Rules) to enforce strict network policies for your build agent environments.

### Metrics/Signal
*   Percentage of builds running on ephemeral vs. static agents (goal: 100%).
*   Average credential lifetime for roles used in CI/CD pipelines.
*   Number of firewall logs showing denied egress traffic from build agents to unauthorized destinations.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about visibility. How do you know an attack is happening? You need to collect the right logs and monitor for suspicious activity. For this scenario, this means watching for unusual behavior in Jenkins itself (e.g., someone changing security settings), on the build agents (e.g., a build process trying to connect to a weird IP address), and in your downstream systems (e.g., an AWS account suddenly showing API calls from a Jenkins role at 3 AM).

### Insight
Attackers have to interact with the system to achieve their goals, and these interactions create noise. A build script that suddenly runs `whoami` or `ifconfig`, a user logging in from an unknown IP address, or a script trying to read `/etc/passwd` are all deviations from normal behavior. Effective detection is about establishing a baseline of "normal" so you can spot these anomalies.

### Practical
*   **Centralize Logs:** Forward Jenkins application logs, system logs, and audit logs to a centralized Security Information and Event Management (SIEM) system.
*   **Monitor Build Activity:** Instrument your build agent environment to monitor process execution and network connections. Alert on the execution of reconnaissance commands (`ls`, `id`, `uname`) or network tools (`curl`, `wget`, `ncat`) when not expected.
*   **Monitor Cloud Activity:** Use your cloud provider's security monitoring tools to watch for suspicious API calls made with credentials originating from Jenkins. For example, an IAM role used for building a container image should never be used to spin up new VMs.

### Tools/Techniques
*   [Audit Trail Plugin](https://plugins.jenkins.io/audit-trail/): Logs all security-sensitive actions in Jenkins, like logins, job configuration changes, and script approvals.
*   [Falco](https://falco.org/): An open-source runtime security tool that can detect anomalous behavior inside containers, perfect for monitoring ephemeral build agents. For example, you can write a rule to alert if a process other than `mvn` or `npm` makes an outbound network connection.
*   [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) / [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit): The definitive source for all API activity in your cloud account. Ingest these logs into your SIEM and build alerts for suspicious behavior tied to CI/CD service roles.

### Metrics/Signal
*   Alert fires when a user logs into Jenkins from a new or suspicious geolocation.
*   Alert fires when a build agent process attempts to connect to an IP address not on an allowlist.
*   Alert fires on a CloudTrail event showing a Jenkins IAM role being used for an action it has never performed before (e.g., `ec2:RunInstances`).

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This final stage is about building muscle memory. You can have all the best tools and processes, but if your team doesn't know how to use them under pressure, they will fail. You need to regularly practice responding to this exact attack scenario in a controlled way. This could range from a simple discussion-based exercise to a full-blown red team simulation.

### Insight
Security is a team sport. Running these exercises helps more than just the security team; it educates developers on the real-world impact of a seemingly small mistake, like committing a `Jenkinsfile` with a hardcoded password. When a developer has actively participated in an exercise where they see how that mistake leads to a full system compromise, they are far less likely to make it again.

### Practical
*   **Tabletop Exercise:** Get the development, operations, and security teams in a room. Present the attack scenario step-by-step ("The attacker has just gained RCE on the Jenkins controller. What do we see in our logs? What is our first action?"). This tests your incident response plan without touching any live systems.
*   **Live Fire Drill:** In a non-production environment, have a security engineer (or a "purple team") attempt to carry out parts of the attack. For example, can they get a build pipeline to print a secret to the log? Does this trigger an alert? This tests your detection and response controls in a realistic way.
*   **CI/CD Security Game Day:** Create a "capture the flag" style challenge where developers are given a deliberately vulnerable Jenkins setup and have to find and exploit the flaws (e.g., bypass the sandbox, find a hardcoded secret) and then fix them.

### Tools/Techniques
*   [Damn Vulnerable Jenkins](https://github.com/redtimmy/Damn-Vulnerable-Jenkins): A pre-packaged, intentionally vulnerable Jenkins environment specifically designed for security training and exercises.
*   [Attack-Range](https://github.com/splunk/attack_range): A framework for quickly building a small lab environment with logging and detection tools (like Splunk) to test attack scenarios.
*   **Internal Training:** Develop short training modules for developers focusing on secure pipeline patterns, such as how to correctly handle secrets and why the sandbox is important.

### Metrics/Signal
*   Reduction in Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) for simulated incidents over time.
*   Percentage of developers who have completed annual CI/CD security training.
*   Number of security improvements or bug fixes generated as a direct result of an exercise.
{% endblock %}