---
 permalink: /battlecards/python2
battlecard:
 title: Python and pip Supply Chain Issues
 category: Package Ecosystem
 scenario: Python + pip
 focus: 
   - typosquatting 
   - malicious postinstall scripts 
   - requirements.txt drift 
---

An attacker targets a fast-growing fintech company that uses Python for its backend services. Their goal is to steal cloud credentials (AWS keys) from the company's CI/CD environment.

The attacker identifies that the company uses the popular `python-dateutil` package. They create and publish a malicious package to PyPI named `python-datetutil`—a common typo. This malicious package is a direct copy of the real one, but with a crucial modification to its `setup.py` file. It includes a post-install script that scans the environment variables for anything matching the pattern `AWS_*` and exfiltrates them via a Base64-encoded POST request to an attacker-controlled server.

A developer at the company is manually adding a new dependency. In a hurry, they type `pip install python-datetutil` and add the typo to their project's `requirements.txt`. The change is committed, and the CI/CD pipeline kicks off. The pipeline executes `pip install -r requirements.txt`, which downloads and installs the malicious package. The post-install script runs within the build container, finds the CI/CD role's AWS credentials, and sends them to the attacker. The attacker now has credentials to access the company's cloud resources.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. They aren't targeting you specifically yet, but rather looking for opportunities within the Python ecosystem. They use automated tools to scan PyPI, the public Python Package Index, for popular packages. They focus on packages with high download counts, especially those used in commercial applications (e.g., data science, web frameworks, cloud SDKs). They then generate a list of potential typosquatting names for these packages by swapping characters, adding or removing letters, or using common misspellings. They might also scan public GitHub repositories for `requirements.txt` files to identify commonly used packages and organizational patterns, making their fake packages more believable.

### Insight
Attackers operate on probability. They know that out of millions of `pip install` commands run every day, a small percentage will contain typos. By impersonating a popular package, they maximize their chances of a developer making a mistake. Your company's public code, documentation, and even job postings can provide attackers with clues about your tech stack, making you a more attractive target.

### Practical
Assume that any dependency you use can be a target for typosquatting. Understand that your public repositories are visible to attackers. Review your organization's public code on GitHub to see what information you might be leaking about your internal technology choices.

### Tools/Techniques
*   **Public Data Sources**: Attackers use public sources to find targets.
*   [PyPI Stats](https://pypistats.org/): To identify popular, high-value packages to impersonate.
*   [GitHub Code Search](https://github.com/search): To find `requirements.txt` files in public repositories, revealing which packages companies use.
*   **Permutation Generators**: Tools to create convincing typos.
*   [dnstwist](https://github.com/elceef/dnstwist): While designed for domain names, the same logic is used to generate package name permutations.

### Metrics/Signal
*   This stage is performed by the attacker, so there are no direct defensive metrics. However, you can monitor for new packages being published to PyPI that are typo-variants of your own company's public packages.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is your internal audit. How susceptible are you to this attack? A developer can assess this by looking at processes and code. The primary vulnerability is how your team manages dependencies. Do you have unpinned versions in your `requirements.txt` (e.g., `requests>=2.0`)? This is "requirements drift" and it means a `pip install` could pull a newer, potentially malicious version without you knowing. Do developers add dependencies without a code review? Is there a formal process for vetting a new open-source library before it's adopted?

### Insight
Your biggest vulnerability is often an informal or inconsistent process. A culture of "just install it if it works" is a massive security risk. The `requirements.txt` file is a manifest of trust; every line is an external entity you are giving permission to execute code in your environment. Without strict controls, that trust is easily exploited.

### Practical
Review your project's `requirements.txt` files. Are all versions pinned using `==`? Check your Git history to see how often new dependencies are added and if those changes are scrutinized in pull requests. Ask your team: "If we needed a new library to parse XML, how would we choose it, and what's the process to get it approved?"

### Tools/Techniques
*   **Code Scanning**:
*   [pip-audit](https://github.com/pypa/pip-audit): Scans your environment for packages with known vulnerabilities. A high number of findings often correlates with poor dependency hygiene.
*   [Snyk](https://snyk.io/): A commercial tool that scans `requirements.txt` for vulnerabilities and provides reports on dependency health.
*   **Manual Check**: A simple `grep -v '==' requirements.txt` can quickly show you unpinned or loosely-pinned dependencies.

### Metrics/Signal
*   **Dependency Pinning Rate**: Percentage of dependencies in `requirements.txt` files that are pinned with `==`. Aim for 100%.
*   **New Dependency Review**: All pull requests that add or change a dependency must have at least one approval from a designated code owner or security champion.
*   **Vulnerability Scan Results**: Number of critical/high vulnerabilities detected in your dependencies. A falling number indicates improving hygiene.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is where you build your defenses. The goal is to make it technically difficult or impossible for a malicious package to enter your system. The most effective defense is to be explicit and deterministic about your dependencies. This means pinning not only your direct dependencies but also your *transitive* dependencies (the dependencies of your dependencies). You should also verify the integrity of packages by checking their hashes against a known-good value.

### Insight
A simple `requirements.txt` file is not enough because it doesn't control transitive dependencies. A **lock file** is the solution. A lock file is a machine-generated, fully deterministic list of every package and sub-package required, pinned to an exact version and, ideally, a checksum hash. This ensures that the `pip install` you run today is identical to the one you run six months from now, eliminating drift and making it impossible for a new, malicious package to be introduced silently.

### Practical
Use a tool to generate a lock file from a high-level list of dependencies. For example, you maintain a `requirements.in` with your direct dependencies (`requests`, `boto3`), and you use a tool to compile it into a `requirements.txt` file containing every dependency pinned with hashes. Commit this lock file to your source control and use it in your CI/CD pipeline.

### Tools/Techniques
*   **Lock File Generation**:
*   [pip-tools](https://github.com/jazzband/pip-tools): Use `pip-compile requirements.in` to generate a fully-pinned `requirements.txt`.
*   [Poetry](https://python-poetry.org/): A modern dependency management tool that uses `pyproject.toml` and a `poetry.lock` file by default.
*   **Hash Checking**:
*   Enforce hash checking during installation: `pip install -r requirements.txt --require-hashes`. This will cause the installation to fail if a package's hash doesn't match the one in the file.
*   **Private Repository**:
*   [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository): Use these as a proxy to PyPI. You can configure them to only allow access to a vetted list of packages, effectively creating a "walled garden" for your developers.

### Metrics/Signal
*   **Lock File Adoption**: 100% of projects use a dependency locking mechanism.
*   **CI/CD Enforcement**: The build pipeline fails if `pip install` is run without `--require-hashes`.
*   **New Package Policy**: A new dependency is only added to the internal repository after a security review is completed and documented.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and their malicious code is running. The goal now is to contain the "blast radius." The damage a malicious script can do is directly proportional to the permissions of the environment it runs in. If your `pip install` command runs in a CI/CD pipeline with admin-level cloud credentials, you’ve lost the kingdom. If it runs in a sandboxed, ephemeral container with no network access and short-lived credentials scoped only to push a container image, the damage is severely limited.

### Insight
Treat your build environment with the same security rigor as your production environment. It is a prime target for attackers because it often contains secrets, credentials, and access to internal systems. The principle of least privilege is your most powerful tool here: grant your build process only the bare minimum permissions it needs to do its job, and for the shortest possible time.

### Practical
Run your dependency installation step in an isolated environment. Use multi-stage Docker builds to install dependencies in one stage and then copy the installed packages to a clean, network-isolated second stage for the application itself. Use short-lived, narrowly-scoped credentials for your build jobs instead of static, long-lived keys.

### Tools/Techniques
*   **Ephemeral/Sandboxed Builds**:
*   [Docker](https://www.docker.com/) multi-stage builds to separate dependency installation from the final application environment.
*   Kubernetes Network Policies to restrict or block egress network traffic from build pods to the internet.
*   **Least-Privilege Credentials**:
*   [GitHub Actions OIDC integration with AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services): Allows your GitHub Actions workflow to assume an IAM role and get short-lived credentials without storing static keys.
*   [AWS IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html): The equivalent for services running on an EKS cluster.

### Metrics/Signal
*   **Credential TTL**: The time-to-live for credentials used in CI/CD is less than 1 hour.
*   **Network Egress Rules**: The CI/CD environment has a default-deny egress network policy, with explicit allow-rules only for necessary endpoints (e.g., your package repository, container registry).
*   **Secret Scans**: No long-lived secrets (API keys, passwords) are found in build logs or environment variables.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
How do you know the attack happened? Detection relies on observing anomalies. A malicious post-install script exfiltrating data will create signals you can monitor. The most obvious is an unexpected outbound network connection from a build agent to an unknown IP address. After the credentials are stolen, you might see API calls from an unusual IP address or region, or the creation of strange resources in your cloud account (like a dozen large GPU instances for crypto-mining).

### Insight
You are unlikely to catch the malicious code *before* it runs. Instead, you should focus on detecting the *behavior* of the malicious code. The goal is to have monitoring and alerting in place that can tell you "this is not normal" so you can investigate immediately. A baseline of normal activity is critical; without it, you can't spot the anomalies.

### Practical
Log all DNS queries and egress network traffic from your build environments. Ingest your cloud provider's audit logs (e.g., AWS CloudTrail) into a security monitoring system. Create alerts for high-risk API calls (e.g., creating a new IAM user, generating new access keys) or for API activity originating from outside your expected IP ranges.

### Tools/Techniques
*   **Cloud Threat Detection**:
*   [Amazon GuardDuty](https://aws.amazon.com/guardduty/): Uses machine learning to detect anomalous API activity, such as credential usage from a known malicious IP.
*   [AWS CloudTrail](https://aws.amazon.com/cloudtrail/): Provides a complete audit trail of all API calls made in your account. Query it for unusual events.
*   **Runtime and Network Monitoring**:
*   [Falco](https://falco.org/): An open-source container runtime security tool that can detect suspicious behavior like unexpected network connections or shell processes being spawned inside a container.
*   **VPC Flow Logs**: Analyze network traffic logs to baseline normal traffic patterns and alert on deviations.

### Metrics/Signal
*   **Mean Time To Detect (MTTD)**: How long does it take from the point of compromise to the first alert being generated?
*   **Egress Anomaly Alerts**: Alerts generated for network connections from build agents to non-allowlisted IP addresses or countries.
*   **CloudTrail Anomaly Alerts**: Alerts generated for API calls that deviate from established patterns (e.g., a user who normally only accesses S3 suddenly tries to launch EC2 instances).

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is how you build muscle memory. You need to practice your response to this scenario in a controlled way. This involves running drills to test your tools, processes, and people. These exercises aren't about pass/fail; they are about identifying weaknesses in a safe environment so you can fix them before a real attack.

### Insight
A security tool that no one knows how to use is worthless. A response plan that only exists in a document is just theory. Running regular exercises—from simple tabletop discussions to live-fire drills—is the only way to ensure your team can execute effectively under the pressure of a real incident.

### Practical
1.  **Tabletop Exercise**: Gather the development and security teams. Present the scenario: "A GuardDuty alert just fired for credential usage from an unknown IP. The credentials belong to our CI/CD role. What are our immediate steps?" Walk through the process of identifying the source, revoking credentials, and assessing the damage.
2.  **Live-Fire Drill**: Create a harmless "malicious" package and host it on an internal repository. This package could, on installation, simply make a DNS query to a unique, monitored domain or write a file to `/tmp/security-drill.txt`. Have a developer add it to a test project. Did your monitoring tools (`Falco`, network logs, etc.) detect it? How quickly did the team respond to the alert?

### Tools/Techniques
*   **Internal Package Repositories**: Use [Artifactory](https://jfrog.com/artifactory/) or [Nexus](https://www.sonatype.com/products/nexus-repository) to host your benign-but-malicious test package for live drills.
*   **Incident Response Platforms**: Use tools like [PagerDuty](https://www.pagerduty.com/) or an internal Slack workflow to simulate the alerting and communication process. Who gets paged at 2 AM? What information is in the alert?
*   **Red Teaming**: For mature organizations, hire an external red team to perform this attack without the development team's prior knowledge to get a true test of your defenses.

### Metrics/Signal
*   **Drill Success Rate**: Percentage of security drills that successfully result in a detection alert being generated and triaged.
*   **Time To Remediate (TTR)**: In a drill, how long does it take from the initial alert to the point where the "compromise" is contained (e.g., credentials revoked, malicious package removed)?
*   **Post-Mortem Action Items**: Number of actionable improvements identified from an exercise, and the rate at which they are implemented.
{% endblock %}