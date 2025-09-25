---
 permalink: /battlecards/aitypesquatting

battlecard:
 title: AI Dependency Typosquatting
 category: Package Ecosystem
 scenario: AI Framework Ecosystems
 focus: 
   - fake PyTorch/TensorFlow packages 
   - malicious Hugging Face libraries 
   - GPU driver/plugin backdoors 
---

An attacker targets an ML team at a fast-growing tech startup. They notice the team's public GitHub repositories frequently use PyTorch and various utility libraries. The attacker creates a malicious Python package named `torch-utilites` (a common typo for "utilities") and publishes it to the Python Package Index (PyPI). This package mimics the functionality of a legitimate but less-known library for data augmentation, but its `setup.py` script contains an extra, obfuscated payload.

When a developer on the team, working against a deadline, quickly searches for a helper library and makes a typo (`pip install torch-utilites`), the malicious package is installed. Upon installation, the payload executes:
1.  It scans the environment variables for `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `HF_TOKEN`.
2.  It exfiltrates these credentials to an attacker-controlled endpoint.
3.  It probes the system for NVIDIA GPU drivers and, if found, attempts to patch a configuration file to inject a malicious shared library on the next driver load, creating a persistent backdoor for siphoning model data or hijacking GPU resources for crypto-mining.

A developer inadvertently commits the typo to their `requirements.txt` file, and the malicious package is now pulled into the team's CI/CD pipeline, compromising build servers and potentially production environments.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. They aren't launching attacks blindly; they're researching targets to find the path of least resistance. For an AI supply chain attack, they're looking for information about your team's technology stack, development habits, and potential weaknesses. It's like a burglar casing a neighborhood, noting which houses have unlocked windows. They want to understand what frameworks (PyTorch, TensorFlow), libraries (Hugging Face Transformers), and tools you use so they can craft a convincing lure.

### Insight
Attackers use automation to find high-value targets. They scan public sources like GitHub, LinkedIn, and Stack Overflow for clues. A job posting for an "ML Engineer with PyTorch & KubeFlow" tells them exactly what technologies to target. They also programmatically search package registries like PyPI for popular packages that have similar, unregistered names (typosquatting) or identify popular but poorly maintained packages they could potentially take over (account hijacking).

### Practical
-   **Audit your public footprint:** Search GitHub for your organization's name. Are there any `requirements.txt` or `pyproject.toml` files in public repositories? Do they expose the exact versions of all your internal dependencies?
-   **Review developer profiles:** Be aware that team members' public GitHub or LinkedIn profiles can reveal your internal tech stack.
-   **Think like an attacker:** Search PyPI or NPM for common misspellings of the packages you use most often. Are they available to be registered?

### Tools/Techniques
-   **GitHub Search:** Use advanced search queries like `org:your-company-name filename:requirements.txt` to find exposed dependency lists.
-   **Grep.app:** A tool to [search across a vast index of public Git repositories](https://grep.app/). Useful for finding mentions of your internal tools or developers.
-   **Social Media Monitoring:** Check job postings on sites like LinkedIn, which often detail the specific frameworks and libraries a team uses.

### Metrics/Signal
-   Number of public repositories containing dependency files.
-   Discovery of available, high-risk typosquatted names for your critical dependencies.
-   Public exposure of internal package names or repository URLs.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you turn the lens on yourself. How would you fare against the scenario? This stage is about honestly assessing your team's current processes, tools, and habits. Do developers `pip install` packages from tutorials without a second thought? Is there a formal process for vetting and approving new third-party dependencies? Are your dependency files pinned to exact versions, or do they use loose ranges that could automatically pull in a new, malicious version?

### Insight
The biggest vulnerability is often cultural, not technical. In a high-pressure environment focused on shipping features, security can be seen as a blocker. The goal of an evaluation is not to assign blame but to identify the specific places where a shortcut taken for speed could open a major security hole. A single unvetted `pip install` can compromise an entire organization.

### Practical
-   **Conduct a Dependency Audit:** Pull your project's main `requirements.txt` or `package.json`. For each dependency, especially the less common ones, ask:
1.  Who is the maintainer? Is it a reputable organization or a random, anonymous account?
2.  When was it last updated?
3.  Does the package name have any common misspellings?
-   **Review your CI/CD Pipeline:** Does it have direct access to production secrets? Can a compromised build job access your model registry or data stores?
-   **Interview your team:** Ask developers how they typically add a new library to a project. Is there a security review step?

### Tools/Techniques
-   **[Socket](https://socket.dev/):** A tool that goes beyond just known CVEs to proactively detect risky behavior in open-source packages (e.g., use of `eval()`, network calls in install scripts).
-   **[pip-audit](https://pypi.org/project/pip-audit/):** Scans your Python environment for packages with known vulnerabilities.
-   **[Snyk Open Source](https://snyk.io/product/open-source-security-management/):** Scans dependencies and provides reports on vulnerabilities and license issues.

### Metrics/Signal
-   Percentage of dependencies that are not pinned to a specific, hashed version.
-   Number of direct dependencies that have a single, non-organizational maintainer.
-   The time it takes for a new dependency to go from a developer's machine to production (a longer, more deliberate time can indicate a review process is in place).

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is the proactive, defensive stage. Based on your evaluation, you now harden your systems, pipelines, and developer practices to prevent the attack from succeeding in the first place. The goal is to build a "secure supply chain" where every dependency is verified and trusted before it ever gets near your production code, data, or models.

### Insight
A strong defense relies on automation and making the secure path the easy path. Developers shouldn't have to be security experts. Instead, the CI/CD pipeline and development tools should enforce security policies automatically. For example, instead of relying on developers to remember to hash their dependencies, use a tool that does it for them and make it a required part of the build process.

### Practical
-   **Pin and Hash Everything:** Don't just specify the version (`==1.2.3`); specify the file hash. This ensures that even if a version is replaced with a malicious file, your build will fail because the hash won't match.
-   **Use a Private Package Repository:** Set up an internal proxy for PyPI, NPM, etc. This acts as a quarantine zone. You can vet and approve packages into your local repository, and all developers/CI systems pull from there exclusively. This prevents them from accidentally pulling a typosquatted package directly from the public internet.
-   **Enforce Security Gates:** Configure your CI pipeline to fail if it detects:
1.  A new, unapproved dependency.
2.  A dependency with a known high-severity vulnerability.
3.  A dependency that is not pinned and hashed.

### Tools/Techniques
-   **[pip-tools](https://github.com/jazzband/pip-tools):** Use `pip-compile --generate-hashes` to create a fully pinned and hashed `requirements.txt` from a simple `requirements.in` file.
-   **[Poetry](https://python-poetry.org/):** A modern Python dependency manager that creates a `poetry.lock` file with exact versions and hashes by default.
-   **[JFrog Artifactory](https://jfrog.com/artifactory/) / [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository):** Self-hosted or cloud-based artifact repositories that can proxy public repositories and enforce security policies.
-   **[Sigstore](https://www.sigstore.dev/):** An emerging standard for signing and verifying software artifacts, helping to ensure the package you are installing is from the developer who claims to have published it.

### Metrics/Signal
-   100% of dependencies in production builds have a matching content hash.
-   Number of build failures caused by the introduction of unapproved or vulnerable packages.
-   All traffic to public package registries (`pypi.org`) is blocked from build agents, forcing all requests through your private proxy.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker succeeded; the malicious package was installed and is running. Limiting the blast radius is about ensuring that this compromise is contained and doesn't lead to a total disaster. If the malicious code is running in your CI pipeline, it shouldn't be able to access your production database. If it's on a developer's laptop, it shouldn't be able to pivot to the rest of the corporate network.

### Insight
The principle of "least privilege" is key. No process, user, or system should have more access than it absolutely needs to do its job. A build server doesn't need persistent admin credentials to your cloud account; it needs temporary, scoped-down credentials that expire after the job is finished. Think in terms of sealed compartments on a ship; a breach in one compartment doesn't sink the whole vessel.

### Practical
-   **Isolate Build Environments:** Run every CI/CD job in a fresh, ephemeral container with no network access by default. Only allowlist the specific domains it needs to contact (e.g., your artifact repository, your git server).
-   **Use Short-Lived, Scoped Credentials:** Instead of storing `AWS_ACCESS_KEY_ID` as a long-lived secret in your CI system, use a mechanism like IAM Roles for Service Accounts (IRSA) on EKS or workload identity federation to grant the build job temporary, fine-grained credentials.
-   **Segment Networks:** Your development environment, build environment, and production environment should be in separate, firewalled network segments.
-   **Containerize Development:** Encourage developers to use containerized development environments (like Docker or Dev Containers in VS Code) to isolate project dependencies from their host machine.

### Tools/Techniques
-   **[Docker](https://www.docker.com/) / [Podman](https://podman.io/):** Use containers to isolate processes. Use `seccomp` profiles and drop Linux capabilities to further harden the runtime environment.
-   **[Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/):** Define firewall rules at the pod level to control which services can communicate with each other.
-   **[HashiCorp Vault](https://www.vaultproject.io/):** A tool for centrally managing secrets and generating dynamic, short-lived credentials for databases, cloud providers, and more.
-   **Cloud IAM:** Leverage features like [AWS STS (Security Token Service)](https://aws.amazon.com/iam/features/security-token-service/) or [Google Cloud Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) to provide temporary credentials.

### Metrics/Signal
-   Time-to-Live (TTL) on credentials issued to automated systems. Should be measured in minutes or hours, not days or months.
-   Number of allowed egress destinations from a CI runner (lower is better).
-   Percentage of internal services that require authentication and authorization (mTLS, OAuth) for communication.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about visibility. How do you detect an attack in progress? If a malicious package starts exfiltrating your AWS keys or scanning your network, you need the right logging, monitoring, and alerting in place to catch it. Without this, the attacker can operate undetected for weeks or months. You need to know what "normal" behavior looks like for your applications and systems so that you can spot anomalies.

### Insight
Attackers often try to blend in with normal traffic, but they can't hide completely. A `pip install` process should never try to read `~/.ssh/id_rsa`. A data processing job might send a lot of data to your own S3 buckets, but it should never open a connection to a random IP address in Eastern Europe. The key is to monitor for these behavioral outliers.

### Practical
-   **Monitor Network Egress:** Log all outbound network connections from your CI runners and production servers. Alert on connections to unknown or suspicious IP addresses or domains.
-   **Log System Calls:** Use a runtime security tool to monitor process activity. Alert on suspicious behaviors like a build script spawning a shell, modifying system binaries, or reading sensitive files.
-   **Instrument GPU Usage:** Monitor GPU utilization, memory usage, and temperature. A backdoor used for crypto-mining will often cause a sustained, high GPU load that is inconsistent with normal ML training workloads.

### Tools/Techniques
-   **[Falco](https://falco.org/):** An open-source cloud-native runtime security tool that can detect anomalous behavior by tapping into system calls. Example rule: `alert on "pip" process making an outbound network connection`.
-   **[Prometheus](https://prometheus.io/) + [NVIDIA DCGM Exporter](https://github.com/NVIDIA/dcgm-exporter):** Use Prometheus to scrape detailed GPU metrics. Create Grafana dashboards and alerts for unusual patterns.
-   **VPC Flow Logs / Cloud Flow Logs:** Enable network flow logging in your cloud environment and feed it into a security analytics tool (SIEM) like [Splunk](https.www.splunk.com/), [Elastic Security](https://www.elastic.co/security), or [OpenSearch](https://opensearch.org/) to hunt for suspicious connections.
-   **[osquery](https://osquery.io/):** An OS instrumentation framework that allows you to query your hosts using SQL-like syntax to detect unexpected changes, like a modified GPU driver configuration file.

### Metrics/Signal
-   Alerts generated for network connections from a build agent to a non-allowlisted destination.
-   Alerts from a runtime security tool indicating a suspicious sequence of system calls (e.g., file read from `/etc/passwd` followed by a network connection).
-   Sustained high GPU utilization outside of a scheduled training job's execution window.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice for game day. A security policy is just a document until it's been tested under pressure. The goal of an exercise is to simulate the attack in a controlled way to see how your people, processes, and tools hold up. Does anyone notice the suspicious package? Do your alerts fire? Does the on-call engineer know how to respond? This builds the "muscle memory" your team needs to react effectively during a real incident.

### Insight
Security exercises shouldn't be "gotcha" tests. They are collaborative learning opportunities. The goal is not to pass or fail but to find the weaknesses in your defenses and fix them before a real attacker does. A well-run exercise will feel like a real incident but without the real damage, providing invaluable experience for everyone involved.

### Practical
-   **Run a Tabletop Exercise:** Gather the dev team, security, and operations. Walk through the scenario verbally: "A developer reports they accidentally installed a malicious PyPI package. What do we do *right now*?" Map out the communication and response steps.
-   **Perform a Live Fire Simulation (Purple Team):**
1.  Create a harmless "malicious" package and upload it to a private repository. Name it something like `pytorch-utilz`.
2.  The package's install script should perform a detectable, benign action: write a file to `/tmp/security-drill.txt` or make a DNS request to a unique domain you control (`drill.your-company.com`).
3.  Have a developer (who is in on the test) add this package to a feature branch and push it.
4.  Now, watch and wait. Does the CI pipeline block it? Does the runtime security tool alert on the file write? How long does it take for someone to notice?
-   **Review and Improve:** After the exercise, hold a blameless post-mortem. What worked well? Where did the process break down? Was the alert clear? Create action items to fix the gaps you found.

### Tools/Techniques
-   **Controlled Test Environments:** Use a dedicated, isolated Kubernetes cluster or set of VMs for live fire exercises to prevent any accidental impact on production.
-   **Attack Simulation Platforms:** Tools like [Stratus Red Team](https://github.com/DataDog/stratus-red-team) can help you emulate specific attacker TTPs (Tactics, Techniques, and Procedures) in a safe and automated way.
-   **Internal Documentation / Runbooks:** Use the exercise to build and refine your incident response runbooks in your company wiki (e.g., Confluence, Notion).

### Metrics/Signal
-   **Time to Detect (TTD):** The time from the simulated malicious code execution to the first alert being generated.
-   **Time to Respond (TTR):** The time from the alert firing to an engineer actively investigating the incident.
-   **Number of Gaps Identified:** The number of concrete improvements (e.g., "add a new Falco rule," "clarify the on-call runbook") that come out of the post-mortem.
{% endblock %}