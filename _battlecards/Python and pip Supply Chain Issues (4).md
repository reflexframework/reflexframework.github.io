---
 permalink: /battlecards/python4
battlecard:
 title: Python and pip Supply Chain Issues
 category: Package Ecosystem
 scenario: Python + pip
 focus: 
   - typosquatting 
   - malicious postinstall scripts 
   - requirements.txt drift 
---

An attacker targets a fast-growing fintech company that uses Python. Their goal is to steal cloud credentials from the company's CI/CD environment to access sensitive customer data.

The attacker identifies that the company uses the popular `requests` library. They create and publish a malicious package to PyPI named `reqeusts`—a common typo. This malicious package is a direct copy of the real `requests` library, but with one addition: its `setup.py` file includes a post-install script.

This script executes silently upon `pip install reqeusts`. It scans the environment variables of the machine it's running on (the developer's laptop or, ideally for the attacker, the CI/CD runner), looking for patterns like `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. If found, it base64 encodes them and exfiltrates them via an HTTP POST request to a server the attacker controls.

The attack succeeds when a developer, rushing to fix a bug, makes a typo while manually editing a `requirements.txt` file (`reqeusts==2.25.1`). The change is committed, and the CI/CD pipeline automatically runs `pip install -r requirements.txt`, installing the malicious package and sending the CI runner's AWS credentials directly to the attacker. This happens because the company's `requirements.txt` files are not version-pinned or hash-checked, leading to "dependency drift" and creating the perfect opening.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. For a software supply chain attack, they aren't trying to find open ports on your servers; they are studying your development ecosystem and its dependencies. They will look for popular public packages that are foundational to many projects. Their tactics involve identifying common misspellings (typosquatting), similar names (brand-jacking), or promising-sounding new packages to exploit. They scan public code repositories like GitHub for `requirements.txt` or `pyproject.toml` files to learn what packages your company and developers like you are using. This helps them choose a high-value target package to impersonate.

### Insight
The attacker is exploiting the trust you inherently place in the open-source ecosystem. They know developers often install packages based on a name they read in a tutorial without deeply vetting the package's origin or author. The public nature of open-source development provides attackers with a near-perfect map of your technology stack.

### Practical
Go to your organization's public GitHub page. Can you find dependency files (`requirements.txt`, `package.json`, `pom.xml`) in any of the repositories? This is what an attacker sees. Assume any dependency you use can be targeted.

### Tools/Techniques
*   **GitHub Code Search**: Attackers use advanced search queries like `org:your-company-name filename:requirements.txt` to find dependency lists.
*   **PyPI/NPM Analysis**: Tools that scrape package registries are used to find popular packages and check if common typos of their names are available for registration.
*   **Social Engineering**: Monitoring developer forums, Discord/Slack channels, or Stack Overflow to see what tools and libraries developers are discussing.

### Metrics/Signal
*   Number of public repositories containing dependency manifest files.
*   Popularity score (e.g., download count) of the dependencies you use, as more popular packages are more attractive targets.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you assess your own environment's vulnerability to the scenario. A developer can do this by examining their team's processes and code. Look at your `requirements.txt` file. Are the versions pinned (e.g., `requests==2.28.1`) or are they floating (e.g., `requests`)? More importantly, are you using hashes (`--hash=sha256:...`)? If you're not using hashes, you are vulnerable to a legitimate package being compromised, not just typosquatting. How are new dependencies added to a project? Is there a code review process that scrutinizes changes to dependency files? Does your build process pull directly from the public internet (pypi.org)?

### Insight
Convenience is the enemy of security. A loose dependency definition like `requests>=2.0` is convenient because you automatically get bug fixes, but it also means your build could suddenly pull a new, compromised version without warning. This is "dependency drift," and it's a significant risk. Your vulnerability is directly proportional to how little control you exert over the exact code entering your build pipeline.

### Practical
Perform a quick audit. Pick a project and look at its `requirements.txt`.
1.  Run `pip freeze > current.txt` in the project's virtual environment.
2.  Compare this with the committed `requirements.txt`. Are there differences? Those are your transitive, unmanaged dependencies.
3.  Does your `requirements.txt` include hashes for every package? If not, you are vulnerable.

### Tools/Techniques
*   **Manual Review**: Simply read your `requirements.txt`, `pyproject.toml`, or other dependency manifests.
*   **pip-audit**: A tool from PyPA (the Python Packaging Authority) that scans your environment for known vulnerabilities in your dependencies.
*   **Dependency Graphs**: Use tools to visualize your full dependency tree (including transitive dependencies). You might be surprised what's actually in your application.

### Metrics/Signal
*   Percentage of dependencies that are not pinned to an exact version and hash.
*   Ratio of direct dependencies (in your `requirements.txt`) to transitive dependencies (pulled in by the direct ones). A high ratio can indicate hidden complexity and risk.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening is about taking control of your software supply chain. The most effective defense is to use a "lockfile"—a file that pins every single dependency, including transitive ones, to a specific version and a cryptographic hash. This ensures that every install, on every machine, for every build, is byte-for-byte identical and verified. Additionally, instead of pulling packages directly from public registries during a critical CI build, use an intermediary repository proxy. This proxy can vet, scan, and cache approved packages, acting as a trusted local source.

### Insight
You should treat dependencies with the same rigor as your own source code. They are executable code running with the permissions of your application. The goal is to move from a state of implicit trust ("I hope `requests` is okay") to explicit verification ("I am installing the exact version of `requests` with this specific hash, which we have previously approved").

### Practical
1.  Define your direct dependencies in a file like `requirements.in`.
2.  Use a tool like `pip-compile` to generate a locked `requirements.txt` file from your `.in` file. This new file will contain the entire dependency tree, pinned with versions and hashes.
3.  Commit both files to your repository.
4.  Your CI/CD pipeline should install using the locked file: `pip install --require-hashes -r requirements.txt`.

### Tools/Techniques
*   **Lockfile Generation**:
*   [pip-tools](https://github.com/jazzband/pip-tools): Provides `pip-compile` and `pip-sync` for managing pinned dependencies.
*   [Poetry](https://python-poetry.org/): A modern dependency management tool that generates a `poetry.lock` file by default.
*   **Repository Management**:
*   [JFrog Artifactory](https://jfrog.com/artifactory/): A universal repository manager that can proxy and cache public registries like PyPI.
*   [Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository): Another popular choice for hosting private packages and proxying public ones.
*   **Malicious Package Detection**:
*   [Socket.dev](https://socket.dev/): Scans packages for suspicious characteristics (like post-install scripts or obfuscated code) before you install them.
*   [Snyk](https://snyk.io/): Scans for both known vulnerabilities (CVEs) and potential malicious package indicators.

### Metrics/Signal
*   Build failure rate due to hash mismatches. A non-zero rate is good; it means the system is working and blocking unexpected changes.
*   100% of projects use lockfiles with hashes.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker's malicious package makes it through your defenses and gets installed. The next goal is to contain the "blast radius." The code is executing in your CI/CD runner—what can it actually do? The principle of least privilege is critical here. The build environment should have the absolute minimum permissions required to do its job. It should use short-lived credentials that expire in minutes, not long-lived static keys. It should run in an isolated, ephemeral container with strict network egress rules, preventing it from calling out to arbitrary internet addresses.

### Insight
A compromised build runner shouldn't be a "game over" event. If an attacker steals a credential from your CI pipeline, that credential should be so limited in scope and lifetime that it's practically useless. Think of the build environment as a temporary, untrusted sandbox, not a privileged part of your infrastructure.

### Practical
Review the IAM role or service account used by your CI/CD runner. Can it access production databases? Can it read S3 buckets with customer data? It shouldn't. Its permissions should be tightly scoped to only what's needed for the build, such as "push a container image to ECR" and nothing more. Use modern authentication mechanisms that don't rely on storing secrets as environment variables.

### Tools/Techniques
*   **Short-Lived Credentials**:
*   **Cloud OIDC Providers**: Use OpenID Connect to grant your CI/CD system (e.g., GitHub Actions, GitLab) the ability to assume a short-lived role in your cloud provider (e.g., [AWS IAM Roles for OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html), [Google Cloud Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)). This avoids storing static `AWS_ACCESS_KEY_ID`s.
*   **Network Isolation**:
*   **Kubernetes Network Policies**: If your runners are on Kubernetes, use network policies to deny all egress traffic by default, only allowing connections to your artifact repository and other necessary internal services.
*   **VPC Security Groups/Firewall Rules**: Configure firewall rules for your build agents that block all outbound traffic except to a specific allowlist of IPs (e.g., your corporate proxy or PyPI's IP range).
*   **Ephemeral Environments**: Run every CI job in a fresh, clean container that is destroyed immediately after the job completes.

### Metrics/Signal
*   Time-to-live (TTL) of credentials used in the CI/CD pipeline (should be measured in minutes, not days or months).
*   Number of allowed egress destinations from the build environment's firewall configuration.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack in progress, you need visibility. The malicious post-install script needs to "call home" to exfiltrate the stolen credentials. This is your chance to catch it. You need logging and monitoring on your build infrastructure. This includes logging every package that is installed, monitoring all outbound network connections, and analyzing DNS queries originating from your build runners. A build that has always connected to `pypi.org` and `github.com` suddenly making a DNS query for `attackers-evil-domain.ru` is a high-confidence indicator of compromise.

### Insight
Your CI/CD pipeline is a production system and should be monitored as such. Attacks against it are often noisy because the attacker *must* exfiltrate data to achieve their goal. This exfiltration traffic is the tripwire. By monitoring for anomalous behavior, you can turn their need to communicate into your detection opportunity.

### Practical
Configure your CI runners to ship logs to a central analysis platform. Specifically, capture network flow logs. Set up a baseline of "normal" network activity for a typical build. Create alerts that fire when a build process makes a connection to a new or unexpected IP address or domain. Generate a Software Bill of Materials (SBOM) for every build artifact and store it; this gives you a manifest of what's inside your software for later analysis.

### Tools/Techniques
*   **Network Monitoring**:
*   [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) (AWS), [Google Cloud VPC Flow Logs](https://cloud.google.com/vpc/docs/using-flow-logs), or similar for other clouds.
*   For Kubernetes, service mesh tools like [Istio](https://istio.io/) or eBPF-based tools like [Cilium](https://cilium.io/) can provide deep visibility into network traffic.
*   **SBOM Generation**:
*   [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) are standard formats for SBOMs.
*   Tools like [Syft](https://github.com/anchore/syft) can automatically generate an SBOM from your container images or filesystem.
*   **Behavioral Analysis**:
*   Tools integrated into the developer workflow, like [Socket.dev](https://socket.dev/), can flag suspicious behaviors (e.g., network access, filesystem access) in packages *before* you even install them.

### Metrics/Signal
*   Number of alerts for unexpected outbound network connections from build agents.
*   A diff in the SBOM between two builds showing a new, unvetted dependency, especially one with a suspicious name.
*   DNS query logs showing requests to domains not on an established allowlist.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is how you build muscle memory. Don't wait for a real attack to test your defenses. Run a security drill by simulating the attack in a controlled way. Create a harmless "malicious" package and upload it to a private repository. This package should mimic the real attack by reading an environment variable and "exfiltrating" it to an internal logging endpoint you control. Then, have a developer on your team try to introduce this package into a test application.

### Insight
A security policy is just a document until it's tested under pressure. These exercises reveal the gaps between what you *think* your process is and what actually happens when a developer is facing a deadline. Did the developer notice the typo? Did the code review catch it? If not, did the automated tooling block it? Did the monitoring system fire an alert? Was the alert actionable?

### Practical
**Game Day Scenario**:
1.  **Red Team (Attacker)**: Creates a fake `reqeusts` package. Its `setup.py` reads an environment variable named `TEST_SECRET` and POSTs it to an internal "alert" webhook. The Red Team then submits a pull request to a test project, changing `requests` to `reqeusts` in `requirements.txt`.
2.  **Blue Team (Defender)**: The rest of the development team. They conduct their normal code review and CI process.
3.  **Observe**:
*   Does the PR reviewer spot the typo?
*   If not, does the build fail due to a hash mismatch (if you've fortified)?
*   If not, does the network monitoring system detect and flag the outbound call from the `setup.py` script?
*   How long did it take from PR submission to detection?

### Tools/Techniques
*   **Private Repository**: Use your own [JFrog Artifactory](https://jfrog.com/artifactory/) or a similar tool to host the safe "malicious" package. Don't upload it to the public PyPI.
*   **Alerting/ChatOps**: Integrate your monitoring alerts with a team chat tool like [Slack](https://slack.com/) or [Microsoft Teams](https://www.microsoft.com/en-us/microsoft-teams/group-chat-software) so that the entire team sees when a security event is detected.
*   **Post-Mortem/Retrospective**: After the exercise, hold a blameless retrospective to discuss what worked, what didn't, and how to improve the process or tooling.

### Metrics/Signal
*   **Mean Time to Detect (MTTD)**: How long did it take from the malicious code's introduction to an alert being fired?
*   **Mean Time to Remediate (MTTR)**: How long did it take to identify the cause, block the attack, and roll back the change?
*   Percentage of developers who successfully identified the simulated threat during the review phase.
{% endblock %}