---
layout: battlecard
---
{% block type='battlecard' text='Scenario'%}
An attacker identifies a mid-sized company that uses Python extensively, noting from their public GitHub repositories that they use a common internal library named `acme-corp-utils`. The attacker's goal is to steal CI/CD credentials (e.g., `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`) to gain further access to the company's cloud infrastructure.

The attacker creates a malicious package named `acme-corp-util` (a common typo) and publishes it to the public PyPI registry. The package's `setup.py` contains a post-install script that executes upon installation. This script reads all environment variables, base64 encodes them, and sends them to the attacker's server via an HTTP POST request.

Weeks later, a developer at the company is rushing to finish a feature. They need a function from the internal library and, working from memory, type `pip install acme-corp-util`. They add this to their project's `requirements.txt`. Because the project's dependencies are not pinned (a form of requirements drift), this new line doesn't look out of place among other loose version specifiers like `requests>=2.25.0`.

The developer commits the change. The pull request is approved without a close look at the dependency change. The CI/CD pipeline kicks off, executes `pip install -r requirements.txt`, and installs the malicious package. The post-install script runs, exfiltrating the CI environment's highly privileged credentials to the attacker.

{% endblock %}
{% block type='battlecard' text='Reconnaissance'%}
### Explanation
This is the attacker's information-gathering phase. They aren't guessing randomly; they are researching your organization to find the weakest link. For a package ecosystem attack, they are looking for information about your technology stack, internal tool names, and developer habits. They will browse public code repositories, read developer blogs, and scan social media to build a profile of your software supply chain. Their goal is to find a plausible name for a typosquatted package that a developer might accidentally install.

### Insight
Your organization's public footprint is the attacker's blueprint. Open-source repositories, while great for collaboration, can reveal internal package naming conventions, dependencies, and infrastructure choices. The more an attacker knows about how you build software, the easier it is for them to craft a convincing fake package.

### Practical
As a team, perform your own reconnaissance on your company. Search GitHub for your organization's name and look at the `requirements.txt`, `package.json`, or `go.mod` files. What could an attacker learn? Do you consistently use a specific prefix for internal packages (e.g., `acme-` or `org-`)? These are prime targets for typosquatting.

### Tools/Techniques
*   **GitHub Search:** Use advanced search queries like `org:your-company-name requirements.txt` to find dependency files in your public repositories.
*   **Public Registries:** Manually search [PyPI](https://pypi.org/), [npm](https://www.npmjs.com/), etc., for names that are confusingly similar to your internal or commonly used packages.
*   **OSINT Tools:** Attackers may use tools to scrape developer profiles on LinkedIn or GitHub to understand your tech stack.

### Metrics/Signal
*   Number of public repositories containing dependency manifests.
*   A list of potential typosquatting variations for your most common internal packages.

{% endblock %}
{% block type='battlecard' text='Evaluation'%}
### Explanation
This stage involves looking inward to assess your own vulnerabilities. Given the attacker's tactics, how likely are they to succeed against your environment? The evaluation focuses on your dependency management practices, code review processes, and CI/CD security posture. It's about honestly answering the question: "Could this happen to us?"

### Insight
A vulnerability is often not a single missing tool but a weakness in a process. A culture that rushes pull request reviews or doesn't scrutinize dependency changes is as vulnerable as a system without a firewall. Requirements drift—where the actual installed packages diverge from the intended, secure versions—is a classic symptom of a weak process.

### Practical
Audit a few of your key projects.
1.  Look at `requirements.txt`. Are versions pinned (`requests==2.26.0`) or loose (`requests>=2.25.0`)?
2.  Create a fresh virtual environment, install the dependencies, and run `pip freeze`. Does the output match the `requirements.txt` file exactly? Any differences represent drift.
3.  Review the last five pull requests that added or changed a dependency. Was the change discussed? Was the package's origin questioned?

### Tools/Techniques
*   **pip-tools:** Use [`pip-compile`](https://github.com/jazzband/pip-tools) on a `requirements.in` file to see the full tree of pinned transitive dependencies. This can reveal dependencies you didn't even know you had.
*   **Dependency Scanners:** Tools like [`safety`](https://github.com/pyupio/safety) can check for known vulnerabilities in your installed packages, but they can also highlight a lack of pinning.
*   **Manual Audit:** There is no substitute for a developer-led review of dependency manifests and recent pull requests.

### Metrics/Signal
*   Percentage of projects using pinned dependencies (lockfiles).
*   Average number of unpinned "greater-than-or-equal-to" (`>=`) dependencies per project.
*   Number of dependency-changing pull requests merged without a comment or specific approval.

{% endblock %}
{% block type='battlecard' text='Fortify'%}
### Explanation
Fortification is about actively hardening your systems and processes to prevent the attack from succeeding. This means moving from a reactive to a proactive security posture. For this scenario, the focus is on enforcing strict, verifiable, and automated dependency management practices.

### Insight
The goal is to make the "right way" the "easy way." Developers shouldn't have to remember complex security rules. The tooling and pipeline should enforce them by default. For example, a build should fail if a dependency is not cryptographically verified, removing the possibility of human error.

### Practical
Implement a "zero-trust" policy for dependencies. All packages, whether internal or external, must be explicitly trusted and verified.
1.  **Use Lockfiles:** Mandate the use of fully pinned dependency files that include transitive dependencies.
2.  **Use Hashes:** Add cryptographic hashes for every package. `pip` will verify the hash of the package it downloads against the one in your requirements file, preventing a swapped-out or tampered package.
3.  **Use a Private Registry:** Host your internal packages and approved public packages on a private registry. Configure your pipeline to *only* install from this trusted source.

### Tools/Techniques
*   **Lockfile Generation:** Use [`pip-tools`](https://github.com/jazzband/pip-tools) to generate a fully pinned `requirements.txt` from a simple `requirements.in` file. Run `pip-compile --generate-hashes requirements.in` to include hashes.
*   **Private Package Indexes:** Host your own with tools like [`devpi`](https://github.com/devpi/devpi) or use commercial solutions like [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository).
*   **CI Configuration:** In your CI pipeline, configure `pip` to use your private index and enforce hash checking:
    `pip install --index-url https://my-private-repo/simple --require-hashes -r requirements.txt`
*   **Package Vetting:** Platforms like [Socket.dev](https://socket.dev) or [Snyk](https://snyk.io/) can proactively analyze new packages for risky characteristics, such as the use of install scripts or obfuscated code.

### Metrics/Signal
*   100% of production projects use hashed lockfiles.
*   Build failure rate due to hash mismatches (this is a good sign—it means the check is working).
*   Number of packages served from the private registry vs. public registries.

{% endblock %}
{% block type='battlecard' text='Limit'%}
### Explanation
Assume the attacker's malicious package was installed and its code is executing in your CI/CD environment. The "Limit" phase is about damage control. The goal is to contain the blast radius by ensuring the compromised environment is isolated and has the minimum possible privileges, preventing the attacker from moving laterally or causing significant harm.

### Insight
Your CI/CD environment is a high-value target. Treat it as a potentially hostile environment, not a trusted part of your internal network. The principle of least privilege is critical here: a script that only needs to push a container image to a registry should not have credentials that allow it to delete your entire cloud infrastructure.

### Practical
Review the permissions and network access of your CI/CD runners.
1.  **Credentials:** Replace long-lived, static secrets (like `AWS_ACCESS_KEY_ID`) with short-lived, ephemeral credentials that are generated for each specific job and expire immediately after.
2.  **Network Access:** By default, deny all outbound network traffic from your CI runners. Explicitly allow-list the specific domains required for the build (e.g., your package registry, your cloud provider's API). This would have blocked the malicious script from sending data to the attacker's server.
3.  **Sandboxing:** Run build jobs in isolated, single-use containers or micro-VMs that are destroyed after the job completes.

### Tools/Techniques
*   **Ephemeral Credentials:** Use OpenID Connect (OIDC) providers to enable secure, keyless authentication from your CI environment to cloud providers. See guides for [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) and [GitLab OIDC](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html).
*   **Network Policies:** Use tools like [Cilium](https://cilium.io/) or native Kubernetes Network Policies to define and enforce strict egress rules for your CI pods.
*   **Container Sandboxing:** For highly sensitive builds, consider sandboxing technologies like [gVisor](https://gvisor.dev/) or [Firecracker](https://firecracker-microvm.github.io/) to provide stronger kernel-level isolation.

### Metrics/Signal
*   Percentage of CI jobs using short-lived credentials vs. static secrets.
*   Number of outbound network requests blocked by the CI environment's firewall/network policy.
*   The Time-To-Live (TTL) on CI credentials is less than the average job run time.

{% endblock %}
{% block type='battlecard' text='Expose'%}
### Explanation
This stage is about visibility. How do you detect an attack in progress or after the fact? It involves logging the right information, monitoring for anomalies, and setting up alerts to notify you of suspicious activity. For this scenario, you'd want to know the moment a new, unexpected package is installed or when a build runner tries to make a suspicious network connection.

### Insight
You can't detect what you don't log. Default CI/CD logs often focus on pass/fail status, not security-relevant events. Rich, centralized logging is the foundation of detection. Anomalies are often the first sign of a compromise—a process that normally never touches the network suddenly making an outbound connection is a major red flag.

### Practical
1.  **Log All Installs:** Ensure your build process logs every package that is installed, including version numbers. Ship these logs to a central analysis platform.
2.  **Monitor Network Egress:** Actively monitor all outbound network connections from your CI runners. Alert on any connection to an IP address or domain that is not on a pre-approved allow-list.
3.  **Behavioral Anomaly Detection:** Monitor for unusual behavior during builds. For example, did the `pip install` step suddenly spawn a `curl` or `wget` process? This is highly suspicious.

### Tools/Techniques
*   **Log Aggregation:** Centralize logs from your CI system using platforms like the [Elastic Stack (ELK)](https://www.elastic.co/), [Datadog](https://www.datadoghq.com/), or [Splunk](https://www.splunk.com/).
*   **Runtime Security:** Deploy agents from tools like [Falco](https://falco.org/) (open source), [Aqua Security](https://www.aquasec.com/), or [Sysdig Secure](https://sysdig.com/products/secure/) into your build environments. These tools can detect and alert on suspicious system calls, file access, and network activity in real-time.
*   **Dependency Auditing:** Regularly run automated jobs that compare the list of installed packages from a build's logs against the approved lockfile. Alert on any discrepancies.

### Metrics/Signal
*   Alerts generated for connections to non-allow-listed domains from a CI runner.
*   A diff showing a package was installed during a build that was not present in the committed `requirements.txt` file.
*   A runtime security alert for an unexpected process (e.g., `/bin/bash`) being spawned by a package installation script.

{% endblock %}
{% block type='battlecard' text='eXercise'%}
### Explanation
This is where you practice. Security skills, like any other engineering skill, are built through repetition. By simulating the attack scenario in a controlled way, you can test your defenses, identify gaps in your processes, and build "muscle memory" for your team. The goal is to make responding to a real incident feel familiar and practiced.

### Insight
A security exercise isn't a test to pass or fail; it's a tool for learning. The most valuable outcome is not a successful defense, but a detailed list of what broke, what was confusing, and what could be improved. It's better to find these weaknesses during a drill than during a real attack.

### Practical
1.  **Tabletop Exercise:** Gather the team and walk through the scenario verbally. "A developer opens a PR with a typosquatted package. What happens next? Who reviews it? What do they look for?" This tests the human process.
2.  **Controlled Live Fire:**
*   Create a harmless package on a private registry with a typosquatted name (e.g., `reqeusts` instead of `requests`).
*   The `setup.py` script should do something benign but observable, like printing a specific message to stdout or writing to a temporary file.
*   Have a team member add this package to a non-production application and open a pull request.
*   Observe: Does the peer reviewer spot it? Does the CI pipeline's dependency check fail it? If it gets installed, do your monitoring tools generate an alert?
3.  **Review and Improve:** After the exercise, hold a blameless retrospective. What worked? What didn't? Update your documentation, refine your alert rules, and provide additional training based on the results.

### Tools/Techniques
*   **Private Registries:** Use [devpi](https://github.com/devpi/devpi) or another private index to safely host your test package without publishing it publicly.
*   **CI/CD Systems:** Your existing CI/CD platform ([GitHub Actions](https://github.com/features/actions), [GitLab CI](https://docs.gitlab.com/ee/ci/), etc.) is the environment for the test.
*   **Communication Tools:** Practice your incident response communication using [Slack](https://slack.com/) or your organization's preferred chat tool.

### Metrics/Signal
*   Mean Time to Detect (MTTD): How long did it take from the malicious PR being opened to an alert being generated or a human spotting the issue?
*   Number of defensive layers that successfully identified the test package (e.g., PR review, static analysis, runtime monitoring).
*   Developer feedback from a post-exercise survey on their confidence in identifying and responding to supply chain threats.

{% endblock %}