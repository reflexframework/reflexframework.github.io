---
 permalink: /battlecards/python3
battlecard:
 title: Python and pip Supply Chain Issues
 category: Package Ecosystem
 scenario: Python + pip
 focus: 
   - typosquatting 
   - malicious postinstall scripts 
   - requirements.txt drift 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets a fast-growing tech company, knowing their developers are under pressure to ship features. The attacker identifies a popular Python library the company uses, `python-dateutil`, by scanning their public GitHub repositories. They create and publish a malicious package to PyPI named `python-dateutils` (with an 's').

The attacker's package has a malicious `setup.py` file. When a developer or a CI/CD system runs `pip install python-dateutils`, the script executes. It scans for environment variables like `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, and `DATADOG_API_KEY`, base64 encodes them, and exfiltrates them via a DNS request to a domain the attacker controls.

The attacker waits. Weeks later, a developer is manually cleaning up a `requirements.txt` file and mistakenly types `python-dateutils`. The change is small and looks like a typo fix, so it passes a cursory code review. The next time the CI/CD pipeline runs, it installs the malicious package, and the company's cloud and monitoring credentials are stolen.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers research your organization to find the weakest link in your software supply chain. They aren't guessing; they are using data to find high-value targets. They analyze public information to understand your tech stack, your developers' habits, and your processes. Their goal is to find a dependency they can impersonate or a process they can exploit to inject their code into your system.

### Insight
Your company's public footprint is the attacker's primary source of intelligence. What seems like harmless open-source contribution or developer collaboration on GitHub can be used to build a profile of your internal development practices, tools, and dependencies.

### Practical
- Audit your organization's public repositories on platforms like GitHub or GitLab. Look for checked-in `requirements.txt`, `pyproject.toml`, or `Dockerfile` files that reveal your exact dependencies and versions.
- Search for your developers on GitHub and see if their personal projects or commit messages leak information about internal tools or libraries.
- Assume that any dependency you use is a potential target. The more popular it is, the more likely it is to be targeted for typosquatting.

### Tools/Techniques
- **GitHub Search:** Use advanced search queries to find sensitive files within your organization's public presence (e.g., `org:your-company-name filename:requirements.txt`).
- **Pypistats.org:** Attackers use services like [pypistats.org](https://pypistats.org/) to find popular packages to impersonate. You can use it to see how popular your own dependencies are.
- **Dependency Graph Analysis:** Tools built into GitHub and GitLab can show you the dependency trees of your projects, which is the same view an attacker tries to build.

### Metrics/Signal
- **Signal:** A new package appears on PyPI with a name very similar to a dependency you use.
- **Metric:** Number of public repositories in your organization containing dependency manifests (e.g., `requirements.txt`).

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. How do you manage dependencies today? A developer can assess their team's vulnerability by examining the processes and tools used to add, update, and deploy dependencies. The core issue is often "dependency drift"—where the packages actually installed don't perfectly match what was intended, reviewed, and tested.

### Insight
The biggest vulnerability isn't a specific package, but a weak or inconsistent process for managing them. A process that relies on manual `pip freeze` commands, lacks peer review for dependency changes, or doesn't use lock files is highly susceptible to this attack.

### Practical
- Review your last 10 pull requests that changed a `requirements.txt` or `pyproject.toml` file. Was the change reviewed with the same rigor as application code? Was the reason for adding/changing the dependency clear?
- Ask your team: "What is our process for adding a new open-source dependency?" If there isn't a clear answer, you have a process gap.
- On your local machine, create a fresh virtual environment from your project's `requirements.txt` and compare the installed packages (`pip freeze`) with the file's contents. Are there unexpected differences?

### Tools/Techniques
- **Dependency Scanners:** Run a scan on your repository to identify known vulnerabilities and check for best practices.
- [pip-audit](https://pypi.org/project/pip-audit/): Scans your environment for packages with known vulnerabilities.
- [Safety](https://pyup.io/safety/): Checks installed dependencies for known security vulnerabilities.
- [Snyk](https://snyk.io/): Commercial tool that scans for vulnerabilities, license issues, and code quality problems.

### Metrics/Signal
- **Metric:** Percentage of projects that use pinned, hashed lock files vs. flexible `requirements.txt` files.
- **Metric:** Average time a dependency remains at a vulnerable version after a fix is published.
- **Signal:** High number of dependencies with floating versions (e.g., `package>=1.2.3`).

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening is about creating non-negotiable, automated defenses in your development lifecycle. The goal is to make it mechanically impossible for a malicious package like the one in our scenario to be installed. This involves shifting from trust-based manual processes to automated, verifiable controls.

### Insight
`pip install` is effectively executing remote code on your machine. You should treat dependency management with the same seriousness as code execution. The single most effective defense is using a **lock file with package hashes**. A hash ensures that the package you are installing is bit-for-bit identical to the one you vetted, preventing replacement or tampering.

### Practical
- **Use Lock Files with Hashes:** Do not rely on a simple `requirements.txt` from `pip freeze`. Instead, manage a `requirements.in` file with your direct dependencies and use a tool to compile it into a locked `requirements.txt` file that includes hashes for all transitive dependencies.
- **Mandate PR/MR Reviews for Dependency Changes:** All changes to files like `requirements.in` or `poetry.lock` must be reviewed by at least one other person.
- **Use a Private Package Repository:** Set up an internal repository that acts as a proxy and cache for PyPI. You can create allowlists for vetted packages, reducing the risk of a developer accidentally pulling a malicious one.

### Tools/Techniques
- **Lock File Generation:**
- [pip-tools](https://github.com/jazzband/pip-tools): Use `pip-compile --generate-hashes requirements.in` to create a fully pinned `requirements.txt` with `--hash` entries.
- [Poetry](https://python-poetry.org/): Manages dependencies and generates a `poetry.lock` file by default.
- **Private Repositories:**
- [JFrog Artifactory](https://jfrog.com/artifactory/)
- [Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository)
- **CI/CD Integration:**
- [Dependabot](https://docs.github.com/en/code-security/dependabot): Automates dependency updates in a secure, reviewable way.
- Add a CI step: `pip install -r requirements.txt --require-hashes`. The build will fail if a hash is missing or doesn't match.

### Metrics/Signal
- **Metric:** Percentage of CI/CD pipelines that enforce hash-checking for package installation.
- **Metric:** Number of packages allowed from public repositories vs. a private, vetted repository.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and their malicious code is now running inside your CI/CD pipeline. Limiting the blast radius is about ensuring that this breach is as contained and useless to the attacker as possible. If the malicious script can't access valuable secrets or reach sensitive parts of your network, the attack effectively fails.

### Insight
Your CI/CD environment is a prime target because it's often over-provisioned with powerful, long-lived secrets. The principle of least privilege is critical here. A build job that tests a web app's UI doesn't need access to the production database credentials.

### Practical
- **Use Short-Lived, Scoped Credentials:** Instead of static `AWS_ACCESS_KEY_ID` variables, use mechanisms that provide temporary, auto-rotating credentials that are valid only for the duration of the build and have permissions only for the resources that specific job needs.
- **Isolate Build Environments:** Run each CI job in a fresh, ephemeral container.
- **Restrict Network Egress:** Configure firewall rules for your build agents that deny all outbound network connections by default, only allowing traffic to known, necessary endpoints (like your package repository, cloud provider APIs, etc.). An attempt to exfiltrate data to a random attacker domain would be blocked.

### Tools/Techniques
- **Short-Lived Credentials:**
- [GitHub Actions OIDC Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services): Allows GitHub Actions to assume an IAM role directly without storing a long-lived key.
- [HashiCorp Vault](https://www.vaultproject.io/): A centralized service for managing and vending temporary secrets.
- **Network Controls:**
- **AWS Security Groups / GCP Firewall Rules:** Configure strict egress rules for your CI runner instances.
- **Kubernetes Network Policies:** If your runners are in K8s, use network policies to restrict outbound traffic.

### Metrics/Signal
- **Metric:** Time-to-live (TTL) of credentials used in CI/CD. The shorter, the better.
- **Signal:** A CI/CD job is blocked by a network egress rule. This is a strong indicator of anomalous activity and should trigger an immediate alert.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To catch an attack, you need visibility. Exposing malicious activity means having the right logging, monitoring, and alerting in place to detect anomalies in your development pipeline. You need to know when a strange package is installed, an unusual network connection is attempted, or a process behaves unexpectedly.

### Insight
Your CI/CD system is not just a build tool; it's a critical piece of infrastructure that should be monitored as rigorously as your production servers. A lack of logging and monitoring in your pipeline is a blind spot that attackers rely on.

### Practical
- **Log All Dependency Installations:** Log the name, version, and source of every package installed in every build. Ship these logs to a central analysis platform.
- **Monitor Network Traffic from Build Agents:** Track all outbound network connections. Create a baseline of normal traffic and alert on deviations, such as connections to new IP addresses or DNS lookups for suspicious domains.
- **Audit Environment Variable Access:** If possible with your tooling, log which processes access which environment variables during a build.

### Tools/Techniques
- **Centralized Logging:**
- [Datadog CI Visibility](https://www.datadoghq.com/product/ci-cd-visibility/)
- [Splunk](https://www.splunk.com/)
- **Runtime Security:**
- [Falco](https://falco.org/): Open-source container runtime security tool that can detect anomalous activity, like unexpected network connections or shell processes.
- **Network Monitoring:**
- **VPC Flow Logs (AWS)** or similar cloud provider tools to log all IP traffic from your build agents.

### Metrics/Signal
- **Signal:** A build agent makes a DNS query for a domain that is not on an allowlist.
- **Signal:** A package is installed from a public index (e.g., `pypi.org`) when your policy requires all packages to come from your private repository.
- **Metric:** Time to detect and alert on a malicious package installation from the moment it occurs.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is about building muscle memory for your team and testing your defenses. You can't wait for a real attack to find out if your processes and tools work. By running controlled, simulated attacks, you can identify weaknesses, train developers, and refine your response playbook in a safe environment.

### Insight
Security exercises are not about pass/fail; they are about learning. The goal is to make mistakes in a drill so you don't make them during a real incident. They also help shift the culture from "security is someone else's job" to a shared responsibility.

### Practical
- **Tabletop Exercise:** Gather the development team and walk through the attack scenario verbally. Ask questions at each stage: "What happens next? How would we know? Who would be alerted? What's our response?"
- **Red Team Drill:** Create a benign, private package with a name similar to a common dependency. Have one developer submit a pull request to add it. See if the other developers or the automated tooling catch it during code review or in the CI pipeline.
- **Capture the Flag (CTF):** Create a vulnerable container image that uses a typosquatted package. Challenge developers to investigate the container's logs and network traffic to find the "flag" (the exfiltrated data).

### Tools/Techniques
- **Safe Malicious Packages:** Use purpose-built tools to simulate package vulnerabilities without actual risk.
- [Socket.dev](https://socket.dev/) provides tooling to detect and block supply chain attacks, which can be tested in drills.
- **Internal Documentation:** Create a simple playbook in your wiki (e.g., Confluence, Notion) for "Responding to a Suspected Malicious Dependency" and refine it after each exercise.

### Metrics/Signal
- **Metric:** Time-to-detection for the simulated malicious package in a red team drill.
- **Metric:** Percentage of developers who have participated in a security exercise in the last year.
- **Signal:** Post-exercise feedback identifies a gap in tooling or a confusing step in the process, which then becomes an action item for improvement.
{% endblock %}