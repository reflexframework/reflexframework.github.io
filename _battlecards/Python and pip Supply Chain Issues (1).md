---
 permalink: /battlecards/python1
battlecard:
 title: Python and pip Supply Chain Issues
 category: Package Ecosystem
 scenario: Python + pip
 focus: 
   - typosquatting 
   - malicious postinstall scripts 
   - requirements.txt drift 
---

An attacker identifies `requests`, a highly popular Python library, as a target. They create and publish a malicious package to the public Python Package Index (PyPI) named `reqeusts`—a common misspelling.

This malicious `reqeusts` package has a `setup.py` file containing a post-install script. When a developer or a CI/CD system runs `pip install reqeusts`, this script executes automatically. The script scans the local environment for environment variables like `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `GITHUB_TOKEN`. It also looks for SSH keys in the `~/.ssh/` directory.

The attacker's goal is to trick a developer into making a typo while manually editing a `requirements.txt` file or to have the package pulled in by an unpinned dependency that drifts over time. Once the malicious package is installed, the post-install script exfiltrates any discovered credentials via an encoded HTTP POST request to an attacker-controlled server. The compromise is silent and happens in seconds, stealing secrets from either a developer's machine or, more critically, from the production-adjacent environment of a CI/CD pipeline.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. For this scenario, they aren't targeting your company specifically; they are playing a numbers game against the entire Python ecosystem. They use automated tools to scan PyPI for popular packages and generate a list of plausible typos or name variations (e.g., `reqeusts` for `requests`, `python-dateutils` for `python-dateutil`). They then check if these names are available on PyPI. Their script is generic—it hunts for common credential formats and environment variables, maximizing the potential reward from any victim.

### Insight
Attackers exploit the openness of public repositories. They know developers are under pressure and that typos are common. They also understand that many projects don't perfectly manage their dependencies, creating opportunities for a malicious package to slip in during a routine `pip install`. The attacker's cost is nearly zero, but the potential payoff from stealing cloud or source control credentials is huge.

### Practical
Review your projects on public code-hosting sites like GitHub. If your `requirements.txt` files are public, you are providing attackers with a list of dependencies they can target with typosquatting. While keeping this private isn't a complete defense, it avoids making your project an easy-to-find target.

### Tools/Techniques
*   [PyPI](https://pypi.org/): Attackers search for top packages to impersonate.
*   [GitHub Search](https://github.com/search): Attackers can search for `filename:requirements.txt` to find potential targets and see which libraries are most commonly used.
*   [pypistats.org](https://pypistats.org/): Used to analyze download trends and identify popular packages that are good candidates for typosquatting.

### Metrics/Signal
*   This stage is performed by the attacker, so there are no direct defensive metrics. However, an increase in typosquatted packages being reported in the security community can be a signal of heightened attacker activity in the ecosystem.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking in the mirror. How vulnerable are your development practices to this attack? A developer can assess their environment by asking key questions:
*   Do we manually type package names into `requirements.txt`?
*   Are the versions in our `requirements.txt` files "pinned" to a specific version (e.g., `requests==2.28.1`), or are they open-ended (e.g., `requests`)?
*   Do we use a lock file that includes cryptographic hashes for each package?
*   Does our CI/CD pipeline pull dependencies directly from the public internet without any checks?
*   Do developers on our team store long-lived, high-privilege credentials on their local machines?

### Insight
The most significant vulnerability is often not a complex technical flaw but a weak process. The gap between a developer's local dependency list and what the CI/CD system installs is a common source of "works on my machine" bugs and, in this case, a critical security risk. Inconsistency in how dependencies are added and updated across a team creates the exact opening this attack exploits.

### Practical
Perform a quick audit. Grab a few of your team's projects and examine the `requirements.txt` file. Is it pinned? Now check for a `requirements.lock` or `poetry.lock` file. If one doesn't exist, your project is vulnerable to `requirements.txt` drift. Review your CI/CD pipeline configuration (`.github/workflows/main.yml`, `.gitlab-ci.yml`, etc.). Find the line that runs `pip install` and ask: what controls are wrapped around this command?

### Tools/Techniques
*   Manual code review: Simply reading your project's dependency files is the first and best step.
*   `grep` or similar search tools can be used to scan an entire codebase for unpinned dependencies in `requirements.txt` files.

### Metrics/Signal
*   Percentage of projects that use dependency lock files.
*   The number of unpinned dependencies discovered across all project repositories.
*   Time taken for a new developer to set up a project; a long and manual setup process often indicates inconsistent dependency management.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about building defenses to prevent the malicious package from ever being installed. The most effective defense is to eliminate ambiguity in your dependencies. Instead of just specifying a package name, you should specify the *exact version and a hash of the package contents*. This ensures that even if a new malicious version is published, your builds will fail because the hash won't match.

### Insight
You should treat your dependencies with the same rigor as your own code. They are, in effect, part of your application. Never trust a package name alone. Trusting a name is like trusting a person's identity just because they have the right name tag; you need to check their ID. The hash in a lock file is that ID.

### Practical
1.  **Stop manually editing `requirements.txt`**. Treat it as a build artifact.
2.  Define your direct dependencies in a file like `requirements.in`.
3.  Use a tool to "compile" or "lock" that file into a fully-pinned `requirements.txt` that includes hashes.
4.  Commit both files to your repository. When installing, use the hash-checked `requirements.txt` file.

### Tools/Techniques
*   **Dependency Locking**:
*   [pip-tools](https://github.com/jazzband/pip-tools): A popular tool that uses `pip-compile` to create a fully-pinned `requirements.txt` with hashes from a `requirements.in` file. Install with `pip install -r requirements.txt --require-hashes`.
*   [Poetry](https://python-poetry.org/): A modern Python packaging and dependency management tool that generates a `poetry.lock` file by default.
*   **Vulnerability Scanning**:
*   [pip-audit](https://pypi.org/project/pip-audit/): Scans your installed dependencies for known vulnerabilities. Run this in your CI/CD pipeline.
*   [Snyk](https://snyk.io/): A commercial tool that can be integrated into your repository and CI/CD pipeline to detect vulnerable dependencies, including malicious packages.
*   **Private Repositories**:
*   [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository): Act as a proxy between your developers/CI and PyPI. You can configure them to only allow approved, vetted packages.

### Metrics/Signal
*   CI/CD pipeline build fails if a dependency without a valid hash is introduced.
*   A vulnerability scanner (like Snyk or pip-audit) blocks a build due to a newly discovered malicious package.
*   100% of active projects have a `requirements.in` and a hash-locked `requirements.txt` (or equivalent like `poetry.lock`).

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and the malicious package was installed. The "limit" phase is about containing the blast radius. The damage the post-install script can do is directly proportional to the privileges of the environment it runs in. If `pip install` is run by a root user in a CI/CD runner with access to production secrets, the damage is catastrophic. If it's run inside a minimal, short-lived container with no secrets and restricted network access, the damage is negligible.

### Insight
The principle of least privilege is your most powerful tool for damage control. Your build environment should be considered untrusted. Code from the internet (your dependencies) is being executed there. It should have the absolute minimum access required to perform its task and nothing more.

### Practical
*   **CI/CD**: Use short-lived, narrowly-scoped credentials. Instead of storing a static `AWS_ACCESS_KEY_ID`, use OpenID Connect (OIDC) to issue temporary credentials to your CI/CD job that are only valid for its execution and restricted to specific resources.
*   **Containers**: Run your build steps inside ephemeral containers. Do not mount sensitive directories like `~/.ssh` into the build container.
*   **Network**: Configure egress firewall rules for your build environment. If your build doesn't need to connect to anything other than PyPI and your own artifact repository, block all other outbound traffic on port 443. This would prevent the exfiltration script from phoning home.

### Tools/Techniques
*   **Short-Lived Credentials**:
*   [GitHub Actions OIDC integration](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers) for cloud providers.
*   [HashiCorp Vault](https://www.vaultproject.io/) for dynamically generating secrets.
*   **Network Controls**:
*   [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) to control egress from build pods.
*   [AWS VPC Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html) with restrictive outbound rules for your EC2-based CI runners.

### Metrics/Signal
*   Number of long-lived static credentials used in CI/CD environments (aim for zero).
*   Firewall logs showing blocked outbound network connections from build agents to non-allowlisted destinations.
*   Security audit reports showing that CI/CD roles have the minimum necessary permissions.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about detection. How would you know the attack happened? The malicious `setup.py` script makes a network connection to send the stolen data. This is a high-fidelity signal. A build process that is simply installing dependencies should not be making arbitrary outbound network requests to unknown domains. Monitoring process execution and network traffic from your build environment is key to detecting this anomalous activity.

### Insight
The attack is loudest at the moment of execution. The installation of a dependency is a well-defined process. Any deviation, like spawning a shell or making a network call to a strange IP, is a strong indicator of compromise. You can't detect what you don't monitor.

### Practical
*   Log all DNS queries and outbound network connections from your CI/CD runners.
*   Set up alerts for network connections from build processes (like `pip`) to any destination other than your approved package repositories (e.g., pypi.org, files.pythonhosted.org, or your private Artifactory/Nexus server).
*   Use security tooling that specifically analyzes package behavior during installation.

### Tools/Techniques
*   **Network Monitoring**:
*   [Zeek](https://zeek.org/): An open-source network security monitor that can log all DNS, HTTP, and other traffic for later analysis.
*   [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html): Log all IP traffic from your CI runners and feed it into a monitoring tool for alerting.
*   **Behavioral Analysis**:
*   [Socket.dev](https://socket.dev/): A commercial service that proactively analyzes package dependencies and can detect suspicious behavior like network usage or shell execution in post-install scripts.
*   [Endpoint Detection and Response (EDR)](https://www.crowdstrike.com/cybersecurity-101/endpoint-security/endpoint-detection-and-response-edr/): Tools like CrowdStrike can be installed on build runners to monitor for malicious process behavior.

### Metrics/Signal
*   An alert firing for an outbound connection from a `pip install` command to an IP address not on your allowlist.
*   An unexpected DNS query for a domain that is not a known package index.
*   A log from a tool like Socket.dev indicating that a newly added dependency uses the network during installation.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build muscle memory and test your defenses, you need to practice. A security exercise involves simulating the attack in a safe and controlled manner to see if your `Fortify`, `Limit`, and `Expose` controls work as expected. This isn't a "pass/fail" test; it's a learning opportunity to find the gaps in your tooling, processes, and team knowledge before a real attacker does.

### Insight
Security policies and tools are useless if they don't work in practice or if the team doesn't know how to use them. Running a drill turns abstract security concepts into concrete, memorable experiences for developers and helps justify investments in better tooling and training.

### Practical
1.  **Create a Safe Malicious Package**: Create a simple Python package. In its `setup.py`, add a script that does something benign but detectable, like making a DNS query for `my-test-exfil.your-company-domain.com` or an HTTP request to an internal server you control.
2.  **Host it Privately**: Upload this package to a private repository that your CI/CD system can access.
3.  **Simulate the Typo**: In a test branch of a sample application, add the "malicious" package to the `requirements.txt` file.
4.  **Run the Pipeline**: Push the branch and let your CI/CD pipeline run its normal build process.
5.  **Observe**:
*   **Fortify Test**: Did your hash-checking `pip install` command fail because the new package wasn't in the lock file? (It should).
*   **Limit/Expose Test**: If you bypass the lock file check for the test, does your network monitoring system fire an alert for the DNS query or HTTP call? Do your firewall rules block it?

### Tools/Techniques
*   **Private Repository**: Use a tool like [pypiserver](https://pypi.org/project/pypiserver/) for a simple, temporary private index for the exercise.
*   **Request Sink**: Use a service like [requestbin.com](https://requestbin.com) or an internal web server with logging to act as the "attacker's server" to confirm the exfiltration request was made.
*   **Post-Mortem Meeting**: After the exercise, gather the team to discuss what happened. Did the alerts go to the right people? Was the information clear? What could be improved?

### Metrics/Signal
*   Time-To-Detect (TTD): How long did it take from the "malicious" code execution to an alert being generated?
*   Successful block of the simulated exfiltration call by network policies.
*   An "action items" list generated from the post-mortem, with owners and deadlines for improving processes or tools.
{% endblock %}