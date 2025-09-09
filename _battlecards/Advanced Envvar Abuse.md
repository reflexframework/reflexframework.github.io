---
 permalink: /battlecards/advenvvarabuse
battlecard:
 title: Advanced Envvar Abuse
 category: Developer Environment
 scenario: Local PATH/LD_PRELOAD Variants
 focus: 
   - user-writable PATH dirs 
   - DYLD_* injection 
   - LD_* tricks 
---
{% block type='battlecard' text='Scenario' %}
An attacker gains low-privilege access to a developer's machine or a CI/CD build agent, possibly through a compromised dependency or a malicious IDE extension. Their goal is persistence and lateral movement, not immediate disruption.

The attacker discovers that the developer's shell profile (`.zshrc` or `.bashrc`) prepends a user-writable directory (e.g., `~/.local/bin`) to the system's `PATH`.

`export PATH=~/.local/bin:$PATH`

The attacker places a malicious shell script named `git` inside `~/.local/bin`. This script is a wrapper: it first exfiltrates credentials (like `GITHUB_TOKEN` from the environment) to an external server and then calls the real `git` binary to avoid suspicion.

The next time the developer (or a CI job) runs any `git` command, the attacker's script executes first, stealing credentials and potentially manipulating source code before it's committed. A similar attack could use `LD_PRELOAD` (on Linux) or `DYLD_INSERT_LIBRARIES` (on macOS) to hijack function calls within any dynamically linked application, like `curl` or `npm`, to intercept data or modify behavior without needing to impersonate a binary in the `PATH`.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the "casing the joint" phase. After gaining initial access, the attacker's first goal is to understand the environment to find a weak point for persistence and privilege escalation. They aren't scanning your network from the outside; they are already on a machine and exploring its configuration. They will look for lazy or overly-permissive configurations that are common in development environments where convenience often trumps security.

Their tactics are simple and quiet:
1.  **Analyze Shell Configuration:** They will read `~/.bashrc`, `~/.zshrc`, `~/.profile`, and other shell startup files to find how the `PATH` and other critical environment variables (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) are constructed.
2.  **Inspect the `PATH`:** They run `echo $PATH` to see the order of directories. A user-writable directory like `~/bin`, `.` or `/tmp` at the beginning of the `PATH` is a prime target.
3.  **Check Directory Permissions:** They use `ls -ld` on each directory in the `PATH` to find one their current user account can write to.
4.  **Identify Key Binaries:** They find the real location of common developer tools (`which git`, `which npm`, `which python`) to know what to impersonate and where to pass execution to after their malicious code runs.

### Insight
The attacker is leveraging the developer's own customizations against them. That custom script you wrote to simplify a task, and the `PATH` modification you added to run it easily, becomes the foothold they use to compromise the entire software supply chain. This is a "living off the land" technique—they use the system's own features and binaries to conduct their attack, making it harder to detect.

### Practical
As a developer, you can perform the same reconnaissance on your own machine.
1.  Open a terminal and run `echo $PATH`.
2.  Split the output by the colon (`:`) and examine each directory.
3.  For each directory, ask: "Is this directory writeable by my non-root user? Is it listed before system directories like `/usr/bin`?"
4.  Read through your `.bashrc` or `.zshrc`. Question every `export PATH=...` line. Understand why it's there and if it's configured safely.

### Tools/Techniques
*   **Manual Inspection:**
*   `echo $PATH | tr ':' '\n' | xargs ls -ld`: A one-liner to list all directories in your `PATH` and their permissions.
*   `cat ~/.bashrc ~/.zshrc ~/.profile`: Review your own startup files.
*   **Automated Scripts:**
*   [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): A popular privilege escalation checker that automates searching for this and many other misconfigurations.

### Metrics/Signal
*   **Configuration Drift:** Any change to shell startup files (`~/.bashrc`, etc.) on a build agent should be considered a security event.
*   **Anomalous `PATH`:** A developer machine or build agent whose `PATH` variable does not conform to a predefined team standard.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about self-assessment. How would your own development environment, build pipelines, and practices stand up to the attack scenario? Developers need to analyze their setups with an attacker's mindset, looking for the easy wins an adversary would exploit. This isn't just about your laptop; it includes every environment your code touches, especially CI/CD agents, which are often powerful and trusted.

### Insight
Developer environments are often "high-trust" zones full of credentials, source code, and access to internal systems. However, they are frequently configured with a focus on productivity, leading to security gaps. A common blind spot is the build agent: developers might have a locked-down laptop, but the CI `Dockerfile` might be full of writable directories and `curl | bash` installers, creating the same vulnerability in an automated, high-value environment.

### Practical
1.  **Audit Your `PATH`:** Run `echo $PATH`. If you see `.` (current directory), `~/bin`, or any other custom directory *before* `/usr/bin` or `/usr/local/bin`, you are vulnerable. The safe pattern is `export PATH="$PATH:/my/custom/dir"`, not the other way around.
2.  **Review CI/CD Configurations:** Scrutinize your `Jenkinsfile`, `Dockerfile`, `gitlab-ci.yml`, etc. Look for lines that modify the `PATH` or use `LD_PRELOAD`. Check the `USER` specified in your `Dockerfile`—is it `root`? Does that user have write access to directories in the `PATH`?
3.  **Check Installed Tooling:** How do you install helper tools and CLIs? Do you use a package manager (good), or do you download and run installer scripts from the internet (risky)? Where do these tools get installed, and what permissions do those directories have?

### Tools/Techniques
*   **Linting/Static Analysis:**
*   [ShellCheck](https://github.com/koalaman/shellcheck): A static analysis tool for shell scripts that can flag dangerous practices.
*   [Hadolint](https://github.com/hadolint/hadolint): A Dockerfile linter that can help enforce best practices, like using a non-root user.
*   **Vulnerability Scanning:**
*   [Trivy](https://github.com/aquasecurity/trivy): Can be used to scan container images for misconfigurations, although `PATH` issues are more about runtime configuration.

### Metrics/Signal
*   **Policy Compliance Score:** The percentage of build agents and developer environments that adhere to a baseline secure `PATH` configuration.
*   **Linter Failures:** The number of CI/CD pipeline definitions that fail a linting check for unsafe `PATH` manipulation.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about proactively hardening your systems to eliminate the vulnerabilities identified during evaluation. The goal is to make the attacker's reconnaissance fruitless by closing the security gaps they rely on. This involves enforcing secure defaults and making it difficult for developers (or attackers) to create insecure configurations.

### Insight
The most effective security controls are often the simplest. You don't need a complex new tool to fix this problem. It's about discipline and establishing secure patterns. A key principle is to treat developer and build environments with the same rigor as production. They are a critical part of your software supply chain.

### Practical
1.  **Sanitize the `PATH`:** Enforce a "system paths first" policy. Always append custom binary directories to the end of the `PATH`.
*   **Bad:** `export PATH="~/bin:$PATH"`
*   **Good:** `export PATH="$PATH:~/bin"`
2.  **Use Immutable, Minimalist Build Environments:** Every CI/CD job should run in a fresh, ephemeral container created from a minimal base image (like [Distroless](https://github.com/GoogleContainerTools/distroless) or Alpine). The container should contain only the tools necessary for that specific build step. Do not allow the build process to install new software or modify the environment.
3.  **Enforce Least Privilege:**
*   **Inside Containers:** Always use a non-root user in your Dockerfiles (`USER nonrootuser`).
*   **On Build Agents:** The user running the build should have minimal permissions on the host machine. They should not have `sudo` access.
4.  **Harden System Settings:**
*   On macOS, ensure [System Integrity Protection (SIP)](https://support.apple.com/en-us/HT204899) is enabled. It prevents modification of system directories and restricts `DYLD_*` variable abuse.
*   On Linux, use security modules like [SELinux](https://selinuxproject.org/) or [AppArmor](https://apparmor.net/) to enforce policies that prevent processes from writing to unexpected locations or loading untrusted shared libraries.

### Tools/Techniques
*   **Configuration as Code:** Use tools like [Ansible](https://www.ansible.com/) or [Puppet](https://www.puppet.com/) to manage the configuration of developer VMs and build agents, ensuring a consistent, secure baseline.
*   **Container Security Policies:** Use a policy-as-code engine like [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) or [Kyverno](https://kyverno.io/) to enforce rules in your Kubernetes cluster, such as blocking containers from running as root.
*   **Signed Binaries:** Use tools and package managers that verify the cryptographic signature of the binaries they install, ensuring you're running what you expect.

### Metrics/Signal
*   **Policy Enforcement Rate:** 100% of CI/CD jobs should run in containers that are non-root and conform to the hardening policy.
*   **Time to Revert:** How quickly is an unauthorized change to a build agent's configuration (like a `PATH` modification) automatically reverted?

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Limitation, or "blast radius reduction," assumes the attacker has succeeded despite your fortifications. A malicious script is now running. The goal now is to contain the damage. What can that script *do*? Can it access secrets from other projects? Can it move from the build agent to other parts of your network? A well-designed system will ensure the answer is "very little."

### Insight
The identity is the new perimeter. The scope of what an attacker can achieve is defined by the permissions and access of the compromised process. In a modern developer workflow, this means short-lived, narrowly-scoped credentials are your most powerful containment tool. The compromise of one build job should never lead to the compromise of the entire system.

### Practical
1.  **Use Ephemeral, Scoped Credentials:** Instead of storing long-lived secrets (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`) in the CI/CD environment, fetch them dynamically for each job. The credentials should be valid only for the duration of the job and have permissions only for the specific resources that job needs.
2.  **Isolate Build Jobs:** Each CI/CD job must run in its own isolated environment (e.g., a separate container or VM). It should have no network access by default. Explicitly allowlist only the specific hosts it needs to contact (e.g., your code repository, package registry, and artifact store).
3.  **Run as Non-Root Inside Containers:** If an attacker compromises a process running as a non-root user inside a container, their ability to harm the host system or even other processes in the same container is severely restricted.
4.  **Network Segmentation:** Your CI/CD infrastructure should be on a separate network segment from both your corporate and production environments. A compromised build agent should not be able to connect to a production database.

### Tools/Techniques
*   **Secrets Management:**
*   [HashiCorp Vault](https://www.vaultproject.io/): A tool for managing secrets and generating dynamic, short-lived credentials.
*   **Cloud IAM Roles:** Use features like [GitHub OIDC with AWS IAM](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-aws) to allow a GitHub Actions job to assume an AWS role without any long-lived secrets.
*   **Container Runtimes:**
*   [gVisor](https://gvisor.dev/) and [Firecracker](https://firecracker-microvm.github.io/): Provide stronger isolation than standard container runtimes by using a user-space kernel or micro-VM, respectively.
*   **Network Policy:**
*   [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/): Define firewall rules at the pod level to control traffic flow within a cluster.

### Metrics/Signal
*   **Credential TTL:** The average time-to-live for credentials used in CI/CD jobs. Aim for minutes, not hours or days.
*   **Network Reachability:** The number of internal services or hosts reachable from a standard build container. This number should be as low as possible.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about detection and visibility. How do you know an attack is happening? You need to collect the right signals and monitor for anomalies. In this scenario, the signals are subtle: a change to a dotfile, a common process (`git`) being executed from an unusual path, or a build agent making an unexpected network connection. Without explicit monitoring, these events are invisible.

### Insight
Attackers rely on noise and a lack of monitoring to hide their actions. A developer modifying their own `.bashrc` is normal. But that same file being modified on a supposedly immutable build agent is a critical security alert. The context of the event is everything. Your goal is to separate legitimate developer activity from malicious behavior by establishing clear baselines.

### Practical
1.  **Monitor Process Execution:** Log all process creations (`execve` syscalls) on build agents and developer machines. Your monitoring should be able to answer: "Show me all `git` commands that were not executed from `/usr/bin/git`."
2.  **File Integrity Monitoring (FIM):** Actively monitor critical configuration files (`.bashrc`, `.zshrc`, `.profile`) and directories listed in the `PATH` for any changes, additions, or deletions.
3.  **Audit Shell History:** Ingest the shell history from all build jobs into a central logging system. A command like `chmod +x ~/bin/git` appearing in a build log is a major red flag.
4.  **Egress Traffic Monitoring:** Monitor all outbound network connections from your CI/CD environment. A connection to a strange IP address or a non-standard port is highly suspicious and should be blocked and alerted on.

### Tools/Techniques
*   **Endpoint Auditing:**
*   [osquery](https://osquery.io/): A powerful open-source tool that lets you query your fleet of machines using SQL-like syntax. You can write queries to periodically check for processes running with `LD_PRELOAD`, suspicious PATHs, or unexpected listening ports.
*   [auditd](https://linux.die.net/man/8/auditd): The native Linux auditing framework. It's powerful but can be complex to configure. It can log every syscall, including file modifications and process executions.
*   **Endpoint Detection and Response (EDR):**
*   Open source tools like [Wazuh](https://wazuh.com/) or commercial solutions provide FIM, process monitoring, and threat detection capabilities in a more user-friendly package.
*   **Log Aggregation:**
*   Tools like [OpenSearch](https://opensearch.org/)/[Elasticsearch](https://www.elastic.co/) and [Promtail](https://grafana.com/docs/loki/latest/clients/promtail/)/[Fluentd](https://www.fluentd.org/) for collecting and analyzing logs.

### Metrics/Signal
*   **High-Fidelity Alerts:** An alert is generated whenever a process is executed from a user-writable directory that is also in the `PATH`.
*   **Baseline Deviation:** An alert is triggered when a CI/CD job makes a network connection to a host not on its predefined allowlist.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about building muscle memory through practice. Security policies and monitoring tools are only effective if the development team knows how to use them and understands the threats they prevent. By running controlled attack simulations, you can test your defenses, train your developers to spot suspicious activity, and refine your response procedures.

### Insight
A security exercise turns abstract threats into concrete experiences. When a developer successfully "hacks" a test environment using a misconfigured `PATH`, they will never forget to check their own. This proactive, hands-on approach is far more effective than reading static documentation. It fosters a culture of security ownership within the development team.

### Practical
1.  **Run a Tabletop Exercise:** Walk through the attack scenario with the development and operations teams. Ask questions at each step: "The attacker has placed a fake `git` in the `PATH`. What is our first alert? Who gets notified? What is their first action?"
2.  **Conduct a Red Team Simulation:** Have a security engineer (or a developer playing the role) attempt the attack on a non-production CI/CD environment. The goal is to see if the `Fortify`, `Limit`, and `Expose` controls work as expected. Did you block the attack? If not, did you detect it? How long did it take?
3.  **Build a "Capture The Flag" (CTF) Challenge:** Create a containerized challenge for developers. Give them a simple `Dockerfile` with a vulnerable `PATH` configuration. Their task is to perform a simple action, but the environment is booby-trapped. This teaches them to inspect their environment before running commands.
4.  **Lunch & Learn Demos:** Do a live, 15-minute demo showing how trivial it is to hijack the `ls` or `git` command with a bad `PATH`. Seeing is believing.

### Tools/Techniques
*   **Attack Simulation Frameworks:**
*   [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team): An open-source library of small, focused tests that map to the MITRE ATT&CK framework. It includes specific tests for [Hijack Execution Flow: Path Interception](https://attack.mitre.org/techniques/T1574/007/).
*   **Internal Documentation:**
*   Create a simple, one-page guide with the "dos and don'ts" of environment configuration and share it widely.
*   **Custom Scripts:** Develop simple scripts to run during simulations that mimic the attacker's actions (e.g., create a fake binary, exfiltrate a fake credential).

### Metrics/Signal
*   **Mean Time to Detect (MTTD):** During a simulation, how long does it take from the moment the "attack" is launched until the first alert fires?
*   **Mean Time to Remediate (MTTR):** How long does it take for the team to correctly identify the issue and deploy a fix?
*   **Developer Training Engagement:** Percentage of developers who have completed the CTF challenge or attended the security training.
{% endblock %}