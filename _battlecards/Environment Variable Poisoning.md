---
 permalink: /battlecards/envvars
battlecard:
 title: Environment Variable Poisoning
 category: Developer Environment
 scenario: Environment Variables
 focus: 
   - PATH poisoning 
   - LD_PRELOAD 
   - BASH_ENV abuse 
---

An attacker gains low-privilege shell access to a shared development server or a long-lived CI/CD build agent. The environment is used to build multiple projects, including a Node.js application and a Python-based machine learning model. The build process is orchestrated by a shell script (`build.sh`) which is triggered by a Jenkins pipeline. This script calls common commands like `git`, `npm`, and `python` to fetch dependencies, build the application, and train the model.

The attacker's goal is not to crash the server, but to steal secrets (like `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`) exposed to the build process and inject a backdoor into the final application artifact or ML model.

The attack unfolds as follows:
1.  The attacker identifies a world-writable directory, `/tmp/attacker-tools`.
2.  They create a malicious script named `npm` inside this directory. This fake `npm` script first exfiltrates all environment variables to an external server and then passes its arguments to the *real* `npm` binary to avoid raising suspicion.
3.  They modify the `~/.bashrc` file of the `jenkins` user to prepend their malicious directory to the `PATH` environment variable: `export PATH=/tmp/attacker-tools:$PATH`.
4.  The next time the Jenkins pipeline runs a build as the `jenkins` user, the `build.sh` script is executed. When the script calls `npm install`, the shell finds the attacker's malicious `/tmp/attacker-tools/npm` first, executing it.
5.  The malicious script captures the secrets and the build continues, seemingly without error, but the organization's credentials are now compromised.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's first step after gaining initial access is to understand the environment. They are not looking for root access immediately; they are looking for the user account that runs the builds (e.g., `jenkins`, `gitlab-runner`). They will map out how your development and deployment processes work by examining files and processes. They want to find the weakest link in the chain—a script that calls a command without a full path, a directory anyone can write to, or a configuration file that sets up the environment in an insecure way.

A common tactic is to look for build scripts (`Jenkinsfile`, `build.sh`, `.gitlab-ci.yml`) to understand what tools are used (`git`, `npm`, `maven`, `docker`). They will check the user's profile scripts (`.bashrc`, `.profile`) to see how the environment is configured. They are essentially drawing a map of your automation to find the best place to set a trap.

### Insight
Developers often assume that the build environment is a safe, internal system. Attackers see it as a high-value target because it centralizes access to source code, credentials, and artifact registries. The `jenkins` user might be more powerful than a typical system user because it has the keys to your entire software supply chain.

### Practical
As a developer, you can perform your own reconnaissance.
1.  Log into your build agent.
2.  Run `env` and inspect the `PATH`, `LD_PRELOAD`, and `BASH_ENV` variables. Are there any unusual or non-standard directories in the `PATH`?
3.  Examine your main build script. Are you calling commands like `python` or `npm`? Or are you using absolute paths like `/usr/bin/python3`? Every command without a full path is a potential hook for an attacker.

### Tools/Techniques
*   **Attacker Tools**: Attackers use enumeration scripts like [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) to automatically find misconfigurations, writable directories, and interesting files.
*   **Developer Tools**: Use `find / -type d -perm -o+w 2>/dev/null` to find world-writable directories. Manually inspect CI/CD configuration files and shell scripts for commands that don't use absolute paths.

### Metrics/Signal
*   **Metric**: Percentage of commands in build scripts that use absolute paths. Aim for 100% for critical binaries.
*   **Signal**: The presence of unexpected executable files in directories like `/tmp`, `/var/tmp`, or a user's home directory.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about assessing your vulnerability. Thinking like an attacker, review your development environment's configuration. Where are environment variables defined? In a Dockerfile (`ENV` instruction), in the CI/CD system's global settings, or directly within a pipeline script? Do you have processes that allow one build to affect the environment of another? For example, if builds run sequentially on the same agent, an attacker could compromise one build to drop a malicious file that a later build executes.

For `LD_PRELOAD` abuse, evaluate if your application binaries are dynamically linked, which most are. If an attacker can control this variable, they can load a malicious shared library (`.so` file) before any other library, allowing them to hijack function calls to steal data or alter program behavior. This is particularly dangerous for compiled languages like Java, Go, or C++.

### Insight
Your CI/CD pipeline definition (`Jenkinsfile`, `actions.yml`) is code, and it should be reviewed for security vulnerabilities just like your application code. A common blind spot is trusting the runner's environment implicitly. Never assume the `PATH` is safe or that `LD_PRELOAD` is not set.

### Practical
1.  **Audit `Dockerfile`s**: Look for `ENV PATH=...` instructions that add insecure directories like `./bin` or `/app/node_modules/.bin` to the *beginning* of the `PATH`.
2.  **Review CI/CD Configurations**: Check your `Jenkinsfile`, GitHub Actions workflow, or GitLab CI YAML files. How are secrets passed? As environment variables? Who can modify these pipeline definitions?
3.  **Check Script Hygiene**: Scan all shell scripts used in your automation. Do they start with `set -e` to exit on error? Do they validate inputs? Do they reset key environment variables?

### Tools/Techniques
*   **Static Analysis**: Use tools like [Checkov](https://www.checkov.io/) to scan infrastructure-as-code files (like Dockerfiles) for security issues.
*   **Manual Inspection**: There is no substitute for a manual review of your `build.sh` or equivalent scripts. A simple `grep -rE "npm|git|python|mvn"` in your scripts directory can help you find all the places external commands are being called.

### Metrics/Signal
*   **Metric**: A count of CI/CD pipelines that do not explicitly sanitize or set a known-good `PATH`.
*   **Signal**: A build job that has `LD_PRELOAD` or `BASH_ENV` set when it is not expected.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about proactive hardening. The goal is to make the attack scenario difficult or impossible to execute. This involves writing more defensive build scripts and configuring your environment to be as lean and secure as possible. Never trust the environment your script runs in.

For `PATH` poisoning, always use absolute paths for critical commands. For `LD_PRELOAD` and `BASH_ENV`, explicitly unset them at the beginning of your scripts unless you have a very specific, intentional reason to use them. This ensures that even if an attacker manages to set these variables, their effect is nullified before your script's logic begins.

### Insight
Think of your build script as a program's `main` function. The very first thing it should do is sanitize its inputs and environment. A few lines of boilerplate at the top of every script can eliminate entire classes of vulnerabilities.

### Practical
Add a "secure entrypoint" block at the start of your primary build scripts:
```bash
#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Security Hardening ---
# 1. Reset the PATH to a known-good, minimal set of directories.
export PATH="/usr/local/bin:/usr/bin:/bin"

# 2. Unset potentially dangerous variables that can be used for code injection.
unset LD_PRELOAD
unset BASH_ENV

# --- Main script logic ---
echo "Starting secure build..."
/usr/bin/git clone ...
/usr/bin/npm install
```

### Tools/Techniques
*   **ShellCheck**: A static analysis tool for shell scripts. It can catch a variety of issues, including some security-sensitive ones. Integrate it into your pre-commit hooks or CI pipeline. [ShellCheck Website](https://www.shellcheck.net/).
*   **Minimal Base Images**: Use minimal container base images like `distroless` or `alpine` for your build environments. Fewer tools and libraries mean a smaller attack surface. [GoogleCloudPlatform/distroless on GitHub](https://github.com/GoogleCloudPlatform/distroless).
*   **Immutable Runners**: Configure your CI/CD system to use ephemeral, single-use build agents. This means each build starts with a completely clean environment, wiping out any changes an attacker might have made.

### Metrics/Signal
*   **Metric**: Percentage of build scripts in your organization that include the "secure entrypoint" boilerplate.
*   **Metric**: Vulnerability scan results for your standard build container images. Aim for zero critical or high vulnerabilities.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker succeeds and executes their malicious `npm` script. The goal of this stage is to contain the "blast radius." What can the attacker actually do or access? The damage can be limited by ensuring the build process runs with the absolute minimum privilege required. It should not be able to access production databases, other projects' code, or long-lived cloud credentials.

By running builds in isolated, ephemeral containers and providing them with short-lived, narrowly-scoped credentials, you change the outcome of a successful attack from "attacker owns our cloud account" to "attacker accessed one repository for 5 minutes."

### Insight
Credentials are the keys to the kingdom. Moving from static, long-lived secrets (like an `AWS_SECRET_ACCESS_KEY` stored in Jenkins Credentials) to dynamic, short-lived tokens is one of the most impactful security improvements you can make to a CI/CD environment.

### Practical
1.  **Isolate Builds**: Use container-based CI/CD runners (e.g., Docker or Kubernetes runners). Each build job should run in a fresh, new container that is destroyed when the job completes.
2.  **Least Privilege Secrets**: Instead of giving your build runner a powerful, persistent IAM user key, use OpenID Connect (OIDC) to exchange a temporary token from your CI provider for short-lived cloud credentials. These credentials should be scoped to only the resources needed for that specific build (e.g., permission to push to a single ECR repository).
3.  **Network Policies**: Apply network policies to your build runners that restrict egress traffic. The build agent should only be able to connect to expected domains (e.g., `github.com`, `npmjs.org`, your artifact registry). This can prevent an attacker from exfiltrating stolen data.

### Tools/Techniques
*   **Workload Identity/OIDC**:
*   [GitHub Actions: Configuring OIDC in Amazon Web Services](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
*   [GitLab: Connect to AWS using OIDC](https://docs.gitlab.com/ee/ci/cloud_deployment/aws/#connect-to-aws-using-oidc)
*   **Secrets Management**: Use a dedicated secrets manager like [HashiCorp Vault](https://www.vaultproject.io/) or your cloud provider's native solution (e.g., AWS Secrets Manager) to manage and inject secrets dynamically.
*   **Container Runtime Security**: Tools like [gVisor](https://gvisor.dev/) or [Firecracker](https://firecracker-microvm.github.io/) can provide stronger isolation between the build container and the host than standard containers.

### Metrics/Signal
*   **Metric**: Percentage of CI/CD pipelines using short-lived credentials (OIDC) vs. static secrets.
*   **Metric**: Time-to-live (TTL) configured for dynamic credentials. Shorter is better (e.g., 15-60 minutes).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack, you need visibility into what's happening inside your build environment. If you don't log process executions, file modifications, and network connections, the attack in our scenario would be invisible. The build would succeed, and you would only discover the breach later when the stolen credentials are abused.

Detection involves collecting the right telemetry and setting up alerts for anomalous behavior. For our scenario, a key indicator would be a process like `npm` executing from an unexpected path (`/tmp/attacker-tools/npm` instead of `/usr/bin/npm`) or a build process making a network connection to an unknown IP address.

### Insight
Your CI/CD environment is a critical piece of infrastructure and should be monitored with the same rigor as your production servers. Many developers treat it as a "black box," but its activity provides some of the most important security signals in your organization.

### Practical
1.  **Log All Executed Commands**: Configure your build agents to log all process executions, including the full command path, arguments, and parent process.
2.  **File Integrity Monitoring (FIM)**: Monitor critical files and directories on your build agents for changes, such as the `jenkins` user's `.bashrc` or binaries in `/usr/bin`.
3.  **Baseline Behavior**: Establish a baseline of normal activity. What processes normally run during a build? What network connections are normal? Alerts can then be triggered on deviations from this baseline.

### Tools/Techniques
*   **Runtime Security Tools**: [Falco](https://falco.org/) is an open-source tool that can detect anomalous activity in containers and on hosts using a simple rule-based language. A Falco rule could easily detect the scenario:
```yaml
- rule: Unexpected shell binary execution path
desc: Detects a shell binary running from a non-standard path
condition: evt.type = execve and proc.name in (bash, sh, npm, git) and not proc.exepath startswith (/bin, /usr/bin)
output: "Suspicious process executed (user=%user.name command=%proc.cmdline path=%proc.exepath parent=%proc.pname)"
priority: WARNING
```
*   **Endpoint Detection and Response (EDR)**: Commercial EDR tools like [CrowdStrike Falcon](https://www.crowdstrike.com/products/endpoint-security/falcon-insight/) or [SentinelOne](https://www.sentinelone.com/) can be deployed on long-lived build agents to provide deep visibility and automated detection.
*   **Log Aggregation**: Funnel logs from your build agents into a centralized logging platform like [Splunk](https://www.splunk.com/), [Elasticsearch](https://www.elastic.co/elasticsearch/), or [Datadog](https://www.datadoghq.com/) for analysis and alerting.

### Metrics/Signal
*   **Signal**: An alert fires because a process was executed from a non-standard directory (`/tmp`, `/dev/shm`).
*   **Signal**: An alert fires for an outbound network connection from a build agent to a destination not on an allowlist.
*   **Metric**: Time-to-Detect (TTD): The time from the start of a malicious action to when a security alert is generated.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about building muscle memory. Don't wait for a real attack to test your defenses. Run regular, controlled security drills where you simulate the attacker's actions. These exercises test your tools (Did Falco fire an alert?), your processes (Who received the alert and what did they do?), and your people (Does the developer on-call know how to respond?).

By intentionally trying to break your own systems in a safe environment, you can find and fix weaknesses before a real adversary exploits them. It also helps educate developers on secure coding and operational practices in a memorable, hands-on way.

### Insight
A security tool that no one understands is useless. A security process that is too cumbersome will be bypassed. Exercises are the best way to ensure that your security measures are not only effective but also practical for your development teams to work with.

### Practical
1.  **Schedule a "Game Day"**: Once a quarter, schedule a security game day. Create a test repository with a vulnerable CI/CD pipeline.
2.  **Red Team / Blue Team**: Assign one developer (or pair) to be the "Red Team" (the attackers). Their goal is to use `PATH` poisoning to steal a fake secret from the build environment. Assign another group to be the "Blue Team" (the defenders). Their job is to use the monitoring tools to detect the attack in real-time.
3.  **Capture the Flag (CTF)**: Create a simple challenge. The "flag" is a fake API key (`FLAG{...}`) in an environment variable. Challenge developers to write a script that can exfiltrate this flag by exploiting a vulnerable build script you provide.
4.  **Review and Improve**: After the exercise, hold a retrospective. What worked? What didn't? Was the alert clear? Did we have the right logs? Use the findings to improve your tooling, documentation, and processes.

### Tools/Techniques
*   **Attack Simulation Script**: Provide a simple script for the "Red Team" to use, which automates creating a fake `git` or `npm` and modifying the `PATH`.
```bash
# Attacker's setup script to be run on the build agent
mkdir -p /tmp/malicious
echo '#!/bin/bash\nprintenv > /tmp/stolen_secrets.txt\n/usr/bin/git "$@"' > /tmp/malicious/git
chmod +x /tmp/malicious/git
echo 'export PATH=/tmp/malicious:$PATH' >> ~/.bashrc
echo "Attack prepped. Wait for the next build."
```
*   **Training Platforms**: Use platforms like [Secure Code Warrior](https://www.securecodewarrior.com/) or [Hack The Box](https://www.hackthebox.com/) for more structured security training that includes CI/CD and infrastructure-related challenges.

### Metrics/Signal
*   **Metric**: Time-to-Remediate (TTR) during the exercise. How long did it take the Blue Team to not only detect but also contain the simulated threat (e.g., by fixing the script and cleaning the agent)?
*   **Metric**: Developer participation rate in security exercises.
{% endblock %}