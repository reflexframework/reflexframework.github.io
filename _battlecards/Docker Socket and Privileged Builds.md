---
 permalink: /battlecards/docker-socket-and-privileged-builds
battlecard:
 title: Docker Socket and Privileged Builds
 category: Containers/Infra
 scenario: Docker Socket & Privileged Builds
 focus: 
   - /var/run/docker.sock abuse 
   - privileged runner compromise 
   - container escape 
---
{% block type='battlecard' text='Scenario' %}
An attacker identifies a popular open-source Python library used in your project and successfully introduces a malicious update. Your project's `requirements.txt` is configured to pull the latest minor version, so your CI/CD pipeline automatically ingests the compromised code during the next build.

The build job runs inside a Docker container on a self-hosted CI runner. To enable building and pushing Docker images, the pipeline is configured to mount the host's Docker socket (`/var/run/docker.sock`) into the build container.

When the pipeline executes `pip install`, the malicious code in the compromised library runs. It first checks for the existence of the Docker socket file. Finding it, the script uses the Docker client (which it installs silently) to communicate with the Docker daemon on the host machine.

It then executes the following command:
`docker run --rm -it --privileged --pid=host -v /:/hostfs alpine chroot /hostfs bash`

This command launches a new, privileged container, mounts the entire host filesystem into it, and gains a root shell on the underlying CI runner. From here, the attacker has full control of the runner. They steal the runner's cloud credentials, pivot to other servers in the same network segment, and inject a backdoor into the final application artifact before it gets deployed to production.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. For this scenario, they aren't targeting you specifically at first, but rather a widely used public dependency. Once the dependency is compromised, their payload lies dormant, waiting for a CI/CD system with a specific misconfiguration. The payload's own reconnaissance is automated: it simply checks "Am I in a container with access to `/var/run/docker.sock`?" Attackers also scan public code repositories (like GitHub or GitLab) for CI/CD configuration files (e.g., `.gitlab-ci.yml`, `Jenkinsfile`, GitHub Actions workflows) that explicitly mount the Docker socket or use a `privileged: true` flag. These files act as a public blueprint of your internal build infrastructure.

### Insight
Your CI/CD configuration is not just build logic; it's infrastructure-as-code that defines the security posture of your build environment. Attackers treat it like a treasure map. The convenience of Docker-in-Docker via socket mounting is a well-known and actively exploited pattern.

### Practical
As a developer, you can perform the same reconnaissance an attacker would. Search your entire codebase for the string `/var/run/docker.sock`. Check your CI/CD job logs and configurations for any mention of "privileged" mode. Ask yourself: "Does this specific build job *really* need root-level access to the entire host machine just to build a container image?"

### Tools/Techniques
*   **Code Search:** Use your IDE's search, `git grep`, or GitHub's code search to find instances of `/var/run/docker.sock` or `privileged: true` in your repositories.
*   **CI/CD Static Analysis:** Use tools that scan your pipeline configurations for security issues before they are committed.
*   [Checkov](https://www.checkov.io/): Scans infrastructure-as-code files, including GitLab CI, GitHub Actions, and more, for misconfigurations.
*   [Pin-Point](https://github.com/CheckPointSW/Pin-Point): A tool by CheckPoint to help discover insecure configurations in CI/CD pipelines.

### Metrics/Signal
*   **Signal:** A pull request is opened that adds or modifies a CI/CD configuration to include Docker socket mounting.
*   **Metric:** Number of build pipelines that currently mount the Docker socket or run in privileged mode. The goal should be zero.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you assess your own environment against this attack. Does your CI/CD setup allow a build script to talk to the host's Docker daemon? It’s like giving a temporary worker (the build job) a master key to the entire building. The most common way this happens is mounting `/var/run/docker.sock`. Another is running the build container itself with the `--privileged` flag. Both effectively disable the security boundary between the container and the host.

### Insight
The danger here is subtle because it feels like a standard pattern. Many online tutorials demonstrate mounting the Docker socket as the "easy way" to build images in CI. This normalizes a highly insecure practice. The context matters: a build job is running code from dozens or hundreds of third-party dependencies, making it an untrusted environment by default.

### Practical
Go to your main application's repository and look at the CI/CD configuration file (e.g., `.github/workflows/build.yml`). Look for lines that mount volumes, specifically `-v /var/run/docker.sock:/var/run/docker.sock`. Also, look for settings like `services` or `jobs` that have a `privileged: true` key. To test the impact, add a simple command to a test branch's build script: `ls -la /var/run/docker.sock && docker ps`. If it runs successfully, you are vulnerable.

### Tools/Techniques
*   **Manual Inspection:** Read your CI/CD YAML files. This is the most direct way to find the vulnerability.
*   **Runtime Checks:** Add a "linting" or "security check" step at the beginning of your pipeline that fails the build if it detects the Docker socket is mounted.
```bash
if [ -S /var/run/docker.sock ]; then
echo "ERROR: Docker socket is mounted. This is a security risk."
exit 1
fi
```

### Metrics/Signal
*   **Signal:** A build log shows the successful execution of `docker` commands (like `docker ps` or `docker build`) inside a build step that is not explicitly using a secure builder tool.
*   **Metric:** A periodically updated inventory of CI/CD jobs and runners, noting which ones have privileged access or socket mounts.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
To harden your system, you must break the connection between the build container and the host's Docker daemon. The modern approach is to use "daemonless" or "rootless" container image builders. These tools are specifically designed to build container images inside an unprivileged container, without ever needing to talk to a Docker daemon. They build the image layer by layer within the filesystem and then export it as a standard OCI-compliant image.

### Insight
You are not trying to use "Docker-in-Docker" but rather "Build-container-images-in-Docker". The distinction is crucial. The goal is to produce a container image artifact, not to manage the host's containers from within a container. Adopting daemonless builders slightly changes the `build` command in your script but fundamentally severs the dangerous link to the host.

### Practical
Modify your CI/CD script. Instead of using a base image with Docker and running `docker build`, you will use a dedicated builder tool. For example, a `docker build` command is replaced with a `kaniko` command that points to your Dockerfile. This requires changing just a few lines in your CI/CD configuration file.

### Tools/Techniques
*   **Daemonless Builders:** These are the preferred solution. They run entirely in userspace and don't need any special privileges.
*   [Google's Kaniko](https://github.com/GoogleContainerTools/kaniko): Executes builds inside a container or Kubernetes cluster. You run the Kaniko image and provide it with the context (your Dockerfile and source code).
*   [Buildah](https://buildah.io/): A tool that facilitates building OCI container images. It's powerful and scriptable.
*   **Rootless Docker:** If you absolutely must use the Docker daemon, configure it to run in [rootless mode](https://docs.docker.com/engine/security/rootless/). This runs the Docker daemon and containers in a user namespace, so even if an attacker escapes, they are a low-privilege user on the host, not root.

### Metrics/Signal
*   **Signal:** A pull request is merged that removes a Docker socket mount and replaces it with a call to a Kaniko or Buildah executor.
*   **Metric:** Percentage of container image builds in your organization that are performed using a daemonless builder.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker has compromised the runner despite your best efforts. Your goal now is to contain the "blast radius." What can that runner actually do? If it can access your production database, secrets vault, and other servers, the damage will be catastrophic. A well-designed system ensures the CI runner is heavily firewalled and operates with minimal, short-lived credentials. The runner should be treated as a hostile environment. Using ephemeral, single-use runners is a powerful containment strategy—the entire environment is destroyed after the job, erasing the attacker's foothold.

### Insight
Think of your CI/CD environment as a series of locked rooms with single-use key cards. The runner's key card (its credentials) should only open the doors it absolutely needs (e.g., the code repo, the artifact registry) and should expire the moment the job is done. Static, long-lived credentials on a shared runner are like leaving a master key lying around.

### Practical
*   **Use Ephemeral Runners:** Instead of a fleet of long-running, self-hosted virtual machines, configure your CI/CD system to spin up a fresh container or VM for each job and destroy it immediately after.
*   **Network Segmentation:** Place your runners in an isolated network segment (a dedicated VPC or subnet) with strict firewall rules that deny all outbound traffic by default, only allowing connections to specific required services (e.g., `github.com`, your artifact repository).
*   **Short-Lived Credentials:** Stop using static API keys. Use OpenID Connect (OIDC) to issue short-lived, single-use credentials from your cloud provider (AWS, GCP, Azure) directly to a specific job.

### Tools/Techniques
*   **Ephemeral CI/CD Runners:**
*   [GitHub-hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners) are ephemeral by default.
*   For self-hosting on Kubernetes, use the [actions-runner-controller (ARC)](https://github.com/actions/actions-runner-controller) for GitHub or the [GitLab Kubernetes Executor](https://docs.gitlab.com/runner/executors/kubernetes.html).
*   **Identity and Credential Management:**
*   [Configuring OIDC with GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers) to provide temporary cloud credentials.
*   [HashiCorp Vault](https://www.vaultproject.io/) can also be used to dynamically issue secrets to CI jobs.
*   **Network Controls:** [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/), [AWS Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html), or [GCP Firewall Rules](https://cloud.google.com/vpc/docs/firewalls).

### Metrics/Signal
*   **Signal:** A network flow log shows a CI runner attempting to connect to a production database or an internal developer service. This should be blocked and trigger an immediate alert.
*   **Metric:** Percentage of CI jobs that run with short-lived OIDC credentials vs. long-lived static secrets.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack in progress, you need visibility into what's happening on the runner host and within your build containers. This means logging all Docker daemon API calls, monitoring process executions, and analyzing network traffic. An attacker launching a privileged container from a build job is a noisy, anomalous event that should stand out immediately against the baseline of normal build activity. The key is to have the logs and tools in place to see it.

### Insight
Your CI/CD system is a production system and should be monitored as such. An attacker's actions—installing new tools (`netcat`, `docker`), starting a new privileged container, accessing the host filesystem—are behaviors that a normal build process for your Java or Python app would never exhibit. The absence of monitoring is an open invitation for attackers to operate undetected.

### Practical
Ensure that logs from the Docker daemon on your runner hosts are shipped to a central security information and event management (SIEM) or logging platform. Deploy a runtime security sensor on the hosts. Create alerts for high-risk events, such as: "A container has been launched with the `--privileged` flag" or "A process inside a build container is attempting to communicate with the Docker socket."

### Tools/Techniques
*   **Runtime Security Monitoring:**
*   [Falco](https://falco.org/): The de facto open-source standard for runtime threat detection in containers and hosts. It can detect suspicious activity like spawning shells in containers or creating privileged containers.
*   Commercial tools like [Sysdig Secure](https://sysdig.com/products/secure/) or [Aqua Security](https://www.aquasec.com/products/cnapp/) provide more advanced features and management.
*   **Log Aggregation and Analysis:**
*   Ship Docker daemon logs and system audit logs (`auditd`) to a platform like [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or the [Elastic Stack](https://www.elastic.co/elastic-stack).
*   **Example Falco Rule:**
```yaml
- rule: Privileged container launched in CI
desc: Detects a privileged container being launched, potentially from a compromised build job.
condition: container.privileged=true and proc.pname=dockerd and spawned_process and ci_job_process
output: A privileged container was launched from a CI job (user=%user.name command=%proc.cmdline container_id=%container.id image=%container.image.repository)
priority: CRITICAL
```

### Metrics/Signal
*   **Signal:** A Falco or Sysdig alert fires for "Privileged Container Started" or "Write below root directory" originating from a CI runner.
*   **Metric:** Mean Time to Detect (MTTD) for a simulated container escape. How many minutes/hours pass between the malicious action and an alert being generated?

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
The best way to prepare is to practice. Run a controlled security exercise, often called a "Red Team" or "Purple Team" exercise. Create a sandboxed, isolated copy of your CI/CD environment that is intentionally configured with the Docker socket vulnerability. Then, challenge a team of developers (the "Blue Team") to detect an "attack." A security engineer (the "Red Team") will commit code with a benign payload that mimics the attack scenario (e.g., it creates a privileged container that just writes a file to `/tmp` on the host). The goal isn't just to "win," but for developers to see the attack path firsthand and test whether their monitoring and alerting (the "Expose" stage) actually works.

### Insight
This turns an abstract security policy into a hands-on, memorable experience. When a developer sees for themselves how a simple `pip install` can lead to a root shell on the host, they will become a permanent champion for secure CI/CD practices. It builds "muscle memory" for both preventing and detecting these attacks.

### Practical
1.  **Setup:** Clone your build environment to a dedicated, isolated cloud account or VPC.
2.  **Define Scenario:** The goal is to use a malicious dependency to launch a privileged container and write a file named `/tmp/pwned.txt` on the host.
3.  **Execute:** The Red Team commits the code. The Blue Team (your developers) monitors the logs, dashboards, and alerts you've set up.
4.  **Debrief:** Did the alerts fire? Were they clear? Could the developers trace the activity back to the source? What could be improved? Use the findings to update your monitoring rules, logging, and incident response runbooks.

### Tools/Techniques
*   **Sandboxed Environments:** Use a separate AWS/GCP/Azure account or a dedicated Kubernetes cluster with strict network isolation for the exercise.
*   **Attack Simulation:** You don't need fancy tools. A simple Python script in a fake package that runs `os.system("docker run ...")` is sufficient to simulate the core attack.
*   **Collaborative Documentation:** Use a shared document or wiki (like Confluence or Notion) to track the exercise timeline, what the Blue Team is seeing, and the final lessons learned.

### Metrics/Signal
*   **Metric:** Time-to-Detect during the exercise. How long did it take from the malicious commit to a developer raising the alarm?
*   **Metric:** Number of developers participating in security exercises per quarter.
*   **Signal:** After the exercise, developers proactively open pull requests to fix similar vulnerabilities in other pipelines.
{% endblock %}