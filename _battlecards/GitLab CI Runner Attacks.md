---
 permalink: /battlecards/cicd2
battlecard:
 title: GitLab CI Runner Attacks
 category: CI/CD
 scenario: GitLab CI
 focus: 
   - runner compromise 
   - shared cache poisoning 
---
{% block type='battlecard' text='Scenario' %}
An attacker identifies a popular open-source Python project that uses GitLab CI with shared runners. They find a less-common, indirect dependency used by the project's test suite—a code formatting helper library. The attacker publishes a malicious version of this helper library to PyPI with a version bump (e.g., `1.2.4` instead of `1.2.3`), a technique called typosquatting or dependency confusion.

A developer on the target project, intending to update dependencies, runs `pip install --upgrade -r requirements-dev.txt`. The malicious package is pulled in. The package's `setup.py` contains a malicious script that executes upon installation.

When the developer pushes their changes, a GitLab CI pipeline kicks off on a shared runner. During the `pip install` phase of the job:
1.  **Runner Compromise:** The malicious `setup.py` script executes. It scans the runner's environment variables for secrets like `AWS_ACCESS_KEY_ID`, `GCP_SA_KEY`, and the `CI_JOB_TOKEN`, exfiltrating them to an attacker-controlled server.
2.  **Shared Cache Poisoning:** The script then identifies the GitLab CI cache path (e.g., `/cache/my-org/my-project/default-key`). It finds a commonly cached library, like the popular `requests` library, and injects a subtle backdoor into one of its source files. The script ensures the file modification time is preserved to avoid suspicion.

Later, a completely different project within the same organization, also using the same shared runner pool, starts a pipeline. Its cache is hit. The build process now uses the poisoned `requests` library. When the project builds its Docker image, the backdoored library is included and deployed to production, ready to receive commands from the attacker.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's goal is to understand your development ecosystem to find the weakest link. They aren't guessing; they are systematically mapping out your tools, processes, and dependencies. They will browse your public GitLab or GitHub repositories, looking at your `.gitlab-ci.yml`, `package.json`, `pom.xml`, or `requirements.txt` files. They are hunting for dependencies that are obscure, unmaintained, or have names that are easy to typosquat. They study GitLab's documentation to understand exactly how shared runners, caching, and environment variables work, so they can craft a payload that is both effective and stealthy.

### Insight
Your CI/CD configuration and dependency manifests are a public blueprint for attackers. They reveal your choice of frameworks, tools, cloud providers, and development practices. The more complex and obscure your dependency tree, the larger your attack surface.

### Practical
As a developer, periodically review your own public repositories from an outsider's perspective.
- Ask yourself: "If I wanted to attack this project, what would I target?"
- Look at your dependencies. Do you know what each one does? When was it last updated?
- Check your `.gitlab-ci.yml`. Does it reveal sensitive server names, user accounts, or internal project structures?

### Tools/Techniques
*   **GitHub/GitLab Search:** Attackers use advanced search queries to find files like `.gitlab-ci.yml` or `package.json` within specific organizations or that use certain technologies.
*   **Dependency Analysis Tools:** Tools that map dependency trees can be used by attackers to find obscure, nested dependencies as potential targets.
*   [Socket.dev](https://socket.dev/): Scans `npm` packages for supply chain risks, including suspicious install scripts.
*   [Dependabot](https://github.com/dependabot): While a defensive tool, its dependency graphing capabilities illustrate what an attacker sees.
*   [Open Source Insights](https://deps.dev/): Provides a comprehensive view of a package's full dependency tree.

### Metrics/Signal
*   **High number of unmaintained dependencies:** A signal that your project relies on code that is not receiving security patches.
*   **High number of indirect dependencies:** A complex dependency tree is harder to audit and offers more hiding places for malicious packages.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward and assessing how your current setup would fare against the attack scenario. A developer should ask critical questions about their CI/CD environment. Are we using shared runners across projects with different security requirements? How are our cache keys configured? A cache key that is too broad (e.g., `key: $CI_COMMIT_REF_SLUG`) means a poisoned cache from one branch could infect another. Do we pin our dependency versions, or are we automatically pulling the "latest" version of everything? Do our builds have unrestricted access to the public internet to pull dependencies?

### Insight
Convenience is often the enemy of security. Shared runners and broad caches are convenient and speed up builds, but they break down the isolation between projects, creating a "blast radius" problem where one compromised project can infect many others.

### Practical
- **Review your `.gitlab-ci.yml`:** Look specifically at the `cache:key:` definitions. Is the key specific enough to your project and branch? Ideally, it should be tied to the lock file, like `key: { files: [package-lock.json] }`.
- **Check your runner configuration:** In GitLab's `Settings > CI/CD > Runners`, see if your critical projects are using shared runners (`is-shared` tag) or dedicated, project-specific runners.
- **Audit your dependencies:** Run a tool to check for known vulnerabilities and also to understand what install scripts are being executed.

### Tools/Techniques
*   **GitLab CI/CD Configuration:** Review the [cache documentation](https://docs.gitlab.com/ee/ci/caching/) and [runner documentation](https://docs.gitlab.com/ee/ci/runners/).
*   **Dependency Audit Tools:**
*   `npm audit fix`: Scans and attempts to fix vulnerabilities in Node.js projects.
*   `pip-audit`: Audits Python environments for known vulnerabilities.
*   [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/): A utility that identifies project dependencies and checks if there are any known, publicly disclosed vulnerabilities (for Java, .NET, etc.).

### Metrics/Signal
*   **Percentage of projects using shared runners:** A high percentage indicates a larger potential blast radius.
*   **Cache key specificity:** A low score here (e.g., many projects using just the branch name as a key) is a red flag.
*   **Number of unpinned dependencies:** Dependencies specified with `*` or `latest` are high-risk.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification involves hardening your CI/CD pipeline to prevent the attack from succeeding in the first place. This means enforcing strict controls over dependencies, isolating build environments, and securing the cache. The goal is to make your pipeline a hostile environment for an attacker's payload.

### Insight
A secure pipeline is built on layers of defense. No single control is perfect. Combining runner isolation, cache integrity, and dependency verification creates a much stronger posture than relying on just one.

### Practical
- **Isolate Build Environments:** Use dedicated, ephemeral runners for critical projects. Each job should start with a clean, fresh environment, preventing any chance of state or cache poisoning between jobs or projects.
- **Harden Caching:**
- Use highly specific [cache keys](https://docs.gitlab.com/ee/ci/caching/#use-a-variable-to-control-when-jobs-share-a-cache). A great practice is to key the cache to a hash of the dependency lock file (e.g., `package-lock.json`, `Gemfile.lock`, `poetry.lock`). This ensures the cache is only reused when dependencies are identical.
- `key: { files: [ "package-lock.json" ] }`
- **Lock and Verify Dependencies:**
- Always use lock files (`package-lock.json`, `yarn.lock`, `poetry.lock`, etc.) and commit them to your repository. This ensures that every build uses the exact same version of every dependency.
- In your CI script, use commands that verify integrity against the lock file, like `npm ci` instead of `npm install`.
- **Scan Everything:** Integrate automated security scanning into your pipeline for dependencies, source code (SAST), and container images.

### Tools/Techniques
*   **GitLab Runner Tags:** Use tags to ensure critical projects only use specific, isolated runners. See [Use tags to control which jobs a runner can run](https://docs.gitlab.com/ee/ci/runners/configure_runners.html#use-tags-to-control-which-jobs-a-runner-can-run).
*   **Dependency Scanners:**
*   [Trivy](https://github.com/aquasecurity/trivy): An open-source scanner for vulnerabilities in container images, filesystems, and Git repositories.
*   [Snyk](https://snyk.io/): A developer security platform that can be integrated directly into GitLab pipelines to scan dependencies and code.
*   **Artifact Signing:**
*   [Sigstore](https://www.sigstore.dev/): A project for signing, verifying, and proving the provenance of software artifacts. This helps ensure the artifacts you deploy are the ones your CI system built.

### Metrics/Signal
*   **Percentage of projects using ephemeral/dedicated runners:** Aim for 100% for production-critical applications.
*   **Pipeline failure rate on vulnerability scans:** A non-zero rate shows that the system is working and catching issues before they reach production.
*   **Adoption of `npm ci` vs. `npm install`:** A higher ratio of `ci` indicates better dependency hygiene.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker's code *does* execute on your runner. The goal now is to contain the blast radius. If the malicious script runs, what can it actually do? Limiting the damage involves applying the Principle of Least Privilege to your CI/CD jobs. A build job for a documentation site shouldn't have access to production database credentials. By restricting the permissions of each job to the absolute minimum required, you make a successful compromise far less valuable to the attacker.

### Insight
Secrets are the currency of CI/CD compromises. The most effective way to devalue that currency is to make them short-lived and narrowly scoped. A stolen API key that expires in five minutes and can only access one specific S3 bucket is far less damaging than a permanent key with admin access.

### Practical
- **Use Short-Lived Credentials:** Instead of storing static `AWS_ACCESS_KEY_ID` variables in GitLab, use [GitLab's OIDC support](https://docs.gitlab.com/ee/ci/cloud_services/) to request temporary, short-lived credentials directly from your cloud provider (AWS, GCP, Azure) for each job.
- **Scope the `CI_JOB_TOKEN`:** By default, the `CI_JOB_TOKEN` has broad access. [Limit its scope](https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html#limit-the-job-token-scope) to only the specific projects it needs to interact with.
- **Network Isolation:** Configure your runners in a firewalled network that restricts egress traffic. A build job should only be able to connect to your package repository and internal services, not an attacker's random IP address on the internet.

### Tools/Techniques
*   **Cloud IAM/OIDC Integration:**
*   [Configuring OpenID Connect in AWS](https://docs.gitlab.com/ee/ci/cloud_services/aws/)
*   [Configuring OpenID Connect in Google Cloud Platform](https://docs.gitlab.com/ee/ci/cloud_services/gcp/)
*   **Secrets Management:**
*   [HashiCorp Vault](https://www.vaultproject.io/): A centralized secrets management tool that can be integrated with GitLab CI to provide just-in-time, dynamically-generated secrets.
*   **Network Policies:** If your runners are on Kubernetes, use [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) to restrict outbound traffic from runner pods.

### Metrics/Signal
*   **Percentage of CI/CD jobs using OIDC vs. static secrets:** A higher OIDC adoption rate indicates a more secure, dynamic environment.
*   **Number of network egress alerts:** An increase in denied outbound network connections from runners could signal an attempted exfiltration.
*   **Audit logs showing the scope of `CI_JOB_TOKEN` access:** This should be regularly reviewed to ensure it remains minimal.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack, you need visibility. You can't stop what you can't see. This means logging relevant events, monitoring for anomalies, and setting up alerts. What constitutes "suspicious activity" in this scenario? A build job making a network connection to an unknown IP address. The hash of a cached file changing when the lock file hasn't. A runner using an unusual amount of CPU or network bandwidth. You need to collect the right signals and have a system in place to analyze them.

### Insight
CI/CD job logs are only part of the story. They tell you what the job was *supposed* to do. To detect a compromise, you need to monitor what the runner's environment is *actually* doing at the system call, process, and network level.

### Practical
- **Log Runner Activity:** Forward logs from the GitLab Runner process and the underlying system (e.g., syslog, journald) to a centralized logging platform (e.g., ELK Stack, Splunk, Datadog).
- **Monitor Network Traffic:** Track all outbound network connections from your runners. Baseline what is "normal" (e.g., connections to `npmjs.org`, `pypi.org`, your container registry) and alert on anything else.
- **Cache Integrity Checks:** As a step in your pipeline, you can calculate and log the hash of critical cached directories or files. If the hash changes unexpectedly between runs, it could indicate tampering. `find . -type f -print0 | xargs -0 sha256sum | sha256sum`
- **Audit GitLab Events:** Use GitLab's [Audit Events API](https://docs.gitlab.com/ee/api/audit_events.html) to monitor for suspicious changes to project settings, CI/CD variables, or runner configurations.

### Tools/Techniques
*   **Runtime Security Monitoring:**
*   [Falco](https://falco.org/): An open-source tool that detects unexpected application behavior at the kernel level. You can run it on your runner hosts to detect suspicious activity like unexpected network connections or file writes.
*   **Centralized Logging/SIEM:**
*   [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or the [ELK Stack](https://www.elastic.co/elastic-stack) for collecting and analyzing logs.
*   **GitLab Audit Logs:** Natively available in GitLab for monitoring user and system activity.

### Metrics/Signal
*   **Alert on new outbound IP destinations:** A high-fidelity signal that a runner is communicating with an unknown server.
*   **Unexpected cache hash mismatch:** An alert indicating that cached content has been modified by an unknown process.
*   **Anomalous resource usage:** A sudden spike in CPU or network I/O on a runner node without a corresponding change in job complexity.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build resilience, your team needs to practice responding to this type of attack. Security exercises, or "gamedays," turn theoretical knowledge into practical skill. The goal is to simulate the attack in a controlled way to test your defenses, monitoring, and response procedures. This builds muscle memory for developers and helps identify gaps in your tooling and processes before a real attacker does.

### Insight
The purpose of an exercise is not to pass or fail, but to learn. A failed detection or slow response during a drill is a cheap lesson that helps you fortify your systems for a real event. It's better to discover your blind spots in a safe environment.

### Practical
- **Tabletop Exercise:** Gather the team and walk through the scenario verbally. "A developer reports a build is failing with a weird network error. What do you do first? What logs do you check? Who do you notify?" This tests your incident response plan.
- **Live Fire Exercise (Controlled):**
1.  Create a harmless "malicious" package that, instead of stealing secrets, simply writes a file to a known location or makes a DNS request to a controlled domain (e.g., using a service like [interact.sh](https://github.com/projectdiscovery/interactsh)).
2.  Introduce this package into a non-production project's dependencies.
3.  Trigger a CI build.
4.  Now, see what happens. Did any alerts fire? Can the team use the available logs and tools to trace the activity back to the malicious package? How quickly can they determine the "blast radius" (i.e., which other projects could have been affected)?
- **Post-Mortem:** After the exercise, document what went well, what didn't, and create actionable tickets to improve tooling, processes, or documentation.

### Tools/Techniques
*   **Internal Playbooks:** A simple document in your team's wiki outlining the step-by-step process for responding to a suspected CI/CD compromise.
*   **Threat Modeling Frameworks:** Use a framework like [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) to proactively think about and categorize potential threats to your CI/CD pipeline during design and review sessions.
*   **Red Teaming / Pen-testing:** Engage an internal or external security team to perform a controlled, adversarial simulation against your CI/CD environment.

### Metrics/Signal
*   **Mean Time to Detect (MTTD):** How long did it take from the simulated attack's execution to the first alert or manual detection?
*   **Mean Time to Respond (MTTR):** How long did it take to identify the root cause, assess the impact, and contain the threat (e.g., by rotating secrets and cleaning the cache)?
*   **Post-exercise improvements:** The number of concrete improvement tickets (e.g., "Add Falco to runners," "Refine cache key strategy") generated from the exercise.
{% endblock %}