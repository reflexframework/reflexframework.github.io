---
permalink: /provenance-and-sbom-tampering

battlecard:
 title: Provenance and SBOM Tampering
 category: Cross-cutting
 scenario: Provenance & SBOM Tampering
 focus: 
   - forged provenance 
   - altered SBOMs 
   - hidden vulnerable dependencies 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets a popular open-source Python data processing library, `fast-DataFrame`, which your company uses in its flagship AI-powered analytics product. The attacker's goal is to inject a backdoor to steal sensitive data processed by your customers.

The attacker finds a `fast-DataFrame` maintainer with weak account security and compromises their GitHub account. They push a new version, `1.5.1`, which contains a subtle backdoor that activates only when it detects it's running in a cloud environment and exfiltrates environment variables (like API keys) to a remote server.

To cover their tracks, the attacker also compromises the project's build server on `CircleCI`. When the CI pipeline for version `1.5.1` runs, it generates a Software Bill of Materials (SBOM) listing all dependencies. The attacker uses a script to intercept this process, generate a *fake* SBOM that omits the newly added malicious exfiltration library (`py-networking-utils`), and then attaches this clean, but forged, SBOM to the official release.

Your automated dependency scanner pulls `fast-DataFrame==1.5.1` and its SBOM. The scanner checks the SBOM, sees nothing wrong, and approves the update. The tampered library is now embedded in your product, and the forged provenance makes it invisible to your standard security checks.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
In this stage, the attacker isn't looking at your code, but at your dependencies and build processes. They are hunting for the weakest link in your software supply chain. They will analyze your public code repositories (`GitHub`, `GitLab`) to see your `requirements.txt`, `package.json`, or `pom.xml` files, identifying every open-source component you rely on. They profile these dependencies, looking for projects with inactive maintainers, poor security practices (e.g., no 2FA on package manager accounts), or complex build processes that are hard to secure. Their goal is to find a soft target they can compromise, which then flows downstream into your application.

### Insight
Attackers view your application not as a single piece of code, but as a graph of dependencies. They know that compromising a single, popular, and trusted dependency is far more efficient than trying to breach your company's network directly. They are mapping your "software nervous system."

### Practical
*   **Audit your dependencies:** As a team, review your key dependencies. When was the last commit? How many maintainers are active? Does the project have a published security policy?
*   **Check your public footprint:** Look at your company's public repositories. Are you exposing more information about your tech stack and build tools than necessary?

### Tools/Techniques
*   **GitHub Code Search:** Attackers use advanced search queries to find projects using specific, vulnerable libraries.
*   **Dependency Analysis Tools:** Tools like [Socket.dev](https://socket.dev/) or [Snyk Advisor](https://snyk.io/advisor/) can be used to assess the health and risk of open-source packages, something attackers also do to find targets.
*   **Social Engineering:** Monitoring developer forums, Discord servers, or social media to understand who the key maintainers are and what build systems they use.

### Metrics/Signal
*   An increase in forks or clones of your public repositories from unknown or suspicious accounts.
*   Unusual "phishing" or social engineering attempts targeting developers on your team, asking about specific libraries or build configurations.
*   A dependency you use suddenly changes ownership or adds new, unknown maintainers.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is about turning the lens inward. How would you know if your own process is vulnerable to this attack? You need to assess the integrity of your build and dependency management lifecycle. Do you generate SBOMs for your software? If so, are they cryptographically signed? Where are they stored, and who has access? Do you just trust the SBOM provided by an upstream dependency, or do you verify it? The key question is: "Could an attacker alter a component *or* its accompanying SBOM without anyone noticing?"

### Insight
An SBOM is only as trustworthy as the process that creates it. Having an SBOM file in your artifact repository is a good start, but if it can be easily replaced or was generated from a compromised source, it provides a false sense of security.

### Practical
*   **Whiteboard your build pipeline:** Draw out every step, from `git clone` to container push. At each step, ask: "What prevents an attacker from altering the code, a dependency, or a generated artifact here?"
*   **Check your artifact storage:** Who has write access to the location where you store your SBOMs and built artifacts (e.g., an S3 bucket, JFrog Artifactory)? Are the permissions too broad?
*   **Verify, don't trust:** Check if you have a step in your pipeline that validates an incoming dependency's checksum against a known-good source, rather than just relying on a version number.

### Tools/Techniques
*   **SBOM Generators:** Use tools like [Syft](https://github.com/anchore/syft) (from a container image) or [CycloneDX Maven Plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin) (for Java) to see if you can generate an SBOM. The absence of such a tool is a major gap.
*   **CI/CD Configuration Review:** Manually inspect your `Jenkinsfile`, `.gitlab-ci.yml`, or `GitHub Actions` workflow YAML files. Look for unsigned artifact uploads or commands that pull and execute scripts from un-vetted sources.

### Metrics/Signal
*   No SBOMs are being generated or stored for your production builds.
*   SBOMs and other build artifacts are stored without any access control or audit logs.
*   Your build pipeline lacks a step to verify the cryptographic signature of either dependencies or their provenance attestations.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening is about creating a trustworthy and tamper-resistant build process. The goal is to ensure that what's in your source code is exactly what ends up in your production artifact, and you have a secure, verifiable record of how it got there. This involves generating SBOMs and other provenance data within a secure, isolated build environment, and then cryptographically signing everything. You should also shift from pulling dependencies from public repositories directly in your main build to using a trusted internal artifact repository that caches and vets them first.

### Insight
Treat your build pipeline with the same security rigor as your production infrastructure. It is a critical piece of infrastructure that manufactures your product. If the factory is compromised, the product cannot be trusted. Frameworks like [SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) provide a clear roadmap for this.

### Practical
*   **Sign everything:** Use code-signing certificates for your final artifacts. More importantly, use tools like Sigstore to sign your SBOMs, container images, and other build attestations.
*   **Isolate and lock down builds:** Configure your CI/CD jobs to run in ephemeral, single-use environments. The build process should be fully automated, with no human intervention.
*   **Use dependency pinning:** Use lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`) and commit them to your source control. This ensures that builds are reproducible and use exact, vetted dependency versions.

### Tools/Techniques
*   **[Sigstore](https://www.sigstore.dev/):** An open-source standard for signing software artifacts. The `cosign` tool can sign container images and SBOMs, making them tamper-evident.
*   **[in-toto](https://in-toto.io/):** A framework to secure the software supply chain. It allows you to create a layout of your expected pipeline and cryptographically verify that each step was performed by the right person/tool in the right order.
*   **Private Artifact Repositories:** Use [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository) as a caching proxy. When a developer needs a dependency, it's pulled from the internal repo, which has already scanned and approved it.
*   **Reproducible Builds:** Follow best practices for [reproducible builds](https://reproducible-builds.org/) to ensure that given the same source code, you always produce the exact same binary output. This makes tampering easier to detect.

### Metrics/Signal
*   Percentage of production artifacts (containers, binaries, SBOMs) that are cryptographically signed.
*   SLSA level achieved for your build pipeline (e.g., aiming for [SLSA Level 3](https://slsa.dev/spec/v1.0/levels)).
*   All external dependencies in a production build are sourced from your internal, trusted repository.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful. The tampered `fast-DataFrame` library is now running in your production environment. The key to limiting the damage is runtime security and the principle of least privilege. The malicious code wants to exfiltrate data to `evil-server.com`. If your application is running in a container with a strict network policy that only allows communication with your database and a specific internal API, the attack fails. The backdoor is present but neutered.

### Insight
Your runtime environment is the last, and arguably most important, line of defense. A secure supply chain is crucial, but a hardened runtime can contain the blast radius of a failure. Don't assume code is safe just because it passed your pipeline checks.

### Practical
*   **Minimalist Base Images:** Use minimal container base images like [distroless](https://github.com/GoogleContainerTools/distroless) or `alpine`. If a shell (`/bin/sh`) or tools like `curl` don't exist in the container, it's much harder for an attacker to explore the environment or exfiltrate data.
*   **Strict Network Policies:** In Kubernetes, use `NetworkPolicy` resources to define exactly which pods can talk to each other and to external endpoints. Deny all egress traffic by default and only allowlist known, required connections.
*   **Read-only Filesystems:** Run your containers with a read-only root filesystem. If the malicious code tries to write a file or modify a binary, the container runtime will block it.

### Tools/Techniques
*   **Kubernetes `NetworkPolicy`:** A native K8s resource for controlling traffic flow at the IP address or port level.
*   **Service Mesh:** Tools like [Istio](https://istio.io/) or [Linkerd](https://linkerd.io/) provide more powerful, application-aware L7 network policies (e.g., "this service can only make GET requests to that service's `/api/v1/data` endpoint").
*   **Runtime Security Tools:** Tools like [Falco](https://falco.org/) or [Tetragon](https://github.com/cilium/tetragon) can monitor kernel-level system calls to detect and block suspicious behavior, like a process trying to make an unexpected network connection or read a sensitive file like `/etc/shadow`.
*   **Sandboxing:** Use technologies like [gVisor](https://gvisor.dev/) or `seccomp-bpf` profiles to severely restrict the system calls a containerized process is allowed to make.

### Metrics/Signal
*   Alerts from runtime security tools (e.g., "Falco alert: Outbound connection to non-allowed IP from pod `analytics-processor-xyz`").
*   Number of `NetworkPolicy` violations logged by your CNI plugin (e.g., Cilium).
*   Zero pods running with `privileged: true` or unnecessary capabilities in your production environment.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This stage is about detection. How do you find the tampered dependency when the forged SBOM looks clean? The key is to compare the "as-built" reality with the "as-running" reality. In your CI pipeline, you generate and sign an SBOM. This is your ground truth. Then, you need a process that periodically scans your running containers, generates a *new* SBOM from the live filesystem, and compares it to the original, signed SBOM from the build. Any discrepancy—a new library, a different version, or a mismatched file hash—is a red flag indicating potential tampering.

### Insight
Detection requires continuous verification. A one-time check at build time is not enough. The state of your running application must be periodically compared against a trusted, immutable record of its intended state.

### Practical
*   **Runtime SBOM Scans:** Schedule a recurring job (e.g., a Kubernetes `CronJob`) that uses a tool like Trivy to scan your production container images and output an SBOM.
*   **Automate the Comparison:** Write a script to automatically compare the SBOM generated at runtime with the signed SBOM stored in your artifact repository for that specific application version.
*   **Monitor Build Logs:** Ingest CI/CD logs into a security information and event management (SIEM) system. Create alerts for suspicious build behavior, such as a step that takes unusually long, has a sudden high network output, or where a dependency hash unexpectedly changes.

### Tools/Techniques
*   **Runtime Scanners:** [Trivy](https://github.com/aquasecurity/trivy) and [Grype](https://github.com/anchore/grype) can scan running container images and generate a list of installed packages.
*   **Log Analysis:** Tools like [Splunk](https://www.splunk.com/), [Elasticsearch](https://www.elastic.co/elasticsearch/), or [Datadog](https://www.datadoghq.com/) can be used to ingest and analyze CI/CD and runtime logs for anomalies.
*   **Continuous Verification:** Projects like [Rekor](https://github.com/sigstore/rekor) (part of Sigstore) create a tamper-evident transparency log for software artifacts. You can query it to ensure the signature and provenance of your artifacts haven't been compromised.

### Metrics/Signal
*   An alert fires because the hash of `lib-fast-dataframe.so` in a running container does not match the hash recorded in the build-time SBOM.
*   A diff between the build-time and run-time SBOMs shows the presence of the unexpected `py-networking-utils` library.
*   A CI/CD log alert shows that the checksum for `fast-DataFrame==1.5.1.whl` suddenly changed between two builds, even though the version number stayed the same.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is about building muscle memory through practice. You don't want your first time dealing with a supply chain attack to be a real one. Run controlled drills to test your defenses. A "game day" or red team exercise could involve a team member manually injecting a modified library into a build and then forging the SBOM. The goal is to see if your `Fortify`, `Limit`, and `Expose` controls actually work. Did the build fail? Did the runtime security block it? Did your monitoring systems create an alert?

### Insight
Security is not just about tools; it's about people and processes. Exercises reveal the gaps in your documentation, your on-call runbooks, and your team's understanding. They turn theoretical knowledge into practical skill.

### Practical
*   **Tabletop Exercise:** Gather the team and walk through the scenario on a whiteboard. "We just got an alert that `fast-DataFrame` has a critical vulnerability. Our SBOM says we are not affected. How do we verify this? Who do we call? What's the process to patch and redeploy?"
*   **Live Red Team Drill:** Create a benign but "malicious" version of a library (e.g., one that just writes a log message to `/tmp/pwned.txt`). Challenge a developer to get this library into a staging environment without being detected by the automated systems.
*   **Threat Model Your Pipeline:** Use a framework like [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-stride-categories) to formally model your build pipeline. This helps you think like an attacker and identify weak spots (e.g., "What if someone could *tamper* with the SBOM before it's uploaded?").

### Tools/Techniques
*   **CI/CD for Attack Simulation:** You can use your own `GitHub Actions` or `Jenkins` pipeline to codify the red team drill. A separate workflow can be built to simulate the attack steps.
*   **Chaos Engineering:** While typically used for resilience, chaos engineering principles can be adapted. Use a tool like [LitmusChaos](https://litmuschaos.io/) to inject a "fault" where a container image is replaced with a slightly altered one to see if your detection mechanisms fire.

### Metrics/Signal
*   **Time To Detect (TTD):** In a drill, how long did it take from the moment the tampered artifact was deployed until the first alert was raised?
*   **Time To Remediate (TTR):** How long did it take the team to identify the malicious component, block it, and deploy a safe version?
*   Number of process gaps or tool misconfigurations discovered during the exercise. These become action items for the next sprint.
{% endblock %}