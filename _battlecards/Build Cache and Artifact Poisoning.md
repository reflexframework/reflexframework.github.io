---
 permalink: /battlecards/build-cache-and-artifact-poisoning
 
battlecard:
 title: Build Cache and Artifact Poisoning
 category: Build Systems
 scenario: Build Cache/Artifact Poisoning
 focus: 
   - Maven/Gradle cache poisoning 
   - artifact proxy substitution 
   - remote build cache compromise 
---

A sophisticated attacker gains initial access to a developer's workstation via a targeted phishing email. From this foothold, they move laterally across the internal network, mapping out the company's software development infrastructure. They identify a self-hosted Artifactory instance serving as the central Maven/Gradle repository and a Gradle Enterprise server providing a remote build cache for CI/CD pipelines.



The attacker targets a widely-used internal Java library named `com.mycorp:auth-client`, which handles authentication and authorization for hundreds of microservices. Their goal is to inject a backdoor that exfiltrates production service credentials.

The attacker gains administrative access to the Gradle Enterprise server through a stolen, poorly-secured service account credential found on the developer's machine. They use this access to poison the remote build cache. They craft a malicious version of the `auth-client` library's compiled JAR file. This malicious JAR is identical in size and metadata to the real one, but contains a small, obfuscated payload.

They upload this malicious artifact directly into the remote build cache, associating it with the source code hash of the legitimate `auth-client` library. The next time a CI pipeline runs a build for a service that depends on `auth-client`, the Gradle build system checks the remote cache. It finds a matching entry for the `auth-client` source code, downloads the pre-compiled (and now malicious) JAR from the cache, and skips the compilation step entirely.

The poisoned library is now silently bundled into dozens of new microservice deployments. Once in production, the payload activates, collecting AWS IAM role credentials from the environment and sending them to an external command-and-control server. The breach remains undetected for weeks, as build logs appear normal and all builds are successful.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They act like spies, trying to understand your development ecosystem to find the weakest link. Initially, they'll look at public sources like your company's GitHub organization, developer blogs, and job postings to learn your tech stack (e.g., "We use Gradle, Kubernetes, and Artifactory"). Once they gain a foothold inside your network (e.g., through phishing), they'll start mapping internal systems. They'll look for your CI servers (Jenkins, GitLab), artifact repositories (`artifactory.internal.corp`), and build cache nodes. They read internal wikis to understand your build processes, naming conventions, and which libraries are most critical.

### Insight
Attackers don't attack blindly; they look for the path of least resistance. They know that non-production systems like build tools are often less hardened and monitored than production servers, yet can be a stepping stone to compromising everything that gets deployed. The very tools you use for efficiency—like a remote build cache—become a prime target because they are designed to be trusted implicitly by the build process.

### Practical
- Audit your public-facing assets. Scan your public GitHub repositories for any accidentally committed configuration files, internal hostnames, or developer comments that describe your infrastructure.
- Treat your developer infrastructure like a production system. The principle of least privilege should apply to build servers, artifact repositories, and their administrative consoles.
- Foster a culture where developers are aware that their machines are high-value targets for attackers seeking to pivot into core development systems.

### Tools/Techniques
*   [**Shodan**](https://www.shodan.io/): A search engine for finding internet-connected devices. Attackers use it to see if your Artifactory, Nexus, or Jenkins instances are accidentally exposed to the public.
*   [**TruffleHog**](https://github.com/trufflesecurity/trufflehog): An open-source tool to scan repositories for secrets, keys, and credentials that an attacker could use to access internal systems.
*   **Network Mapping Tools**: Once inside, attackers use tools like `nmap` to discover live hosts and open ports, helping them find servers running services like Artifactory (port 8081/8082) or Gradle Enterprise.

### Metrics/Signal
*   Number of secrets or internal hostnames found in public code repositories.
*   Unusual or widespread network scanning activity originating from developer workstations.
*   Number of developer-facing systems (e.g., Jenkins, Artifactory) that are publicly accessible.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you turn the attacker's lens on yourself. It's a self-assessment to find the security gaps in your build and dependency management processes before an attacker does. Ask critical questions:
- Can any developer or CI job publish artifacts to our release repository without a review?
- Are we pulling dependencies directly from public repositories (e.g., Maven Central, npmjs.com) in our CI builds, or are we forcing them through a trusted internal proxy?
- Do our build scripts use dynamic or "snapshot" versions (e.g., `1.3.+`, `2.1-SNAPSHOT`) that can change without warning?
- What are the credentials and permissions for our build cache server? Is access tightly controlled?

### Insight
The tension between developer velocity and security is where vulnerabilities hide. Features designed for convenience, like mutable SNAPSHOT versions or permissive repository permissions, are easily abused. A common weak point is the service account used by the CI/CD system; if it has broad permissions to write to both the build cache and the artifact repository, it becomes a single point of failure.

### Practical
- **Review Repository Permissions**: Map out who (users and service accounts) has write/deploy permissions to your artifact repositories. Drastically limit write access to critical `release` repositories.
- **Audit Build Scripts**: Systematically scan your `pom.xml` and `build.gradle` files for insecure practices like pulling from public repos over HTTP or using dynamic dependency versions.
- **Check Network Policies**: Verify that build agents cannot access the public internet directly. They should only be able to reach your internal artifact repository. Similarly, verify who can access the administrative interfaces of your build tools.

### Tools/Techniques
*   **Repository User/Permission Audits**: Both [JFrog Artifactory](https://jfrog.com/help/r/jfrog-platform-administration-documentation/manage-users) and [Sonatype Nexus](https://help.sonatype.com/repomanager3/security/users) have built-in tools for auditing user roles and permissions.
*   [**Open Policy Agent (OPA)**](https://www.openpolicyagent.org/): Can be used to write "policy as code" to enforce rules, such as "no builds may use dependencies from unknown repositories."

### Metrics/Signal
*   Percentage of projects that use pinned, immutable dependency versions.
*   Number of user/service accounts with administrative or deploy-level access to your artifact repository and build cache.
*   Time since last credential rotation for CI/CD service accounts.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is the proactive hardening stage—building strong defenses to prevent poisoning attacks. The goal is to establish a chain of trust from the source code to the final artifact. This means ensuring that every piece of code you build or download is exactly what you expect it to be, with no tampering. You achieve this by using a single, trusted source for dependencies, verifying their integrity, and cryptographically signing your own artifacts.

### Insight
A core principle for a secure build process is "hermeticity." A hermetic build is self-contained and relies only on a known, verified set of inputs. This prevents the build from being influenced by ambient network conditions or compromised external services. By proxying all dependencies and verifying their checksums, you move closer to a hermetic, and therefore more secure, build environment.

### Practical
- **Mandate a Repository Manager**: Configure all developer machines and CI agents to resolve dependencies *only* through your internal repository manager (Artifactory, Nexus). Use network policies (firewalls) to block direct access to public repositories like Maven Central.
- **Enforce Checksum and Signature Verification**: Configure your build tool to verify the integrity of every dependency it downloads. This ensures the artifact your proxy downloaded from the upstream repository is the one the original author published.
- **Sign Your Artifacts**: Implement GPG signing for all internally produced artifacts before they are published. This allows downstream consumers (other builds and services) to verify that the artifact was produced by your trusted CI system and not an impostor.

### Tools/Techniques
*   [**Gradle Dependency Verification**](https://docs.gradle.org/current/userguide/dependency_verification.html): A mechanism built into Gradle that automatically verifies the checksums and PGP signatures of dependencies against a committed `verification-metadata.xml` file.
*   [**Maven GPG Plugin**](https://maven.apache.org/plugins/maven-gpg-plugin/): The standard tool for signing artifacts during a Maven build.
*   [**Sigstore**](https://www.sigstore.dev/): A modern, open-source standard for signing, verifying, and proving the provenance of software. It's becoming popular in the container and cloud-native space.
*   [**Reproducible Builds**](https://reproducible-builds.org/): An initiative to create toolchains that produce bit-for-bit identical artifacts from the same source code, making unauthorized changes easier to detect.

### Metrics/Signal
*   Percentage of builds that enforce dependency verification (should be 100%).
*   Number of unsigned artifacts in your release repositories (should be 0).
*   Firewall logs confirming that no build agents have made outbound connections to public artifact repositories.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker has succeeded and a malicious artifact is now in your system. The "Limit" phase is about damage control. The goal is to contain the "blast radius" so that the compromised component can do as little harm as possible. This is achieved by running builds and deployments with the absolute minimum level of privilege required. A compromised build should not be able to access production secrets, modify other pipelines, or deploy to sensitive environments.

### Insight
The Principle of Least Privilege is the most effective tool to limit the impact of a breach. Attackers often rely on overly-permissive systems to move from their initial point of compromise to their ultimate goal. If a compromised build runs in a temporary, isolated container with no access to long-lived secrets or the production network, the attacker is effectively trapped in a box.

### Practical
- **Ephemeral and Isolated Build Environments**: Run every CI job in a fresh, single-use container that is destroyed after the job completes. This prevents a compromised build from affecting subsequent builds.
- **Short-Lived, Scoped Credentials**: Instead of using static, long-lived secrets, use a secrets management system to issue temporary, tightly-scoped credentials for each stage of a pipeline. The "build" stage should have credentials to read/write to the artifact repository, but not to deploy to Kubernetes.
- **Network Segmentation**: Create strict firewall rules that isolate your build network from your production and staging environments. A build agent should have no network path to a production database.

### Tools/Techniques
*   **Container-based CI Runners**: Systems like [GitLab Runners (Docker Executor)](https://docs.gitlab.com/runner/executors/docker.html) or [Jenkins on Kubernetes](https://www.jenkins.io/doc/book/installing/kubernetes/) excel at creating ephemeral build environments.
*   [**Tekton**](https://tekton.dev/): A Kubernetes-native framework for creating CI/CD pipelines where each step runs in its own isolated container.
*   **Secrets Management**: Tools like [HashiCorp Vault](https://www.vaultproject.io/) or cloud provider services like [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) can be integrated with CI/CD to provide short-lived credentials.

### Metrics/Signal
*   The Time-To-Live (TTL) configured for credentials used in CI jobs (shorter is better).
*   Number of persistent build agents vs. ephemeral ones.
*   A clear "deny-all" default rule in the network policies separating build and production environments.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about building a detection system—your "burglar alarm." To catch a poisoning attack, you need visibility into your build process. This means logging critical events and monitoring those logs for anomalies. Key events to watch include: who publishes an artifact, which dependencies are downloaded, which builds use a cached result, and what's inside the artifacts you produce. An attack often creates a subtle but detectable deviation from the normal pattern.

### Insight
Attackers rely on the high volume and noise of build logs to hide their activity. Your goal is to find the meaningful signal. For instance, an immutable release artifact being overwritten is a huge red flag that should never happen. Similarly, a sudden change in the transitive dependencies of a library between two minor patch versions could indicate that a compromised dependency has been injected.

### Practical
- **Centralize and Monitor Logs**: Forward logs from your artifact repository, CI server, and build cache to a central logging platform. Create dashboards and alerts for suspicious events.
- **Generate a Software Bill of Materials (SBOM)**: For every build, generate an SBOM—a complete inventory of all components and dependencies in your application. Store and compare SBOMs between builds to detect unexpected changes.
- **Monitor Cache Behavior**: Log cache hits and misses. A build that was consistently hitting the cache but suddenly reports a miss and recompiles a component could indicate that someone tampered with the cache entry, causing an integrity check to fail.

### Tools/Techniques
*   **Log Aggregation**: [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or the open-source [ELK Stack](https://www.elastic.co/elastic-stack) are standard tools for analyzing logs from multiple systems.
*   **SBOM Generation Tools**: [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) are popular SBOM formats. Tools for Maven ([`cyclonedx-maven-plugin`](https://github.com/CycloneDX/cyclonedx-maven-plugin)) and Gradle make generation easy.
*   [**Dependency-Track**](https://dependencytrack.org/): An open-source platform that ingests SBOMs and can monitor your projects for vulnerabilities and license issues, as well as track dependency changes over time.
*   **Binary and Cache Scanners**: Some security tools can scan artifacts in your repository or entries in your remote cache for known malware signatures or suspicious code patterns.

### Metrics/Signal
*   Alerts firing on an attempt to overwrite or delete a versioned artifact in a release repository. This count should always be zero.
*   The rate of unexpected new dependencies appearing in SBOM diffs between minor releases.
*   Anomalous cache uploads from IP addresses outside of your known build agent network.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is the "fire drill" stage. You can't wait for a real attack to test your defenses and response plan. The goal is to build muscle memory for your team by simulating a cache poisoning attack in a controlled environment. These exercises test your tools (did the alerts fire?), your processes (do people know who to call?), and your people (can they analyze the situation and respond effectively?).

### Insight
Security is not just about tools; it's about people and process. A security exercise will quickly reveal gaps in your documentation, misunderstandings about roles and responsibilities, and weaknesses in your monitoring setup. The goal is not to "pass" or "fail," but to learn and improve in a low-stakes environment.

### Practical
- **Tabletop Exercise**: Gather the development, operations, and security teams in a room. Present the attack scenario and walk through the response step-by-step. "The alert for a release artifact overwrite just fired. What do we do now? Who is responsible for disabling the compromised pipeline?"
- **Live Red Team/Blue Team Simulation**: In a sandboxed copy of your build environment, have a "red team" (the attackers) attempt to upload a modified (but harmless) artifact. The "blue team" (the defenders) must use their existing monitoring tools to detect the activity, identify the "malicious" artifact, and follow the incident response plan.
- **Capture the Flag (CTF)**: Create a specific challenge for developers. Give them a project that has been built with a "poisoned" dependency and ask them to find it using tools like SBOM diffing, log analysis, or by inspecting build cache metadata.

### Tools/Techniques
*   **Incident Response Runbooks**: A documented plan, often in a wiki like [Confluence](https://www.atlassian.com/software/confluence) or in a Markdown file in a repository, that details the step-by-step procedure for responding to a supply chain attack.
*   **Threat Modeling Frameworks**: Use frameworks like [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) to proactively brainstorm potential attack vectors against your build system before an exercise.
*   **Sandboxed Infrastructure**: Use Infrastructure as Code (e.g., Terraform, CloudFormation) to quickly spin up an isolated, temporary copy of your artifact repository and CI system for the exercise.

### Metrics/Signal
*   **Mean Time to Detect (MTTD)**: In a simulation, how long did it take from the moment the malicious artifact was uploaded until the blue team raised an alert?
*   **Mean Time to Remediate (MTTR)**: How long did it take to identify all potentially affected applications and contain the threat (e.g., by quarantining the artifact and forcing rebuilds)?
*   Post-exercise survey results from developers on the clarity and effectiveness of the runbook and tooling.
{% endblock %}