---
 permalink: /battlecards/java1
 title: Java and Maven/Gradle Dependency Risks
battlecard:
 title: Java and Maven/Gradle Dependency Risks
 category: Package Ecosystem
 scenario: Java + Maven/Gradle
 focus: 
   - dependency confusion 
   - malicious plugins 
   - poisoned mvnw/gradlew 
---
{% block type='battlecard' text='Scenario' %}
An attacker, "APT-JavaJolt," targets a company that uses Java with Maven for its build process. Their goal is to steal cloud credentials from the company's CI/CD environment.

1.  **Reconnaissance:** The attacker scans the company's public GitHub repositories and discovers a `pom.xml` file. It references an internal, private dependency: `com.fincore.metrics-client`. This package is hosted on the company's internal Artifactory server, but the build configuration is not set up to prevent lookups to public repositories.

2.  **Initial Foothold (Dependency Confusion):** The attacker develops a malicious JAR file with the *exact same name* (`com.fincore.metrics-client`) and publishes it to the public Maven Central repository with a very high version number (`99.9.9-RELEASE`). The malicious code in this JAR is simple: upon execution, it reads all environment variables and sends them to an attacker-controlled server.

3.  **Exploitation (Poisoned Wrapper):** When a developer on the team (or, more likely, a CI/CD build agent) runs `mvn clean install`, Maven checks for the latest version of `com.fincore.metrics-client`. Because `99.9.9-RELEASE` is higher than any internal version, and the build system is configured to check public repositories, it downloads and executes the attacker's malicious package. The CI/CD environment variables, including `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, are immediately exfiltrated. The attacker now has credentials to the company's cloud environment. As a persistence mechanism, the malicious code also subtly modifies the project's `mvnw` (Maven Wrapper) script, adding a line to download and execute a remote payload every time the wrapper is run.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}

### Explanation
This is the attacker's planning phase. They are looking for information about your technology stack, internal processes, and people to find the weakest link. For this scenario, their primary goal is to find the names of your private, internal packages. They know developers often reuse these names in public-facing code, commit `pom.xml` files by accident, or discuss them in public forums.

### Insight
Your organization's public footprint is a goldmine for an attacker. What seems like a harmless configuration file in a public "dotfiles" repository or an old example project can provide the exact blueprint an attacker needs. They aren't hacking; they are simply observing what you've made public.

### Practical
- Audit all your organization's public code repositories on platforms like GitHub or GitLab.
- Search for any files that define dependencies (`pom.xml`, `build.gradle`, `settings.xml`).
- Look for hardcoded names of internal servers, artifact repositories, or package groups (e.g., `com.mycorp.*`).
- Use automated secret scanning tools to find not just passwords, but also internal hostnames and other sensitive identifiers.

### Tools/Techniques
- **[GitHub Code Search](https://github.com/search)**: Use advanced search directives like `org:your-org-name "com.your.internal.group"` to find mentions of your private package namespaces.
- **[gitleaks](https://github.com/gitleaks/gitleaks)**: An open-source tool to scan Git repositories for hardcoded secrets and other sensitive data, including internal package names if configured with custom rules.
- **[TruffleHog](https://trufflesecurity.com/trufflehog)**: Scans your environment for secrets, helping to identify leaked credentials or internal configuration details that could guide an attacker.

### Metrics/Signal
- **Metric**: Number of internal dependency names or repository URLs found in public code. The goal should be zero.
- **Signal**: A new public repository is created within your organization containing build configuration files. This should trigger an automated scan.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}

### Explanation
This stage is about looking in the mirror. You need to assess how your development and build environments would stand up to the attack scenario. Are you vulnerable to dependency confusion? Could a malicious plugin run unchecked? Is the integrity of your build wrappers verified? This is where you play the role of the attacker against your own system to find the holes before they do.

### Insight
Convenience is often the enemy of security. A default Maven or Gradle setup will happily pull dependencies from both your private repository and the public internet, usually preferring the highest version number. This "magical" convenience is the very mechanism that a dependency confusion attack exploits.

### Practical
- **Review Build Configs**: Examine your `pom.xml` or `build.gradle` and the global `settings.xml` (`~/.m2/settings.xml`) or `init.gradle` files. Check the order of repositories. If a public repository like Maven Central is listed alongside your private one without strict controls, you are vulnerable.
- **Test for Confusion**: Pick an internal library name. Can you search for it on [Maven Central](https://search.maven.org/)? If the name is available, an attacker could claim it.
- **Check Wrapper Integrity**: Calculate the SHA-256 hash of your `mvnw` or `gradlew` files and the associated wrapper JAR (`.mvn/wrapper/maven-wrapper.jar`). Compare these against the hashes of official, known-good versions published by Maven or Gradle. Any discrepancy is a major red flag.

### Tools/Techniques
- **[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)**: While primarily for known CVEs, it helps inventory all your dependencies, which is the first step in understanding what you're using.
- **[JFrog Artifactory](https://jfrog.com/artifactory/) / [Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository)**: Both have features to create "virtual" repositories or "repository groups" that proxy multiple repos. Review their configuration to see if you are correctly prioritizing internal packages.
- **Manual Checksum**: Use `shasum -a 256 .mvn/wrapper/maven-wrapper.jar` and compare the output to the official checksums published with each Maven release.

### Metrics/Signal
- **Metric**: Percentage of projects whose build configurations exclusively resolve internal packages from a private repository.
- **Signal**: A build log shows a dependency that has always been internal (`com.fincore.*`) is suddenly being downloaded from Maven Central.

{% endblock %}
{% block type='battlecard' text='Fortify' %}

### Explanation
Fortification is about actively strengthening your defenses. Based on what you found during the evaluation, you now implement changes to your tools, processes, and code to block the attack. This is about making your build supply chain resilient to tampering and confusion.

### Insight
The best defense is to be explicit and deterministic. Your build should never have to "guess" where a package should come from. You should tell it exactly where to find internal packages and where to find public ones, with no overlap or ambiguity.

### Practical
- **Isolate Dependency Resolution**:
- **In Maven**: Configure your repository manager (Artifactory/Nexus) to serve all dependencies from a single "group" URL. In that group, configure a routing rule that states "all packages starting with `com.fincore.*` *must* come from our private `fincore-releases` repo." This prevents Maven from ever looking for them on Maven Central.
- **In Gradle**: Use `exclusiveContent` in your `settings.gradle` file. This lets you explicitly declare which repository should be used for specific dependency groups.
- **Lock Your Dependencies**: Use a dependency locking mechanism. This creates a file that records the exact versions and hashes of all transitive dependencies. Any deviation in a future build (like a malicious package with a higher version) will fail the build.
- Maven: Use the `maven-enforcer-plugin` with its `requireUpperBoundDeps` and `dependencyConvergence` rules. For stricter locking, consider third-party plugins.
- Gradle: Has built-in [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html) functionality.
- **Verify Wrapper Integrity**: Don't just trust the `mvnw` or `gradlew` scripts in a project. Create a centrally-managed, known-good version of these scripts and their associated JARs. Use a script in your CI/CD pipeline to verify that the project's wrapper files match the blessed versions' checksums before executing them.

### Tools/Techniques
- **[Gradle Exclusive Content](https://docs.gradle.org/current/userguide/declaring_repositories.html#sec:declaring_content_for_repository)**: The modern, preferred way to prevent dependency confusion in Gradle.
- **[Maven Enforcer Plugin](https://maven.apache.org/enforcer/maven-enforcer-plugin/)**: A powerful tool to enforce rules like version convergence, banning certain dependencies, and ensuring a reproducible build environment.
- **[Repository Manager Configuration]**: Both Nexus and Artifactory support routing rules or repository inclusion/exclusion patterns. This is your most powerful server-side defense.

### Metrics/Signal
- **Metric**: 100% of active projects have dependency locking enabled.
- **Signal**: A CI build fails due to a dependency lock file mismatch or a wrapper integrity check failure. This is a sign the defense is working as intended.

{% endblock %}
{% block type='battlecard' text='Limit' %}

### Explanation
Assume the attacker has succeeded—the malicious package is running. The "Limit" stage is about damage control. How can you structure your systems to ensure that a breach in one part of your development lifecycle doesn't lead to a total compromise? This is about containing the "blast radius."

### Insight
A build agent in your CI/CD pipeline should be treated with the same security scrutiny as a production server. It is a prime target because it often has access to a wide range of secrets: artifact repository credentials, cloud provider keys, and SSH keys for deployment.

### Practical
- **Run Builds in Ephemeral Environments**: Each CI/CD job should run in a fresh, clean container that is destroyed after the job completes. This prevents an attacker from establishing persistence on the build agent itself.
- **Embrace Short-Lived, Scoped Credentials**: Do not use static, long-lived `AWS_ACCESS_KEY_ID`s in your CI environment. Instead, use mechanisms that provide temporary, tightly-scoped credentials that are only valid for the duration of the build.
- **Restrict Network Egress**: Your build agents almost never need to make arbitrary outbound connections to the internet. Configure firewall rules (e.g., AWS Security Groups, Kubernetes Network Policies) to only allow traffic to specific, required endpoints like your artifact repository, your source control server, and required cloud APIs. The attacker's attempt to exfiltrate data to `evil-server.com` would be blocked at the network level.

### Tools/Techniques
- **[Docker](https://www.docker.com/) / [Kubernetes](https://kubernetes.io/)**: Use these to create isolated, ephemeral environments for each build job.
- **[HashiCorp Vault](https://www.vaultproject.io/)**: A tool for managing secrets and providing dynamic, short-lived credentials to applications and CI/CD pipelines.
- **[AWS IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)**: If you run CI on EKS, this is the standard way to provide temporary AWS credentials to build pods without storing static keys.
- **[Cilium](https://cilium.io/)**: A CNI for Kubernetes that can enforce powerful L3/L4 and even L7 network policies to control egress traffic.

### Metrics/Signal
- **Metric**: Percentage of CI/CD pipelines that run without static, long-lived credentials.
- **Signal**: A network firewall log shows a build agent attempting to connect to an unauthorized external IP address and being blocked.

{% endblock %}
{% block type='battlecard' text='Expose' %}

### Explanation
How do you know an attack is happening? The "Expose" stage is about building the visibility and alerting you need to detect suspicious activity. Without monitoring and logging, the attacker could be in your system for months without you knowing. This is about turning on the lights.

### Insight
Your build logs are a rich source of security data, but they are often ignored until a build fails. By actively parsing and monitoring these logs, you can spot the subtle signs of a supply chain attack in progress, such as a dependency being pulled from an unexpected location.

### Practical
- **Monitor Your Artifact Repository**: Log every dependency download request and, critically, which repository it was resolved from (e.g., `internal-releases` vs. `public-proxy`). Alert when a package matching an internal namespace (e.g., `com.fincore.*`) is downloaded from a public repository.
- **Analyze Build Agent Behavior**: Monitor network traffic from your build agents. Establish a baseline of normal behavior and alert on deviations. A build that normally only contacts GitHub and Artifactory suddenly making a DNS query to a Russian domain is a massive red flag.
- **Instrument Your Build Wrappers**: Add logging to your centralized, blessed versions of `mvnw`/`gradlew`. Log the exact command being executed and any child processes that are spawned. This can help detect if the wrapper itself has been poisoned to execute a hidden command.

### Tools/Techniques
- **[Repository Manager Logs](https://www.jfrog.com/confluence/display/JFROG/Log+Analytics)**: Both Artifactory and Nexus produce detailed access logs. Ingest these into a log analysis platform.
- **[SIEM Tools (e.g., Splunk, Elastic Stack)](https://www.elastic.co/what-is/siem)**: Centralize and analyze logs from your artifact repository, CI server, and network firewalls to correlate events and create high-fidelity alerts.
- **[Falco](https://falco.org/)**: An open-source container runtime security tool that can detect anomalous behavior within your build containers, such as unexpected network connections or file writes to sensitive locations.

### Metrics/Signal
- **Signal**: An alert fires because a dependency was resolved from an unexpected source repository.
- **Signal**: A build agent makes an outbound network connection to an IP address not on the established allow-list.
- **Metric**: Time-to-detect for a simulated attack (e.g., from an exercise). How long did it take from the malicious download to an alert being raised?

{% endblock %}
{% block type='battlecard' text='eXercise' %}

### Explanation
This is where you practice. Security is not just about tools; it's about people and processes. By running realistic drills, you build "muscle memory" for your development team. The goal is to make responding to a potential incident a practiced, calm, and effective process, rather than a frantic, chaotic scramble.

### Insight
A security policy document that nobody has ever read or practiced is useless in a real incident. A live fire drill, even a simple one, is more valuable than a hundred pages of documentation because it reveals the real-world gaps in your tools, communication, and understanding.

### Practical
- **Run a Controlled Dependency Confusion Drill**:
1.  Create a harmless "malicious" package (e.g., one that just prints "EXERCISE: Package compromised!" to the build log).
2.  Give it the name of one of your real internal libraries, but with a high version number (`99.9.9-EXERCISE`).
3.  Publish it to a *controlled, internal, non-default* public-style repository that you temporarily add to a single project's build file.
4.  Run the build. Does it fail because of a locking mechanism? Do your monitoring tools generate an alert? Does the developer notice the strange log message?
- **Tabletop Exercise**: Gather the development team and security stakeholders. Walk through the scenario verbally: "We just received an alert that `com.fincore.metrics-client` version 99.9.9 was downloaded from Maven Central. What are our immediate next steps? Who is responsible for what? How do we determine the blast radius?"
- **Education**: Run a lunch-and-learn session demonstrating how easy it is to execute a dependency confusion attack. Show developers the `exclusiveContent` or repository routing rules and explain *why* they are critical.

### Tools/Techniques
- **[Internal Wiki (e.g., Confluence)](https://www.atlassian.com/software/confluence)**: Document your incident response plan. Who to contact, how to rotate secrets, how to audit builds.
- **[Red Team / Blue Team Drills]**: Formalize the exercise by having one team (red) try to execute the attack while another (blue) tries to detect and stop it using the available tools and logs.
- **[CI/CD Pipeline as a Lab]**: Use your CI/CD system to automate parts of the drill, measuring the time from "compromise" to automated alert generation.

### Metrics/Signal
- **Metric**: Time-to-detection and Time-to-remediation during a drill. How long did it take the team to notice the issue and "fix" it (e.g., by correcting the build file and purging the malicious package)?
- **Metric**: Percentage of developers who have participated in a security exercise or training session in the last 6 months.
- **Signal**: After an exercise, new action items are created to improve tooling or processes, showing the team is learning and adapting.
{% endblock %}