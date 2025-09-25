---
 permalink: /battlecards/java3 
battlecard:
 title: Java and Maven/Gradle Dependency Risks
 category: Package Ecosystem
 scenario: Java + Maven/Gradle
 focus: 
   - dependency confusion 
   - malicious plugins 
   - poisoned mvnw/gradlew 
---

An attacker group, "ShadowBuild", targets a fintech company to steal cloud credentials from its CI/CD environment. Their plan has three parallel tracks:

1.  **Dependency Confusion:** They discover the company uses an internal Maven repository for a private package named `com.fincore.auth-client`. They publish a malicious package with the same name to a public repository like Maven Central. The malicious version contains code to scan and exfiltrate environment variables. They bet that a misconfigured developer machine or CI runner will resolve this package from the public repository instead of the internal one.
2.  **Malicious Plugin:** The malicious `com.fincore.auth-client` also declares a dependency on a seemingly harmless but compromised Maven plugin, `build-stats-maven-plugin`. This plugin is designed to execute during a standard build phase (e.g., `package`) and will attempt to read the developer's `~/.m2/settings.xml` or `~/.aws/credentials` files and upload them to an attacker-controlled server.
3.  **Poisoned Wrapper:** For developers who have locked-down dependency resolution, ShadowBuild forks a popular open-source tool the company's developers are known to use. They subtly modify the `mvnw` (Maven Wrapper) script, adding a few lines of obfuscated shell code. This code downloads and executes a remote script when a developer runs a command like `./mvnw clean install`, compromising their local machine.

The goal is to compromise either a CI/CD pipeline or a developer's machine to gain access to sensitive credentials, API keys, and other secrets.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. For this scenario, they aren't trying to breach your network directly. Instead, they are studying your company's public footprint to find the names of internal software packages, understand your technology stack, and identify popular tools your developers use. They will scan public code repositories (like GitHub), read developer blogs, analyze job postings ("Experience with our internal 'Fincore' libraries is a plus!"), and look for any leaked `pom.xml` or `build.gradle` files. These files are treasure troves, revealing internal `groupId`s and `artifactId`s that are perfect targets for a dependency confusion attack.

### Insight
Your internal package names are not truly secret. Developers often, and accidentally, expose this information in public forums, personal GitHub projects, or résumés. Attackers know this and use automated tools to scrape this "data exhaust" to build a target list. The more they know about your internal libraries and tools, the more convincing their malicious packages will be.

### Practical
*   **Ego-Surf Your Code:** Periodically search GitHub, GitLab, and other public code sites for your company's internal package names, `groupId`s (e.g., `com.mycompany.*`), and proprietary library names.
*   **Review Your Digital Footprint:** Check what your company's technical job postings and developer blogs reveal about your internal tooling and architecture.
*   **Educate Your Team:** Remind developers not to share snippets of `pom.xml` or `build.gradle` files containing internal repository URLs or package names in public places like Stack Overflow.

### Tools/Techniques
*   **GitHub Dorks:** Use advanced search queries on GitHub to find sensitive information (e.g., `org:your-company-name "com.yourcompany.internal"`).
*   **Public Code Search:** Use tools like [Sourcegraph](https://sourcegraph.com/search) to search across a vast index of public code for mentions of your internal libraries.
*   **TruffleHog:** While known for secret scanning, [TruffleHog](https://github.com/trufflesecurity/trufflehog) can be used to scan public repositories for specific patterns, including your internal package names.

### Metrics/Signal
*   **Signal:** Discovery of an internal `groupId` or `artifactId` in a public repository or forum.
*   **Metric:** Number of internal project names found publicly per quarter. The goal is to drive this number down.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking in the mirror. As a developer, you need to assess how your own environment would react to the attacker's plan. Can you resolve and build your project on a network outside the corporate VPN? If so, where are your dependencies coming from? You should inspect your `pom.xml`, `build.gradle`, and global `settings.xml` files to understand your repository configuration. Do you explicitly define which packages come from which repository, or do you have a "grab bag" of internal and public repositories that Maven/Gradle checks in a potentially ambiguous order? Do you checksum your `mvnw`/`gradlew` wrapper scripts to ensure they haven't been tampered with?

### Insight
The default behavior of build tools is often "convenient but insecure." Maven and Gradle will happily check multiple repositories for a dependency, and the first one to respond with a valid package wins. This race condition is the core of the dependency confusion attack. An attacker just needs your build environment to check a public repository before your internal one.

### Practical
*   **Test Your Build:** In a safe, containerized environment, try building your project from a public network with no VPN access. Observe the logs to see where it attempts to download dependencies from. Does it fail safely, or does it try to hit public repos for internal packages?
*   **Audit Your Repositories:** Manually review your project's and your global build configurations. Is the order of repositories explicit? Are you using a repository manager that isolates internal and external dependencies?
*   **Verify Wrapper Scripts:** Calculate the SHA256 checksum of the `mvnw`/`gradlew` scripts in your project and compare it against a known-good version from a fresh project generated by a trusted source like the [Spring Initializr](https://start.spring.io/).

### Tools/Techniques
*   **Repository Manager:** Review the configuration of your repository manager (e.g., [Nexus Repository](https://www.sonatype.com/products/nexus-repository) or [JFrog Artifactory](https://jfrog.com/artifactory/)). Check if it's configured to prevent "proxying" requests for your internal namespaces out to the internet.
*   **Build Scans:** Use [Gradle Build Scans](https://scans.gradle.com/) to visualize dependency resolution paths and identify which repositories are being used for which dependencies. Maven has similar plugins.
*   **Checksum Verification:** Use command-line tools like `sha256sum mvnw` to check wrapper integrity.

### Metrics/Signal
*   **Signal:** A build log showing an internal package being searched for in a public repository (e.g., `repo.maven.apache.org`).
*   **Metric:** Number of projects that do not have a repository manager configured or have ambiguous repository ordering.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about proactive hardening. The goal is to make the attacker's techniques ineffective by design. This means configuring your build systems to be explicit and strict. Instead of relying on developers' local setups, you enforce security controls centrally. All dependency requests should go through a single, trusted repository manager that acts as a gatekeeper. This manager serves your private packages and safely proxies approved public packages, but critically, it should be configured to never request your private namespaces from a public source. You should also treat build scripts like `mvnw` as code: commit them, vet them, and own them.

### Insight
Your build process is part of your production system and should be treated with the same rigor. Trust should never be implicit. Every dependency, plugin, and build script is a potential vector and must be sourced from a controlled, verified location.

### Practical
*   **Use a Repository Manager:** Mandate that all builds (local and CI) resolve dependencies through a repository manager like Nexus or Artifactory. Configure it to host your internal packages and proxy public ones.
*   **Namespace Protection:** In your repository manager, configure "routing rules" or "repository targets" to prevent requests for your internal `groupId`s (e.g., `com.fincore.*`) from ever being sent to public repositories like Maven Central.
*   **Lock Your Dependencies:** Use mechanisms to "lock" the resolved versions of your dependencies. This ensures that every build uses the exact same set of approved artifacts. Changes to the lockfile must be reviewed in a pull request.
*   **Vet and Commit Wrappers:** Generate `mvnw`/`gradlew` wrappers from a trusted source, review them for any suspicious code, and commit them to your repository. Reject any pull requests that attempt to modify them without clear justification.

### Tools/Techniques
*   **Repository Managers:** [Nexus Repository](https://www.sonatype.com/products/nexus-repository) and [JFrog Artifactory](https://jfrog.com/artifactory/) are industry standards for this.
*   **Maven Enforcer Plugin:** Use the [Maven Enforcer Plugin](https://maven.apache.org/enforcer/maven-enforcer-plugin/) with its `requirePluginVersions` and `bannedRepositories` rules to enforce strict controls on plugins and repository sources.
*   **Gradle Dependency Locking:** Use Gradle's built-in [dependency locking mechanism](https://docs.gradle.org/current/userguide/dependency_locking.html) to create and maintain a lockfile.
*   **Dependency Checkers:** Use tools like [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) to scan for known vulnerabilities, but remember this doesn't protect against novel zero-day malicious packages.

### Metrics/Signal
*   **Metric:** Percentage of projects building exclusively through the mandated repository manager.
*   **Metric:** Percentage of repositories with dependency lockfiles enabled and up-to-date.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the worst: a malicious package was downloaded and its code is executing within your CI pipeline. Limiting the blast radius is about ensuring that this compromised build environment is a dead end for the attacker. The build agent should operate under the principle of least privilege. It should have no standing credentials or broad network access. Secrets (like API keys or deployment credentials) should be fetched just-in-time from a secure vault and be short-lived. The build should run in an ephemeral, isolated environment (like a container) that is destroyed after the job, and its network access should be restricted to only the necessary endpoints (e.g., your code repository, your artifact repository, and nothing else).

### Insight
Your CI/CD environment is one of the most valuable targets for an attacker. It often contains the "keys to the kingdom." By treating every build as potentially hostile and isolating it, you turn a catastrophic breach into a contained, low-impact security event.

### Practical
*   **Ephemeral Build Agents:** Run every CI job in a fresh container that is destroyed immediately after the job completes. This prevents persistence.
*   **Just-in-Time Secrets:** Do not store secrets in environment variables. Integrate your CI system with a secrets manager to fetch credentials that are valid only for the duration of the build.
*   **Network Egress Control:** Configure firewalls or network policies for your build agents. By default, deny all outbound network traffic. Only allowlist the specific IP addresses of your internal repository manager and code hosting service. The malicious code's attempt to "phone home" will be blocked.

### Tools/Techniques
*   **Secrets Management:** Integrate CI with tools like [HashiCorp Vault](https://www.vaultproject.io/) or [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/).
*   **Containerized Builds:** Use [Docker](https://www.docker.com/) or [Kubernetes](https://kubernetes.io/) to run your CI jobs in isolated, disposable environments.
*   **Network Policies:** Use [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) or cloud-specific security groups to lock down outbound traffic from your build agents.
*   **Credential-less Authentication:** Use OIDC integration where possible, for example, with [GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services), to allow your CI jobs to authenticate with cloud providers without long-lived keys.

### Metrics/Signal
*   **Signal:** A firewall log showing a blocked outbound connection attempt from a CI build agent to an unknown IP address.
*   **Metric:** Time-to-live (TTL) for secrets used in the CI pipeline. Shorter is better.
*   **Metric:** Percentage of CI jobs running with restrictive network egress policies.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Exposure is about creating a "nervous system" for your software supply chain. How do you detect an attack in progress? You need to actively monitor the key control points. This means logging all dependency resolution activity in your repository manager and shipping those logs to a security information and event management (SIEM) system for analysis. An alert should fire if a request for an internal namespace suddenly gets resolved from a public repository. You should also monitor public package repositories for any new packages being published that use your company's name or internal namespaces. Finally, network traffic from build agents should be monitored for any suspicious outbound connections.

### Insight
You cannot defend against what you cannot see. Your build and dependency infrastructure generates a huge amount of valuable security data. Without monitoring and alerting, this data is just noise. By treating build events as critical security signals, you can move from reactive incident response to proactive threat detection.

### Practical
*   **Log Everything:** Configure your repository manager to create detailed audit logs for every package request, including the source IP, user agent, and the repository it was resolved from.
*   **Centralize and Analyze Logs:** Send logs from your repository manager, CI servers, and network firewalls to a central logging platform (like Splunk, Datadog, or an ELK stack).
*   **Create Targeted Alerts:** Build specific alerts for high-fidelity indicators of an attack:
*   A request for an internal `groupId` being proxied to a public repository.
*   An unexpected outbound network call from a build agent to a non-allowlisted IP.
*   A developer's machine attempting to resolve dependencies from a strange repository URL.
*   **Monitor Public Repositories:** Use services that scan public repositories and alert you if a package is published that appears to be squatting on your namespace.

### Tools/Techniques
*   **Repository Firewall/Auditing:** Use features like [Sonatype Nexus Firewall](https://www.sonatype.com/products/nexus-firewall) or the audit capabilities in JFrog Artifactory.
*   **SIEM/Log Analysis:** Tools like [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or [Elastic Stack](https://www.elastic.co/elastic-stack) are essential for this.
*   **Public Package Monitoring:** Services like [Socket.dev](https://socket.dev/) or [Snyk](https://snyk.io/) can monitor for brand-impersonating or malicious packages.

### Metrics/Signal
*   **Signal:** An alert firing for "Internal Namespace Requested from Public Repository."
*   **Metric:** Mean Time To Detect (MTTD) for a malicious package download in a test scenario.
*   **Signal:** A successful build of a project from an external network that should have failed.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice for game day. A security exercise involves simulating the attack in a controlled environment to test whether your `Fortify`, `Limit`, and `Expose` controls actually work. You would intentionally create a harmless "malicious" package (e.g., one that just prints "I am a malicious package!" to the build log) and publish it to a test public repository under one of your internal names. Then, you'd configure a test project to be vulnerable and run it through your CI system. Did it pull the bad package? Did your alerts fire? Was the build's network access blocked? This process builds muscle memory for your team and validates your tooling.

### Insight
Security policies and tools are just theory until they are tested against a realistic scenario. Running exercises reveals the gaps between what you *think* your security posture is and what it *actually* is. It's better to find those gaps yourself in a drill than to have an attacker find them for you.

### Practical
*   **Tabletop Exercise:** Gather the development and security teams. Walk through the attack scenario on a whiteboard. Ask "what would we do?" and "what would we see?" at each step. This identifies procedural gaps.
*   **Live Fire Exercise (Staging):**
1.  Create a harmless package `com.fincore.test-harness` and publish it to a public test repository.
2.  Create a new branch in a non-critical application. Modify its `pom.xml` to be vulnerable (e.g., add the test repository).
3.  Push the branch and let the CI pipeline run.
4.  Observe: Did the `Fortify` controls (repository manager) block it? Did the `Expose` controls (monitoring) generate an alert? Did the `Limit` controls (network policy) block the "phone home" call?
*   **Review and Improve:** After the exercise, hold a retrospective. What worked? What didn't? Update your tools, processes, and documentation based on the findings. Educate the wider team on the results.

### Tools/Techniques
*   **Private Test Repositories:** Use a separate instance of Nexus/Artifactory or a simple file-based repository to act as your "attacker's" public repo.
*   **"Benign" Malicious Code:** Your test package can be as simple as a Maven plugin that executes `System.out.println` or tries to `curl` a known internal endpoint.
*   **Chaos Engineering Tools:** While not a direct fit, principles from chaos engineering (intentionally injecting failure) are relevant for testing the resilience of your security controls.

### Metrics/Signal
*   **Metric:** Time to detection and time to remediation during the exercise.
*   **Metric:** Number of procedural gaps identified during the tabletop exercise.
*   **Signal:** Successful completion of the exercise with all defensive controls firing as expected.
{% endblock %}