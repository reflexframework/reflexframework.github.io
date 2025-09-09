---
 permalink: /battlecards/java4 
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
An attacker targets a company that uses a private JFrog Artifactory server for its internal Java libraries. Their goal is to steal cloud credentials from the CI/CD environment.

The attacker discovers the name of an internal library, `com.fintech.billing-connector`, by scraping a developer's public GitHub profile where an old project's `pom.xml` was accidentally committed. They notice the company doesn't own the `fintech.com` domain.

The attacker registers `fintech.com`, creates a corresponding `com.fintech` group on Maven Central, and uploads a malicious version of `billing-connector` with a higher version number (e.g., `3.0.0-RELEASE`) than the company's internal version (`2.5.0-RELEASE`). This malicious JAR contains code that, upon execution during the build's test phase, reads all environment variables and sends them to the attacker's server.

Because the company's build environment is configured to check public repositories first, or in a non-deterministic order, the next time a developer builds the main application, Maven resolves the dependency to the higher-versioned, malicious package from Maven Central. The malicious code executes within the CI runner, exfiltrating the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, giving the attacker access to the company's cloud infrastructure.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They are looking for the names of your private packages, your technology stack, and even your developers' names. For a Java ecosystem, they hunt for any `pom.xml` or `build.gradle` file that lists internal dependencies. These are often found in public code repositories (GitHub, GitLab), developer forum posts (Stack Overflow), public slide decks, or even job descriptions that mention internal tooling. The goal is to find a package name that exists on your private repository but is not registered on a public one like Maven Central.

### Insight
Your organization's digital footprint is the attacker's reconnaissance playground. What seems like harmless information sharing—like a developer asking a question on Stack Overflow with a snippet of a build file—can provide the exact puzzle piece an attacker needs. They aren't guessing randomly; they are systematically piecing together a map of your internal software supply chain from your public data.

### Practical
As a developer, periodically search for your company's proprietary package names or group IDs on public sites like GitHub. Check your own public repositories for any accidentally committed build files, configuration, or `.jar` files. Encourage your team to sanitize any code snippets they share publicly, removing internal package names, repository URLs, or other sensitive identifiers.

### Tools/Techniques
*   **GitHub Code Search:** Use advanced search queries to find mentions of your internal group IDs or artifact names (e.g., `org:your-company-name com.mycompany.internal`).
*   **Google Dorking:** Use search operators to find exposed files, e.g., `site:github.com "com.yourcompany.project" filetype:xml`.
*   **Public Breach Data:** Attackers may search through public data breaches to find credentials or information related to your internal systems.

### Metrics/Signal
*   An increase in `404 Not Found` errors in your artifact repository logs for packages that look similar to your internal naming scheme. This can indicate that an attacker is probing for valid names.
*   Discovering one of your internal package names in a public repository during a routine search.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you assess how vulnerable your own environment is to the attack scenario. For a Java developer, this means auditing your build configurations. Check the order of repositories in your `pom.xml`, `build.gradle`, and especially your global `~/.m2/settings.xml` or `~/.gradle/init.gradle` files. Does your build tool check public repositories (like Maven Central) *before* your internal one (like Artifactory/Nexus)? If so, you are vulnerable to dependency confusion. Also, do you verify the integrity of your build wrapper scripts (`mvnw`, `gradlew`)? An attacker could commit a poisoned version that compromises the build on any machine that runs it.

### Insight
Default configurations are often insecure. Both Maven and Gradle are designed for convenience and will happily search all configured repositories to find a dependency. The attacker is exploiting this "first one wins" or "highest version wins" behavior. Your build process might seem to be working fine, but it could be a ticking time bomb if the resolution order is not strictly controlled.

### Practical
1.  **Check Repository Order:** Open your project's `pom.xml` or `build.gradle` and your global settings. If you see a public repository listed before your internal one, that's a major red flag.
2.  **Test a Package Name:** Take one of your internal library names (e.g., `com.mycorp.auth-lib`) and check if the corresponding group ID and artifact are available for registration on Maven Central. If they are, you have a potential vulnerability.
3.  **Audit Wrapper Scripts:** Compare the `mvnw`, `mvnw.cmd`, and `gradlew` scripts in your repository with the official, known-good versions generated by Maven or Gradle. Has anyone modified them?

### Tools/Techniques
*   **Manual Inspection:** The most direct method is to read your `pom.xml`, `build.gradle`, and global configuration files.
*   **Dependency-Check:** While primarily for finding known vulnerabilities (CVEs), the [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) tool can help inventory all your dependencies, making a manual audit easier.
*   **Wrapper Validation:** Use a validation action like the [Gradle Wrapper Validation Action](https://github.com/gradle/wrapper-validation-action) in your CI pipeline to automatically check the checksum of the wrapper scripts against a list of known-good hashes.

### Metrics/Signal
*   Finding a build configuration that prioritizes a public repository over an internal one.
*   Identifying an internal package name that is not "claimed" or reserved in public repositories.
*   A failed CI build due to the wrapper validation check.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification involves hardening your build process to prevent these attacks. The core principle is to be explicit and remove ambiguity from your dependency resolution. You should configure your build tools and repository manager to ensure that internal packages are *only* ever sourced from your internal repository, and never from a public one. This breaks the dependency confusion attack chain. Additionally, you should lock down build scripts and plugins to prevent tampering.

### Insight
The best defense is to eliminate the possibility of a "name collision." Your build system should never have to ask, "Should I get this package from my private repo or the public one?" By creating strict rules based on package names (e.g., anything starting with `com.mycompany.internal.*` MUST come from our Artifactory), you remove the ambiguity that attackers exploit.

### Practical
*   **Use a Repository Manager:** Centralize all dependency management through a proxy like [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus](https://www.sonatype.com/products/repository-oss). Do not let individual developers' machines or CI runners reach out directly to public repositories.
*   **Enforce Scopes/Routing Rules:** In your repository manager, configure routing rules so that requests for your internal group IDs (e.g., `com.mycompany.*`) are *only* ever resolved against your private repositories. Block these requests from ever being proxied to public sources like Maven Central.
*   **Use Explicit Repository Content:** In Gradle, use the `exclusiveContent` feature to strictly define which group IDs can be found in which repository. This is a powerful, built-in defense.
*   **Verify Wrapper Integrity:** Add a step in your CI pipeline to verify the checksums of `mvnw` and `gradlew` files against known-good values before executing them.
*   **Pin Plugin Versions:** In your `pom.xml` or `build.gradle`, explicitly define the version for every Maven/Gradle plugin you use. Avoid version ranges or using `LATEST`, as this could allow an attacker to publish a malicious new version of a legitimate plugin.

### Tools/Techniques
*   **Artifactory/Nexus:** Use the "virtual repository" and "routing rule" features to control dependency resolution flow.
*   **Gradle `exclusiveContent`:** [See documentation](https://docs.gradle.org/current/userguide/declaring_repositories.html#sec:declaring_content_for_repository). This is a highly effective, native control.
*   **Maven:** While less flexible than Gradle, you can carefully configure repository mirrors and profiles in `settings.xml` to control access. The best approach is to rely on routing rules in your repository manager.
*   **Pre-commit Hooks:** Use a `pre-commit` hook (with a tool like [pre-commit](https://pre-commit.com/)) to run a script that validates wrapper checksums before a commit is even allowed.

### Metrics/Signal
*   CI build logs that clearly show internal dependencies are being resolved from the internal repository and public ones from the public proxy.
*   A CI build fails because it was configured to look for an internal package in a public repository, and the routing rules in your artifact manager blocked it. This is a successful defense.
*   All plugins in your build files have hardcoded version numbers.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Limitation assumes the attacker has already succeeded and malicious code is running in your build environment. The goal now is to contain the "blast radius." What can the malicious code actually do? A build running in a CI/CD pipeline should operate under the principle of least privilege. It should have minimal network access, no standing credentials to production systems, and should run in an isolated, ephemeral environment that is destroyed after the job completes.

### Insight
Treat your CI/CD environment as a zero-trust environment. Do not assume that the code running there is safe. If your build agent has a permanent, highly privileged IAM role or a Kubernetes service account that can deploy to production, then a single compromised dependency gives the attacker the keys to the kingdom. By limiting the build's permissions, you turn a potential catastrophe into a contained incident.

### Practical
*   **Ephemeral Build Agents:** Configure your CI system (e.g., Jenkins, GitHub Actions, GitLab CI) to use fresh, containerized agents for every build. This prevents malware from persisting between builds.
*   **Scoped, Short-Lived Credentials:** Do not store secrets like `AWS_ACCESS_KEY_ID` as long-lived environment variables in your CI settings. Instead, use a secrets manager to inject temporary, tightly-scoped credentials that expire shortly after the build is complete.
*   **Network Egress Filtering:** By default, your build agent should not be able to make network connections to the public internet, except for a specific allow-list (e.g., your artifact repository, your container registry). This would block the malicious code from sending stolen credentials to the attacker's server.

### Tools/Techniques
*   **Secrets Management:** [HashiCorp Vault](https://www.vaultproject.io/), [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), or [GCP Secret Manager](https://cloud.google.com/secret-manager) can integrate with CI systems to provide temporary credentials.
*   **Containerized Builds:** Run builds inside Docker containers. For stronger isolation, consider sandboxing technologies like [gVisor](https://gvisor.dev/).
*   **Network Policies:** Use [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/), AWS Security Groups, or firewall rules on your CI runners to restrict outgoing network traffic.

### Metrics/Signal
*   An alert from your firewall or network policy tool that a build agent attempted to connect to an unauthorized IP address on the internet.
*   Audit logs from your secrets manager showing that each build job requested and used a unique, short-lived credential.
*   Security scan reports showing that no long-lived secrets are stored in your CI environment variables.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about detection and visibility. How do you know an attack is happening? You need to be monitoring the right signals. This includes logs from your artifact repository, your CI/CD system, and network traffic from your build agents. An attacker's actions will create anomalies; you need the right logging and alerting to spot them. For instance, a sudden download of a new, major version of a stable internal library from a public source is a massive red flag.

### Insight
Attackers are noisy, but you have to be listening. The evidence of a supply chain attack is almost always present in the logs. The key is to have a baseline of what "normal" looks like. If you know that `com.fintech.billing-connector` is always version `2.x` and always comes from your internal Artifactory, then an alert on "version `3.0.0` from Maven Central" becomes a high-fidelity signal of an active attack.

### Practical
*   **Monitor Artifact Logs:** Ingest logs from Artifactory/Nexus into a log analysis platform. Create alerts for suspicious events, such as:
*   An internal package (e.g., matching `com.mycompany.*`) being downloaded from a public repository proxy.
*   A massive spike in `404`s for packages, which could indicate probing.
*   **Monitor Build Logs:** Watch for unusual behavior during a build, such as unexpected network connections, file system access outside the project directory, or the spawning of strange processes (`curl`, `nc`).
*   **Monitor Network Traffic:** Analyze egress traffic from your build agents. An unexpected connection to an IP address in a strange country or a known bad domain like Pastebin is a strong indicator of compromise.

### Tools/Techniques
*   **Log Aggregation & Alerting:** [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or an [ELK Stack](https://www.elastic.co/what-is/elk-stack) for analyzing logs and creating alerts.
*   **Runtime Security Monitoring:** Tools like [Falco](https://falco.org/) can be deployed on CI nodes or within build containers to detect suspicious system calls in real-time (e.g., "Java process opened a network connection to a non-local IP").
*   **Dependency Monitoring Services:** Services like [Socket](https://socket.dev/) or [Snyk](https://snyk.io/) can proactively monitor dependencies for suspicious behavior, including dependency confusion attacks.

### Metrics/Signal
*   An alert firing because a package was resolved from an unexpected repository.
*   A runtime security alert from Falco that the `mvn` or `gradle` process is trying to read `/etc/passwd` or connect to an unknown IP.
*   A CI build takes significantly longer than usual or consumes an unusual amount of CPU or network resources.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about building muscle memory through practice. You don't want the first time you handle a dependency confusion attack to be during a real, high-pressure incident. By running controlled security exercises, you can test your defenses, identify weaknesses in your processes, and train your developers to spot and respond to threats.

### Insight
Security is not just about tools; it's about people and processes. A fire drill is not meant to see if the building burns down, but to ensure everyone knows the evacuation route. Similarly, a security exercise tests your team's response plan. Did the right people get alerted? Did they know which logs to check? How quickly could they identify and block the malicious package?

### Practical
*   **Run a Tabletop Exercise:** Gather the development and security teams and walk through the attack scenario. Ask questions like: "A build just failed with a strange network error. What's your first step? Who do you call? Where do you look for evidence?"
*   **Conduct a Benign Red Team Exercise:**
1.  Identify a safe, internal test package.
2.  Have your security team (or a trusted developer) register and publish a harmless, higher-versioned copy of it to a public repository like Maven Central. This package should only contain code that prints a message like `SECURITY EXERCISE: Dependency confusion successful`.
3.  Trigger a build of a test application that uses this dependency.
4.  Observe: Were your monitoring systems triggered? Did developers notice the message? How long did it take for the team to detect and remediate the issue?
*   **Review and Improve:** After the exercise, hold a post-mortem to discuss what went well and what didn't. Turn the findings into actionable tickets to improve tooling, alerting, and documentation.

### Tools/Techniques
*   **Internal Red Team:** Use your own security team to simulate the attacker.
*   **Dependency Confusion Testers:** Use open-source tools like [Dependency Combobulator](https://github.com/doyensec/dependency-combobulator) to automatically scan for potential dependency confusion vulnerabilities.
*   **Capture The Flag (CTF) Events:** Create an internal CTF where developers have to find and fix a dependency confusion vulnerability in a sample application.

### Metrics/Signal
*   **Time to Detection:** How long did it take from the moment the malicious package was introduced to when the first alert was triggered or a developer noticed the issue?
*   **Time to Remediation:** How long did it take to block the malicious dependency and restore the build to a known-good state?
*   A post-mortem document with at least one concrete action item assigned to a team to improve defenses.
{% endblock %}