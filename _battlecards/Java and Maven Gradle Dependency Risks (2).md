---
 permalink: /battlecards/java2
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
An attacker targets "ACME Corp," a company known to use Java. The attacker's goal is to inject malicious code into ACME's build process to steal credentials and establish a persistent foothold in their cloud environment.

The multi-pronged attack unfolds as follows:
1.  **Dependency Confusion:** Through public code searches, the attacker discovers ACME uses an internal dependency named `com.acme.corp:auth-helpers:1.2.0`. They publish a malicious package to Maven Central with the same name but a higher version, `com.acme.corp:auth-helpers:99.9.9`. They know that if ACME's build system is misconfigured, it will fetch their higher-versioned, malicious package from the public repository instead of the internal one.
2.  **Malicious Plugin:** The malicious `auth-helpers` JAR also contains a rogue Maven/Gradle plugin. When the build runs, this plugin activates, scanning the build environment for environment variables, system properties, and files like `~/.aws/credentials` or `~/.kube/config`.
3.  **Poisoned Wrapper:** As a parallel effort, the attacker finds a public-facing utility repository owned by an ACME developer. They submit a seemingly benign pull request to "update the Gradle wrapper." However, the PR subtly modifies the `gradle-wrapper.properties` file, changing the `distributionUrl` to point to the attacker's server. If this change is merged and used in an internal project, the developer's machine will download and execute a tampered Gradle distribution, compromising the build process at its root.

When a developer at ACME runs a build for a project that depends on `auth-helpers`, the dependency confusion attack succeeds. The malicious package is downloaded, and its embedded plugin executes, exfiltrating the CI server's cloud credentials to the attacker's endpoint.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's "casing the joint" phase. They are looking for weaknesses in your software supply chain by analyzing publicly available information. They aren't launching exploits yet; they're gathering the intelligence needed to craft a believable and effective attack. They want to understand what you build, how you build it, and who builds it.

### Insight
Attackers operate like corporate spies, piecing together a mosaic of your internal world from tiny, seemingly harmless public scraps of data. A single leaked `pom.xml` file on a developer's public GitHub repository can be the thread they pull to unravel your entire internal package namespace.

### Practical
-   Go to GitHub and search for your company's internal package names (e.g., `com.yourcompany.`).
-   Review your organization's public repositories. Are there any `pom.xml`, `build.gradle`, or `settings.gradle` files that have been committed by mistake?
-   Check the public repositories of your developers. Do they have forks of internal projects or personal projects that might expose internal configuration details?

### Tools/Techniques
*   **GitHub Code Search:** Use advanced search queries to find mentions of your internal package structures or repository URLs. Example: `org:YourCompany "com.acme.internal" filename:pom.xml`.
*   **Public Breach Data:** Search data from past breaches to see if any of your company's source code or developer credentials have been exposed.
*   **Decompilers:** Tools like [Jadx](https://github.com/skylot/jadx) or [Fernflower](https://github.com/fesh0r/fernflower) can be used on any of your publicly distributed JARs (e.g., an Android app) to reveal internal dependency names.

### Metrics/Signal
*   Number of public search results for internal-only package names or artifact IDs. A result greater than zero is a signal of information leakage.
*   Number of publicly exposed configuration files (`pom.xml`, `build.gradle`) belonging to your organization.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you turn the attacker's lens on yourself. You need to assess your own development and CI/CD environment to see if the weaknesses the attacker is looking for are present. The goal is to find the holes before they do. Are your builds configured to prefer public packages? Do you validate the integrity of your build tools?

### Insight
The most dangerous vulnerabilities are often not in your code, but in the *configuration* of the tools you use to build and deploy it. Default settings for build tools like Maven and Gradle are often optimized for convenience and functionality, not for a hostile security environment.

### Practical
-   Check your `pom.xml` or `build.gradle` files. In what order are repositories declared? If a public repository like Maven Central is listed before your internal repository (or if there's no specific ordering), you are vulnerable.
-   Look at a `mvnw` or `gradlew` script in your project. Can you trace the `distributionUrl` to a trusted, official source? Do you have any process to verify the checksum of the downloaded distribution?
-   Review your dependency resolution logs. Where are your dependencies *actually* coming from? Are you surprised to see any of them being pulled from public repositories?

### Tools/Techniques
*   **Build Scans:** [Gradle Enterprise](https://gradle.com/enterprise/) provides detailed build scans that show exactly where every dependency was resolved from.
*   **Maven Dependency Plugin:** Use the `mvn dependency:tree` or `mvn dependency:resolve` goals to inspect the dependency resolution path and the source repository for each artifact.
*   **Checksum Verification:** Use simple command-line tools like `sha256sum` to compare the checksum of your downloaded wrapper distribution against the official checksums published on the [Gradle Distribution page](https://gradle.org/releases/).

### Metrics/Signal
*   A "pass/fail" checklist for project configurations. Does the build script correctly isolate internal and external repositories?
*   Percentage of projects in your organization that have an explicit, secure repository declaration order.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This stage is about proactively hardening your systems to shut down the attack vectors identified in the evaluation phase. It's about changing configurations, adding new tools, and adopting stricter practices to make the attack impossible or at least significantly harder to execute.

### Insight
A robust defense is layered. You can't just fix one thing. You need to secure the dependency sources, validate the integrity of your tools, and lock down the build process itself. The goal is to create a "zero trust" build environment where nothing is trusted by default.

### Practical
-   **Isolate Namespaces:** Configure your repository manager (e.g., Artifactory, Nexus) to use a "virtual repository." This virtual repo should serve requests for your internal packages (`com.acme.corp.*`) *only* from your internal repository. All other requests are proxied to public repositories. This makes dependency confusion impossible.
-   **Use Content Trust/Filtering:** Use features like Gradle's `exclusiveContent` to explicitly declare which repository can serve which group of dependencies.
-   **Validate Your Wrappers:** Add a step to your CI pipeline that automatically verifies the checksum of the `gradlew.jar` and the Gradle distribution ZIP against a list of known-good hashes. Fail the build if a mismatch is found.
-   **Pin Dependencies:** Use a lockfile mechanism to ensure that your build always uses the exact same version of every transitive dependency, preventing an attacker from sneaking in a newer, malicious version.

### Tools/Techniques
*   **Repository Managers:** [JFrog Artifactory](https://jfrog.com/artifactory/) and [Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository) are essential for managing and proxying dependencies securely.
*   **Gradle `exclusiveContent`:** A feature for fine-grained repository and dependency matching. [See docs](https://docs.gradle.org/current/userguide/declaring_repositories.html#sec:repository-content-filtering).
*   **Gradle Wrapper Validation:** Use the [Gradle Wrapper Validation GitHub Action](https://github.com/gradle/wrapper-validation-action) or a similar script in your CI/CD pipeline.
*   **Dependency Locking:** Gradle has built-in [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html). For Maven, you can use the [Maven Enforcer Plugin](https://maven.apache.org/enforcer/maven-enforcer-plugin/) to enforce specific dependency versions.

### Metrics/Signal
*   100% of CI builds validate the integrity of the build wrapper.
*   Automated dependency scans show no packages being resolved from unexpected public repositories.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker succeeds and their malicious code executes during your build. The "Limit" stage is about damage control. The goal is to contain the blast radius, ensuring that a compromised build cannot lead to a wider system compromise. If the attacker gets in, you want to trap them in a very small, locked room with nothing valuable in it.

### Insight
Your CI/CD environment is one of the most sensitive parts of your infrastructure; it often holds the keys to production. Treating build agents as ephemeral, untrusted, and disposable resources is a critical mindset shift. A build agent should have the absolute minimum access required to do its job, and nothing more.

### Practical
-   **Ephemeral Build Agents:** Run every single build in a fresh, clean container (e.g., Docker) that is destroyed immediately after the build completes. Do not reuse build environments.
-   **Network Egress Filtering:** Configure strict firewall rules for your build agents. They should only be allowed to connect to a specific, allow-listed set of internal IPs/domains (e.g., your repository manager, your source control system). All other outbound traffic should be blocked by default.
-   **Least-Privilege Credentials:** If a build needs to access a cloud service, provide it with short-lived, single-purpose credentials that are scoped to the exact task it needs to perform (e.g., "permission to upload `app.jar` to S3 bucket X and nothing else").

### Tools/Techniques
*   **Containerized CI/CD:** Use CI systems that support running jobs in containers, such as [GitHub Actions](https://docs.github.com/en/actions) (with container jobs), [GitLab CI](https://docs.gitlab.com/ee/ci/), or Jenkins with Kubernetes/Docker plugins.
*   **Kubernetes Network Policies:** Use `NetworkPolicy` resources in Kubernetes to define strict ingress and egress rules for the pods that run your builds.
*   **Cloud IAM:** Leverage services like [AWS IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) or [Google Cloud Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) to issue fine-grained, temporary credentials to your build pods.

### Metrics/Signal
*   Firewall logs showing the number of blocked egress connection attempts from build agents. A non-zero number is a sign that your defense is working.
*   Security alerts from runtime container security tools like Falco when a build process attempts a suspicious action (e.g., writing to a sensitive file, opening a raw socket).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about making the invisible visible. How do you know an attack is happening? You need systems to detect, monitor, and alert on suspicious activity related to your build process. Without visibility, an attacker could be living in your build system for months without you ever knowing.

### Insight
Your build logs are more than just a tool for debugging failed compilations; they are a rich source of security telemetry. Every dependency downloaded, every plugin executed, and every network connection made is a potential clue. By centralizing and analyzing this data, you can spot the anomalies that signal an attack.

### Practical
-   **Centralize Logs:** Forward all logs from your CI/CD runners, repository manager, and source control system to a centralized logging platform (e.g., ELK Stack, Splunk).
-   **Monitor Network Traffic:** Capture and analyze network flow data (e.g., NetFlow, VPC Flow Logs) from your build agents. Look for connections to unusual IP addresses or countries.
-   **Analyze Dependency Graphs:** Periodically snapshot your project's complete dependency graph. Alert on any new dependencies, especially those from new or untrusted sources.

### Tools/Techniques
*   **Log Management:** [Elastic Stack (ELK)](https://www.elastic.co/elastic-stack), [Splunk](https://www.splunk.com/), or [Graylog](https://www.graylog.org/) for collecting and analyzing logs.
*   **Supply Chain Security Tools:** Tools like [Socket](https://socket.dev/), [Snyk](https://snyk.io/), or [Dependabot](https://github.com/dependabot) can monitor your dependencies and alert on suspicious characteristics (e.g., a package that was just published, has a name similar to an existing package, or contains install scripts).
*   **Runtime Threat Detection:** [Falco](https://falco.org/) can be used in your Kubernetes cluster to detect and alert on suspicious behavior inside your build containers in real-time.

### Metrics/Signal
*   An alert is triggered when a build process attempts to connect to an IP address not on the established allow-list.
*   A high-severity alert from a tool like Snyk indicating that a newly-added dependency is attempting to read environment variables or make network calls during installation.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about practicing for a bad day. You wouldn't expect a firefighter to be effective without running drills, and developers shouldn't be expected to respond to a security incident without practice. By simulating the attack scenario in a controlled way, you can test your defenses, identify weaknesses, and build "muscle memory" for the real thing.

### Insight
Security is as much about people and process as it is about tools. An exercise doesn't just test your firewall; it tests your communication, your incident response plan (or lack thereof), and your team's ability to react under pressure. It's better to find out your playbook is confusing during a drill than during a real attack.

### Practical
-   **Run a Red Team Exercise:** Task an internal or external security team to try and execute the attack scenario. Can they get a fake "malicious" dependency into your build? Can they get a poisoned wrapper committed?
-   **Conduct a Tabletop Exercise:** Gather the development and security teams in a room. Walk through the scenario step-by-step: "A developer reports a slow build. The logs show a dependency being downloaded from an unknown URL. What do we do *right now*? Who do we call? How do we stop the bleeding?"
-   **Capture the Flag (CTF) for Developers:** Create a mini-challenge where developers are given a vulnerable build environment and have to identify and fix the security flaws related to dependency management.

### Tools/Techniques
*   **Attack Simulation:** Use frameworks like [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) to get ideas for specific TTPs (Tactics, Techniques, and Procedures) to simulate, adapting them for a CI/CD environment.
*   **Internal Documentation:** Maintain a simple, clear incident response plan for a supply chain compromise in your team's wiki (e.g., Confluence, Notion). Who is the point of contact? What are the immediate steps?
*   **Security Training:** Use services like [Secure Code Warrior](https://www.securecodewarrior.com/) or run internal workshops to educate developers on these specific risks.

### Metrics/Signal
*   **Time to Detect (TTD):** During an exercise, how long did it take from the moment the "attack" was launched until your monitoring systems fired an alert?
*   **Time to Remediate (TTR):** How long did it take for the team to identify the root cause, contain the threat, and patch the vulnerability?
*   Percentage of developers who have participated in a security exercise or completed relevant training in the last 12 months.
{% endblock %}