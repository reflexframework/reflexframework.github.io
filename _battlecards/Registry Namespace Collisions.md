---
 permalink: /battlecards/registry-namespace-collisions
battlecard:
 title: Registry Namespace Collisions
 category: Package Ecosystem
 scenario: Internal Registry Namespace Collisions
 focus: 
   - private vs public overlap 
   - scoped namespace conflicts 
   - registry misrouting 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets your company by exploiting how your development tools handle internal and public software packages. They identify the name of a private, internal-only package your company uses, for example, `acme-corp-auth-client`. This package exists only in your company's private registry (like JFrog Artifactory or Sonatype Nexus).

The attacker then publishes a malicious package with the *exact same name* (`acme-corp-auth-client`) to a public registry like npmjs, PyPI, or Maven Central, but gives it a much higher version number (e.g., `99.99.9`).

Your build systems or a developer's local machine is configured to look for packages in both your internal registry and the public one. When the package manager (npm, pip, etc.) resolves dependencies for a project, it sees the `99.99.9` version on the public registry and, believing it's a legitimate and urgent update, downloads and installs it instead of your internal version.

The malicious package contains a `postinstall` script. As soon as it's installed, this script executes, stealing environment variables from your CI/CD pipeline (`AWS_ACCESS_KEY`, `DB_PASSWORD`) and sending them to the attacker's server, creating a backdoor into your build environment.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's first step is to discover the names of your private, internal packages. They aren't hacking your servers at this stage; they are simply gathering intelligence from publicly available information. It’s like a burglar looking at mail to figure out who lives in a house before breaking in. They search for these names in places where developers might have accidentally leaked them.

Common tactics include:
*   **Public Code Repositories:** Scanning GitHub, GitLab, or Bitbucket for public repositories belonging to current or former employees. They look for configuration files like `package.json`, `requirements.txt`, or `pom.xml` that were committed by mistake and list your internal dependencies.
*   **Leaked Infrastructure-as-Code:** Searching for exposed CI/CD configuration files (`.gitlab-ci.yml`, `Jenkinsfile`) or `Dockerfile`s that reference internal package names.
*   **Developer Discussions:** Scraping public forums like Stack Overflow or even social media where your developers might have posted code snippets for help, inadvertently including an internal package name.
*   **Job Postings:** Analyzing your company's job descriptions, which often mention proprietary internal tools and frameworks by name to attract candidates.

### Insight
This attack surface is not your application's code; it's your organization's information footprint. The vulnerability is often created by a simple mistake—a developer pushing a personal project to GitHub without scrubbing internal references first. Attackers automate this process, constantly scanning the internet for these small leaks.

### Practical
*   **Audit Your Public Footprint:** Periodically search for your company's name or known internal project codenames on public code hosting sites.
*   **Educate Developers:** Train engineers on the risk of posting code with internal dependencies online and the importance of sanitizing any public-facing examples or personal projects.
*   **Review Job Postings:** Work with HR to ensure job descriptions are generic about internal tooling (e.g., refer to "our proprietary CI platform" instead of "Project HermesBuilder").

### Tools/Techniques
*   [**gitleaks**](https://github.com/gitleaks/gitleaks): An open-source tool to scan Git repositories for hardcoded secrets, which can also be configured to find specific patterns like internal package names.
*   [**GitHub Code Search**](https://github.com/search): Manually perform advanced searches using your organization's name combined with file names like `package.json`.
*   [**TruffleHog**](https://github.com/trufflesecurity/trufflehog): Scans repositories for secrets, but its pattern-matching capabilities can be extended to find internal naming conventions.

### Metrics/Signal
*   **Signal:** Discovery of an internal package name, API key, or other sensitive identifier in a public location.
*   **Metric:** Number of publicly exposed internal dependency names found per quarter. The goal should be zero.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking at your own environment to see if it's susceptible to this kind of attack. The core vulnerability lies in your package manager's configuration. You need to determine how your tools would behave if presented with two versions of the same package—one internal, one public.

Ask yourself these questions:
1.  **Where do my tools look for packages?** Check the configuration files for your package managers (`.npmrc`, `pip.conf`, `settings.xml`). Do they list both an internal registry and a public one?
2.  **What is the order of priority?** If both are listed, which one is checked first? Is the behavior consistent across developer machines, CI/CD runners, and production environments?
3.  **How is version resolution handled?** Will the tool always prefer the package with the highest version number, regardless of which registry it comes from? This is the most dangerous configuration and the default for many tools.

### Insight
The riskiest setup is a "hybrid" or "pass-through" registry configuration where the package manager is allowed to freely query both sources. Developers often set this up for convenience, but it creates the exact ambiguity the attacker needs to exploit. The vulnerability isn't in your code, it's in the plumbing of your build process.

### Practical
*   **Inspect Configuration Files:** On your machine, run commands like `npm config list`, `pip config list`, and review the `registries` or `index-url` settings.
*   **Audit CI/CD Configuration:** Check the setup scripts in your CI/CD pipeline files (`.gitlab-ci.yml`, `Jenkinsfile`, GitHub Actions workflows). This is where registry settings are often dynamically configured and can differ from a developer's local setup.
*   **Run a Test:** Attempt to install one of your known internal packages from the public registry (e.g., `npm install acme-corp-auth-client --registry https://registry.npmjs.org`). If it fails with a "not found" error, that's good. If it succeeds, you have a serious problem.

### Tools/Techniques
*   [**confused**](https://github.com/visma-prodsec/confused): A tool from Visma to check if your Python (`requirements.txt`, `setup.py`), PHP (`composer.json`), or Node.js (`package.json`) projects use dependencies that could be vulnerable to dependency confusion.
*   **Manual Inspection:** Directly view configuration files: `~/.npmrc`, `~/.pip/pip.conf`, `~/.m2/settings.xml`.

### Metrics/Signal
*   **Signal:** A project's build configuration resolves dependencies from more than one registry for the same namespace or scope.
*   **Metric:** Percentage of projects/teams whose build configurations have been audited and confirmed to not be vulnerable to this resolution ambiguity.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your systems against this attack means making your package resolution logic explicit and unambiguous. You need to remove any possibility for the package manager to get "confused" about where to find a package. The goal is to create a clear boundary: "These packages are internal and ONLY come from our registry; everything else is public."

### Insight
The most robust defense is to claim your namespace. Just as you register a domain name to protect your brand on the web, you should register your organization or scope on public package registries to prevent anyone else from using it. This is a proactive, one-time action with a massive security payoff.

### Practical
1.  **Use and Reserve Scoped/Grouped Packages:** This is the most effective control.
*   **Node.js:** Name all internal packages under a single npm scope (e.g., `@acme-corp/auth-client`). [Register your organization on npmjs.com](https://www.npmjs.com/org/create) to claim your scope, even if you never publish anything to it.
*   **Java:** Use a consistent `groupId` for all internal artifacts (e.g., `com.acmecorp.auth`). [Register this namespace on Maven Central via Sonatype](https://central.sonatype.org/publish/requirements/coordinate/).
*   **Python:** There is no official namespacing, so a strong, unique prefix (e.g., `acme-corp-`) is the next best thing. You can also [register a placeholder package on PyPI](https://pypi.org/project/acme-corp-placeholder/) to claim the name.

2.  **Configure Explicit Routing:** Configure your package managers to route requests based on these namespaces.
*   In your `.npmrc` file, specify that your scope always resolves to your private registry:
`@acme-corp:registry=https://artifactory.acme-corp.com/api/npm/npm-local`
*   In a Maven `pom.xml` or `settings.xml`, configure your internal repository and ensure it's the only source for your `com.acmecorp` group.

3.  **Use a Repository Manager as a Proxy:** Set up a tool like Artifactory or Nexus to act as the single source of truth for all developers and builds. It will serve your private packages and proxy/cache public ones. This centralizes control and ensures consistent resolution rules for everyone.

### Tools/Techniques
*   [**JFrog Artifactory**](https://jfrog.com/artifactory/): Can be configured as a proxy that cleanly separates requests for internal packages from requests for public ones.
*   [**Sonatype Nexus Repository**](https://www.sonatype.com/products/nexus-repository): Similar to Artifactory, it can manage private packages and proxy public repositories.
*   **Package Manager Configurations:** `.npmrc`, `pip.conf`, `pom.xml` are your primary tools for implementation.

### Metrics/Signal
*   **Signal:** A build log shows that a package with your internal scope/group (`@acme-corp/...`) was successfully fetched from your private registry.
*   **Metric:** 100% of internal projects use a reserved organizational scope/group ID.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the worst: the attacker succeeded, and their malicious code is now running inside your build environment. The goal now is to contain the "blast radius." What the malicious code can do depends entirely on the permissions of the environment it's running in. A build running on a developer's laptop might have access to their local files and SSH keys, while a build in a CI/CD pipeline might have access to cloud credentials.

### Insight
The principle of least privilege is your most powerful tool for damage control. Build processes should be treated as untrusted and given the absolute minimum access required to do their job, and for the shortest possible time. A build job that tests a UI component should not have credentials to access a production database.

### Practical
*   **Isolate Build Execution:** Run all CI/CD jobs in ephemeral, sandboxed environments, like disposable Docker containers or virtual machines. This prevents an attack from persisting or affecting other builds.
*   **Implement Short-Lived Credentials:** Do not use long-lived static API keys (`AWS_SECRET_ACCESS_KEY`) in your CI environment. Instead, use dynamic, short-lived credentials.
*   For cloud providers, use OIDC federation to grant a CI job a temporary role with tightly scoped permissions that expire automatically after the job finishes.
*   **Restrict Network Egress:** Configure firewalls for your build agents to only allow outbound network connections to expected locations (your artifact registry, your source control, your cloud provider's API endpoint). A malicious script trying to send data to `http://attackers-evil-server.com` would be blocked by default.
*   **Separate Environments:** Use completely separate credentials, networks, and infrastructure for development, staging, and production environments. A compromise of a development build should never provide a path to production.

### Tools/Techniques
*   [**GitHub Actions OIDC Connect**](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect): Allows your GitHub Actions workflows to authenticate directly with cloud providers like AWS, Azure, or GCP to receive short-lived tokens without storing secrets.
*   [**HashiCorp Vault**](https://www.vaultproject.io/): A secrets management tool that can generate dynamic, on-demand secrets for your applications and build jobs.
*   **Kubernetes Network Policies:** If your builds run in Kubernetes, use Network Policies to strictly control which inbound and outbound connections are allowed from your build pods.
*   **Cloud Firewalls:** AWS Security Groups, Azure Network Security Groups, or GCP Firewall Rules can all be used to control egress traffic.

### Metrics/Signal
*   **Signal:** A firewall log shows a blocked outbound connection attempt from a build agent to an unknown IP address.
*   **Metric:** Percentage of CI/CD pipelines that use short-lived, OIDC-based credentials instead of static secrets.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
How do you know an attack is happening or has already happened? Since the build might not fail, you can't rely on red "failed" indicators. You need to actively monitor the behavior of your build systems for anomalies. This means logging the right information and setting up alerts for suspicious patterns.

The key is to look for deviations from the norm:
*   **Wrong Source:** A package that is known to be internal is suddenly downloaded from a public registry.
*   **Suspicious Version:** A package dependency suddenly jumps to an absurdly high version number (e.g., from `1.2.4` to `99.99.9`).
*   **Unexpected Network Activity:** A build agent, which normally only talks to GitHub and Artifactory, suddenly makes a DNS query for a strange domain or opens a connection to an IP address in a different country.
*   **Anomalous Credential Use:** A set of credentials issued to a build job is used to access an unexpected service (e.g., the build job for the documentation site tries to list all S3 buckets).

### Insight
Your build logs are a security goldmine. By default, they often only show high-level status, but with verbose settings, they reveal every single URL a package manager accesses. Centralizing and analyzing these logs is as important as analyzing application or web server logs.

### Practical
*   **Increase Log Verbosity:** Configure your package managers to run in verbose mode during CI builds (e.g., `npm install --verbose`, `pip install -v`). This will log the full URLs for every package downloaded.
*   **Centralize and Analyze Logs:** Ship your build logs, network flow logs from your build agents, and cloud audit logs (like AWS CloudTrail) to a centralized logging system or SIEM.
*   **Create Specific Alerts:**
*   Alert when a package matching your internal naming pattern (e.g., `@acme-corp/*` or `com.acmecorp.*`) is downloaded from any domain other than your private registry.
*   Alert on any outbound network connection from a build agent to an IP not on an allow-list.
*   Alert on significant version jumps for any dependency.

### Tools/Techniques
*   **SIEM Systems:** [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or [Elastic SIEM](https://www.elastic.co/siem) can ingest and analyze logs from various sources to detect anomalies and trigger alerts.
*   **Cloud Provider Logging:** [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) (for API activity), [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) (for network traffic).
*   [**Socket**](https://socket.dev/): A commercial tool that proactively monitors dependencies for suspicious indicators, including changes in `install` scripts.

### Metrics/Signal
*   **Signal:** An alert fires indicating a package was downloaded from an unexpected registry.
*   **Metric:** Time to detection (TTD) for a simulated dependency confusion attack—how long does it take from the moment the malicious package is installed to when the security team is alerted?

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To ensure your defenses work and your team is ready, you need to practice. A security exercise is a controlled, simulated attack that tests your technical controls (like logging and firewalls) and your team's response procedures. This builds "muscle memory" so that when a real attack happens, everyone knows what to do.

### Insight
The goal of an exercise is not to pass or fail, but to find the weak points in your system and processes in a safe environment. It's better to discover that your alerts are misconfigured during a drill than during a real incident.

### Practical
1.  **Plan a Red Team Exercise:**
*   Define a scope: Choose a single, non-critical application to target.
*   Create a safe "malicious" package: Create a test package named like an internal one (e.g., `acme-test-auditor`).
*   Publish it to a public registry (PyPI, npmjs) with a high version number. The `postinstall` script should do something harmless and observable, like printing "SECURITY EXERCISE: PACKAGE EXECUTED" to the build log and then calling a known, allow-listed internal webhook.
*   Do not inform the direct engineering team. Let them "discover" it through the alerting and monitoring systems you built.

2.  **Conduct a Tabletop Exercise:**
*   Gather the development team, security, and operations.
*   Present the scenario: "A build just failed, and the logs show a security alert for a suspicious package. What are the next five steps we take? Who is responsible for what? How do we determine the blast radius?"
*   Walk through your incident response plan and identify gaps or ambiguities.

3.  **Review and Improve:**
*   After the exercise, conduct a blameless post-mortem.
*   Did the alerts fire as expected? If not, why?
*   Did the developers know who to contact?
*   Were you able to quickly identify which builds and credentials were affected?
*   Use the findings to improve tooling, update documentation, and provide targeted training.

### Tools/Techniques
*   **Internal Security Team/Champions:** The group responsible for planning and executing the test.
*   **Public Registries:** A free account on [npmjs.org](https://www.npmjs.com/) or [PyPI](https://pypi.org/) is all that's needed to publish the test package.
*   **Incident Response Plan:** A documented playbook for how to handle security incidents.

### Metrics/Signal
*   **Signal:** The harmless payload from the exercise package is successfully detected by your monitoring systems.
*   **Metric:** Reduction in Mean Time to Detect/Respond (MTTD/MTTR) for this specific scenario across multiple exercises.
*   **Metric:** Percentage of developers who have participated in at least one security exercise or training session on supply chain security in the last year.
{% endblock %}