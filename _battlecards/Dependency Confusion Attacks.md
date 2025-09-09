---
 permalink: /battlecards/depfoo
battlecard:
 title: Dependency Confusion Attacks
 category: Cross-cutting
 scenario: Dependency Confusion
 focus: 
   - internal vs public namespace overlap 
   - registry misconfiguration 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets "InnovateCorp," a company known for its modern CI/CD practices. The attacker discovers a public GitHub repository belonging to an InnovateCorp developer. Inside the repository, they find a `package.json` file that references a private, internal npm package named `innovate-corp-auth-client`.

The attacker checks the public npm registry and finds that the name `innovate-corp-auth-client` is not registered. They quickly create and publish a malicious package with the exact same name to the public npm registry, but with a higher version number (e.g., `99.9.9`). This malicious package contains a `postinstall` script designed to read environment variables (like `AWS_ACCESS_KEY_ID`, `CI_JOB_TOKEN`) and send them to the attacker's server.

Later, a new developer at InnovateCorp sets up their laptop. Unaware of the correct `.npmrc` configuration, they run `npm install` on a project. Their npm client, configured by default to query the public registry, sees the high-versioned malicious package and pulls it instead of the company's internal one. The `postinstall` script executes, and the developer's credentials are stolen. The same can happen to a misconfigured CI/CD build agent, compromising sensitive pipeline secrets.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They are looking for one simple thing: the names of your private, internal software packages. Because many development ecosystems don't enforce a unique, private namespace by default, an internal package name like `my-company-utils` might be available for anyone to register on a public registry like PyPI, npm, or Maven Central. Attackers find these names by scraping public data sources for clues you've unintentionally left behind.

### Insight
Attackers don't need to breach your network to plan their attack; they use your public footprint against you. Leaked configuration files, developer dotfiles in public repos, or even a screenshot in a blog post can provide the exact package names they need. This is a low-effort, high-reward activity for them.

### Practical
- **Audit Public Code:** Regularly search your organization's public repositories on GitHub, GitLab, etc., for files that list dependencies (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`).
- **Google Dorking:** Use advanced search queries to find files on the public internet. For example: `site:github.com "my-company-name" in:file "package.json"`.
- **Review Your Digital Footprint:** Check public-facing web apps and JavaScript bundles. Sometimes, dependency names are exposed directly in the client-side code.

### Tools/Techniques
*   **GitHub Code Search:** Use GitHub's own search functionality to find mentions of your internal naming conventions in public code.
*   **[TruffleHog](https://github.com/trufflesecurity/trufflehog):** While primarily for finding secrets, it's excellent at scanning repositories for file types (like `package.json`) that can leak dependency names.
*   **[dependency-check](https://owasp.org/www-project-dependency-check/):** Run this against any of your public projects. The dependency graph it generates can reveal the names of internal components.

### Metrics/Signal
*   Number of internal package names discovered in public sources per quarter.
*   Automated alert when a file like `package.json` is committed to a public repository within your organization.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. You need to determine if your development environments and CI/CD pipelines are configured to prefer a malicious public package over your legitimate internal one. The vulnerability lies in the package manager's resolution logic. If it's configured to check a public registry first, or to check multiple registries and simply pick the highest version number, you are vulnerable.

### Insight
This is not a flaw in the package manager itself, but a consequence of a misconfiguration. The package manager is doing what it was told: "find this package and get me the latest version." The ambiguity of *where* to look is the weakness an attacker exploits. This is especially dangerous with tools like Python's `pip` when using `extra-index-url`, which explicitly tells the client to look elsewhere if a package isn't in the primary index.

### Practical
- **Audit Your Configs:** Manually review the package manager configurations on developer machines and, crucially, on your CI/CD build runners.
- **Node.js/npm:** Check the contents of `.npmrc` files for the `registry` setting. Is it pointing exclusively to your private registry for your internal scope?
- **Python/pip:** Examine `pip.conf` or `requirements.txt`. The presence of `--extra-index-url https://pypi.org/simple` alongside your private index is a major red flag.
- **Java/Maven:** Inspect `settings.xml`. A `<mirror>` of `*` pointing to a public repository can override private `<repository>` definitions.
- **Run a Controlled Test:** Create a new internal test package (e.g., `test-dep-confusion-pkg`). Then, publish a package with the same name and a higher version to a public registry. Run an install from a typical developer or CI environment. Which one gets installed?

### Tools/Techniques
*   **[dependency-confusion-scanner](https://github.com/pre-commit/dependency-confusion-scanner):** A simple script to check your manifest files for packages that don't exist in a public index, which could be vulnerable.
*   **Repository Manager Logs:** Your artifact repository (e.g., Artifactory, Nexus) logs can show you where your build tools are looking for packages. Look for requests for your internal packages that are being proxied to public upstreams.

### Metrics/Signal
*   Percentage of CI/CD build agents with a validated, secure package manager configuration.
*   A "pass/fail" checklist for each package manager type used in your organization.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your environment is about removing ambiguity from the package resolution process. You must create clear, explicit rules that tell your package manager exactly where to find internal packages, and to never look for them elsewhere.

### Insight
Using namespaces is the single most effective defense. A package named `@innovatecorp/auth-client` is fundamentally different from `auth-client`. The `@innovatecorp` part is a scope that you can control and configure your tools to trust implicitly. This moves you from a vulnerable state of "name overlap" to a secure state of "name uniqueness."

### Practical
1.  **Enforce Scoped Packages:** Mandate that all new internal projects use a unique, organization-specific scope or group ID (e.g., `@your-company/` for npm, `com.yourcompany.` for Maven, a unique prefix like `yc-` for PyPI packages).
2.  **Explicit Registry Configuration:** Configure your package managers to associate that scope with your private registry *only*.
- **npm:** In your `.npmrc`, add the line: `@your-company:registry=https://your.private.registry.com`
- **Maven:** Use a repository manager and ensure your `settings.xml` does not use a global mirror that could override your internal repository definitions.
- **Python:** For builds needing internal packages, configure `pip` to use `--index-url https://your.private.pypi.com` and **avoid** `--extra-index-url`. Your private repository should be configured to act as a proxy for public packages from PyPI.
3.  **Reserve Your Namespace Publicly:** Proactively register your organization and scope names on public registries (npm, PyPI, etc.). You don't need to publish packages, just claim the name to prevent an attacker from squatting on it.

### Tools/Techniques
*   **[JFrog Artifactory](https://jfrog.com/artifactory/) / [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository):** These tools are essential for proxying public repositories and hosting your private packages. You can configure them to never search public upstreams for packages matching your internal namespace.
*   **Policy as Code:** Use tools like [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) to write policies that can validate build configurations, for instance, by failing a CI job if it detects an insecure package manager configuration.

### Metrics/Signal
*   100% of newly created internal packages use the official company scope/namespace.
*   A CI/CD linter that automatically fails any build containing unscoped internal packages.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and their malicious package is now running inside your infrastructure (e.g., during a CI/CD job). The goal now is to contain the "blast radius." The code in that malicious package will run with the same permissions as the user or process that installed it. If that process is a CI job with admin-level cloud credentials, the damage can be catastrophic. If it's a sandboxed process with no network access and temporary, single-use credentials, the damage is negligible.

### Insight
The initial compromise via dependency confusion is often just the foothold. The real damage happens when the attacker uses that foothold to pivot and access more valuable systems. Your build environment should be treated as a hostile, zero-trust environment.

### Practical
- **Least Privilege for CI/CD:** Your build jobs should have the absolute minimum permissions required to run. They should not use long-lived, static administrator keys.
- **Use Short-Lived Credentials:** Leverage features like OpenID Connect (OIDC) to have your CI/CD jobs dynamically request short-lived, narrowly-scoped credentials from your cloud provider for each run.
- **Network Egress Filtering:** By default, your build runners should not have open access to the internet. Explicitly whitelist the domains they are allowed to contact (e.g., your artifact registry, your Git server, your cloud provider's API endpoints). This would prevent a malicious script from "phoning home" to the attacker's server.
- **Run Builds in Ephemeral Containers:** Each CI job should run in a clean, fresh container that is destroyed afterward. This prevents an attacker from establishing a persistent presence on a build agent.

### Tools/Techniques
*   **OIDC Integration:** Both [GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) and [GitLab CI](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html) have robust OIDC support for securely authenticating with AWS, GCP, and Azure.
*   **Kubernetes Network Policies:** If your builds run on Kubernetes, use [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) to strictly control inbound and outbound traffic from your build pods.
*   **Immutable Infrastructure:** Use tools like [Packer](https://www.packer.io/) and [Terraform](https://www.terraform.io/) to define your build agent environments as code, ensuring they are consistent and can be rebuilt from a known good state.

### Metrics/Signal
*   Percentage of CI/CD pipelines that use short-lived credentials vs. static secrets.
*   Number of denied egress network connections from the build environment firewall/proxy.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Detection is about finding the needle in the haystack. How do you spot a dependency confusion attack in progress? You need to monitor for anomalies in your package sources, build behaviors, and network traffic. A legitimate build installing a private package should never involve a download from a public registry or a network connection to an unknown server.

### Insight
Your central artifact repository (like Artifactory or Nexus) is your most critical monitoring point. It is the gatekeeper for all dependencies entering your organization. Its logs contain the "ground truth" about what packages are being requested and where they are coming from.

### Practical
- **Monitor Public Registries:** Set up automated alerts that notify you whenever a package is published to a public registry (npm, PyPI) with a name that matches your internal naming patterns.
- **Audit Artifact Repository Logs:** In your central repository manager, look for logs indicating that a request for a package in your private namespace was resolved by proxying to a public repository. This should never happen and is a strong indicator of an attack.
- **Analyze Egress Traffic:** Monitor DNS queries and outbound network connections from your build agents. A `npm install` process making a connection to a suspicious domain is a major red flag.
- **Immutable Bill of Materials:** Generate a Software Bill of Materials (SBOM) for every successful build. Monitor for deviations, such as a package suddenly being sourced from a public URL instead of your private registry.

### Tools/Techniques
*   **SIEM/Log Analysis:** Ingest logs from your artifact repository, CI/CD system, and network firewall into a tool like [Splunk](https://www.splunk.com/) or an ELK stack ([Elasticsearch](https://www.elastic.co/), Logstash, Kibana). Create a rule: `ALERT if (package_name matches "internal-pattern-*") AND (source_repository is "public-npm-proxy")`.
*   **[Socket.dev](https://socket.dev/):** A service that actively monitors for supply chain risks, including dependency confusion, by analyzing package behavior.
*   **[Dependency-Track](https://dependencytrack.org/):** An open-source component analysis platform that can consume SBOMs and help you monitor your dependencies over time.

### Metrics/Signal
*   Alert fires when a public package is created with a name matching an internal package.
*   A non-zero count of private packages being fetched from a public source in your artifact repository logs.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build resilience, you must practice. Security exercises turn theory into practical skill, building the "muscle memory" developers and responders need to identify and stop an attack. The goal is to safely simulate a dependency confusion attack to test your defenses (Fortify), containment measures (Limit), and detection capabilities (Expose).

### Insight
A successful exercise is not one where nothing goes wrong, but one where you discover flaws in your assumptions, tools, or processes in a safe environment. The goal is to learn and improve before a real attacker forces you to.

### Practical
- **Red Team Simulation:**
1.  The "attacker" team identifies a real (but non-critical) internal package name.
2.  They create a benign lookalike package. Instead of malicious code, the `postinstall` script simply runs `curl` to a test endpoint they control, or prints "EXERCISE: Dependency Confusion Successful" to the build log.
3.  They publish this package to the public npm registry.
4.  The "blue team" (developers, security) must now detect this using their existing monitoring (Expose) and demonstrate that containment measures (Limit), such as network egress filtering, would have blocked a real attack.
- **Tabletop Exercise:** Gather the relevant teams (Dev, Sec, Ops) and walk through the scenario verbally. "An alert just fired that `innovate-corp-auth-client` was downloaded from the public npm registry. What is our playbook? Who is the incident commander? How do we determine the blast radius? How do we eradicate the threat?"
- **Developer Education:** Create a small, vulnerable sample project and challenge developers to first exploit the dependency confusion flaw, and then fix it by applying the correct namespacing and configuration (Fortify).

### Tools/Techniques
*   **[Verdaccio](https://verdaccio.org/):** A lightweight, private npm proxy registry. You can use it to create a sandboxed environment to simulate both your private registry and a "public" one for safe testing.
*   **CI/CD Test Pipeline:** Dedicate a specific CI/CD pipeline and a non-production build agent for running these attack simulations without risk to your actual development workflow.
*   **Internal CTF (Capture The Flag) Platforms:** Use platforms like [CTFd](https://ctfd.io/) to create and host security challenges for developers.

### Metrics/Signal
*   Time To Detect (TTD): How long did it take from the moment the "malicious" package was published to the first alert being triggered?
*   Number of gaps in the response playbook identified during the tabletop exercise.
*   Percentage of developers who have successfully completed the dependency confusion training module/CTF.
{% endblock %}