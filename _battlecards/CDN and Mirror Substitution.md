---
 permalink: /battlecards/cdn-and-mirror-substitution
 
battlecard:
 title: CDN and Mirror Substitution
 category: Cross-cutting
 scenario: CDN/Mirror Substitution
 focus: 
   - fake CDN scripts 
   - registry mirror swap 
   - shadowed package sources 
---

An attacker targets a mid-sized tech company by poisoning its software supply chain. They identify a popular, open-source JavaScript charting library the company uses on its customer-facing dashboard. Instead of attacking the library's official NPM package, they target a widely used but less secure public CDN that hosts it.

The attacker uses a man-in-the-middle (MITM) attack or compromises the CDN directly to replace the legitimate `charting-library.min.js` file with a malicious version. The malicious script is nearly identical, but it includes a few extra lines of code to skim credit card information from the checkout page of any site that includes it.

A developer at the target company, working on a new feature, includes the library using a simple `<script>` tag pointing to the compromised CDN, as recommended in the library's outdated documentation. Because the company doesn't use Subresource Integrity (SRI) checks, the browser happily fetches and executes the malicious script. The change is code-reviewed and deployed to production. The attack goes unnoticed for weeks, silently exfiltrating customer payment data to the attacker's server.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They aren't trying to break in yet; they're creating a map of your development ecosystem to find the weakest link. They will analyze public code on GitHub, read your engineering blogs, and scan your web applications to identify the technologies, libraries, CDNs, and package registries you rely on. Their goal is to find a "soft" dependency source—an obscure mirror, an unprotected CDN link, or a misconfigured internal registry—that is easier to compromise than your primary infrastructure.

### Insight
Attackers think in terms of paths of least resistance. Why attack your hardened production servers when they can poison a dependency you'll willingly pull in and run yourself? They know developers often trust content from "known" CDNs or package managers implicitly, making this a highly effective and stealthy entry point. This extends beyond code to container base images (`FROM ubuntu:latest`) and even AI models pulled from public hubs.

### Practical
- **Audit your sources**: As a team, review a project's `package.json`, `pom.xml`, `requirements.txt`, and `Dockerfile` files. Ask: "Where is this *actually* coming from?" Trace the URLs and registry configurations.
- **Check your HTML**: Manually inspect your web application's frontend source code for any `<script>` or `<link>` tags that pull resources from third-party domains.
- **Map your CI/CD pipeline**: Document every external service your build pipeline communicates with. This includes package registries, base image repositories, and download sites.

### Tools/Techniques
- **Public Code Analysis**: Manually searching repositories like [GitHub](https://github.com) or [GitLab](https://gitlab.com) for dependency files (`package.json`, `Gemfile`, etc.).
- **Network Scanners**: Using tools like [nmap](https://nmap.org/) or search engines like [Shodan](https://www.shodan.io/) to find misconfigured or exposed internal package mirrors (e.g., an Artifactory or Nexus instance accidentally made public).
- **Web Application Inspection**: Using browser developer tools to inspect network requests and identify all third-party scripts, styles, and fonts being loaded.

### Metrics/Signal
- **Dependency Source Map**: A documented list of every unique domain and IP address from which your project and pipeline fetch dependencies.
- **Number of Unvetted Sources**: A count of external sources that have not been explicitly approved by your security or platform engineering team.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about turning the attacker's perspective on yourself. How easy would it be to trick your systems into pulling a malicious dependency? You need to assess your environment for blind trust in external sources. This involves checking if you are using insecure protocols (HTTP instead of HTTPS), if you are locking dependency versions, and if you have any formal process for vetting a new CDN, mirror, or package source before using it.

### Insight
The most significant vulnerability is often not a complex technical flaw but a weak process. If any developer can add a new CDN link or a new Python package source to a project without review, you have a process vulnerability. The "it just works" mentality can be dangerous when it comes to your supply chain.

### Practical
- **Review Registry Configurations**: Check your global and project-level configurations for package managers. For example, inspect your `.npmrc` for custom registries or `pip.conf` for a custom `index-url`. Are they using HTTPS?
- **Analyze Lockfiles**: Examine your `package-lock.json`, `yarn.lock`, or `poetry.lock`. Are they being used and enforced in your CI builds? Or are you just running `npm install` and hoping for the best?
- **Check for Version Pinning**: Look at your `Dockerfile`s. Are you using floating tags like `:latest` or `:alpine`? This allows an upstream source to change the underlying image without your knowledge.
- **Assess Script Tags**: Are your frontend HTML templates pulling in scripts from CDNs? If so, are they using the `integrity` attribute for Subresource Integrity (SRI)?

### Tools/Techniques
- **OWASP Dependency-Check**: While primarily for vulnerability scanning, the reports from [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) can help you inventory all your transitive dependencies.
- **Manual Configuration Review**: There is no substitute for manually reading your build configuration files (`.npmrc`, `build.gradle`, CI YAML files) to understand your true sources.

### Metrics/Signal
- **Unpinned Dependency Percentage**: The percentage of dependencies (packages, Docker images) that use floating versions or ranges instead of exact, pinned versions.
- **Unencrypted Source Count**: The number of dependency sources configured to use `http://` instead of `https://`.
- **SRI Coverage**: The percentage of external `<script>` and `<link>` tags that have a valid `integrity` attribute.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about establishing and enforcing trust. Instead of pulling dependencies from dozens of public sources, you route all requests through a single, trusted, internal repository that you control. For assets you can't proxy, like public CDN scripts, you enforce integrity checks to ensure the content hasn't been tampered with. This approach turns your supply chain from a web of unvetted sources into a controlled, auditable pipeline.

### Insight
A centralized package repository doesn't just improve security; it improves build performance (caching) and reliability (shielding you from public outages). Security and good engineering practice are often one and the same. This principle also applies to the emerging AI supply chain: cache and vet models from hubs like [Hugging Face](https://huggingface.co/) in your own controlled storage before use.

### Practical
- **Implement a Repository Manager**: Set up an internal repository manager to proxy and cache all your public dependencies. Configure all your developer machines and CI/CD runners to *only* use this internal manager.
- **Enforce Subresource Integrity (SRI)**: For any script or stylesheet loaded from a third-party CDN, generate a cryptographic hash and add it to the `integrity` attribute of the HTML tag. The browser will refuse to load the resource if the hash doesn't match.
- **Use Lockfiles Everywhere**: Commit your `package-lock.json`, `yarn.lock`, etc., to version control. In your CI/CD pipeline, use commands that strictly install from the lockfile (e.g., `npm ci` instead of `npm install`).
- **Sign Your Artifacts**: For Docker images, use signing tools to create a cryptographic signature for each image you build and push to your registry. Configure your runtime environment (e.g., Kubernetes) to only pull and run signed images.

### Tools/Techniques
- **Repository Managers**: [JFrog Artifactory](https://jfrog.com/artifactory/), [Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository), [Cloudsmith](https://cloudsmith.com/).
- **SRI Generation**: Use an online tool like [SRI Hash Generator](https://www.srihash.org/) or a command-line tool like `openssl dgst -sha384 -binary file.js | openssl base64 -A`.
- **Container Image Signing**: [Docker Content Trust (Notary v1)](https://docs.docker.com/engine/security/trust/content_trust/), or the more modern CNCF project [Sigstore](https://www.sigstore.dev/) with its `cosign` tool.

### Metrics/Signal
- **Proxy Adoption Rate**: Percentage of build jobs and developer machines configured to use the internal repository manager.
- **SRI Enforcement**: Build fails if a PR adds an external script tag without an `integrity` hash (checked via a linter or pre-commit hook).
- **Signed Images Ratio**: The percentage of container images in your production registry that are cryptographically signed.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume your fortifications fail and a malicious package gets executed in your build environment. The goal now is to contain the "blast radius." This means ensuring the compromised process can do as little damage as possible. Run builds in ephemeral, isolated environments with no access to the internet (except for your trusted package repository) and no access to production secrets. Similarly, in the browser, use security policies to restrict what a potentially malicious script is allowed to do.

### Insight
Attackers often use a compromised build server as a pivot point to move laterally through your network or to steal long-lived credentials. By treating your build environment with the same "zero trust" security posture as you would production, you can neutralize the majority of the potential damage from a supply chain attack.

### Practical
- **Isolate Build Jobs**: Configure your CI/CD system to run each job in a fresh, single-use container. The container should be destroyed immediately after the job completes.
- **Restrict Network Egress**: Use firewall rules or service mesh configurations to block all outbound network traffic from your build runners, except to a specific allow-list of required domains (e.g., your internal package repository, your source control system).
- **Implement Content Security Policy (CSP)**: In your web application, send the `Content-Security-Policy` HTTP header. This allows you to define an explicit allow-list of domains from which scripts, styles, and other resources can be loaded, preventing a compromised script from loading its own malicious payloads.
- **Use Secretless Builds**: Never store long-lived credentials (like AWS keys) directly on build runners. Use short-lived tokens obtained via protocols like OIDC or from a secrets management vault at the start of the build.

### Tools/Techniques
- **CI/CD Isolation**: Native container-based execution in [GitLab CI](https://docs.gitlab.com/ee/ci/docker/using_docker_build.html), [GitHub Actions](https://docs.github.com/en/actions), and [Jenkins](https://www.jenkins.io/doc/book/pipeline/docker/) with Kubernetes or Docker agents.
- **Network Policy**: [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) or cloud provider security groups to restrict traffic.
- **CSP Management**: [Content Security Policy (CSP) on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).
- **Secrets Management**: [HashiCorp Vault](https://www.vaultproject.io/), [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), [GitHub Actions OIDC integration](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services).

### Metrics/Signal
- **Build Environment Network Alerts**: Alerts triggered by a build job attempting to connect to an unauthorized external IP address.
- **CSP Violation Reports**: A spike in CSP violation reports logged from user browsers, which could indicate an attempt to execute an unauthorized script.
- **Secret Lifespan**: The average time-to-live (TTL) for credentials used in the build pipeline. Shorter is better.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about making the invisible visible. How do you detect that a substitution has occurred? This requires active monitoring and logging at key points in your supply chain. You need to log every package download, verify its hash against a known-good manifest, and monitor the behavior of both your build pipeline and your running application for anomalies. The goal is to spot the attack as it happens, or shortly after, not weeks later during a forensic investigation.

### Insight
You can't rely on catching the substitution itself in real-time. A more robust strategy is to detect the *symptoms* of a compromise. A malicious build script might try to make a strange network connection, or a compromised frontend script might trigger a flood of Content Security Policy (CSP) violation reports. Look for these secondary signals.

### Practical
- **Generate and Compare SBOMs**: Create a Software Bill of Materials (SBOM) for every successful build. Compare the SBOM of a new build against the previous one. Alert on any unexpected changes, like a new dependency appearing or a version changing when it shouldn't have.
- **Verify Hashes in CI**: As part of your build script, after downloading a dependency, calculate its checksum and compare it against a hash stored securely in your source code repository. If they don't match, fail the build immediately.
- **Monitor Network Logs**: Actively monitor and alert on network traffic from your build environment. A build for your frontend application should never be making an outbound connection to an unknown IP in Eastern Europe.
- **Aggregate CSP Reports**: Configure your web server to collect CSP violation reports sent by browsers. A sudden spike in reports for a specific script or domain is a strong indicator of a cross-site scripting (XSS) or resource injection attack.

### Tools/Techniques
- **SBOM Generation**: [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) are standard formats. Tools like [Syft](https://github.com/anchore/syft) can generate an SBOM from a container image.
- **Network Monitoring**: Infrastructure monitoring tools like [Datadog](https://www.datadoghq.com/) or open-source solutions like [Zeek](https://zeek.org/) can baseline and alert on anomalous network flows.
- **CSP Reporting Endpoints**: Services like [Report URI](https://report-uri.com/) or [Sentry](https://sentry.io/) can aggregate and analyze CSP violation reports from your users.

### Metrics/Signal
- **Build Failures on Hash Mismatch**: A non-zero count of builds that have failed because a dependency's checksum did not match the expected value. This is a sign your defense is working.
- **Anomalous Egress Traffic**: An alert fires because a build agent tried to connect to a destination not on its allow-list.
- **SBOM Drift**: An alert indicating that a dependency has changed between two consecutive builds without a corresponding change in the `package.json`.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice defending against the attack. By simulating a CDN or mirror substitution in a controlled environment, you can test your defenses, processes, and people. A good exercise will validate your tooling (Did the hash check fail the build?) and your team's response (Did the on-call developer know what to do with the alert?). This builds the "muscle memory" needed to react effectively during a real incident.

### Insight
Security exercises are not pass/fail exams; they are learning opportunities. The most valuable outcome of a drill is often identifying a broken process or a gap in understanding. For example, you might find that your alerting system works perfectly, but the alert message itself is too cryptic for a developer to act on.

### Practical
- **Tabletop Exercise**: Gather the team and walk through the scenario verbally. "We just received an alert that the checksum for `react-dom.js` failed in the CI pipeline. What are our immediate steps? Who do we notify? How do we verify if production is affected?"
- **Live Fire Drill (Internal)**:
1.  Set up a private, malicious package mirror using a tool like [Verdaccio](https://verdaccio.org/).
2.  Upload a modified version of a common internal library. The modification can be something benign, like logging a message to the console.
3.  In a separate, non-production project, temporarily change the `.npmrc` to point to this malicious mirror.
4.  Run the build.
5.  Observe what happens. Do your checksum verifications fail the build? Do your network monitors flag the connection to the new mirror?
- **Red Team Engagement**: Hire an external security team to perform a controlled attack on your supply chain to test your defenses from a real attacker's perspective.

### Tools/Techniques
- **Private Registries for Simulation**: [Verdaccio](https://verdaccio.org/) for npm, or a simple Nginx server for hosting fake CDN files.
- **Chaos Engineering**: While often used for reliability, principles from chaos engineering can be applied to security. Intentionally inject a "bad" dependency to see how the system reacts.

### Metrics/Signal
- **Time to Detect (TTD)**: During the exercise, how long did it take from the moment the malicious package was introduced to the moment an alert was generated?
- **Time to Remediate (TTR)**: How long did it take the team to identify the root cause (the malicious mirror) and take corrective action (e.g., block the mirror, revert the commit)?
- **Process Improvement Tickets**: The number of new tickets created in your issue tracker to fix gaps in tooling, documentation, or processes that were identified during the exercise.
{% endblock %}