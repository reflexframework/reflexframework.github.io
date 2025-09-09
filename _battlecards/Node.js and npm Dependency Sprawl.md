---
permalink: /battlecards/nodejs-and-npm-dependency-sprawl
battlecard:
 title: Node.js and npm Dependency Sprawl
 category: Package Ecosystem
 scenario: JavaScript/Node + npm
 focus: 
   - supply-chain malware 
   - typosquatting 
   - transitive dependency risk 
---
## Scenario
An attacker identifies a popular, but infrequently maintained, npm package named `color-helper` which is a dependency of a widely-used command-line tool, `cool-cli-tool`. The attacker notices the maintainer of `color-helper` has an inactive GitHub profile.

The attacker creates and publishes a new package to npm called `colour-helper`. This is a typosquatting attack, hoping developers misspell the original package. Simultaneously, the attacker successfully takes over the original `color-helper` npm account via a leaked password from another service.

The attacker publishes a malicious patch version of the legitimate `color-helper` package (e.g., `v1.2.3` becomes `v1.2.4`). This new version contains the original code plus a stealthy `postinstall` script. This script reads environment variables (like `AWS_ACCESS_KEY_ID`, `NPM_TOKEN`), base64 encodes them, and exfiltrates them via a DNS query to a domain the attacker controls (e.g., `lookup.attacker-cdn.com`).

A developer working on a project that uses `cool-cli-tool` runs `npm update`. Npm sees the new patch version of `color-helper` (a transitive dependency) and pulls it in. The `postinstall` script executes silently in the background on the developer's machine or, more devastatingly, in the CI/CD pipeline, stealing the pipeline's cloud credentials.

## Reconnaissance
### Explanation
This is the attacker's planning phase. They are not targeting you directly yet; they are looking for the weakest link in the vast software supply chain. They methodically scan public package registries and code repositories to find ideal targets for compromise. Their goal is to find a package that will give them the widest possible distribution for their malware with the least amount of effort.

### Insight
Attackers act like strategic investors, seeking assets (packages) that are undervalued (poorly maintained) but have high potential returns (a large number of downstream dependents). They understand that the trust developers place in package managers is their primary attack vector. The complexity of a modern dependency tree, with hundreds or thousands of transitive dependencies, provides the perfect camouflage for their malicious code.

### Practical
As a developer, you can think like an attacker to understand your own exposure. Map your dependency tree and identify your project's "weak links."
1.  Generate a full dependency tree for your project (`npm ls --all`).
2.  Look at the transitive dependencies—the dependencies of your dependencies.
3.  For key dependencies, check their npm page: Who is the maintainer? How recently was it updated? How many other packages depend on it? Is the source repository active?

### Tools/Techniques
*   **Dependency Viewers**: Tools that help you visualize your dependency graph.
    *   [npm ls](https://docs.npmjs.com/cli/v8/commands/npm-ls): The built-in npm command to list the dependency tree.
    *   [npm-graph](https://www.npmjs.com/package/npm-graph): A tool to generate dependency graphs for npm projects.
    *   [Snyk's Dependency Graph](https://snyk.io/product/software-composition-analysis/): Can visualize and analyze dependencies for security vulnerabilities.
*   **Public Data Mining**: Attackers use scripts to query the npm registry API and scan GitHub for `package.json` files to find packages with specific characteristics (e.g., few maintainers, old last-publish date, many dependents).

### Metrics/Signal
*   **Dependency Freshness**: The average age of the packages you depend on. A high number of stale, un-maintained packages is a risk signal.
*   **Maintainer Count**: The number of dependencies maintained by a single person. These are higher-risk targets for account takeover.

## Evaluation
### Explanation
This stage involves assessing your own environment's susceptibility to the attack. It's about looking at your project's configuration, your team's practices, and your automation pipelines to find the security gaps that an attacker could exploit. The question to answer is: "If a malicious package got into our dependency tree, how easy would it be for it to get installed and do damage?"

### Insight
Your biggest vulnerability is often not a specific package version, but a weak process. Relying on `npm install` without a lockfile in CI, giving your build server long-lived, admin-level cloud credentials, or developers having inconsistent local setups are all process-level failures that make this attack much more likely to succeed.

### Practical
Perform a self-audit by asking these questions:
1.  **Lockfiles**: Is a `package-lock.json` or `yarn.lock` file committed to your repository? Is your CI/CD pipeline configured to use it?
2.  **Dependency Updates**: How do you update dependencies? Is it an automated, un-reviewed `npm update`, or is there a process involving tools like Dependabot and a human review?
3.  **CI/CD Credentials**: What secrets does your build environment have access to? Are they long-lived static keys (`AWS_ACCESS_KEY_ID`) or short-lived tokens obtained via OIDC? What is the blast radius if those secrets are stolen?
4.  **Local Setups**: Do developers on your team have local `npm` tokens with publish rights configured by default?

### Tools/Techniques
*   **Vulnerability Scanners**:
    *   [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit): Checks for known vulnerabilities but doesn't detect novel malicious packages. Still good for basic hygiene.
    *   [Snyk](https://snyk.io/): Scans for known vulnerabilities and can also identify packages with risky characteristics (e.g., no recent updates).
    *   [Socket](https://socket.dev/): Specifically designed to detect supply-chain risks, such as packages that add `install` scripts or contain obfuscated code.
*   **CI/CD Configuration Review**: Manually inspect your CI configuration files (`.github/workflows/`, `.circleci/config.yml`, etc.) for how secrets are handled and how `npm install` is run.

### Metrics/Signal
*   **Lockfile Presence**: A simple binary check: `true` or `false` for every repository.
*   **Number of Vulnerabilities Found**: The raw count of vulnerabilities reported by tools like `npm audit` or Snyk.
*   **Credential Type in CI**: The number of pipelines using static, long-lived secrets vs. short-lived, OIDC-based tokens.

## Fortify
### Explanation
Fortification is about proactively hardening your development and deployment processes to prevent the malicious package from being installed in the first place. This is your primary line of defense, focused on creating a secure, repeatable, and strict environment for managing dependencies.

### Insight
The single most effective defense is consistency. By ensuring every install—from a new developer's laptop to the production deployment pipeline—is identical and verified, you eliminate the variability that attackers exploit. Using a lockfile isn't just about reproducible builds; it's a critical security control that acts as an allow-list for your dependencies.

### Practical
1.  **Enforce Lockfiles**: Always commit `package-lock.json` or `yarn.lock`. In your CI/CD pipeline, use `npm ci` instead of `npm install`. `npm ci` performs a clean install based *only* on the lockfile, and will fail if the `package.json` and `package-lock.json` are out of sync, preventing accidental updates.
2.  **Vet Dependencies**: Before adding a new dependency, vet it. Check its popularity, maintenance status, and any open security issues.
3.  **Automate Scanning**: Integrate a security scanner into your CI pipeline. Configure it to fail the build if a high-severity vulnerability or a suspicious package (e.g., one that adds a new `postinstall` script) is detected in a pull request.
4.  **Use a Private Registry**: For internal packages, use a private registry. This prevents confusion with public packages and can also be used to proxy and cache approved public packages, giving you a central point of control.

### Tools/Techniques
*   **CI Commands**:
    *   [npm ci](https://docs.npmjs.com/cli/v8/commands/npm-ci): The command to use for clean, reproducible builds in automated environments.
*   **Automated Dependency Management**:
    *   [GitHub's Dependabot](https://github.com/dependabot): Automatically creates pull requests to update your dependencies, allowing you to review changes before merging.
    *   [Renovate](https://github.com/renovatebot/renovate): A highly configurable alternative to Dependabot.
*   **Security Scanners**:
    *   [Socket](https://socket.dev/): Integrates with GitHub to analyze pull requests, flagging risky changes in dependencies like the addition of install scripts.
    *   [Snyk](https://snyk.io/): Can be configured to run in CI and fail builds based on vulnerability policies.
*   **Private Registries**:
    *   [Verdaccio](https://verdaccio.org/): A lightweight, open-source private npm proxy registry.
    *   [JFrog Artifactory](https://jfrog.com/artifactory/): A commercial, full-featured binary repository manager.

### Metrics/Signal
*   **CI Build Failures**: An increase in builds failing due to `npm ci` mismatches or security scanner findings is a sign that the system is working.
*   **Dependency Update PRs**: A steady stream of pull requests from Dependabot or Renovate indicates that your dependencies are staying fresh in a controlled manner.

## Limit
### Explanation
Assume your "Fortify" stage has failed and the malicious code is now running inside your environment. The "Limit" stage is about damage control. The goal is to ensure that even if the malicious `postinstall` script executes, its "blast radius" is tiny. It should be trapped in a sandbox with minimal permissions, unable to access sensitive data or move to other parts of your infrastructure.

### Insight
The principle of least privilege is your most powerful tool here. A script that installs dependencies has no legitimate reason to access production database credentials or AWS admin keys. By treating your build environment as a zero-trust zone, you can run potentially untrusted code with confidence, knowing it can't cause significant harm.

### Practical
1.  **Isolate Build Environments**: Run your CI/CD jobs in ephemeral, isolated environments like containers. The environment should be created for the job and destroyed immediately after.
2.  **Use Short-Lived, Scoped Credentials**: Do not use static, long-lived secrets in your CI/CD environment variables. Instead, use a workload identity mechanism (like OIDC) to grant the specific job a short-lived, tightly-scoped access token for only the resources it needs. For example, a token that only allows it to push a container image to a specific repository and nothing else.
3.  **Block Egress Network Traffic**: By default, your build runners should not be allowed to make arbitrary outbound network connections to the internet. Explicitly allow-list the domains they need to contact (e.g., `registry.npmjs.org`, `github.com`). The attacker's DNS exfiltration would be blocked.

### Tools/Techniques
*   **Workload Identity/OIDC**:
    *   [GitHub Actions OIDC integration with AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
    *   [Google Cloud Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
*   **Secrets Management**:
    *   [HashiCorp Vault](https://www.vaultproject.io/): A centralized service for managing secrets and providing dynamic, short-lived credentials.
*   **Container Runtimes**:
    *   [Docker](https://www.docker.com/): Use fresh containers for each build job.
*   **Network Policies**:
    *   Use cloud security groups, firewall rules, or service mesh network policies (like [Istio](https://istio.io/)) to control egress traffic from your build agents.

### Metrics/Signal
*   **Credential Type**: The percentage of CI/CD pipelines using short-lived tokens vs. static secrets. Aim for 100%.
*   **Network Egress Blocks**: Logs from your firewall or network proxy showing denied outbound connections from build agents. This is a strong signal of a successful containment.

## Expose
### Explanation
This stage is about detection. How do you know an attack is happening or has already happened? The malicious code is designed to be stealthy, so you can't rely on obvious crashes or errors. You need to actively monitor for the subtle footprints the malware leaves behind, such as unexpected network traffic, processes, or file system access.

### Insight
You can't detect what you don't monitor. Your application logs are useless here. The evidence of this attack is found in the infrastructure logs of your build environment. The malicious script's attempt to exfiltrate data via a DNS query is a network-level event. Detecting it requires you to be logging and analyzing network traffic from what is often considered a "trusted" internal environment.

### Practical
1.  **Monitor Network Egress**: Log all outbound network connections and DNS queries from your build agents and developer machines.
2.  **Establish Baselines**: Know what normal looks like. Your build process should be predictable. It should always connect to the same handful of domains (`npmjs.org`, `github.com`, your artifact registry). A connection to a new, unknown domain is a major red flag.
3.  **Monitor Process Execution**: Log the processes spawned during your build. An `npm install` command should not be spawning `curl` or running arbitrary shell commands.
4.  **Centralize Logs**: Send all relevant logs (network, process, file access) from your build agents to a centralized logging and analysis platform where you can set up automated alerts.

### Tools/Techniques
*   **Runtime Security Monitoring**:
    *   [Falco](https://falco.org/): An open-source tool that detects anomalous activity in your applications and containers at runtime (e.g., "A shell was spawned in a container" or "A sensitive file was read").
*   **Network Monitoring**:
    *   Use firewall logs, VPC flow logs (in AWS), or tools like [Zeek](https://zeek.org/) to capture and analyze network traffic.
*   **Log Aggregation and Alerting**:
    *   [Datadog](https://www.datadoghq.com/), [Splunk](https://www.splunk.com/), or the open-source [ELK Stack](https://www.elastic.co/elastic-stack) can be used to ingest logs and create alerts for suspicious patterns. For example: `alert when a process named 'node' in a CI build runner makes a DNS query to a non-allow-listed TLD`.

### Metrics/Signal
*   **Anomalous Egress Alert**: An alert firing for a network connection from a build agent to a suspicious or unknown domain. This is the smoking gun for this scenario.
*   **New Process Execution**: An alert for an unexpected process (`sh`, `curl`, `wget`) being executed as a child of your `npm` command.

## eXercise
### Explanation
This is where you practice your defenses. You can't wait for a real attack to find out if your monitoring, alerting, and response plans work. By running controlled security drills, you build "muscle memory" for the team, validate your tooling, and identify gaps in your processes before an attacker does.

### Insight
A security exercise is not a test to pass or fail; it's a learning opportunity. The goal is to discover weaknesses in a safe environment. It's often the human element—communication, knowing who to call, having the authority to act—that is the weakest link, and these exercises are the best way to strengthen it.

### Practical
1.  **Tabletop Exercise**: Gather the development and security teams and walk through the attack scenario verbally. What would the first alert look like? Who would receive it? What is their first action? Who needs to be informed? How would you verify the threat? How would you stop a deployment?
2.  **Live Fire Drill (Non-production)**:
    *   Create a harmless "malicious" package. Instead of stealing secrets, its `postinstall` script just performs a DNS lookup to a unique domain you control (e.g., `security-drill-q1.your-company.com`).
    *   Publish it to a private registry.
    *   Add it as a transitive dependency to a test project.
    *   Have a developer "accidentally" update their dependencies and push the change, triggering a CI build.
    *   Now, watch and wait. Did your `Expose` systems detect the DNS lookup? Did the right people get alerted? How long did it take?

### Tools/Techniques
*   **Private Registry**: Use [Verdaccio](https://verdaccio.org/) to host your safe, pseudo-malicious package for the drill.
*   **DNS Logging**: Ensure you have a system to monitor and verify that the DNS lookup from your drill was detected.
*   **Incident Response Plan**: Have a documented plan for what to do during a supply-chain attack. Use the drill to test and refine this document.

### Metrics/Signal
*   **Time to Detect (TTD)**: The time from when the malicious code runs to when the first alert is generated.
*   **Time to Remediate (TTR)**: The time from the alert to when the threat is contained (e.g., the build is stopped, the malicious package is identified and blocked).
*   **Post-Mortem Action Items**: The number of concrete improvements to tooling, process, and training that come out of the exercise.