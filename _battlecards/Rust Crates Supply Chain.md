---
 permalink: undefined
battlecard:
 title: Rust Crates Supply Chain
 category: Package Ecosystem
 scenario: Rust + crates.io
 focus: 
   - malicious crate uploads 
   - unsafe transitive dependencies 
---

An attacker identifies a popular but unmaintained utility crate, `rust-utilities-v2`, that is a common transitive dependency in many projects. The attacker gains control of the crate on `crates.io`, either by social engineering the original author or by taking over an expired domain associated with the author's account.

The attacker publishes a new minor version, `rust-utilities-v2 v2.1.1`, which seems like a routine bugfix. This new version adds a new, seemingly innocuous transitive dependency of its own: a typosquatted crate named `url-parse` (instead of the legitimate `url_parse`).

This malicious `url-parse` crate contains a `build.rs` script. When a developer's project using `rust-utilities-v2` is compiled in a CI/CD pipeline, the `build.rs` script executes. It scans the build environment for environment variables like `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, or other secrets, base64 encodes them, and exfiltrates the data via a DNS request to an attacker-controlled domain (e.g., `aBcDeFg123.malicious-domain.com`, where `aBcDeFg123` is the encoded secret).

The developer is unaware of the compromise until they discover fraudulent cloud resource usage or receive a security alert from their provider.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers study the ecosystem to find the weakest link. They aren't hacking your code directly; they are finding subtle ways to inject their code into your build process. They look for popular crates, especially those that are transitive (dependencies of your dependencies), as they are less likely to be scrutinized. They identify crates that are unmaintained, have maintainers with poor operational security, or have names that are easy to misspell (typosquatting). They analyze public `Cargo.toml` files on GitHub to understand what companies use, enabling them to craft targeted attacks like dependency confusion, where they publish a crate with the same name as an internal company package to a public registry.

### Insight
The attack surface is larger than your application code; it includes your entire dependency tree and the operational security of hundreds of other developers. The `build.rs` script is a primary target for attackers because it's a Turing-complete Rust script that runs with the full permissions of your build user *before* your actual code is even compiled. It can access the network, file system, and environment variables.

### Practical
- Treat any new dependency, direct or transitive, as untrusted until vetted.
- Periodically check the maintenance status of your key dependencies. Is the project still active? Are issues being addressed?
- Be wary of adding dependencies for very small tasks that could be written yourself. The cost of a new dependency is more than just the lines of code it saves.
- When creating internal crates, use a distinct naming prefix to make dependency confusion attacks harder.

### Tools/Techniques
- **GitHub Search**: Search for your organization's name or your internal project names alongside `Cargo.toml` to find leaked dependency information.
- **[crates.io API](https://crates.io/api/v1/summary)**: Can be scripted to analyze dependency trends, download counts, and identify popular but infrequently updated crates that might be ripe for takeover.
- **[Sourcegraph](https://sourcegraph.com/)**: Use it to search across public code to see how specific crates are being used and how popular they are within certain ecosystems.

### Metrics/Signal
- **Dependency Freshness**: Track the last update date for all your project's dependencies. A high number of stale, unmaintained crates is a risk indicator.
- **Public Mentions**: Number of public repositories that mention your internal package names or infrastructure details.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is about looking inward at your own development practices to see where the cracks are. How do you add new dependencies? Is there a review process? Do you blindly trust `cargo update`? A key vulnerability is an uninspected or ignored `Cargo.lock` file. This file is your exact dependency manifest; without it, every build can pull in different, potentially malicious, minor versions of transitive dependencies. You also need to assess the build environment itself. Does it have access to more secrets or network permissions than it strictly needs?

### Insight
A `Cargo.lock` file is not a developer convenience; it is a critical security control. It ensures reproducible and verifiable builds. Ignoring it in your `.gitignore` is equivalent to leaving your front door unlocked. Similarly, the presence of `unsafe` code blocks in dependencies should be treated with caution, as they bypass Rust's core memory safety guarantees and can be a vector for vulnerabilities.

### Practical
- **Audit `Cargo.lock`**: Never ignore it. When it changes, the code diff should be reviewed with the same scrutiny as application code. What was added? What was updated? Why?
- **Review New Dependencies**: Before adding a crate, inspect its `crates.io` page for red flags: recent ownership changes, low download count but recent publication, a suspicious-looking repository link, or a name that is very similar to a popular crate.
- **Assess Build Environment Permissions**: Document every secret and network permission available to your CI/CD jobs. Challenge whether each one is absolutely necessary for the build to complete.

### Tools/Techniques
- **[`cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit)**: Scans your `Cargo.lock` against the official RustSec Advisory Database for known vulnerabilities.
- **[`cargo-geiger`](https://github.com/rust-secure-code/cargo-geiger)**: Scans dependencies for the usage of `unsafe` Rust code, which requires extra scrutiny.
- **[`cargo-crev`](https://github.com/crev-dev/cargo-crev)**: A social code review system. It allows you to trust reviews from other developers you trust, creating a web of trust for vetting crates.

### Metrics/Signal
- **Number of Dependencies with Known Vulnerabilities**: A non-zero count from `cargo-audit` indicates an immediate risk.
- **Count of `unsafe` Dependencies**: The output from `cargo-geiger`. A high or increasing number warrants a deeper review.
- **Dependency Churn**: High frequency of changes in `Cargo.lock` could indicate instability or a need for better version management.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening is about putting technical controls in place to prevent the malicious code from ever running. This involves strict dependency management and securing the build environment. You should lock down which packages can be introduced and what those packages can do if they are compromised. This means configuring `cargo` to be more secure and treating your CI/CD pipeline as a production environment that needs to be locked down.

### Insight
The principle of "shift left" security applies here. It's far cheaper and safer to prevent a malicious package from being added than it is to detect and respond to a breach later. Your defense should be layered: use tools to block bad packages, configure the build environment to be restrictive, and have manual processes for review.

### Practical
- **Enforce `Cargo.lock`**: Use `cargo build --locked` in your CI pipeline to ensure the build fails if `Cargo.lock` is out of sync with `Cargo.toml`.
- **Use Private Registries**: For internal crates, use a private registry to prevent dependency confusion attacks. Configure Cargo to only use that registry for your organization's packages.
- **Vet Dependencies Proactively**: Integrate a security scanner into your CI pipeline that checks pull requests for new, vulnerable, or untrustworthy dependencies and blocks the merge if issues are found.
- **Sandbox Your Builds**: Run build steps in containerized environments with minimal privileges. If a build script doesn't need network access, block it.

### Tools/Techniques
- **Cargo `[registries]` Configuration**: Use the `.cargo/config.toml` file to define a private source for your own crates, preventing them from being pulled from `crates.io`. See the [docs](https://doc.rust-lang.org/cargo/reference/registries.html).
- **Supply Chain Security Tools**:
- **[Socket.dev](https://socket.dev)**: Proactively scans packages for risk signals (e.g., new maintainers, use of `build.rs`, filesystem access) before you install them.
- **[Snyk](https://snyk.io/)**: Scans dependencies for known vulnerabilities and licensing issues, and can be integrated directly into CI/CD.
- **Containerization**: Use [Docker](https://www.docker.com/) with flags like `--network=none` for build stages that don't need to connect to the internet.

### Metrics/Signal
- **Blocked PRs**: Number of pull requests automatically blocked by security scans due to risky dependencies.
- **Builds Using `--locked`**: 100% of production builds should use this flag.
- **Use of Private Registry**: Percentage of internal projects configured to use a private registry.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and their malicious code is now running in your build environment. The goal now is to contain the "blast radius." If the malicious `build.rs` script executes, what can it actually do? Limiting the damage is about applying the principle of least privilege to your build process. The build job should only have the exact permissions and secrets it needs for the duration of the build, and nothing more.

### Insight
Secrets in your CI/CD environment are a primary target. A long-lived, overly permissive `AWS_SECRET_ACCESS_KEY` is a goldmine for an attacker. By switching to short-lived, narrowly-scoped credentials, you can turn a catastrophic breach into a minor, contained incident. The compromise of a single build should not compromise your entire cloud infrastructure.

### Practical
- **Use Short-Lived Credentials**: Avoid static secrets in environment variables. Use OpenID Connect (OIDC) to issue temporary, short-lived credentials to your CI/CD jobs directly from your cloud provider.
- **Implement Network Egress Filtering**: Configure firewall rules for your build agents. Only allow outbound connections to known, required domains (like `crates.io`, your artifact registry, etc.). Deny all other traffic.
- **Isolate Build Stages**: Run dependency installation in a separate, more restrictive step or container than the step that requires production deployment keys. The `cargo fetch` step should not have access to deployment secrets.

### Tools/Techniques
- **OIDC Integration**:
- [Configuring OIDC in GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers)
- [AWS IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [Google Cloud Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- **Network Policy**: Use [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) or cloud provider security groups to restrict outbound traffic from build pods or VMs.

### Metrics/Signal
- **Credential TTL**: The time-to-live for credentials used in CI/CD should be measured in minutes, not hours or days.
- **Blocked Outbound Connections**: An increase in logs showing denied egress traffic from build agents is a strong signal of a potential exfiltration attempt.
- **Number of IAM Permissions**: The count of permissions attached to the build role should be minimal and audited regularly.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To catch an attack in progress, you need visibility. How do you know your build process is doing something it shouldn't? This stage is about monitoring, logging, and alerting on suspicious activity within your build pipeline. Because a legitimate build process can be noisy (downloading files, running compilers), the key is to establish a baseline of normal behavior and then look for anomalies.

### Insight
The exfiltration vector is often the network. Malicious code needs to "phone home" to deliver its stolen data. Monitoring for unexpected DNS queries and outbound TCP/UDP connections from your build environment is one of the most effective ways to detect this kind of attack. The signals are there; you just need to be listening for them.

### Practical
- **Log all Network Activity**: In your build environment, log every outbound connection, including the destination IP/domain and the process that initiated it.
- **Monitor DNS Queries**: DNS is a common and often overlooked channel for data exfiltration. Log all DNS queries and alert on requests to new or suspicious-looking domains.
- **Baseline Process Activity**: Establish a "known good" set of processes that are expected to run during a build. Alert on any new or unexpected process execution, especially those spawned by `build.rs` scripts.
- **Centralize Logs**: Send all CI/CD, network, and process logs to a centralized analytics platform where they can be correlated and monitored for anomalous patterns.

### Tools/Techniques
- **eBPF-based Monitoring**: Tools like [Cilium's Tetragon](https://github.com/cilium/tetragon) or [Falco](https://falco.org/) can provide deep kernel-level visibility into process execution, file access, and network activity with low overhead.
- **Log Analysis Platforms**: Use platforms like the [ELK Stack](https://www.elastic.co/elastic-stack) or [Splunk](https://www.splunk.com/) to ingest logs from build agents and create dashboards and alerts. Example alert: "Alert if a build process initiates a network connection to a domain not on our allowlist."
- **DNS Sinkholing**: Route egress DNS queries through a security service like [Cisco Umbrella](https://umbrella.cisco.com/) or an internal DNS server that can log requests and block known malicious domains.

### Metrics/Signal
- **Anomalous Network Egress Alerts**: Number of alerts firing for connections to unexpected destinations from build agents.
- **First-Seen DNS Queries**: An alert on the first time a build environment tries to resolve a particular domain can be an early warning.
- **Mean Time to Detect (MTTD)**: How long does it take from the moment a malicious build runs to the moment an alert is generated?

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is the "flight simulator" for security incidents. You can't wait for a real attack to test your defenses. You must proactively and regularly test your systems, tools, and team response. This involves creating controlled simulations of the attack scenario—a "fire drill"—to see if your defenses work as expected and if your team knows what to do. The goal is to build muscle memory for both prevention and response.

### Insight
Technical controls are only half the battle. If your detection system fires an alert but no one knows what it means or how to respond, the defense has failed. Exercises reveal gaps in your processes, tooling, and training in a safe environment, allowing you to fix them before a real attacker exploits them.

### Practical
- **Run a "Red Team" Exercise**: Create a benign "malicious" crate. Instead of stealing secrets, its `build.rs` script could touch a file named `/tmp/pwned` or make a DNS query to a special test domain like `redteam.yourcompany.internal`.
- **Add the Test Crate**: Add your test crate as a transitive dependency to a sample project and have a developer submit a pull request.
- **Observe and Document**:
- Did the `Fortify` CI scans block the PR?
- If not, did the `Limit` controls (like network policies) prevent the script from calling out?
- Did the `Expose` monitoring systems generate an alert?
- How did the on-call developer respond to the alert?
- **Conduct Tabletop Exercises**: Walk through the scenario verbally with the development and security teams. "We just received a credible report that a malicious crate is in our main application. What are our first five steps?"

### Tools/Techniques
- **Internal "Malicious" Crate**: A simple Rust project published to a private registry used specifically for security testing.
- **Threat Modeling frameworks**: Use a framework like [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) to brainstorm potential attack vectors in your supply chain.
- **Incident Response Plan (IRP)**: A documented plan that details the steps to take during a supply chain compromise. This should be reviewed and updated after every exercise.

### Metrics/Signal
- **Exercise Success Rate**: What percentage of simulated attacks were automatically blocked or detected?
- **Mean Time to Remediate (MTTR)**: In a simulation, how long did it take from detection to the "malicious" code being identified and removed?
- **Team Confidence Score**: Survey developers after an exercise to gauge their understanding of and confidence in the security processes.
{% endblock %}