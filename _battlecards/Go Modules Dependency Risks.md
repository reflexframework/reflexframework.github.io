---
 permalink: /battlecards/godeps
battlecard:
 title: Go Modules Dependency Risks
 category: Package Ecosystem
 scenario: Go + modules
 focus: 
   - vanity imports 
   - private/public repo mix-ups 
---

An attacker targets "WidgetCorp," a company that uses Go and maintains both public and private repositories on GitHub. The attacker identifies a vanity import path, `widget.corp/internal/auth`, used across WidgetCorp's public projects. This vanity path is intended to resolve to a private repository, `github.com/WidgetCorp-private/auth`.

The attacker registers the public repository path that could be a potential resolution target, `github.com/WidgetCorp/auth` (or takes over the old, unmaintained public repository if one existed). They publish a malicious Go module to this public repository with a higher version number (e.g., `v1.99.0`) than the legitimate private one.

The attack succeeds when a developer with a misconfigured `go` environment (missing `GOPRIVATE`) or a CI/CD pipeline without proper safeguards runs `go get -u` or `go mod tidy`. The Go command, unable to distinguish the private module, resolves `widget.corp/internal/auth` to the public, malicious repository due to the higher version tag, injecting the attacker's code into the build. The malicious code, executed via an `init()` function during testing or compilation, steals secrets from the build environment and exfiltrates them to the attacker's server.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's goal is to discover your internal package names and exploit ambiguities in how they are resolved. They will scan your public code repositories, read your documentation, and analyze your `go.mod` files to find your vanity import paths (e.g., `your.company/pkg/utils`). They treat your organization as a black box and probe it: does `your.company/pkg/utils` resolve publicly? Is the corresponding public repository available for registration? They are essentially looking for a namespace they can squat on that your own tools might accidentally use.

### Insight
A vanity import URL is a contract. It promises that a human-friendly name will always resolve to a specific code repository. Attackers probe these contracts for weaknesses, such as inconsistent configurations between developer laptops and CI/CD systems, or between different projects within your organization. The attacker is betting on a single misconfiguration in a complex system.

### Practical
- **Audit your public footprint:** Search GitHub, GitLab, and other public registries for packages that use your company's name or vanity URL patterns.
- **Map your dependencies:** Use `go list -m all` on your main projects and identify all modules that use your internal vanity domain. Cross-reference this list with what is publicly resolvable.
- **Check your vanity server:** Use `curl -L 'https://your.company/pkg/utils?go-get=1'` to see the HTML response containing the `go-import` meta tag. Is this endpoint public? Does it leak information about your private repository structure?

### Tools/Techniques
- **Google Dorking:** Use advanced search queries like `site:github.com "your.company/pkg/"` to find public files that reference your internal modules.
- **GitHub Code Search:** Search across all of public GitHub for your vanity URL to see if third parties are trying (and failing) to import your private packages, which is a strong signal of a potential mix-up.
- **[go-mod-graph-viewer](https://github.com/subchen/go-mod-graph-viewer):** A tool to visualize your project's dependency graph, making it easier to spot unexpected or non-standard packages.

### Metrics/Signal
- **Number of private package paths that have a publicly available namespace.** A value greater than zero indicates a potential for dependency confusion.
- **Inbound traffic logs on your vanity URL server.** An unusual number of requests from unknown IP addresses could signal an attacker's reconnaissance efforts.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage involves looking inward to assess how vulnerable your development lifecycle is to this attack. The key weakness is inconsistency. A developer must ask: "Is my local `go` environment configured the same way as my teammate's? Is it the same as our CI/CD pipeline's?" If `go get` behaves differently in different places, you have a vulnerability. The evaluation focuses on your Go environment variables (`GOPRIVATE`, `GOPROXY`), your Git configuration, and the assumptions your build scripts make.

### Insight
The most secure system in the world can be compromised by the least-configured developer environment that contributes to it. This attack doesn't target a code vulnerability (like an SQL injection); it targets a *process and configuration* vulnerability. Your `go.mod` file is a manifest of intent, but the final build artifact is a product of the environment it was built in.

### Practical
- **Run `go env`:** On your local machine, a teammate's machine, and a CI/CD runner, execute `go env` and compare the output. Pay close attention to `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, and `GOPROXY`.
- **Audit CI/CD pipeline definitions:** Check your `.github/workflows/`, `.gitlab-ci.yml`, etc. Are the Go environment variables hardcoded and enforced for every build step? Or is it possible for a step to run with a default, insecure configuration?
- **Check repository access:** Can your build systems access your private repositories using SSH keys or do they fall back to HTTPS? An HTTPS fallback can sometimes bypass certain private resolution configurations.

### Tools/Techniques
- **Environment Auditing Script:** Write a simple shell script that you can run in your CI pipeline to print the key `go env` variables and fail the build if they don't match the expected secure values.
- **[pre-commit](https://pre-commit.com/):** Use pre-commit hooks to run a script that checks for a properly configured `GOPRIVATE` on a developer's machine before they can commit code.

### Metrics/Signal
- **Percentage of build agents and developer machines with a centrally-managed, correct Go environment configuration.** Aim for 100%.
- **Number of distinct `GOPROXY` configurations found across your organization.** A high number indicates inconsistency and risk.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your system means making the secure path the only path. You must explicitly tell the Go toolchain which packages are private and should never be looked for in public sources. This is done by configuring every Go environment to know about your private repositories and, ideally, routing all dependency requests through a trusted, private proxy that can enforce these rules.

### Insight
The principle of "explicit is better than implicit" is critical here. The Go toolchain's default behavior is to be helpful and look everywhere it can. Your job is to constrain that behavior. By setting `GOPRIVATE`, you are telling the Go tools: "For these specific paths, do not *ever* consult public sources like the Go proxy or checksum database."

### Practical
- **Enforce `GOPRIVATE`:** Use environment variables in your CI/CD system to set `GOPRIVATE="your.company/*"`. For developer machines, use shell profiles (`.bashrc`, `.zshrc`) or a tool to manage environment variables.
- **Use a Private Go Proxy:** Set up a proxy that has access to both your private repositories and public modules. Point all developers and CI/CD systems to this proxy using `GOPROXY`. This centralizes control, logging, and caching.
- **Use Git `insteadOf`:** To ensure Git always uses SSH for your private organization, configure it with `git config --global url."git@github.com:WidgetCorp-private/".insteadOf "https://github.com/WidgetCorp-private/"`. This prevents credential prompts and potential leaks.
- **Archive, Don't Delete:** If you move a public repository to a private one, do not delete the old public repo. Archive it, make it read-only, and add a prominent `README.md` file explaining that it is deprecated and no longer maintained. This prevents an attacker from reclaiming the namespace.

### Tools/Techniques
- **[Athens](https://github.com/gomods/athens):** An open-source, self-hostable Go module proxy.
- **[JFrog Artifactory](https://jfrog.com/artifactory/):** A commercial artifact repository that can serve as a secure Go proxy and provides fine-grained access control.
- **[GitHub Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-go-registry):** Use GitHub's built-in package registry to host your private Go modules.

### Metrics/Signal
- **All CI/CD build pipelines successfully use a private `GOPROXY` endpoint.** Monitor proxy logs to confirm traffic.
- **A build fails if `GOPRIVATE` is not set correctly.** This demonstrates that your hardening is being enforced automatically.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and their malicious code is now inside your build environment. The goal is to contain the "blast radius." What can that code actually do? Can it access production keys? Can it connect to the internet? Limiting the damage means building your software in a minimal, zero-trust environment where the build process has only the permissions it absolutely needs to do its job and nothing more.

### Insight
The moment `go test` or `go build` runs, you are executing third-party code, including potentially malicious `init()` functions. Treat your build pipeline with the same security scrutiny as your production environment. It's an executable environment that can be an attractive target for attackers.

### Practical
- **Ephemeral and Sandboxed Build Environments:** Each CI/CD job should run in a fresh, clean container or VM that is destroyed afterward.
- **Minimize Network Access:** Use container networking policies (e.g., Kubernetes `NetworkPolicy`) to deny all egress traffic from build containers by default. Only allow connections to your trusted Go proxy and version control system.
- **Use Short-Lived Credentials:** Avoid static, long-lived secrets in the build environment. Use OpenID Connect (OIDC) to issue short-lived, narrowly-scoped credentials to the build job just-in-time.
- **Scan Dependencies:** Use a Software Composition Analysis (SCA) tool to scan your `go.mod` for known vulnerabilities or malicious packages *before* the build starts.

### Tools/Techniques
- **[gVisor](https://gvisor.dev/):** A container sandbox that can limit the system calls a build process can make, preventing many common exploits.
- **Kubernetes `NetworkPolicy`:** A standard Kubernetes resource for controlling network traffic between pods.
- **[HashiCorp Vault](https://www.vaultproject.io/):** A tool for managing secrets and generating short-lived credentials for applications and CI/CD jobs.
- **[SLSA Framework](https://slsa.dev/):** Adopt SLSA principles to generate signed, verifiable provenance for your builds, ensuring that you can prove exactly which source code and dependencies went into a build artifact.

### Metrics/Signal
- **Time-To-Live (TTL) on build credentials.** This should be measured in minutes, not hours or days.
- **Number of allowed egress network destinations from a build container.** This number should be small and well-defined (e.g., 3: GitHub, your Go proxy, your artifact registry).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack, you need visibility into your build process. What dependencies are being downloaded? From where? What is the build process doing? An attack reveals itself as an anomaly: a private package is suddenly downloaded from a public URL, a test run makes an unexpected network connection, or the checksum of a module changes unexpectedly. Effective detection relies on logging these events and alerting on deviations from the established baseline.

### Insight
Your build logs are a rich source of security-relevant data. Don't treat them as just a stream of text to be ignored unless the build fails. By structuring and analyzing these logs, you can turn your CI/CD system into a sophisticated intrusion detection system for your software supply chain.

### Practical
- **Log All Dependency Resolutions:** Centralize the logs from your private Go proxy. Every module download for every build should be logged, including the module path, version, and source URL.
- **Monitor Network Traffic:** In your CI/CD environment, monitor all outbound DNS queries and network connections made by the build container. Alert on any connection to a destination that is not on an allow-list.
- **Checksum Verification:** The `go.sum` file is a critical security control. Ensure your build process *never* skips this check. Log and alert on any instance where a module is added to `go.sum` from a source that is not your private proxy.
- **Log Build Provenance:** After a successful build, generate and store a log of exactly what went into it. Run `go list -m -json all` and save the output. This creates an immutable record you can audit later.

### Tools/Techniques
- **[Falco](https://falco.org/):** An open-source runtime security tool that can detect unexpected application behavior, such as a Go test process opening a network connection.
- **[Socket.dev](https://socket.dev/) or [Snyk](https://snyk.io/):** Security tools that can be integrated into your CI pipeline to monitor dependencies for suspicious attributes (e.g., new maintainers, obfuscated code in install scripts).
- **SIEM (Security Information and Event Management):** Forward your Go proxy logs and CI/CD network logs to a SIEM (like Splunk or Elastic) to create dashboards and alerts for anomalous activity.

### Metrics/Signal
- **Alert fires when the resolved source of a `GOPRIVATE` package is a public URL.** This is a high-fidelity signal that a dependency confusion attack is underway.
- **A non-zero count of outbound network connections from a `go test` job to an untrusted IP address.**

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build resilience, you must practice defending against this attack. This involves running controlled drills where you simulate the attacker's actions. The goal is to test whether your `Fortify`, `Limit`, and `Expose` controls work as expected. These exercises build "muscle memory" for developers and security teams, making the response to a real attack faster and more effective.

### Insight
Security exercises are not about assigning blame; they are about finding weaknesses in the *system*, not in the people. A successful drill is one where you learn something new, whether that's a gap in your monitoring, a confusing alert, or an opportunity to simplify a security process for developers.

### Practical
- **Run a "Red Team" Drill:**
1. **Setup:** Have one team member (the "attacker") create a public repository at a path that mimics a private one (e.g., `github.com/some-user/auth`). Publish a simple Go module there.
2. **Simulate:** The attacker then asks another developer (the "target") to try and build a project after temporarily commenting out the `GOPRIVATE` variable in their local environment or a branch of a test project in CI.
3. **Observe:** Does the build pull the malicious package? Do your monitoring tools generate an alert? Does the sandboxed build environment block the malicious code from doing anything dangerous (like making a network call)?
- **Tabletop Exercise:** Gather the development team and walk through the attack scenario verbally. Ask questions like: "What would you do if you saw a build log showing a private package was downloaded from GitHub? Who would you notify? What's the first command you would run to investigate?"
- **Review and Improve:** After each exercise, document what worked and what didn't. Create action items to fix the gaps (e.g., "Improve the alert message for dependency confusion events," "Add a link to the runbook in the CI/CD failure message").

### Tools/Techniques
- **[Caddy Server](https://caddyserver.com/):** A simple, easy-to-configure web server you can use to temporarily host a fake vanity URL page for a drill.
- **Dedicated Test Project:** Maintain a sample Go project in your source control specifically for running these security drills.
- **Runbook:** Create a markdown document in your team's wiki or repository that details the step-by-step procedure for responding to a suspected supply chain compromise.

### Metrics/Signal
- **Time to Detect (TTD):** How long does it take from the moment the malicious package is injected into a build to the moment an automated alert is generated?
- **Developer Confidence Score:** After a drill, survey the developers involved. How confident are they in their ability to detect and respond to this type of attack? This qualitative metric helps measure the effectiveness of your training and tooling.
{% endblock %}