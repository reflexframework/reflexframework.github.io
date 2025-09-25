---
 permalink: /battlecards/lockfile-and-semver
battlecard:
 title: Lockfile and SemVer Range Abuse
 category: Package Ecosystem
 scenario: Lockfile & SemVer Range Abuse
 focus: 
   - lockfile tampering 
   - caret/tilde version drift 
   - dependency version pinning bypass 
---

An attacker identifies a popular open-source project that uses a permissive version range for one of its less-maintained, indirect dependencies. For example, a widely-used Node.js web framework depends on `utility-parser: ^1.4.2`.

The attacker gains control of the `utility-parser` package, either by social engineering the original maintainer or compromising their account. They publish a new malicious patch version, `1.4.3`. This new version contains the original functionality plus a subtle backdoor that reads environment variables (like `AWS_SECRET_ACCESS_KEY`) and sends them to the attacker's server, but only when it detects it's running in a production environment (e.g., `NODE_ENV=production`).

A developer on a target team, running a routine `npm install` to update packages, unknowingly pulls in the malicious `utility-parser@1.4.3`. Their `package-lock.json` file is updated. Because it's "just a patch update," the change is approved with minimal scrutiny and merged. The CI/CD pipeline builds the application with the compromised package and deploys it to production, where the backdoor activates and exfiltrates the company's cloud credentials.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers don't start by writing code; they start by researching targets. They scan public repositories on platforms like GitHub or GitLab, looking for dependency manifests like `package.json`, `pom.xml`, or `requirements.txt`. Their goal is to find projects that rely on dependencies with loose Semantic Versioning (SemVer) ranges, such as `^1.4.2` (caret) or `~1.4.2` (tilde). These ranges automatically accept new minor and patch versions, creating a window of opportunity. The attacker then cross-references these dependencies to find ones that are poorly maintained, have few contributors, or have maintainer accounts with weak security, making them easier to compromise. This is called a supply chain attack, where they poison a dependency rather than attacking the target application directly.

### Insight
The most attractive targets for attackers aren't always the biggest libraries like React or Express. They are often the smaller, forgotten "transitive" dependencies—the dependencies of your dependencies. A single, obscure utility package could be used by hundreds of other packages, giving an attacker a massive blast radius from a single compromise.

### Practical
A developer can think like an attacker by auditing their own project. Use built-in tooling to view the entire dependency tree, not just the packages you explicitly installed. Pay close attention to the small, single-purpose libraries deep in the tree. Ask questions like: "Who maintains this? When was it last updated? How many other projects depend on it?"

### Tools/Techniques
*   **GitHub Code Search**: Attackers use advanced search queries to find `package.json` files with specific vulnerable packages or versioning patterns.
*   **npm ls `[package-name]`**: A developer can use this command to see where a specific dependency is coming from in their project's dependency tree.
*   **Dependency Graph Tools**: Tools like [Snyk's dependency graph](https://snyk.io/product/software-composition-analysis/), GitHub's built-in `Dependency graph`, or [Socket.dev](https://socket.dev/) can visualize the entire supply chain, making it easier to spot obscure, risky dependencies.

### Metrics/Signal
*   **Dependency Tree Depth**: A very deep dependency tree can be a signal of complexity and increased attack surface.
*   **Number of Unmaintained Dependencies**: A high count of dependencies that haven't been updated in over a year.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is the "look in the mirror" stage. A developer can assess their project's vulnerability by examining their own practices. Do you use ranged dependencies (`^`, `~`) in your `package.json`? If so, you are explicitly trusting the maintainers of those packages not to introduce a malicious patch. More importantly, how does your build process work? If your CI/CD pipeline runs `npm install` instead of `npm ci`, it might ignore the lockfile and fetch a newer, potentially malicious version of a dependency. The core vulnerability is a mismatch between the declared dependency range and the locked, tested version, combined with a build process that doesn't enforce the lock.

### Insight
A `package-lock.json` file is not just a performance optimization. It is a security control. It represents the exact, reproducible set of dependencies that you have tested and vetted. If your development and CI processes don't treat it as the single source of truth, it provides a false sense of security. The difference between `npm install` (which can modify the lockfile) and `npm ci` (which installs exactly from the lockfile or fails) is critical.

### Practical
1.  **Review your `package.json`**: Search for `^` and `~`. For each one, ask: "Do we have a strong reason to trust every future patch/minor release of this package implicitly?"
2.  **Inspect your CI/CD configuration (`.gitlab-ci.yml`, `Jenkinsfile`, etc.)**: Look for the package installation step. Does it use `npm install`, `yarn`, or `pip install -r requirements.txt`? It should be using the strict/frozen lockfile equivalents.
3.  **Check Pull Requests**: When a developer updates dependencies, does the PR reviewer scrutinize the lockfile changes? A change from `utility-parser` version `1.4.2` to `1.4.3` should be questioned just as much as a code change.

### Tools/Techniques
*   **Strict Install Commands**: Use `npm ci`, `yarn install --frozen-lockfile`, or `pip install -r requirements.txt --require-hashes` in automated environments.
*   **Linters**: Custom scripts or policies in tools like [Trivy](https://github.com/aquasecurity/trivy) can be configured to fail a build if it detects ranged dependencies in a `package.json`.

### Metrics/Signal
*   **Percentage of Pinned vs. Ranged Dependencies**: Track the ratio of dependencies in `package.json` that are pinned to an exact version. Aim for 100%.
*   **Build Log Warnings**: Monitor build logs for warnings about lockfile mismatches or automatic updates.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your project means establishing trust and then enforcing it. The first step is to "pin" your dependencies to exact versions in your `package.json`. This eliminates version drift. The second, and most crucial, step is to use a lockfile that includes cryptographic hashes of each package (e.g., `package-lock.json`'s `integrity` field). Finally, you must configure your CI/CD pipeline to use a strict installation command (`npm ci`) that validates and installs *only* what is specified in the lockfile. If the `package.json` and the lockfile disagree, the build should fail. This makes your build process deterministic and tamper-resistant.

### Insight
Think of your dependency installation as a financial transaction. Your `package.json` is a request ("I'd like to buy milk, preferably around version 2%"). Your `package-lock.json` is the final, itemized receipt ("You received Organic Valley 2% Milk, Lot #A4B2, for $3.99"). Running `npm install` is like telling the cashier to "just ring me up for what I asked for," while `npm ci` is like saying "charge me for exactly what is on this receipt, and if anything doesn't match, cancel the whole transaction."

### Practical
*   **For Node.js**: In your CI pipeline script, replace `npm install` with `npm ci`.
*   **For Python**:
1.  Use a tool like `pip-tools` to compile a `requirements.in` file (where you list your direct dependencies) into a `requirements.txt` file, which pins the full tree.
2.  Run `pip-compile --generate-hashes` to add `--hash` entries for each package.
3.  In your CI pipeline, use `pip install -r requirements.txt --require-hashes`.
*   **Adopt a Private Registry**: Use a tool like [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository) to act as a proxy. You can cache and approve specific versions of open-source packages, preventing your developers or build systems from fetching anything that hasn't been vetted.

### Tools/Techniques
*   **Package Managers**: `npm ci`, `yarn install --frozen-lockfile`, `pnpm install --frozen-lockfile`.
*   **Dependency Management Tools**: [pip-tools](https://github.com/jazzband/pip-tools) for Python, [Dependabot](https://github.com/dependabot) for automated and secure dependency updates.
*   **Supply Chain Security Platforms**: [Socket.dev](https://socket.dev/) or [Snyk](https://snyk.io/) can be integrated into your CI pipeline to scan for not just known vulnerabilities, but also suspicious package behavior (e.g., a patch release that adds network access).

### Metrics/Signal
*   **CI Build Failures on Lockfile Mismatch**: A CI build that fails because of a `package-lock.json` mismatch is a sign the system is working correctly.
*   **Package Hash Verification Failures**: An installation that fails due to a hash mismatch is a critical signal of potential package tampering.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Even with the best defenses, assume a breach is possible. Limiting the blast radius means ensuring that if malicious code *does* get into your application, it can't do much damage. This is achieved through the principle of least privilege. Your application's runtime environment should be aggressively constrained. For example, if your web application has no legitimate reason to access environment variables other than its database connection string, it should be blocked from reading anything else. If it never needs to write to the filesystem or spawn a new process, those permissions should be revoked at the container or OS level.

### Insight
The malicious code from our scenario needed two things to succeed: access to environment variables and egress network access to the attacker's server. By denying one or both of these at the infrastructure level, the attack would have been rendered useless, even though the malicious code was present. Security should be layered; don't just rely on preventing the breach, also plan to contain it.

### Practical
*   **Container Security**: Run your application in a Docker container as a non-root user (`USER someuser`). Make the container's root filesystem read-only (`--read-only`) and only mount specific directories that require write access (like `/tmp`) as temporary filesystems.
*   **Network Policies**: If using Kubernetes, define strict `NetworkPolicy` objects. Create a default-deny policy, then explicitly allow only the traffic your application needs (e.g., "allow egress traffic only to `tcp/5432` on the pods in the `postgres` namespace"). This would have blocked the credential exfiltration to the attacker's random IP address.
*   **Environment Variable Management**: Use a secret management system like [HashiCorp Vault](https://www.vaultproject.io/) or your cloud provider's service (e.g., AWS Secrets Manager). Inject secrets into the application at runtime, rather than using traditional environment variables, which are often broadly accessible to the running process.

### Tools/Techniques
*   **Containerization**: [Docker](https://www.docker.com/), using security-enhancing features.
*   **Orchestration**: [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
*   **Kernel Security**: Use profiles for [seccomp-bpf](https://docs.docker.com/engine/security/seccomp/) or [AppArmor](https://wiki.ubuntu.com/AppArmor) to restrict the specific system calls a process can make.

### Metrics/Signal
*   **Network Policy Violations**: Alerts from your CNI (e.g., Calico, Cilium) that a pod attempted to make a blocked network connection.
*   **Filesystem Write Errors**: Logs from a container showing "permission denied" errors when trying to write to a read-only path.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Detection focuses on observing behavior that deviates from the norm. To know you are under attack, you need visibility into your build process and your application's runtime behavior. During the build, log every dependency that is downloaded, including its version and hash. In production, the key is to monitor for anomalies. Does your Node.js web server suddenly spawn a shell process (`/bin/sh`)? Is it making DNS requests for a domain it has never contacted before? Is it trying to read files like `~/.aws/credentials`? These are strong indicators of compromise.

### Insight
The malicious code is designed to hide. It won't announce itself. Your best chance of catching it is by establishing a baseline of normal behavior and then alerting on any deviation. Modern attacks are often silent, focusing on data exfiltration, so monitoring for unusual outbound network traffic is one of the most effective detection strategies.

### Practical
*   **Log Dependency Resolutions**: Configure your build system to produce a verbose log of all packages being fetched. Periodically review these logs or feed them into an analysis system to look for unexpected packages or versions.
*   **Monitor System Calls**: Use a runtime security tool to monitor the system calls your application makes. A web application process executing `execve` to run a shell is a massive red flag.
*   **Monitor Network Egress**: Log all outbound connections and DNS queries from your application pods. Alert on connections to new or suspicious destinations (e.g., raw IP addresses, domains with low reputation).

### Tools/Techniques
*   **Runtime Threat Detection**: Open-source tools like [Falco](https://falco.org/) can be used to detect anomalous application behavior in real-time by tapping into kernel system calls.
*   **Log Aggregation**: Platforms like [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or an [ELK Stack](https://www.elastic.co/what-is/elk-stack) are essential for collecting and analyzing logs from all your systems to spot suspicious patterns.
*   **Dependency Auditing Tools**: Tools like [Socket.dev](https://socket.dev/) can be configured to alert you when a new version of a dependency is published that introduces risky behavior, such as accessing the network or filesystem for the first time.

### Metrics/Signal
*   **Spawning of Shell Processes**: An alert that `nginx`, `java`, or `node` has spawned a `sh` or `bash` process.
*   **Anomalous DNS Queries**: A spike in queries to new or algorithmically generated domains.
*   **Unexpected File Access**: An alert that your application process attempted to read from `/etc/passwd` or `~/.ssh/id_rsa`.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build muscle memory, you must practice. A security exercise, or "game day," involves simulating the attack in a controlled environment to test your defenses. The goal is to see if your people, processes, and tools can successfully prevent or detect the attack. This isn't about blaming individuals; it's about finding the gaps in your system before a real attacker does.

### Insight
A security policy is just a document until it's tested. You might have a rule that "all lockfile changes must be scrutinized," but a drill will show you if developers actually do it under the pressure of daily work. The most valuable outcome of an exercise is not a "pass" or "fail," but the conversation it sparks about how to improve.

### Practical
**The "Malicious Patch" Drill**:
1.  **Setup**: A designated "red team" member creates a harmless look-alike package. They publish a new "malicious" patch version (`1.1.2`) of an internal, non-critical dependency to a private package registry ([Verdaccio](https://verdaccio.org/) is great for this). The "malicious" payload could be as simple as writing a file to `/tmp/attack_drill.txt` or making a DNS query to `attack-drill.your-company.com`.
2.  **Execution**: A developer on the red team runs `npm install` on a test project that depends on the target package with a range (`^1.1.0`). This updates their `package-lock.json` to include the new "malicious" `1.1.2` version. They submit a pull request with the title "chore: update dependencies."
3.  **Observation**: The team observes:
*   **Code Review**: Does the PR reviewer spot the suspicious, small version bump in the lockfile and question it?
*   **CI Pipeline**: Does your CI pipeline have a check that fails the build because a new, unvetted dependency was introduced?
*   **Runtime Detection**: If it gets deployed to a staging environment, do your monitoring tools (like Falco) detect the file write or the anomalous DNS query and fire an alert?
4.  **Debrief**: The whole team discusses the results. What worked? What didn't? Do we need to add a new CI check? Do we need to provide more training on reviewing lockfiles?

### Tools/Techniques
*   **Private Registries**: [Verdaccio](https://verdaccio.org/) (Node.js), [devpi](https://github.com/devpi/devpi) (Python).
*   **Game Day Platforms**: Use your existing CI/CD and monitoring tools to run the exercise.
*   **Documentation**: Record the results and action items in your team's wiki (e.g., Confluence, Notion).

### Metrics/Signal
*   **Mean Time to Detection (MTTD)**: How long did it take from the PR submission to someone (human or machine) flagging the issue?
*   **Drill Success Rate**: Percentage of drills that are successfully blocked or detected by automated systems versus those requiring manual intervention.
*   **Team Feedback**: Qualitative feedback from developers on whether the training was useful and what could be improved.
{% endblock %}