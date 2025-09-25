---
 permalink: /battlecards-and-vendored-code-drift/
battlecard:
 title: Submodule and Vendored Code Drift
 category: Source Control
 scenario: Monorepo/Submodule/Vendored Drift
 focus: 
   - malicious submodules 
   - outdated vendored code 
   - bypassing SCA checks 
---

An attacker targets a popular open-source Machine Learning (ML) project that uses a Git submodule to include a custom data-processing library. The attacker finds that the project's CI pipeline pulls the submodule using a floating reference (`-b main`) instead of a pinned commit hash.

After gaining access to the library maintainer's account via a leaked credential, the attacker pushes a malicious commit to the library's `main` branch. This new code appears benign but is engineered to scan the build environment for environment variables prefixed with `AWS_`, `GCP_`, or `AZURE_`, and then exfiltrate them to the attacker's server during the build's "test" phase.

Because the main project's CI automatically pulls the latest `main` branch of the submodule, the next Pull Request triggers a build that unknowingly executes the malicious code. The project's Software Composition Analysis (SCA) tool only scans the `requirements.txt` file and is not configured to analyze the submodule's source code, allowing the attack to go completely undetected. The attacker now has the project's cloud credentials, compromising the entire infrastructure.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They aren't trying to break in yet; they're looking for the easiest way in. For this scenario, they are hunting for projects that manage dependencies insecurely. They’ll look for source code management practices that create blind spots, like using submodules that track a branch instead of a specific commit, or large chunks of "vendored" code (third-party code copied directly into your repository). These are perfect hiding places for malicious code because they are often trusted implicitly and skipped by security scanners.

### Insight
Attackers love complexity and drift. The more complex your dependency tree, especially with non-standard dependencies like submodules or vendored code, the more likely it is that something is unmonitored. They know that developers are under pressure to ship features and may not perform a line-by-line review of a "minor" submodule update. They are exploiting a gap between how code is managed and how it's secured.

### Practical
*   **Audit your dependencies:** Go beyond `package.json` or `pom.xml`. Look for `.gitmodules` files or directories like `vendor/` or `third_party/`.
*   **Analyze your CI/CD configuration:** Look at files like `.github/workflows/ci.yml` or `.gitlab-ci.yml`. Search for commands like `git submodule update --remote`. This command is a red flag because it pulls the latest changes from a submodule's branch, not a specific pinned commit.
*   **Review contributor access:** Who can merge to `main` in your dependencies' repos? If you rely on a small, unmaintained submodule, its maintainer is a single point of failure.

### Tools/Techniques
*   **GitHub Code Search:** Attackers use advanced search queries to find vulnerable configurations, e.g., `filename:.gitmodules` combined with `filename:.github/workflows "git submodule update --remote"`.
*   **Public Git history:** Tools like `truffleHog` or `gitleaks` aren't just for finding secrets in *your* repo. Attackers can scan the history of your dependencies to understand their security posture and look for compromised maintainer accounts.

### Metrics/Signal
*   **Number of unpinned submodules:** Any submodule tracking a branch is a potential vulnerability. The goal should be zero.
*   **Age of vendored code:** A metric showing the last time vendored code was updated or audited. Code that hasn't been touched in years is a sign of drift and potential unpatched vulnerabilities.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is your internal threat assessment. You're putting yourself in the attacker's shoes and examining your own project. How easy would it be to sneak malicious code into your build via a submodule or vendored dependency? Does your SCA scanner even look at that code? Do your pull request review processes require scrutiny for these types of changes? The goal is to find your blind spots before an attacker does.

### Insight
Developers often have a strong sense of ownership over the code they write but a weaker sense of ownership over the code they import. This creates a psychological blind spot. We trust that a dependency, especially if it's vendored or included as a submodule, is "done" and doesn't need the same level of scrutiny as application code. This is exactly the assumption attackers rely on.

### Practical
*   **Manually inspect your `.gitmodules` file:** Check if your submodules are pinned to a specific commit hash. If they point to a branch, you are vulnerable.
*   **Run a "grep test":** Can you easily find all vendored code in your repository? `grep -r "Copyright (c) 2018 SomeThirdParty"` might reveal code you didn't even know was there.
*   **Challenge your SCA tool:** Manually introduce a known vulnerability (e.g., using an old, insecure function) into a submodule or vendored directory. Run your SCA scan. Did it find it? If not, you have a coverage gap.
*   **Review PRs with submodule updates:** Look at recent pull requests that updated a submodule. Did the reviewer just see `Subproject commit <hash1>...<hash2>` and approve it? Or did they click through and review the actual code changes in the submodule's repository?

### Tools/Techniques
*   **Your own Git client:** Use `git submodule status` to see exactly which commit each submodule is pointing to. Use `git log --submodule` to review changes.
*   **SCA Tools with comprehensive scanning:**
*   [Snyk](https://snyk.io/): Can be configured to scan submodules and has features for monitoring code dependencies.
*   [GitHub Advanced Security](https://docs.github.com/en/code-security/dependabot): Dependabot can be configured for submodules, and CodeQL can scan the source of vendored code.
*   **Source Code Scanners (SAST):**
*   [Semgrep](https://semgrep.dev/): Use it to write custom rules to scan your vendored directories for deprecated or dangerous functions.
*   [CodeQL](https://codeql.github.com/): Can perform deep semantic code analysis on vendored dependencies just as it does on your own code.

### Metrics/Signal
*   **SCA/SAST tool coverage score:** A percentage indicating how much of your codebase (including submodules and vendored code) is being actively scanned.
*   **Time-to-patch for vendored code:** How long does it take for your team to update a vendored dependency after a new version is released? A long delay indicates a poor maintenance process.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is the hardening phase. Based on your evaluation, you'll now implement changes to your code, tools, and processes to close the identified gaps. The core principle is to treat all code, whether you wrote it or imported it, with the same level of suspicion. This means locking down dependencies to known-good versions and ensuring all code is scanned before it gets built.

### Insight
The goal is to make your build process deterministic and auditable. A build should produce the exact same result today as it did yesterday if the inputs are the same. Using floating branches for submodules or un-versioned vendored code introduces non-determinism, which is an enemy of security and reliability.

### Practical
*   **Pin your submodules:** This is the most critical fix. Instead of tracking a branch, always pin your submodule to a specific, audited commit hash.
*   Before: `git submodule add -b main https://github.com/some/dependency.git`
*   After: Go into the submodule directory, `git checkout <specific-commit-hash>`, go back to the parent repo, and commit the change. The `.gitmodules` file will now point to a fixed commit.
*   **Automate dependency updates securely:** Use tools like [Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file) or [Renovate](https://www.mend.io/free-developer-tools/renovate/). They will create pull requests to update your pinned submodule commits, allowing you to review the changes before merging.
*   **Implement a policy for vendored code:** Create a `VENDORED_CODE_POLICY.md` in your repo. It should state that any update to vendored code requires a link to the upstream release notes and a line-by-line review from two engineers.
*   **Integrate deeper scanning into CI:** Configure your CI pipeline to explicitly run a SAST tool like Semgrep or CodeQL on your submodule and vendored code directories during every build. Fail the build if new, high-severity issues are found.

### Tools/Techniques
*   **Git:** Use `git config --global submodule.recurse true` to make sure your submodules are always in sync.
*   **CI/CD Pipeline Configuration:**
*   **GitHub Actions:** Use a workflow step to run a script that verifies no submodules are tracking a branch.
*   **GitLab CI:** Use `pre-build` scripts to perform the same checks.
*   **Policy as Code:**
*   [Open Policy Agent (OPA)](https://www.openpolicyagent.org/): Can be used to enforce rules in your CI/CD pipeline, such as "fail the build if a submodule reference is not a commit hash."

### Metrics/Signal
*   **Number of pinned vs. unpinned dependencies:** Track the ratio of dependencies (submodules, vendored libraries) that are pinned to a specific version. Aim for 100%.
*   **CI build failures due to policy violations:** An increase in builds failing because of security policy checks (like an unpinned submodule) is a good sign that your automated controls are working.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker succeeded and malicious code is now running in your CI/CD pipeline. The "Limit" stage is about damage control. How can you minimize the harm? The key is to run your build and test processes in a sandbox with the least possible privilege. If the malicious code executes, it shouldn't be able to access production secrets, other systems, or exfiltrate sensitive data.

### Insight
Modern CI/CD systems are powerful, distributed computers. Developers often configure them with broad permissions for convenience (e.g., a single powerful `AWS_ACCESS_KEY_ID` for the entire pipeline). Attackers know this and specifically target build environments as a juicy source of credentials. The principle of least privilege is your strongest defense here.

### Practical
*   **Use ephemeral, isolated build agents:** Each CI job should run in a fresh, clean container or VM that is destroyed immediately after the job completes. This prevents persistence.
*   **Implement network egress controls:** Your build environment should not be allowed to make arbitrary outbound network connections. Use a proxy or firewall rules to whitelist only the domains it needs to function (e.g., your package repository, your company's artifact registry). This would block the attacker's exfiltration attempt.
*   **Use short-lived, scoped credentials:** Instead of storing long-lived secrets in your CI/CD environment, use a service that provides temporary, job-specific credentials.
*   For AWS, use IAM Roles for Service Accounts (IRSA) on EKS or IAM roles for EC2.
*   For GCP, use Workload Identity.
*   For HashiCorp Vault, use its JWT auth method.

### Tools/Techniques
*   **CI/CD Runners/Agents:**
*   [GitHub Actions hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners): These are ephemeral and isolated by default.
*   [Kubernetes-based runners (e.g., for GitLab or Jenkins)](https://docs.gitlab.com/runner/executors/kubernetes.html): Allows you to define `NetworkPolicy` to restrict network access for build pods.
*   **Network Policy:**
*   [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/): A powerful way to control traffic flow at the IP address or port level (OSI layer 3 or 4).
*   [Istio](https://istio.io/) or other service meshes can provide application-layer (L7) policy enforcement.
*   **Credential Management:**
*   [HashiCorp Vault](https://www.vaultproject.io/): A tool for managing secrets and providing short-lived credentials.
*   [Spiffe/Spire](https://spiffe.io/): An open-source standard for providing verifiable identities to software workloads.

### Metrics/Signal
*   **Number of denied network egress calls from CI:** This is a high-fidelity signal that something in your build is trying to phone home to an unauthorized location.
*   **Credential lifetime:** The average time-to-live (TTL) for credentials used in your CI pipeline. Shorter is better. Aim for minutes, not hours or days.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about visibility. How do you know an attack is happening? You need to collect the right signals (logs, events) and have a system to analyze them for anomalies. For this scenario, you'd want to know if a build process suddenly tries to connect to a weird IP address, or if a submodule is updated right before a build starts behaving strangely. Effective detection requires looking at multiple layers: the source code changes, the build environment behavior, and the network traffic.

### Insight
Attackers' actions often look like normal developer activity on the surface (e.g., pushing code, running a build). The key to detection is context and correlation. A submodule update is normal. A submodule update followed by the build process making a network call to a Dropbox IP is not. You need logging and monitoring that can connect these dots.

### Practical
*   **Log all Git operations:** Ensure your source control platform (GitHub, GitLab) has a detailed, accessible audit log. Log every push, merge, and change to repository settings.
*   **Monitor CI/CD runtime behavior:** Use runtime security tools to monitor what your build jobs are actually doing. What processes are they spawning? What files are they accessing? What network connections are they making?
*   **Centralize and analyze logs:** Ship your source control logs, CI/CD runner logs, and network flow logs to a centralized logging platform. Create dashboards and alerts for suspicious patterns.
*   **Alert idea:** `(submodule_updated) AND (new_network_destination_in_build)` within a 10-minute window.

### Tools/Techniques
*   **Audit Logs:**
*   [GitHub Audit Log](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-the-audit-log-for-your-enterprise)
*   [GitLab Audit Events](https://docs.gitlab.com/ee/administration/audit_events.html)
*   **Runtime Security Monitoring:**
*   [Falco](https://falco.org/): An open-source runtime security tool that can detect anomalous behavior inside containers using system calls. You can run it on your CI/CD nodes.
*   **Example Falco Rule:** `- rule: CI Credentials Exfiltration Attempt condition: spawned_process and container.image contains 'cicd-runner' and (proc.name = curl or proc.name = wget) and evt.arg.request contains 'api.dropbox.com' output: "Possible credential exfiltration from CI runner (user=%user.name command=%proc.cmdline)" priority: CRITICAL`
*   **Log Aggregation and Analysis:**
*   [OpenSearch/Elasticsearch](https://opensearch.org/): For storing and searching logs.
*   [Grafana Loki](https://grafana.com/oss/loki/): A log aggregation system designed to be easy to operate and scale.

### Metrics/Signal
*   **Mean Time To Detect (MTTD):** How long does it take from the moment the malicious commit is pushed to the moment your team gets an alert?
*   **Alert fidelity:** The ratio of true-positive alerts to false-positives. A noisy system will be ignored. Tune your alerts to only fire on high-confidence signals.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice. You can't wait for a real attack to test your defenses. You need to simulate attacks in a controlled way to build "muscle memory" for your team and find weaknesses in your tools and processes. A security exercise, or "game day," for this scenario would involve deliberately creating a "malicious" submodule and seeing if your fortified pipeline and detection systems catch it.

### Insight
Security is not just about tools; it's about people and process. An exercise reveals the human element: Do developers know what to do when they get an alert? Is the process for rotating compromised keys clear? Practicing builds confidence and dramatically reduces response time during a real incident.

### Practical
*   **Plan a Red Team exercise:**
1.  **Objective:** Test if a malicious submodule can exfiltrate a fake secret from the CI/CD pipeline without detection.
2.  **Setup:** Create a private repository to act as the "malicious" submodule. Add a simple script to it that `curl`s a fake secret to a controlled endpoint (like a [RequestBin](https://requestbin.com/) or a simple Netcat listener).
3.  **Execution:** Have a team member create a PR in a test application that adds this submodule and points to it.
4.  **Observe:** Did the build fail due to network policies? Did the SAST scan flag the `curl` command? Did Falco or another runtime tool generate an alert? Did the security team get notified?
*   **Conduct a tabletop exercise:**
*   Get the development and security teams in a room.
*   Present the scenario: "We just received a credible alert that our CI system's AWS keys were posted on a public forum. The last change to the main branch was a submodule update. What do we do, right now?"
*   Walk through the incident response plan step-by-step. This identifies gaps in the plan before a real crisis.
*   **Educate and train:** Use the findings from the exercise to create targeted training for developers. Show them examples of vulnerable `.gitmodules` files and explain *why* pinning is critical.

### Tools/Techniques
*   **Threat Modeling Frameworks:**
*   [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-stride-categories): Use this framework during design sessions to think about how a feature involving new dependencies could be attacked.
*   **CI/CD for the exercise:** Use a non-production CI/CD environment to run the test safely.
*   **Documentation and Runbooks:** Use tools like [Confluence](https://www.atlassian.com/software/confluence) or just Markdown files in a Git repo to document your incident response playbooks. The exercise is a great way to validate if they are accurate and useful.

### Metrics/Signal
*   **Exercise Success Rate:** Did the automated defenses block the simulated attack? (e.g., blocked / attempted attacks).
*   **Mean Time To Remediate (MTTR) during exercise:** How long did it take the team to identify the malicious submodule, rotate the fake secret, and fix the vulnerability in the exercise? This is a direct measure of your team's readiness.
{% endblock %}