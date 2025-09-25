---
 permalink: /battlecards/github-actions
battlecard:
 title: GitHub Actions Workflow Poisoning
 category: CI/CD
 scenario: GitHub Actions
 focus: 
   - poisoned workflows 
   - unpinned actions 
   - malicious PR triggers 
---

An attacker targets a popular open-source Python project that uses GitHub Actions for its CI/CD pipeline. The attacker's goal is to steal the project's `PYPI_API_TOKEN` to publish a malicious version of the popular library, thereby initiating a widespread supply chain attack.

The attacker identifies that the project's workflow uses the common `actions/setup-python@v4` action but doesn't pin it to a specific commit hash. They also notice the repository accepts PRs from forks and has a workflow that runs on the `pull_request_target` trigger, which is designed to run in the context of the base repository to, for example, label PRs.

The attacker forks the repository and submits a pull request with a benign-looking change, like fixing a typo in the `README.md`. However, in the *same PR*, they make a one-line modification to the `.github/workflows/ci.yml` file. They change the action `uses: actions/setup-python@v4` to `uses: malicious-forker/setup-python@main`. This points to their own malicious fork of the popular `setup-python` action.

Because the workflow uses the `pull_request_target` trigger, it runs with access to the repository's secrets. The malicious action code executes, reads the `secrets.PYPI_API_TOKEN` from the environment, and exfiltrates it to an attacker-controlled server using a simple `curl` command. The maintainer, seeing only a simple typo fix in the PR description, might overlook the subtle change in the workflow file and approve the workflow run, leading to the immediate theft of the publishing token.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They aren't trying to break anything yet; they're mapping out your project's processes and technology to find the weakest link. For our scenario, they will systematically search public repositories on GitHub for specific patterns in workflow files. They look for projects that use popular but unpinned third-party actions, especially those that run workflows from forked pull requests. They are essentially looking for unlocked doors.

The attacker uses GitHub's own search functionality with queries like `path:.github/workflows/ "pull_request_target"` or `path:.github/workflows/ "actions/checkout@v"`. They build a list of potential targets, prioritizing projects with many users (high impact) and responsive maintainers (more likely to merge a "helpful" PR quickly). They also study the contribution process to understand how to craft a PR that looks legitimate and is likely to be accepted.

### Insight
Attackers see your CI/CD configuration as a blueprint of your internal processes. The actions you use, the events that trigger them, and the permissions you grant are all clues. They understand that developers trust well-known actions (like `actions/checkout`) and may not scrutinize their versions, making this a high-value target for a supply chain attack.

### Practical
As a developer, you can perform the same reconnaissance on your own projects.
1.  Open your repository and navigate to the `.github/workflows` directory.
2.  Read through each `.yml` file. Do you see `uses:` lines with version tags like `@v3` or `@main`? These are potential vulnerabilities.
3.  Check which events trigger your workflows. If you see `on: pull_request_target`, understand that this workflow runs with elevated privileges and is a prime target.
4.  Look at the third-party actions you depend on. Who maintains them? Have they been updated recently?

### Tools/Techniques
*   **GitHub Code Search**: Use it on your own organization to find dangerous patterns (e.g., `org:my-org path:.github/workflows/ on: pull_request_target`).
*   **[OpenSSF Scorecard](https://github.com/ossf/scorecard)**: A tool that automatically scans your repository for security best practices, including `Pinned-Dependencies`.
*   **[grep.app](https://grep.app/)**: A public code search tool that attackers can use to find vulnerable configurations across all of GitHub.

### Metrics/Signal
*   **Number of unpinned actions**: Any number greater than zero is a risk.
*   **Number of workflows using `pull_request_target`**: Each instance increases your attack surface and requires careful review.
*   **Dependency freshness**: How old are the actions you depend on? Stale dependencies may have unpatched vulnerabilities.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage involves turning the lens inward to assess how vulnerable your specific environment is to the scenario. It's about asking, "Could that attack work against *us*?" You need to review your code, repository settings, and developer practices. A developer should simulate the attacker's mindset and examine their own workflows for the exact weaknesses the attacker is looking for: unpinned actions, overly permissive triggers (`pull_request_target`), and a code review process that might miss a subtle, malicious change in a workflow file.

### Insight
A common blind spot for developers is "configuration-as-code" fatigue. We are diligent about reviewing application code (`.py`, `.js`) but often treat workflow files (`.yml`) as "scaffolding" that, once working, is rarely scrutinized. Attackers know this and hide their malicious changes within these configuration files, counting on reviewers to focus on the application logic.

### Practical
1.  **Conduct a Workflow Audit**: Schedule time with your team to review every file in `.github/workflows`. For each third-party action, verify it is pinned to a full-length commit SHA, not a tag.
2.  **Review Repository Settings**: Go to `Settings > Actions > General`. Check the setting for "Fork pull request workflows from outside collaborators." Is it set to "Require approval for first-time contributors"? This is a critical safety net.
3.  **Assess the PR Process**: Review a few recently merged PRs from external contributors. Was the `.github` directory changed? If so, did the reviewer explicitly comment on and approve those specific changes?

### Tools/Techniques
*   **[StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)**: A GitHub Action you can add to your workflow to monitor for outbound traffic and other suspicious activities during a CI run.
*   **[Gitleaks](https://github.com/gitleaks/gitleaks)**: While focused on finding hardcoded secrets, running it on your repository can help you understand your overall secret management hygiene.
*   **Manual Code Review Checklist**: Create a simple checklist for PRs that includes an item: "Verify any changes in the `.github/` directory are understood and approved."

### Metrics/Signal
*   **Percentage of actions pinned to a SHA**: Aim for 100%.
*   **Time since last workflow audit**: If it's more than a few months, you're likely overdue.
*   **"Approval Ratio" for workflow changes**: In PRs that change both application code and workflow files, what percentage of review comments focus on the workflow? A low ratio indicates a blind spot.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about actively hardening your systems and processes to shut down the attack vectors identified in the previous stages. For our scenario, this means enforcing strict dependency management within your GitHub Actions workflows and implementing process-level controls to prevent a malicious PR from ever being run with elevated permissions.

### Insight
The single most impactful change a developer can make is to treat CI/CD workflow dependencies with the same rigor as application dependencies (e.g., `package.json` or `requirements.txt`). An unpinned GitHub Action is equivalent to using `"left-pad": "*"` in your `package.json`—it exposes you to any future changes, malicious or not, made by the upstream maintainer.

### Practical
1.  **Pin Actions to a Commit SHA**: This is the top priority. Go through every `uses:` line in your workflows. Find the commit hash associated with the version you want to use and change `@v4` to the full SHA (e.g., `@50d4051da738e65264bdf1a5a54054a72dddc4c0`). This ensures you are always running the exact code you've audited.
2.  **Disable or Restrict `pull_request_target`**: Avoid this trigger if at all possible. If you must use it (e.g., for a labeling bot), ensure the workflow has the minimum permissions necessary by adding a top-level `permissions: {}` block and only enabling what's needed, like `pull-requests: write`.
3.  **Enforce Branch Protection Rules**: In your repository settings (`Settings > Branches`), protect your main branches. Require reviews from Code Owners for any changes to the `.github/` directory. This creates a human checkpoint for any attempted modification of your CI/CD pipeline.

### Tools/Techniques
*   **[GitHub Codeowners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)**: Create a `CODEOWNERS` file that assigns ownership of the `.github/workflows/` path to your security team or senior engineers.
*   **[Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/about-dependabot-version-updates)**: Configure Dependabot to automatically create PRs to update your pinned action SHAs, ensuring you stay up-to-date with security patches from the original author in a secure, reviewable way.
*   **[OpenID Connect (OIDC)](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)**: Use OIDC to issue short-lived credentials from your cloud provider (AWS, GCP, Azure) instead of storing long-lived secrets like `AWS_ACCESS_KEY_ID` in GitHub Secrets.

### Metrics/Signal
*   **100% of actions pinned**: This is a binary, achievable goal.
*   **Dependabot coverage**: Is Dependabot configured to track all your GitHub Actions dependencies?
*   **Codeowner rule enforcement**: A successful metric is zero un-reviewed changes merged to workflow files.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Despite your best efforts, assume the attacker succeeds. Limitation is about containing the blast radius. If the attacker steals a secret, how much damage can they do with it? In our scenario, the stolen `PYPI_API_TOKEN` has the power to publish new versions. A well-designed system would limit that power. For example, the token should only be able to publish a specific package, not any package. Secrets should be narrowly scoped and short-lived.

### Insight
The principle of least privilege is your most powerful tool for damage control. A CI/CD pipeline is a powerful system, but not every step in the pipeline needs the same level of power. A workflow that runs unit tests should not have access to production deployment keys. By isolating permissions, you ensure that a compromise in one part of the process doesn't lead to a total system compromise.

### Practical
1.  **Use GitHub Environments**: Instead of storing all secrets at the repository level, create different [Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) (e.g., "build", "test", "publish"). Store the `PYPI_API_TOKEN` only in the "publish" environment.
2.  **Protect Environments**: Configure your "publish" environment to require manual approval from a specific person or team before a job can access its secrets. This adds a critical human intervention point before a release.
3.  **Scoped, Short-Lived Credentials**: If using OIDC, configure your cloud IAM role to have the bare minimum permissions. For tokens like PyPI, use [Trusted Publishers](https://docs.pypi.org/trusted-publishers/) instead of manually generated tokens. This cryptographically ties your package to your GitHub repository, eliminating the need for a long-lived secret entirely.

### Tools/Techniques
*   **[GitHub Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)**: A native GitHub feature for separating secrets and setting protection rules.
*   **[HashiCorp Vault](https://www.vaultproject.io/)**: For more complex secret management, Vault can be used to dynamically generate short-lived secrets for CI/CD jobs.
*   **Cloud IAM Roles**: Use tools like [AWS IAM](https://aws.amazon.com/iam/), [GCP IAM](https://cloud.google.com/iam), or [Azure AD](https://azure.microsoft.com/en-us/products/active-directory) to create narrowly-scoped roles for your CI/CD pipelines when using OIDC.

### Metrics/Signal
*   **Number of secrets per environment**: A high number of secrets in a low-security environment (like "build") is a red flag.
*   **Secret Time-to-Live (TTL)**: For dynamic secrets, the shorter the TTL, the smaller the window of opportunity for an attacker.
*   **Manual approvals required for production access**: The number of workflows that can access production secrets without manual approval should be zero.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about making the invisible visible. How do you know an attack is happening? You need detection and monitoring systems that can spot suspicious activity. For our scenario, this could be an alert when a PR from a non-member modifies a workflow file, or a real-time monitor that flags unexpected network connections from a CI runner (e.g., a `curl` command to a strange IP address). The goal is to get a signal as early as possible in the attack chain.

### Insight
Attackers rely on the "noise" of a busy development environment to hide their actions. A single malicious `curl` command can be lost in thousands of lines of legitimate build logs. Effective detection requires you to define what "normal" looks like for your CI/CD process so that you can spot the anomalies. What network domains do your builds normally connect to? Which processes do they typically run?

### Practical
1.  **Log Everything**: Ensure your organization's GitHub audit log is being streamed to a centralized logging platform (like Splunk, Datadog, or an ELK stack). This provides a searchable record of all activity.
2.  **Create Specific Alerts**: Configure alerts for high-risk events. A key alert is: `Trigger: PR created by non-member`, `Condition: PR modifies files in path '.github/workflows/'`, `Action: Post to #security channel in Slack`.
3.  **Monitor Runner Activity**: For self-hosted runners, use a runtime security agent to monitor process execution and network connections. For GitHub-hosted runners, use actions like StepSecurity's Harden-Runner to add a layer of outbound traffic monitoring.

### Tools/Techniques
*   **GitHub Audit Log Streaming**: A feature for [Enterprise accounts](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise) to send audit data to a SIEM.
*   **[Datadog CI Visibility](https://www.datadoghq.com/product/ci-cd-visibility/)**: A commercial tool that can provide deep insights into your CI pipelines, including security monitoring.
*   **[Falco](https://falco.org/)**: An open-source runtime security tool that can be deployed on self-hosted runners to detect anomalous behavior (e.g., "A shell was spawned in a container" or "Outbound network connection to non-allowed IP").

### Metrics/Signal
*   **Mean Time To Detect (MTTD)**: How long does it take from the moment a malicious PR is opened to the moment a security alert is fired?
*   **Alert fidelity**: What is your ratio of true-positive to false-positive alerts? High noise leads to alert fatigue.
*   **Log completeness**: Are you capturing logs for all critical events, including workflow runs, setting changes, and secret access?

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice defending against the attack to build muscle memory. You don't want the first time you deal with a poisoned workflow to be during a real incident. By running a controlled security drill, you can test your defenses (Fortify), your containment measures (Limit), and your detection systems (Expose) in a safe environment. The exercise involves creating a fake "malicious" PR and seeing if your team and tools can stop it.

### Insight
Security exercises are not about "passing" or "failing." They are about learning. The goal is to uncover the hidden flaws in your process and technology. Maybe the alert fired, but it went to an unmonitored email inbox. Maybe a junior developer approved the PR because they weren't trained on the risks of workflow modifications. These are invaluable lessons that you can only learn by doing.

### Practical
1.  **Plan the Drill**: Define the scope. A simple drill could be: "A designated senior engineer will open a PR from their personal fork. The PR will have a benign description but will modify a CI workflow to add an `echo` statement."
2.  **Execute the Drill (Unannounced)**: The engineer opens the PR during a normal workday. The security team acts as a "white team," observing the response without interfering.
3.  **Observe and Measure**:
*   Did the code reviewer spot the workflow change?
*   Did the automated alert for `.github` modifications fire?
*   How long did it take for someone to question or block the PR?
4.  **Hold a Blameless Post-Mortem**: Review the timeline. What worked well? Where were the delays or gaps? Was the training effective? Use the findings to update your documentation, tooling, and training materials.

### Tools/Techniques
*   **Internal Red Teaming**: Use your own engineers to simulate attacks. It's cost-effective and highly tailored to your environment.
*   **Breach and Attack Simulation (BAS) Platforms**: Tools from vendors like [Palo Alto Networks (Xpanse)](https://www.paloaltonetworks.com/cortex/xpanse) or [Mandiant](https://www.mandiant.com/advantage/validation) can automate more complex security testing scenarios.
*   **[Gameday or "DiRT" (Disaster Recovery Testing)](https://aws.amazon.com/well-architected-labs/operational-excellence/game-day/)**: Frameworks used in SRE culture that can be adapted for security drills.

### Metrics/Signal
*   **Drill Detection Time**: The time from PR creation to the first human response.
*   **Process Adherence Rate**: Did the developers and reviewers follow the documented security checklist for PRs?
*   **Improvement Actions Generated**: A successful exercise should result in a list of concrete actions to improve security (e.g., "Update PR template," "Tune alert rules," "Schedule new developer training session").
{% endblock %}