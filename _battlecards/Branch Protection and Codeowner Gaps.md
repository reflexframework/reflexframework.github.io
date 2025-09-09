---
 permalink: /battlecards/branch-protection-and-codeowner-gaps
battlecard:
 title: Branch Protection and Codeowner Gaps
 category: Source Control
 scenario: Branch Protection/Codeowners Gaps
 focus: 
   - bypassable reviews 
   - missing CODEOWNERS 
   - unprotected critical directories 
---
{% block type='battlecard' text='Scenario' %}
An attacker, using a compromised developer's credentials, identifies a critical microservice responsible for authentication. They notice a newly created directory, `/src/main/java/com/mycorp/auth/mfa`, was added to handle Multi-Factor Authentication logic, but the team forgot to update the `CODEOWNERS` file to cover it. The repository's main branch has a rule requiring one approval, but it doesn't enforce review from the designated `CODEOWNERS` because the new directory has no owner.

The attacker creates a pull request (PR) that adds a subtle backdoor to the new MFA module, allowing them to bypass MFA using a hardcoded value. They request a review from a junior developer on an unrelated team who is known to quickly approve PRs without deep analysis. The PR is approved and merged, as the repository's rules only required a single approval and did not require it from the (missing) code owner. The malicious code is deployed to production in the next release cycle.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's discovery phase. They are mapping out your source control landscape to find the path of least resistance. Using their stolen credentials, they will browse your organization's repositories, just like a normal developer would. They are not looking for complex software vulnerabilities yet; they are looking for broken processes and configuration weaknesses. They'll analyze branch protection settings, read `CODEOWNERS` files, and check commit history to understand who approves what and how quickly. Their goal is to find a repository where they can merge code with minimal scrutiny.

### Insight
Attackers love complexity and organizational drift. A company with hundreds of microservices is more likely to have repositories with inconsistent, outdated, or missing protection rules. A new directory, a new service, or a team reorganization are all opportunities for gaps to appear in what was once a secure process.

### Practical
- **Audit your own repos:** As a developer, periodically check your team's key repositories. Go to `Settings > Branches`. Is there a protection rule for your `main` or `release` branch? What does it require?
- **Read your `CODEOWNERS` file:** Does it exist at the root of your repo? Does it cover all critical directories? Is there a vague `*` rule that assigns ownership to a large, busy team that might rubber-stamp approvals?
- **Review recent merges:** Look at the history of your main branch. Are PRs consistently being reviewed by the right people? Are there any merges that bypassed the review process?

### Tools/Techniques
- **GitHub/GitLab UI:** The simplest tool is the one you use every day. Manually inspecting branch protection rules and `CODEOWNERS` files is a powerful first step.
- **GitHub CLI (`gh`):** You can script checks against repositories. For example, use `gh repo list <org> --json name,branchProtectionRules` to list repos and their protection status. [Link to gh repo list documentation](https://cli.github.com/manual/gh_repo_list).
- **Git log:** Use `git log --graph --oneline --decorate` to visualize the commit history and see how branches are merged.

### Metrics/Signal
- **Unprotected main branches:** The number of active repositories where the default branch lacks any protection rules.
- **`CODEOWNERS` coverage gap:** The percentage of directories in a critical repository not explicitly covered by a `CODEOWNERS` rule.
- **Stale `CODEOWNERS` entries:** Rules pointing to users who have left the company or teams that no longer exist.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you systematically assess your environment for the weaknesses an attacker would look for. It's about turning the reconnaissance tactics on yourself to find gaps before they do. For this scenario, you'd be asking: "Could an attacker merge code into a critical service without the right experts reviewing it?" This involves auditing not just one repo, but the standards applied across your organization.

### Insight
A common failure pattern is "configuration drift." A repository might have been set up securely, but over time, temporary exceptions were made, rules were relaxed for a "hotfix," and never re-instated. Evaluation is not a one-time setup activity; it's a continuous health check.

### Practical
- **Create a checklist:** Develop a simple "Repository Health Checklist" for your team. It should include items like: "Main branch is protected," "Requires at least one review from CODEOWNERS," "Admin override is disabled," "CODEOWNERS file is up-to-date."
- **Audit `CODEOWNERS` files:** Look for wildcard (`*`) entries that are too broad. Ensure that sensitive paths like `infra/`, `.github/workflows/`, `src/auth/` are owned by specific, expert teams, not a general pool of developers.
- **Review user permissions:** Check who has 'admin' or 'maintainer' roles on your repositories. Does everyone on that list still need that level of access? High-privilege accounts are prime targets.

### Tools/Techniques
- **[OpenSSF Allstar](https://github.com/ossf/allstar):** An open-source GitHub App that continuously checks repositories against a set of security policies (e.g., branch protection) and can be configured to enforce them.
- **[GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security):** For enterprises, this provides org-wide security dashboards that can highlight repositories with weak configurations.
- **Custom Scripts:** Use the GitHub/GitLab APIs to write simple scripts in Python or Node.js to iterate through all your organization's repos and check for compliance with your defined standards.

### Metrics/Signal
- **Compliance Score:** A percentage of repositories in your organization that meet the defined security baseline (e.g., 95% of repos have branch protection enabled).
- **Time to Remediate:** When a non-compliant repository is found, how long does it take for the team to fix it?
- **Admin Override Events:** The number of times in the last month that an administrator bypassed branch protection rules to merge a PR.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about closing the gaps you found during evaluation. For this scenario, it means making your source control rules technically impossible to bypass. This isn't about trusting people to follow the process; it's about configuring the tools to enforce the process for everyone, every time.

### Insight
The best security controls are the ones that are invisible and automatic. Developers shouldn't have to remember a complex process; the system should guide them. For example, if a PR touches the authentication code, GitHub should automatically request a review from the security team because the `CODEOWNERS` file is configured correctly.

### Practical
1.  **Enforce `CODEOWNERS` Reviews:** In your branch protection rule, check the box for "Require review from Code Owners." This is the critical step that turns `CODEOWNERS` from a suggestion into a mandatory requirement.
2.  **Protect Critical Directories More:** Add more specific rules to your `CODEOWNERS` file. For example:
```
# Default owners
* @everyone

# Critical infrastructure code requires the infra team
/infra/ @my-org/infra-team

# Authentication code requires security team review
/src/main/java/com/mycorp/auth/ @my-org/security-team
```
3.  **Disable Admin Overrides:** In the branch protection settings, uncheck "Allow administrators to override." While sometimes inconvenient, it closes a significant loophole.
4.  **Require Status Checks:** Bolster your review process by requiring CI checks to pass before merging (e.g., tests, linting, vulnerability scans). This provides an automated layer of quality and security control.

### Tools/Techniques
- **[GitHub's Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches):** The primary tool for hardening your repository.
- **[CODEOWNERS Syntax](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners):** Official documentation is the best source for getting the rules right.
- **[Terraform Provider for GitHub](https://registry.terraform.io/providers/integrations/github/latest/docs):** Manage your repository settings, including branch protection rules, as code. This allows for auditing, versioning, and automated application of your security standards.

### Metrics/Signal
- **Zero Admin Overrides:** A sustained trend of zero merges that bypass branch protection.
- **100% `CODEOWNERS` Enforcement:** All active repositories have the "Require review from Code Owners" setting enabled on their main branch.
- **Reduction in "Rubber-Stamp" Approvals:** An increase in review comments and change requests on PRs for critical code, indicating deeper scrutiny.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Let's assume the worst: an attacker successfully merged malicious code. Limiting the blast radius is about ensuring that this single failure doesn't lead to a catastrophe. The goal is to prevent the malicious code from reaching production and to minimize the damage it can do if it does. This moves the focus from the SCM to the CI/CD pipeline and production environment.

### Insight
A source code compromise is just the first step for an attacker. Their real goal is to get that code running in a privileged environment. Your deployment pipeline is a critical control point. A commit to `main` should never automatically equal a deployment to production.

### Practical
- **Multi-Stage Deployments:** Your CI/CD pipeline should have distinct stages: `build -> test -> staging -> production`. The malicious code might get built, but it should be caught by tests or during manual verification in the staging environment.
- **Production Deployment Gates:** Require a separate, manual approval for any deployment to production. This approval should be logged and require someone different from the original code author/reviewer, like a Tech Lead or SRE.
- **Least-Privilege for CI/CD:** The credentials used by your CI/CD pipeline to deploy to production should be temporary and tightly scoped. A compromised build job should not have access to read production databases or other secrets.
- **Signed Commits:** Enforce signed commits on protected branches. This ensures that a commit genuinely came from a specific developer's machine and their GPG key, making it much harder for an attacker with just a username/password to inject code.

### Tools/Techniques
- **[GitHub Actions Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment):** Allows you to configure protection rules (like required manual approvers) specifically for your production deployment environment.
- **[Spinnaker](https://spinnaker.io/):** A continuous delivery platform that excels at managing complex deployment pipelines with sophisticated approval and rollback strategies.
- **[HashiCorp Vault](https://www.vaultproject.io/):** A tool for managing secrets and providing short-lived, just-in-time credentials to your CI/CD jobs.
- **[Git GPG Signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits):** Instructions on how to set up and use GPG keys to sign your commits.

### Metrics/Signal
- **Staging Dwell Time:** The amount of time code spends in a pre-production environment before promotion. A longer, more thorough verification process can be a positive signal.
- **Production Deployer Diversity:** The number of unique, authorized individuals who approve production deployments. A single person approving all changes is a risk.
- **Percentage of Signed Commits:** The ratio of signed to unsigned commits on the main branch. Aim for 100%.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Expose is about visibility. How do you know when a risky event happens in your source control system? You need to have monitoring and alerting in place to detect suspicious activity, just as you would for a production application. An attacker bypassing branch protection or merging a PR with no comments at 3 AM should be a loud, unmissable signal.

### Insight
Your source control system's audit logs are a rich source of security intelligence. Most organizations ignore them until after an incident. Proactively streaming these logs to a central location and setting up alerts for key events can be the difference between a near-miss and a major breach.

### Practical
- **Alert on high-risk actions:** Configure alerts for events like:
- A branch protection rule is disabled or weakened.
- An administrator overrides a PR approval.
- A new user is given admin access to a critical repository.
- A large number of files are modified in a single commit to an unusual directory.
- **Monitor for credential compromise:** Integrate your SCM with tools that scan for secrets in commits in real-time. A commit containing an `AWS_SECRET_ACCESS_KEY` should trigger an immediate alert and credential rotation.
- **Establish a baseline:** Understand what normal developer activity looks like. A developer who normally commits a few hundred lines of Java code suddenly committing obfuscated PowerShell scripts to a CI/CD configuration is an anomaly worth investigating.

### Tools/Techniques
- **[GitHub Audit Log Streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/streaming-the-audit-log-for-your-enterprise):** Forward your organization's audit logs to a SIEM like [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/product/cloud-siem/), or [Sumo Logic](https://www.sumologic.com/).
- **[GitHub Secret Scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning):** Automatically detects secrets (e.g., API keys, tokens) in your code and can be configured to alert developers and security teams.
- **GitGuardian:** A commercial tool that provides real-time secret detection and security monitoring for source control systems. [Link to GitGuardian](https://www.gitguardian.com/).

### Metrics/Signal
- **Mean Time to Detect (MTTD):** How quickly do you get an alert after a suspicious SCM event occurs?
- **Alert Fidelity:** The percentage of alerts that are true positives and result in a corrective action. Too much noise will cause alert fatigue.
- **Unsigned Commit Alert:** An alert is triggered for every unsigned commit that is merged into a protected branch.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice. Security is a skill, and like any skill, it improves with repetition. You can't wait for a real attack to test your defenses and response plan. By running controlled drills, you build "muscle memory" for the team, identify weaknesses in your processes, and improve your tooling.

### Insight
The most valuable part of an exercise is not "winning" but learning. When a drill fails—a bypass works, an alert doesn't fire—it's a success, because you've found a vulnerability in a safe environment. The debrief after the exercise is more important than the exercise itself.

### Practical
- **Run a Tabletop Exercise:** Gather the team and walk through the scenario verbally. "A developer reports that their GitHub password was compromised. What's the first thing we do? Who do we notify? How do we check for malicious commits?" Document the answers to form a basic incident response playbook.
- **Perform a "Red Team" Drill:**
1.  Create a test repository that mirrors the configuration of a critical one.
2.  Designate one team member as the "attacker." Their goal is to try and merge a "malicious" (e.g., a text file that says "I am a backdoor") PR by exploiting a known or suspected gap in the process.
3.  The rest of the team ("blue team") must use their monitoring and tools to detect and "respond" to the attack.
- **Review and Improve:** After the drill, hold a retrospective. What went well? What was confusing? Did the alerts fire as expected? Was the response plan clear? Use the answers to update your documentation, tooling, and configurations.

### Tools/Techniques
- **[Confluence](https://www.atlassian.com/software/confluence) or a shared Wiki:** A place to document your incident response playbooks so everyone knows what to do.
- **Dedicated Slack/Teams Channel:** Create an `#security-incidents` channel for coordinating responses during an exercise (and a real event).
- **[OpenSSF Scorecards](https://github.com/ossf/scorecard):** Run this automated tool against your repos before and after an exercise to get a quantifiable measure of security posture improvement.

### Metrics/Signal
- **Time to Detect/Respond (in exercise):** How long did it take the blue team to identify the malicious PR merge during the drill?
- **Playbook Clarity Score:** After the exercise, survey the team. On a scale of 1-5, how clear and helpful was the response playbook?
- **Number of Action Items:** The count of concrete improvements (e.g., "fix CODEOWNERS in repo X," "tune alert Y") generated from the exercise retrospective.
{% endblock %}