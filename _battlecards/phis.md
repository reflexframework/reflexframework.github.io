---
permalink: /battlecards/phishing-developers
title: Phishing Developers
battlecard:
 title: Phishing Developers
 category: Social Engineering
 scenario: Phishing Devs
 focus: 
   - credential harvesting 
   - OAuth token theft 
   - fake maintainer invites 
---

An attacker targets a developer, "Alex," who is a known contributor to a popular open-source project your company uses. The attacker's goal is to gain access to your company's private source code, CI/CD pipelines, and cloud infrastructure.

The attack unfolds in a few steps:
1.  **The Lure:** Alex receives a well-crafted email pretending to be from the GitHub Security Team. The email warns of a critical vulnerability discovered in a popular library Alex's project depends on. It uses Alex's real name and references a recent public commit they made, making it highly convincing.
2.  **The Hook:** The email contains a link to what looks like a security advisory on GitHub: `github.com.security-advisory.net/login`. The page is a pixel-perfect clone of the GitHub login page. Alex, concerned about the vulnerability, enters their username, password, and 2FA code. The attacker's server harvests these credentials in real-time.
3.  **The Pivot:** After "logging in," Alex is redirected to a malicious OAuth application consent screen. It's branded as "GitHub Security Scanner" and asks for permission to "scan repositories for vulnerabilities." The requested scopes are dangerously broad, including `repo` (full control of private repositories) and `admin:org` (full control of the organization). In a rush to fix the supposed vulnerability, Alex clicks "Authorize."
4.  **The Prize:** The attacker now has Alex's credentials and a powerful OAuth token. They can clone all private company code, inject malicious code into the `main` branch, steal secrets from CI/CD variables, and potentially move laterally into your cloud environment.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. They act like a detective, gathering publicly available information to build a profile of your developers and organization. Their goal is to find the perfect target and craft a believable story. They aren't just sending random spam; they are carefully selecting their targets based on their digital footprint. For a developer, your public activity on platforms like GitHub, GitLab, Stack Overflow, and even Twitter is a goldmine for them.

### Insight
Your passion for open source and community engagement can be used against you. Attackers exploit the collaborative nature of software development. They look for helpful, active developers because they are more likely to engage with unsolicited "opportunities" or "security alerts."

### Practical
- **Audit your Git profile:** Review your public GitHub/GitLab profile. The email address you use for commits can be scraped. Consider using a `noreply` email address provided by your Git provider for public commits.
- **Sanitize your digital footprint:** Google your name and GitHub handle. What can an attacker learn about your role, projects, and tech stack from public forums, personal blogs, or conference talks? Be mindful of the breadcrumbs you leave.
- **Review project contributors:** Look at your project's `contributors` page. Attackers will do the same to identify key personnel, recent joiners (who may be less familiar with security protocols), or highly active members.

### Tools/Techniques
- **Git Commit History:** Attackers use simple `git log` commands to find developer emails and contribution patterns.
- **GitHub Search:** They use advanced search queries (dorks) to find sensitive information, e.g., `org:your-company filename:.env "SECRET_KEY"`.
- **[git-recon](https://github.com/GONZOsint/git-recon):** Tools like this automate the process of scraping user information from Git hosting platforms.
- **[grep.app](https://grep.app/):** A public code search engine that can be used to find instances where your company's developers might have accidentally committed internal code snippets or credentials to public forks.

### Metrics/Signal
- **Exposed Developer Emails:** The number of unique developer email addresses visible in the commit history of your public repositories.
- **Publicly Attributable Tech Stack:** How easy is it to determine your primary programming languages, frameworks, and cloud provider from public information?

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you turn the attacker's lens on yourself. It's about honestly assessing your current defenses against a targeted phishing attack on a developer. The goal is to identify the weak spots in your environment, processes, and culture before an attacker does. Ask yourself: "If a key developer's GitHub account were compromised *right now*, what could an attacker do?"

### Insight
Security is not just about firewalls and antivirus; for developers, it's deeply tied to identity and access management (IAM) within your development ecosystem. A single compromised developer account can be the key that unlocks the entire kingdom if not properly controlled.

### Practical
- **Review Org Settings:** In GitHub/GitLab, audit your organization's security settings. Who are the owners? Is mandatory 2FA enabled for everyone?
- **Audit OAuth Applications:** Review all third-party OAuth applications that have been granted access to your organization's resources. Look for apps with overly permissive scopes like `repo` or `write:org`. Revoke anything that is unused or suspicious.
- **Map Developer Permissions:** Document what access a typical developer has. Can they push directly to `main`? Can they create new repositories? Can they change CI/CD pipeline definitions? The less privilege they have by default, the better.

### Tools/Techniques
- **[GitHub Security Dashboard](https://docs.github.com/en/enterprise-cloud@latest/code-security/security-overview/about-the-security-overview):** Use your platform's built-in tools to get a high-level view of security risks.
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog):** Scans your repositories, including the entire commit history, for accidentally committed secrets like API keys and private credentials.
- **[GitGuardian](https://www.gitguardian.com/):** Offers automated secret detection and policy enforcement for your SCM, helping you evaluate your exposure in real-time.

### Metrics/Signal
- **MFA Adoption Rate:** Percentage of developers in your organization with 2FA enabled. The goal should be 100%.
- **Number of Privileged Accounts:** The number of users with "Owner" or "Admin" roles in your SCM.
- **Stale Access Tokens:** Number of Personal Access Tokens (PATs) or SSH keys that have not been used in over 90 days.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This stage is about building walls and making the attacker's job as difficult as possible. Fortification involves implementing technical controls, improving processes, and fostering a security-conscious culture. The aim is to make a successful phishing attack highly unlikely, even if a developer clicks the wrong link.

### Insight
The strongest defense is layered. A technical control like a hardware key can block a credential theft attempt, while a well-trained developer can spot the phishing lure in the first place. You need both. A "zero trust" mindset is key—don't automatically trust any request, even if it looks legitimate.

### Practical
- **Enforce Phishing-Resistant MFA:** Mandate the use of FIDO2/WebAuthn hardware keys (like YubiKeys). These are resistant to phishing because the authentication is bound to the legitimate domain, meaning a fake site like `github.com.security-advisory.net` cannot capture a valid credential.
- **Centralize Identity with SSO:** Integrate your Git provider with your company's Identity Provider (e.g., Okta, Azure AD, Google Workspace). This centralizes access control, simplifies on/offboarding, and enforces your company's authentication policies consistently.
- **Sign Your Commits:** Enforce commit signing using GPG or SSH keys. This cryptographically verifies that a commit was made by a trusted developer and hasn't been tampered with, preventing an attacker from injecting code using a compromised account.
- **Educate on OAuth Scopes:** Train developers to scrutinize OAuth consent screens. Teach them to ask: "Why does this linter need write access to all my repositories?" and to deny requests with excessive permissions.

### Tools/Techniques
- **[YubiKey](https://www.yubico.com/):** A popular brand of hardware security keys that support FIDO2/WebAuthn.
- **[GitHub Enterprise Cloud](https://github.com/enterprise)** / **[GitLab Ultimate](https://about.gitlab.com/pricing/ultimate/):** These tiers offer advanced security features like mandatory SSO, commit signing enforcement, and more granular access controls.
- **[Socket.dev](https://socket.dev):** A tool that can detect suspicious behavior in open-source dependencies, such as the use of install scripts that could be used in a fake maintainer invite scenario.

### Metrics/Signal
- **Phishing-Resistant MFA Adoption:** Percentage of developers using hardware keys or other phishing-resistant authenticators.
- **Commit Signature Rate:** The ratio of signed to unsigned commits in your main branches.
- **SSO Enforcement:** A binary metric: is SSO mandatory for all members of your Git organization?

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker succeeded; they have Alex's credentials and an active session. The "Limit" stage is about containing the damage. This is your blast radius control. The goal is to ensure that a single compromised developer account doesn't lead to a full-blown organizational breach. This is achieved by adhering to the principle of least privilege.

### Insight
An attacker with access to a developer's account is inside your perimeter. Your goal should be to make their movement as difficult and noisy as possible. A well-segmented system with strong internal controls can turn a catastrophe into a manageable incident.

### Practical
- **Implement Branch Protection:** Protect your critical branches (`main`, `develop`, `release/*`). Require mandatory code reviews (especially from a `CODEOWNERS` file), passing CI checks, and signed commits before any code can be merged. This prevents a single compromised account from directly pushing malicious code.
- **Use Short-Lived, Scoped Credentials in CI/CD:** Stop using long-lived static secrets (like `AWS_ACCESS_KEY_ID`) in your pipelines. Instead, use OpenID Connect (OIDC) to issue short-lived, single-use credentials from your cloud provider (AWS, GCP, Azure) directly to your GitHub Actions or GitLab CI jobs.
- **Isolate Environments:** Your CI/CD environment should not have standing access to production. Use secure deployment patterns where production "pulls" artifacts from a trusted registry, rather than development "pushing" to production.
- **Restrict Permissions:** Don't use a single "developer" role. Create tiered roles. A junior developer may not need permission to create new repositories or modify CI/CD workflow files.

### Tools/Techniques
- **[GitHub CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners):** Automatically request reviews from specific teams or individuals when changes are made to certain files or directories.
- **[OIDC with Cloud Providers](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect):** Official documentation from GitHub on setting up passwordless, short-lived authentication between Actions and major cloud providers.
- **[HashiCorp Vault](https://www.vaultproject.io/):** A tool for secrets management that can generate dynamic, short-lived credentials for databases, cloud APIs, and more.

### Metrics/Signal
- **Branch Protection Coverage:** Percentage of active repositories with branch protection rules enabled on their default branch.
- **OIDC Adoption in CI/CD:** Percentage of CI/CD workflows that use OIDC for cloud authentication versus static secrets.
- **Mean Time to Live (TTL) for Credentials:** The average lifespan of a credential used by a developer or a CI/CD job. Shorter is better.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about visibility. How can you detect an attack in progress? Attackers leave tracks, and the "Expose" stage is about having the right sensors in place to see them. This involves logging, monitoring, and alerting on suspicious activity within your development ecosystem, from your Git provider to your CI/CD pipelines.

### Insight
The audit log is your most valuable asset during and after an incident. Most malicious actions—cloning a sensitive repo, adding a new SSH key, changing user permissions—generate a log entry. The challenge is filtering the signal from the noise and getting the right alerts to the right people quickly.

### Practical
- **Stream Audit Logs:** Don't leave your audit logs locked inside your Git provider. Stream them to a centralized logging platform or SIEM (e.g., Splunk, Datadog, Elastic) where they can be correlated with other data sources and retained for forensics.
- **Create Custom Alerts:** Set up alerts for high-risk events:
- A new SSH key or PAT is added to an account.
- A user logs in from a new or unusual IP address/country.
- MFA is disabled for an account.
- A new OAuth application is authorized for the organization.
- A large number of repositories are cloned by a single user in a short period.
- **Monitor CI/CD Pipelines:** Instrument your build pipelines to detect anomalous behavior. A CI job that suddenly makes outbound network calls to an unknown IP address or tries to read files outside its working directory (`/etc/passwd`) is a major red flag.

### Tools/Techniques
- **[GitHub Audit Log Streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-the-audit-log-for-your-enterprise/streaming-the-audit-log-for-your-enterprise):** Natively stream your audit logs to platforms like Datadog, Splunk, or an AWS S3 bucket.
- **[Falco](https://falco.org/):** An open-source cloud-native runtime security tool that can detect unexpected application behavior in your build containers.
- **Dependency Scanners with Behavior Analysis:** Tools like [Snyk](https://snyk.io/product/software-composition-analysis/) are beginning to analyze not just vulnerabilities but also the behavior of package install scripts.

### Metrics/Signal
- **Mean Time to Detect (MTTD):** How long does it take from a suspicious event (e.g., a login from a malicious IP) to an alert being generated?
- **Audit Log Coverage:** Are 100% of your SCM and CI/CD audit logs being ingested into your monitoring system?
- **Alert Fidelity:** The ratio of true-positive alerts to false-positive alerts. A high false-positive rate leads to alert fatigue.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice. You can have the best tools and processes in the world, but if your team doesn't know how to use them under pressure, they will fail. The "eXercise" stage is about building muscle memory for developers and security teams through realistic drills and simulations.

### Insight
Security awareness is not a one-time training session; it's a continuous practice. The goal of these exercises is not to shame developers who fall for a simulation but to identify gaps in your defenses and training in a safe environment. It makes security a shared, hands-on responsibility.

### Practical
- **Run Controlled Phishing Campaigns:** Use a phishing simulation tool to send safe, mock phishing emails to your developers. Use realistic lures related to their work: "Your build is broken," "Action required: Update your IDE's access token," or "You've been invited to co-author a new library."
- **Conduct Tabletop Exercises:** Gather the relevant stakeholders (dev leads, security, operations) and walk through the scenario: "We've just detected a compromised developer account. Go." Discuss who is responsible for what, what the communication plan is, and what the technical steps for remediation are (e.g., revoking all sessions, rotating keys).
- **Red Team Engagements:** Hire an external team or use an internal one to perform a "red team" exercise, where they actively try to execute this attack scenario against your organization. This is the ultimate test of your defenses.

### Tools/Techniques
- **[Gophish](https://getgophish.com/):** An open-source phishing framework that lets you create and track your own internal phishing campaigns.
- **[KnowBe4](https://www.knowbe4.com/):** A commercial security awareness training and simulated phishing platform.
- **Incident Response Playbooks:** Create simple, clear, checklist-style playbooks for common scenarios. For this scenario, a playbook should detail how to:
1.  Immediately suspend the user's SCM and SSO accounts.
2.  Globally revoke all active sessions, PATs, and SSH keys for that user.
3.  Analyze audit logs for attacker activity.
4.  Scan all repositories the user had write-access to for malicious code.

### Metrics/Signal
- **Phishing Simulation Click-Rate:** The percentage of users who click a link in a simulated phishing email. This should trend downward over time.
- **Time to Report:** The average time it takes for a developer to report a simulated phishing email to the security team. Faster is better.
- **Mean Time to Remediate (MTTR):** In an exercise, how long does it take your team to fully contain the simulated incident (e.g., from initial alert to full credential rotation)?
{% endblock %}