---
 permalink: /battlecards/ides
battlecard:
 title: Malicious IDE Plugins
 category: Developer Environment
 scenario: IDEs
 focus: 
   - malicious extensions 
   - unsafe run configs 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets developers at a hot new AI startup. They create a VS Code extension called "AI Linter Pro" and publish it to the marketplace. The extension promises to use a GPT model to provide advanced, context-aware linting for Python code, a core language for the startup. To build credibility, the attacker creates a slick landing page, a few positive fake reviews, and even a public (but obfuscated) GitHub repository for the extension.

A developer at the startup, looking for an edge, discovers and installs the extension. Upon installation, the extension does two things silently in the background:
1.  It scans the entire workspace for files matching common credential patterns (`.env`, `credentials.json`, `id_rsa`, `*.pem`) and exfiltrates their contents to a remote server.
2.  It inspects the project's `.vscode/launch.json` file. It finds a common debug configuration like "Python: Current File" and subtly modifies it by adding a `preLaunchTask`. This task, disguised as a "cache warming" step, executes a shell command that downloads and runs a second-stage payload, establishing a persistent backdoor on the developer's machine.

The next time the developer hits F5 to debug their Python script, the malicious task executes, compromising their machine and giving the attacker a foothold inside the startup's network.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's goal is to understand your development environment and social dynamics to craft a believable lure. They aren't launching a brute-force attack; they are creating a targeted tool that solves a real problem for developers, making it irresistible. They research your company's tech stack by looking at job postings and public GitHub repositories. They identify popular IDEs (like VS Code or JetBrains) and the types of tools developers in your domain (e.g., AI/ML, FinTech) are likely to seek out. They then create their malicious extension, often by forking a legitimate open-source extension and injecting malicious code, making it difficult to spot the differences. The final step is social engineering: promoting the tool in developer communities like Reddit, Discord, or Stack Overflow where their targets are active.

### Insight
This is a supply chain attack that targets the *developer*, not the application code directly. Attackers know that developers trust their tools implicitly and that IDE marketplaces are often less stringently policed than OS app stores. Your IDE is a high-privilege execution environment that has access to all your code, credentials, and local network resources.

### Practical
As a developer, be aware of the "brand" of the tools you use. Who is the publisher? Are they verified? Does the extension have a significant number of downloads and a long, positive history? Scrutinize tools that seem too new or too good to be true. Notice how attackers might try to engage with you or your colleagues on public forums to subtly recommend their malicious tool.

### Tools/Techniques
*   **GitHub/GitLab Code Search**: Attackers use this to identify the primary languages, frameworks, and even IDE configurations used by your organization's developers.
*   **Social Media Monitoring**: They watch developer conversations on Twitter, Reddit (e.g., r/python, r/node), and public Discord/Slack channels to understand developer needs and pain points.
*   **Marketplace Analysis**: They look for popular extensions with potential vulnerabilities or identify gaps in the market where a new, malicious tool could gain traction.

### Metrics/Signal
*   An increase in unsolicited messages or posts in your community channels recommending new, unproven developer tools.
*   Attackers "starring" your repositories or following your developers on social platforms to build a profile of your team's stack and habits.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward to assess your own vulnerabilities. How would your current setup and practices stand up to the attack scenario? As a developer, ask yourself: Do you or your team members install IDE extensions without a second thought? Check your installed extensions. Do you recognize all of them and their publishers? Review your project's `.vscode` directory. Is it checked into source control? If so, are you reviewing changes to `launch.json` and `tasks.json` with the same rigor as your application code? The vulnerability often lies in the implicit trust we place in our development tools and the lack of formal process around managing them.

### Insight
Your IDE's configuration is a form of code. It can execute commands and access data. If you don't treat `launch.json`, `tasks.json`, and the extensions you install with the same security scrutiny as a `package.json` or `pom.xml`, you have a significant blind spot.

### Practical
Perform a personal IDE audit.
1.  Go through your list of installed extensions. If you haven't used one in months, uninstall it.
2.  For the remaining extensions, check the publisher. Is it a known, reputable company (e.g., Microsoft, Red Hat) or an individual with a solid open-source track record?
3.  Read the extension's description and review its requested permissions, if available. Does a simple "theme" extension need access to the filesystem or the ability to run shell commands?
4.  Check your source control for any `.vscode` or `.idea` directories. If they exist, audit the contents for any scripts or tasks you don't recognize.

### Tools/Techniques
*   **VS Code Command Line**: Run `code --list-extensions` in your terminal to get a clean list of all installed extensions for easier auditing.
*   **Manual JSON Review**: Open your project's `.vscode/launch.json` and `.vscode/tasks.json` files. Look for any commands in `preLaunchTask`, `postDebugTask`, or any other task that seem suspicious or unfamiliar (e.g., `curl`, `bash -c`).
*   **Marketplace Publisher Info**: On the extension's marketplace page, click on the publisher's name to see their verification status and other extensions they have published.

### Metrics/Signal
*   A high number of extensions from unverified or unknown publishers is a clear indicator of risk.
*   The presence of `.vscode` or `.idea` files containing executable tasks within your project's git history.
*   A lack of a team-wide policy or discussion around vetting and approving developer tools.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening is about proactively reducing the attack surface. This means establishing policies and configuring your tools to be more secure by default. The core principle is to minimize trust and verify everything. Instead of allowing any extension, operate from a default-deny mindset, only allowing extensions that are explicitly vetted and approved. Treat your IDE configuration as a critical part of your secure development lifecycle.

### Insight
A secure default is the most powerful defense. If your environment is configured to block or question potentially risky actions, you've already won half the battle. This shifts the burden from the individual developer having to be vigilant 100% of the time to the system providing a safety net.

### Practical
*   **Create an "Approved Extensions" List**: For your team, maintain a simple, shared document that lists vetted and recommended extensions for your specific tech stack. This helps developers choose safe tools without having to perform a full security audit themselves every time.
*   **Standardize `.gitignore`**: Ensure that `.vscode/` and `.idea/` are included in your project's global or repository-specific `.gitignore` file, unless a specific file (like a shared linter setting) has been explicitly reviewed and approved for sharing.
*   **Configure IDE Security Features**: Enable and configure built-in security features. For VS Code, this is the [Workspace Trust](https://code.visualstudio.com/docs/editor/workspace-trust) feature. Configure it so that you and your team are forced to make a conscious decision to trust a project before any code or tasks are automatically executed.

### Tools/Techniques
*   **VS Code Workspace Trust**: This is a built-in feature that lets you declare whether or not you trust the authors of a project folder. In an "untrusted" workspace, a range of risky actions (like task execution) are disabled by default.
*   **JetBrains secure settings**: Use features like the [safe mode for projects](https://www.jetbrains.com/help/idea/project-security.html) which can prevent arbitrary code execution from Maven or Gradle build scripts on project open.
*   **Settings Sync**: Use the built-in settings sync features in IDEs, but be intentional about what you sync. Syncing your theme and keybindings is fine; syncing potentially project-specific tasks is risky.

### Metrics/Signal
*   The `Workspace Trust` feature is enabled and actively used across the development team.
*   A clear, documented, and accessible list of approved IDE extensions exists and is maintained.
*   Automated checks in your CI/CD pipeline that fail a build if `.vscode/launch.json` or similar sensitive files are found in a pull request.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker has succeeded—the malicious extension is running. Limiting the blast radius is about ensuring that this compromise is contained and doesn't lead to a full-blown disaster. If your IDE is compromised, what can it actually *do*? The damage is determined by the permissions of the IDE process and the sensitivity of the data it can access. If your developer environment has access to production keys, the damage is catastrophic. If it's an isolated environment with short-lived credentials, the damage is minimal.

### Insight
The Principle of Least Privilege is your most important defense here. Your day-to-day development environment should not have standing access to critical systems. Treat your development machine as a potentially hostile environment.

### Practical
*   **Isolate Your Environment**: Use container-based development. Instead of cloning a repo and running it directly on your OS, run it inside a [Dev Container](https://code.visualstudio.com/docs/devcontainers/containers). This isolates the project's dependencies, tools, and the IDE's access to the host filesystem. A malicious extension could only access what's inside the container, not your entire machine.
*   **Manage Secrets Properly**: Never store secrets in plain text `.env` files in your project root. Use a dedicated secrets manager to inject credentials into your application at runtime. The malicious extension can't steal what isn't there.
*   **Use Short-Lived Credentials**: Instead of long-lived IAM user keys, use a tool that generates temporary, short-lived credentials for your development session. If these keys are stolen, they expire within minutes or hours, drastically limiting the attacker's window of opportunity.

### Tools/Techniques
*   **Dev Containers**: [Visual Studio Code Dev Containers](https://code.visualstudio.com/docs/devcontainers/containers) and [JetBrains Fleet](https://www.jetbrains.com/fleet/) with its remote workspace capabilities allow you to define your development environment as code and run it in an isolated Docker container.
*   **Secrets Management**: Use tools like [HashiCorp Vault](https://www.vaultproject.io/), [Doppler](https://www.doppler.com/), or cloud-native solutions like [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) or [Google Secret Manager](https://cloud.google.com/secret-manager).
*   **Short-Lived Credential Tools**: [AWS IAM Identity Center (formerly SSO)](https://aws.amazon.com/iam/identity-center/) provides a command-line utility to generate temporary session credentials.

### Metrics/Signal
*   Zero long-lived cloud credentials stored on developer laptops.
*   Adoption of containerized development environments across the team.
*   Time-to-live (TTL) for developer credentials is set to a low value (e.g., 8 hours or less).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack, you need visibility into what your tools are doing. How would you know if your IDE started making strange network connections or modifying files outside of your active project? Detection relies on monitoring the behavior of your developer tools and looking for anomalies. A text editor shouldn't be spawning shell scripts that make connections to random IP addresses. Changes to your launch configurations should correspond to a commit you remember making.

### Insight
You can't detect what you can't see. Most developers lack deep visibility into the process trees and network activity of their own tools. Adding a layer of monitoring to developer endpoints is just as critical as monitoring production servers.

### Practical
*   **Know Your Baseline**: Pay attention to your IDE's normal behavior. Does it typically use a lot of CPU or network bandwidth? Knowing what's normal makes it easier to spot an anomaly.
*   **Monitor Network Traffic**: Use a local network monitoring tool to see what connections your applications (including your IDE and its extensions) are making. If you see `code` or `java` making a connection to a domain you don't recognize, it's a major red flag.
*   **File Integrity Monitoring**: Be alerted to unexpected changes in sensitive configuration files, especially your `.vscode` or `.idea` directories. Git is a great tool for this—if you see an unexpected change to `launch.json` in your commit staging, investigate immediately.

### Tools/Techniques
*   **Endpoint Detection and Response (EDR)**: Corporate environments should use EDR solutions like [CrowdStrike Falcon](https://www.crowdstrike.com/products/endpoint-security/falcon-insight-edr/) or [SentinelOne](https://www.sentinelone.com/). These tools are designed to monitor process behavior and detect malicious activity, such as an IDE spawning a reverse shell.
*   **Process Monitoring**: On a local machine, you can use tools like [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) on Windows or the built-in `auditd` on Linux to log process execution. You could filter for all child processes spawned by your IDE.
*   **Network Monitoring**: Tools like [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html) for macOS can alert you in real-time when any process attempts to make an outbound network connection, giving you the power to allow or deny it.

### Metrics/Signal
*   An EDR alert is triggered for suspicious process execution originating from your IDE (e.g., `Code.exe -> powershell.exe -> curl.exe`).
*   Your IDE process (`Code`, `idea`) appears in network logs connecting to a new, uncategorized, or known-malicious IP address.
*   A developer reports an unexpected or unauthored change to a `launch.json` or `tasks.json` file during a routine `git add`.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build resilience, you must practice. Security exercises turn theoretical knowledge into practical skill. For this scenario, the goal is to build "muscle memory" for both developers and the security team. How does a developer react when they suspect an extension is malicious? Who do they report it to? What's the incident response plan? By running drills, you can identify gaps in your process, tooling, and communication before a real attack occurs.

### Insight
A policy document that nobody has read is useless in a crisis. Drills and simulations are about building confidence and ensuring that the first time you execute your incident response plan isn't during a real incident. It's about making security a collaborative team activity, not a theoretical chore.

### Practical
*   **Tabletop Exercise**: Gather the development and security teams. Present the scenario: "A developer just reported that their IDE is behaving strangely after installing a new linter extension. Network traffic to a suspicious domain has been detected. What are our next steps?" Walk through the entire process from initial detection to remediation.
*   **Benign "Trojan" Extension**: Create a harmless internal VS Code extension that mimics the *indicators* of a malicious one. For example, on install, it could pop up a message saying "This extension would have read your ~/.aws/credentials file" and send a notification to a central security Slack channel. Encourage developers to install it as part of a security awareness day to test detection and reporting processes.
*   **Security Katas**: Create short, repeatable challenges for developers. For example, provide a sample `launch.json` and ask them to spot the malicious `preLaunchTask`. This makes learning interactive and fun.

### Tools/Techniques
*   **Custom VS Code Extension**: Use the official [Yeoman generator for Code](https://code.visualstudio.com/api/get-started/your-first-extension) to quickly scaffold a simple extension for training purposes.
*   **Incident Response Runbooks**: Use a shared document or wiki (like Confluence or a GitHub Wiki) to document the step-by-step plan for handling this specific type of incident. The tabletop exercise should be used to refine this runbook.
*   **Developer Training Platforms**: Incorporate modules about IDE security into your regular developer security training using platforms that provide hands-on labs.

### Metrics/Signal
*   Mean Time to Report (MTTR): The time it takes from a developer "noticing something odd" to formally reporting it to the security team decreases over time.
*   Improved Runbook Clarity: After an exercise, the incident response runbook is updated with clearer steps, more accurate contact info, and fewer ambiguous instructions.
*   Positive Developer Feedback: Developers report feeling more confident in their ability to spot and report suspicious activity after participating in the exercises.
{% endblock %}