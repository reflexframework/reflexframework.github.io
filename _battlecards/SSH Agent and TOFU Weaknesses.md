---
 permalink: /battlecards/ssh-agent-and-tofu-weaknesses
battlecard:
 title: SSH Agent and TOFU Weaknesses
 category: Cross-cutting
 scenario: SSH Agent / Known Hosts TOFU
 focus: 
   - agent forwarding abuse 
   - tofu trust hijack 
   - man-in-the-middle on git remotes 
---
{% block type='battlecard' text='Scenario' %}
An attacker gains a foothold on a shared bastion (or "jump") host that developers use to access staging and production environments. The company culture encourages using SSH agent forwarding for convenience, so developers can seamlessly `ssh` from the bastion to other internal servers without re-entering their key passphrase.

The attacker waits for a developer, Alex, to `ssh` into the bastion host with agent forwarding enabled (`ssh -A bastion.example.com`). Once Alex is connected, the attacker, who has root on the bastion, has access to Alex's forwarded SSH agent socket.

Using this hijacked socket, the attacker impersonates Alex. They see from Alex's shell history that they frequently interact with a private Git server (`git.internal.example.com`). The attacker uses Alex's forwarded credentials to SSH to the Git server, clone a critical service's repository containing secrets, and then exfiltrates the code.

Separately, in a CI/CD pipeline, a new build agent is provisioned. Its first task is to clone a source repository. The attacker performs a DNS spoofing attack and redirects `git.internal.example.com` to a server they control. The build agent connects, receives the "The authenticity of host ... can't be established" prompt, and because it's running an unattended script that is not configured for strict host key checking, it blindly accepts the attacker's host key (TOFU - Trust On First Use). The attacker now has a Man-in-the-Middle position, capturing the CI/CD system's deploy key and potentially injecting malicious code into the build.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's goal is to understand the environment to find the path of least resistance. After gaining initial access to a single host (like a developer's laptop via phishing or a vulnerable web app), their primary goal is lateral movement. They will look for credentials and patterns of access. SSH agent forwarding is a prime target because it acts like a set of keys left in the ignition of a running car. They will explore the compromised host, looking for shell history files, SSH config files, and active SSH agent sockets to understand who connects to what, and how. For the TOFU attack, they will identify automated systems (like CI/CD runners) that are likely to have lax host key checking policies.

### Insight
Developers often think of their SSH key as protecting their access *from* their laptop. With agent forwarding, the security model is inverted: any machine you connect to can potentially use your key to access other machines on your behalf. Attackers know this and specifically hunt for misconfigured bastion hosts, which act as a central hub for these powerful, forwarded credentials.

### Practical
As a developer, you can simulate this by logging into a server and looking around.
- Check your own `~/.bash_history` or `~/.zsh_history`. What server names and commands are in there?
- Look for running SSH agents: `ls /tmp/ssh-*/agent*`. This is the socket file an attacker would abuse.
- List open connections: `ss -tupn | grep ssh`. This shows who is connected to the machine.

### Tools/Techniques
*   **Living off the land:** Attackers use common system tools to remain stealthy.
*   `ps aux | grep sshd`: Find active SSH sessions and see which users are logged in.
*   `lsof -U | grep 'agent.'`: Find processes that have an SSH agent socket open.
*   `grep -E "Host|HostName" ~/.ssh/config`: Quickly parse a user's SSH config to find potential targets.
*   `history`: To view the user's recently used commands.

### Metrics/Signal
*   An increase in `ssh` login failures on internal servers could indicate an attacker is probing for access.
*   Unexpected reads of shell history files or SSH configuration files, though this is difficult to monitor without specialized tooling.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
To assess your vulnerability, you need to examine your team's SSH and CI/CD practices. The key question is: "Where do we prioritize convenience over security?" Look for the use of `ForwardAgent yes` in personal or system-wide SSH configurations. Review CI/CD pipeline scripts (`.gitlab-ci.yml`, `Jenkinsfile`, GitHub Actions workflows) for how they handle SSH connections. Do they clone code from Git using SSH? If so, how is the `known_hosts` file managed? Is `StrictHostKeyChecking=no` used to suppress errors, effectively automating the blind "yes" to a TOFU prompt?

### Insight
The most dangerous vulnerabilities are often not in complex code but in simple, everyday developer practices that have become normalized. A single line in an SSH config (`ForwardAgent yes`) or a CI script (`ssh -o StrictHostKeyChecking=no`) can unravel layers of security. These are often added to "make it work" and then forgotten.

### Practical
- **SSH Config Audit:** On your team, run `grep -r "ForwardAgent" /etc/ssh ~/.ssh`. Analyze every instance. Is it truly necessary?
- **CI/CD Script Review:** Search your entire codebase for `StrictHostKeyChecking=no`. Each finding is a potential TOFU hijack vulnerability.
- **Bastion Host Review:** If you use bastion hosts, document who has access and whether agent forwarding is common practice for connecting to them.

### Tools/Techniques
*   **Manual Code Review:** The most effective tool here is a careful, manual review of your team's configuration files and automation scripts.
*   **Static Analysis (SAST):** Configure SAST tools to flag risky shell commands in your CI/CD configuration files. For example, a custom rule in a tool like [Semgrep](https://semgrep.dev/) could search for `StrictHostKeyChecking=no`.

### Metrics/Signal
*   Number of SSH configurations with `ForwardAgent` enabled.
*   Count of CI/CD pipeline definitions that disable strict host key checking. A healthy metric is zero.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening against this attack involves shifting from implicit trust to explicit verification.
1.  **Disable Agent Forwarding:** The safest approach is to disable agent forwarding by default. Instead of forwarding your agent to a bastion host, use the `ProxyJump` feature. This creates a secure tunnel *through* the bastion host to the final destination without ever exposing your agent socket on the intermediary machine.
2.  **Enforce Host Key Checking:** Never trust on first use in an automated system. Pre-populate the `~/.ssh/known_hosts` file on all developer machines and CI/CD runners with the public keys of your internal servers (e.g., your private Git server). This can be managed using configuration management tools.
3.  **Use Hardware-Backed Keys:** For developer SSH keys, use a FIDO2/U2F key like a [YubiKey](https://www.yubico.com/). This can be configured to require a physical touch to approve each use of the key, making it impossible for an attacker on a bastion host to use your forwarded key without your physical interaction.

### Insight
`ProxyJump` is the modern, secure replacement for the agent forwarding + bastion host pattern. It provides the same convenience (connecting to an internal machine via a public one) but with a much stronger security posture. It's a direct, practical fix for the agent abuse scenario.

### Practical
- **Update SSH Config:** Educate your team to replace bastion configurations like this:
```ini
# Old, vulnerable way
Host internal-server
HostName 10.0.1.100
ProxyCommand ssh -W %h:%p bastion.example.com
```
with the modern `ProxyJump` directive:
```ini
# New, secure way
Host bastion
HostName bastion.example.com
User your-user

Host internal-server
HostName 10.0.1.100
User your-user
ProxyJump bastion
```
- **Manage known_hosts:** Create a process to manage your `known_hosts` file as code. Use a tool to fetch the fingerprints of your internal servers and distribute them to your fleet.

### Tools/Techniques
*   **`ProxyJump`:** A built-in feature of modern OpenSSH. See `man ssh_config`.
*   **`ssh-keyscan`:** A utility to scan for public SSH host keys. **Important:** Run this from a trusted network to create your initial `known_hosts` file, and verify the fingerprints out-of-band before distributing the file.
*   **Configuration Management:** Tools like [Ansible](https://www.ansible.com/), [Puppet](https://www.puppet.com/), or Terraform can be used to distribute the trusted `known_hosts` file to your CI runners and servers.
*   **[HashiCorp Vault SSH Secrets Engine](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates):** A more advanced solution where Vault issues short-lived SSH certificates instead of using static keys, which completely bypasses the TOFU problem.

### Metrics/Signal
*   Adoption rate of `ProxyJump` in team SSH configurations.
*   CI/CD pipeline success logs confirming that `StrictHostKeyChecking=yes` (the default) is active and not causing failures.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
If an attacker successfully hijacks a key, the goal is to contain the "blast radius."
1.  **Least Privilege for Keys:** Don't use a single SSH key for everything. A CI/CD deploy key for a specific web app repository should not have access to the user database server. Use read-only deploy keys where possible.
2.  **Network Segmentation:** A bastion host should not have open network access to your entire internal infrastructure. Use firewall rules or cloud security groups to restrict its access to only the specific servers and ports required for its function. An attacker on the bastion should not be able to even attempt a connection to the HR database.
3.  **Restricted Commands:** On the server side, use the `command="..."` option in the `~/.ssh/authorized_keys` file. For a key used by a backup script, for example, restrict it to only be able to run `rsync`. For a Git server, the key should only be allowed to run Git-related commands, not open an interactive shell.

### Insight
Think of SSH keys not as identities, but as specific capabilities. Instead of a key identifying "Alex," it should represent the capability to "deploy the web-app" or "read from the git-repo-alpha." This makes it much easier to reason about and limit what an attacker can do if they steal one.

### Practical
- **Audit Deploy Keys:** Look at the deploy keys configured in your GitHub, GitLab, or Bitbucket repositories. Do they have write access when they only need read? Are they used for multiple projects?
- **Review Firewall Rules:** Ask your infrastructure team to show you the firewall rules for your bastion hosts. Can you reach the production database from it? Should you be able to?
- **Example `authorized_keys` restriction:**
```
# This key can ONLY run the git-shell, and not an interactive login
command="git-shell -c \"$SSH_ORIGINAL_COMMAND\"" ssh-ed25519 AAAA... deploy-key-for-app-alpha
```

### Tools/Techniques
*   **Cloud Security Groups/VPC Firewalls:** Use [AWS Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html) or [GCP Firewall Rules](https://cloud.google.com/vpc/docs/firewalls) to enforce strict network segmentation.
*   **[Gitolite](http://gitolite.com/gitolite/index.html):** A granular access control layer for Git that helps enforce least privilege for repositories.
*   **[Teleport](https://goteleport.com/):** A modern access platform that provides short-lived, certificate-based access instead of static keys, along with session recording and RBAC, effectively replacing traditional bastion hosts.

### Metrics/Signal
*   Percentage of SSH keys (especially for automation) that have a `command` restriction.
*   Network logs showing that connections from bastion hosts to unauthorized internal segments are being blocked.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack in progress, you need visibility into SSH activity. You should be logging all SSH authentication successes and failures from all servers and centralizing them. Anomaly detection can then be built on top of these logs. A developer's key being used to access a system it has never touched before, or a CI key being used from an IP address outside of your known build agent range, are strong indicators of compromise. For the TOFU attack, log messages containing "Host key verification failed" or "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" are critical alerts.

### Insight
Logs are useless if they sit unread on individual machines. The key to detection is centralization and correlation. Seeing one failed login on one machine is noise. Seeing failed logins from the same source IP across ten machines in two minutes is a clear signal of an attack.

### Practical
- **Centralize SSH Logs:** Configure `rsyslog` on your Linux servers to forward `auth.log` files to a central logging platform.
- **Create Alerts:** In your logging platform, create alerts for high-priority events:
- Multiple SSH login failures from a single IP in a short time window.
- A user successfully logging in from a new country or IP range for the first time.
- Any `Host key verification failed` log message from a CI/CD runner.
- **Monitor Agent Sockets:** On critical machines like bastion hosts, use auditing tools to monitor for processes other than the user's own shell accessing their SSH agent socket.

### Tools/Techniques
*   **Log Aggregation:** The [ELK Stack](https://www.elastic.co/what-is/elk-stack) (Elasticsearch, Logstash, Kibana), [Graylog](https://www.graylog.org/), or commercial tools like [Splunk](https://www.splunk.com/) and [Datadog](https://www.datadoghq.com/) are essential for centralizing and analyzing logs.
*   **Host-based Intrusion Detection (HIDS):** Tools like [osquery](https://osquery.io/) can be used to monitor for changes in `known_hosts` files or to track shell history for suspicious commands.
*   **Linux `auditd`:** The Linux Auditing System can be configured with rules to monitor for access to `/tmp/ssh-*` sockets, providing a detailed log of potential hijacking activity.

### Metrics/Signal
*   **Alert:** "SSH login from user `alex` to `prod-db-1` from `bastion-1` (unprecedented access pattern)."
*   **Alert:** "CI runner `ci-agent-123` reported 'REMOTE HOST IDENTIFICATION HAS CHANGED' for `git.internal.example.com`."
*   A sudden spike in the volume of SSH authentication logs.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build muscle memory, teams must practice responding to these scenarios in a controlled environment.
1.  **Agent Hijacking Drill:** Set up a lab with two Docker containers: `bastion` and `target`. Give a developer (the "Red Teamer") root on `bastion`. Have another script or person (the "Blue Teamer") `ssh` into `bastion` with agent forwarding. The Red Teamer's goal is to use the forwarded agent to pivot and access the `target` container. The Blue Teamer's goal is to detect the unauthorized access using the logging and monitoring tools you have in place.
2.  **TOFU/MitM Drill:** Create a fake internal service and a DNS entry for it. During a planned exercise, have a team member change the DNS to point to a different machine. Ask another developer to connect to the service for the "first time." See if they question the host key fingerprint they are shown, or if they blindly accept it. Use this as a teaching moment.

### Insight
Security exercises shouldn't be about "gotcha" moments. They are about building confidence and identifying gaps in tooling, processes, and knowledge. The most valuable part of the exercise is the debrief: "What made this difficult to detect? What one change to our tooling would have stopped this? What did we learn?"

### Practical
- **Schedule a "Game Day":** Plan the exercise, define the rules of engagement, and allocate time for it. Don't make it a surprise.
- **Tabletop Exercise:** Before a live drill, walk through the scenario verbally. "Attacker is on the bastion. What logs would we see? Who gets the alert? What's our first step?" This can uncover major gaps without needing a complex technical setup.
- **Educate:** Use the results of the drill to create targeted training. If everyone fails the TOFU test, hold a short session on what SSH host keys are and how to verify them.

### Tools/Techniques
*   **[Docker](https://www.docker.com/) or [Vagrant](https://www.vagrantup.com/):** For creating isolated, disposable environments for the exercises.
*   **[Red Team/Attack Simulation Platforms](https://attack.mitre.org/resources/attack-emulation-plans/):** More advanced organizations can use platforms to automate and track these exercises.
*   **Internal Documentation/Playbook:** Document the scenario, the expected detection signals, and the correct remediation steps in your team's wiki.

### Metrics/Signal
*   **Mean Time to Detect (MTTD):** How long did it take the Blue Team to notice the unauthorized access in the agent hijacking drill?
*   **TOFU Drill Success Rate:** What percentage of developers correctly identified and reported the host key mismatch in the MitM drill?
*   Improvements in these metrics over subsequent exercises.
{% endblock %}