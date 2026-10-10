---
title: Jenkins CI/CD Compromise
category: CI/CD & Build
scenario: Internet-facing Jenkins controller taken over
focus:
  - unpatched core and plugins
  - controller file read and credential theft
  - builds running on the built-in node
---

## Scenario

Your Jenkins controller is reachable from the internet so contractors can see build status. It is two LTS releases behind and nobody has opened the plugin manager in months.

1. An attacker finds it through an internet scan for the `X-Jenkins` header, which also reveals the version.
2. The version is vulnerable to CVE-2024-23897. Using the Jenkins CLI, the attacker reads files from the controller's filesystem without logging in.
3. Anonymous read access is switched on, which lets the bug return whole files. They read job `config.xml` files, workspace files and the Jenkins user's SSH keys.
4. A legacy freestyle job has a long-lived AWS access key in a shell step. Another workspace holds a `.git-credentials` file with a GitHub token that can write to your repositories.
5. Jobs also run on the controller's built-in node, so any pipeline the attacker can trigger runs with full access to `JENKINS_HOME`.

**Real-world precedent:** [CVE-2024-23897](https://www.jenkins.io/security/advisory/2024-01-24/), disclosed in January 2024, let unauthenticated users read arbitrary controller files via the CLI. CISA added it to the Known Exploited Vulnerabilities catalogue in August 2024 after it was used in ransomware attacks, including one against Indian IT firm Brontoo Technology Solutions.

::: {! stage recon}
## Reconnaissance

### Explanation
Jenkins announces itself. Every response carries an `X-Jenkins` version header, and the login page is easy to fingerprint. Attackers sweep the internet for both and match versions against the Jenkins security advisories.

### Insight
A Jenkins controller holds the keys to source control, artifact repositories and cloud accounts. Teams still treat it as an internal tool and leave it exposed and stale.

### Practical
- Search for your own controllers the way an attacker would: your domains and IP ranges on Shodan or Censys, plus DNS names like `jenkins.`, `ci.` and `build.`.
- Check the version header from outside your network:

    ```bash
    curl -sI https://jenkins.example.com/login | grep -i x-jenkins
    ```

- Check whether anonymous users can read anything. Visit the controller in a private browser window. Anonymous read access made CVE-2024-23897 far worse.

### Tools/Techniques
- [Shodan](https://www.shodan.io/) and [Censys](https://search.censys.io/) for internet-exposed controllers.
- [Jenkins security advisories](https://www.jenkins.io/security/advisories/) to match versions to known issues.

### Metrics/Signal
- Number of Jenkins controllers reachable from the internet (target: zero).
- Days since the controller's version was last updated.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Work out how far behind you are and how much damage controller access would do.

### Insight
Plugins are usually the weakest point. A typical controller runs dozens of them, each with its own advisory history.

### Practical
- Open **Manage Jenkins**. Jenkins shows an administrative monitor when installed core or plugins have published security warnings. Treat each one as a ticket.
- Check plugins outside the UI with the plugin manager CLI:

    ```bash
    jenkins-plugin-cli --plugin-file plugins.txt --no-download --available-updates
    ```

    It reports available updates and any security warnings for the listed plugins.
- Check **Manage Jenkins > Nodes > Built-In Node**. If it has more than 0 executors, builds run on the controller itself.
- Check whether pipelines use global shared libraries. Those run outside the Groovy sandbox, so anyone who can push to the library repository can run code on the controller.
- Review **Manage Jenkins > In-process Script Approval** for approved signatures such as `java.lang.Runtime exec`.

### Tools/Techniques
- [jenkins-plugin-cli](https://github.com/jenkinsci/plugin-installation-manager-tool) for version and security warning reports.
- [Jenkins CLI documentation](https://www.jenkins.io/doc/book/managing/cli/) to see which CLI transports are enabled.

### Metrics/Signal
- Count of installed plugins with open security warnings.
- Executors on the built-in node (target: 0).
- Number of approved script signatures.
:::

::: {! stage fortify}
## Fortify

### Explanation
Patch, take the controller off the internet, and stop running builds on it.

### Insight
Jenkins' own guidance is clear: the controller coordinates and agents build. Once builds run elsewhere, a malicious job can no longer read `JENKINS_HOME` directly.

### Practical
- Track the LTS line and update monthly. CVE-2024-23897 was fixed in 2.442 and LTS 2.426.3.
- Put the controller behind a VPN or an identity-aware proxy. Expose only the webhook endpoint if you need inbound events.
- Set the built-in node to 0 executors and run all builds on ephemeral agents (Kubernetes or cloud agents that are destroyed after each build). With Configuration as Code:

    ```yaml
    jenkins:
      numExecutors: 0
    ```

- Disable the CLI if nobody uses it. The 2024-01-24 advisory lists this as a workaround.
- Remove plugins you don't use. Each one is attack surface.
- Keep the Groovy sandbox on for every pipeline. Restrict who can push to repositories configured as global shared libraries.

### Tools/Techniques
- [Configuration as Code plugin](https://plugins.jenkins.io/configuration-as-code/) to keep controller settings reviewable in Git.
- [Kubernetes plugin](https://plugins.jenkins.io/kubernetes/) for per-build agent pods.
- [Controller isolation guidance](https://www.jenkins.io/doc/book/security/controller-isolation/).

### Metrics/Signal
- Time from Jenkins security advisory to patched controller.
- Builds executed on the built-in node in the last 30 days (target: zero).
:::

::: {! stage limit}
## Limit

### Explanation
If the controller falls, the attacker gets whatever credentials it stores. Store fewer, and make them weaker.

### Insight
CVE-2024-23897 was a file read bug. It became a full compromise because readable files on the controller held long-lived keys.

### Practical
- Replace static cloud keys with short-lived credentials. Agents on AWS can use an instance or pod role. Elsewhere, fetch secrets from Vault per build.
- Scope credentials to folders instead of the global store, so a job only sees the credentials of its own team.
- Use fine-grained GitHub tokens or a GitHub App with access to specific repositories instead of a personal token with org-wide write.
- Allow agent egress only to your SCM, artifact repository and cloud APIs.

### Tools/Techniques
- [Credentials Binding plugin](https://plugins.jenkins.io/credentials-binding/) with folder-scoped credentials.
- [HashiCorp Vault plugin](https://plugins.jenkins.io/hashicorp-vault-plugin/) for per-build secrets.
- [GitHub App credentials in GitHub Branch Source](https://github.com/jenkinsci/github-branch-source-plugin/blob/master/docs/github-app.adoc) for repository access.

### Metrics/Signal
- Count of long-lived cloud keys in the global credential store (target: zero).
- Credentials scoped globally versus per folder.
:::

::: {! stage expose}
## Expose

### Explanation
Detect the attack at the controller and wherever its stolen credentials get used.

### Insight
The file read itself is quiet. Its traces are CLI traffic from unusual sources, followed by stolen keys making API calls from unfamiliar places.

### Practical
- Log access to `/cli` and alert on unauthenticated CLI requests, especially if you have disabled the CLI.
- Record configuration and credential changes with the Audit Trail plugin and ship the logs off the controller.
- Alert on cloud API calls from Jenkins credentials originating outside your agent IP ranges.
- Watch GitHub audit logs for the Jenkins token pushing to branches or creating deploy keys.

### Tools/Techniques
- [Audit Trail plugin](https://plugins.jenkins.io/audit-trail/).
- Reverse proxy access logs (nginx, Apache) in front of the controller.
- AWS CloudTrail or your cloud provider's audit log.

### Metrics/Signal
- Requests to `/cli` from outside your network.
- Cloud API calls with Jenkins credentials from unknown IP addresses.
:::

::: {! stage exercise}
## Exercise

### Explanation
Test whether a stolen controller is a disaster or a nuisance.

### Insight
Most teams have never checked what an attacker would actually find in `JENKINS_HOME`. Spend an hour finding out.

### Practical
1. Stand up a disposable copy of your controller from Configuration as Code in an isolated network.
2. Load it with [Canarytokens](https://canarytokens.org/) in place of real credentials, using the same IDs and scopes.
3. From the attacker's seat, list what a job on the built-in node can read, and what a job on an agent can read.
4. Trigger one canary token. Measure how long the alert takes to reach a human.
5. Rehearse rotating every credential the controller holds. Time it.

### Tools/Techniques
- [Canarytokens](https://canarytokens.org/) for fake AWS keys and URLs.
- A disposable Jenkins built from the official `jenkins/jenkins:lts` image.

### Metrics/Signal
- Time to rotate every credential on the controller.
- Time from canary use to alert.
:::

## Further Reading

- [Jenkins security advisory 2024-01-24 (CVE-2024-23897)](https://www.jenkins.io/security/advisory/2024-01-24/)
- [Jenkins: Controller isolation](https://www.jenkins.io/doc/book/security/controller-isolation/)
- [CISA Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News: CISA warns of Jenkins vulnerability used in ransomware attacks](https://thehackernews.com/2024/08/cisa-warns-of-critical-jenkins.html)
