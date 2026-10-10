---
title: SSH Agent Forwarding and Host Key Trust
category: Secrets & Credentials
scenario: Hijacked forwarded agents on a bastion, and unpinned host keys in CI
focus:
  - agent forwarding hijack
  - trust-on-first-use host keys in CI
  - destination-constrained agent keys
  - host key pinning and SSH certificates
---

## Scenario

An attacker gets root on a shared bastion host through an unpatched service. Developers reach internal servers through this bastion, and many of them have `ForwardAgent yes` in their SSH config.

When Alex connects with agent forwarding, sshd on the bastion creates a socket for the forwarded agent. Older OpenSSH puts it under `/tmp/ssh-*`; OpenSSH 10.1 (October 2025) moved it to `~/.ssh/agent/` in Alex's home directory. Either way, root can use it. The attacker points `SSH_AUTH_SOCK` at Alex's socket, runs `ssh-add -l` to see Alex's keys, then connects to `git.internal.example.com` as Alex. They cannot copy the private key, but while Alex stays connected they can use it as often as they like.

Separately, a new CI runner clones from the same Git server over SSH. Its script contains `-o StrictHostKeyChecking=no` because the first build failed with "Host key verification failed". An attacker who can redirect the runner's DNS presents their own host key, and the runner accepts it without question.

The attacker cannot steal the runner's deploy key this way. SSH signatures are bound to the session, so they cannot be replayed to the real server. What the attacker *can* do is serve a doctored repository, and the pipeline builds and ships it.

**Real-world precedent:** In the [April 2019 Matrix.org breach](https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident/), an attacker exploited an outdated Jenkins server and hijacked forwarded SSH agents to reach production. Disabling agent forwarding was the first SSH remediation in the post-mortem. In March 2023 GitHub [replaced its RSA SSH host key](https://github.blog/news-insights/company-news/we-updated-our-rsa-ssh-host-key/) after it was briefly exposed in a public repository, a reminder that pinned host keys need a planned way to change.

::: {! stage recon}
## Reconnaissance

### Explanation

After landing on a shared host, an attacker looks for ways to move sideways. Forwarded agent sockets are an obvious one. They list agent sockets in `/tmp/ssh-*` and `/home/*/.ssh/agent/`, read `~/.ssh/config` and shell histories, and watch who logs in.

For the host key attack they look for automation that connects over SSH without verifying the server: CI scripts with `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, or `ssh-keyscan` piped straight into `known_hosts`.

### Insight

Agent forwarding inverts the usual model. Your key stays on your laptop, but every host you forward to can ask your laptop to sign on its behalf. A compromised bastion becomes a key-signing service for whoever has root there.

### Practical

Look at your own exposure:

```bash
grep -rniE 'ForwardAgent|StrictHostKeyChecking|UserKnownHostsFile' ~/.ssh/config /etc/ssh/ssh_config /etc/ssh/ssh_config.d/ 2>/dev/null
grep -rnE 'StrictHostKeyChecking[= ]no|UserKnownHostsFile[= ]/dev/null|ssh-keyscan' \
    .github/ .gitlab-ci.yml Jenkinsfile scripts/ 2>/dev/null
```

On bastions, check how many forwarded agent sockets exist at a busy time:

```bash
sudo find /tmp /home -type s \( -path '/tmp/ssh-*' -o -path '*/.ssh/agent/*' \) 2>/dev/null
```

### Tools/Techniques

- `grep` across dotfiles, CI configuration and scripts.
- GitHub code search: `org:your-org "StrictHostKeyChecking=no"`.
- `find` on bastions for agent sockets.

### Metrics/Signal

- Developers with `ForwardAgent yes` for broad host patterns.
- CI jobs that disable host key checking.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Work out which access paths depend on forwarding, and which automated connections trust whatever key they are shown.

### Insight

OpenSSH's default for `StrictHostKeyChecking` is `ask`. In an interactive session you see a fingerprint and decide. In CI there is no terminal, so the connection fails, and the common "fix" is to turn checking off. That turns trust-on-first-use into trust-every-time.

`ProxyJump` (and `ProxyCommand ssh -W`) do not forward your agent. They tunnel your connection through the bastion, and authentication to the inner host happens end to end from your laptop. The risky setting is `ForwardAgent yes`.

### Practical

1. List the hosts people forward to and why. Most uses are "so I can SSH onwards", which `ProxyJump` handles without forwarding.
2. List the real remaining needs, such as `git pull` from a server you are logged in to.
3. For each CI job that uses SSH, record how it gets the server's host key.
4. Check sshd versions on bastions. The [xz-utils backdoor (CVE-2024-3094)](https://nvd.nist.gov/vuln/detail/CVE-2024-3094) in 2024 targeted sshd through a compromised library, and bastions are where such a backdoor does the most damage.

### Tools/Techniques

- `ssh -G hostname` to print the effective config for a host.
- `ssh -V` and your package manager to check OpenSSH and library versions.

### Metrics/Signal

- Forwarding use that `ProxyJump` could replace.
- CI jobs with no pinned host key.
:::

::: {! stage fortify}
## Fortify

### Explanation

Replace forwarding with jumping, constrain what a forwarded key can do, and pin host keys everywhere automation connects.

### Insight

OpenSSH 8.9 (2022) added [destination constraints](https://www.openssh.com/agent-restrict.html) for agent keys. You can say "this key may only be used to reach the bastion, and from the bastion only `git.internal.example.com`". A hijacked socket then cannot reach anything else.

### Practical

Use `ProxyJump` and keep forwarding off by default:

```text
Host *
    ForwardAgent no
    StrictHostKeyChecking ask
    UpdateHostKeys yes

Host bastion
    HostName bastion.example.com

Host *.internal.example.com
    ProxyJump bastion
```

If you must forward, constrain the key and require confirmation for each use:

```bash
ssh-add -c \
    -h bastion.example.com \
    -h "bastion.example.com>git.internal.example.com" \
    ~/.ssh/id_ed25519
```

`-c` asks you to approve every signature through `ssh-askpass`. `-h` limits where the key can be used. Destination constraints need OpenSSH 8.9 or later on the client and on the hosts involved, and the host keys must be known.

Pin host keys in CI instead of disabling checks:

```bash
mkdir -p ~/.ssh
printf '%s\n' "$GIT_SERVER_KNOWN_HOSTS" > ~/.ssh/known_hosts
export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$HOME/.ssh/known_hosts"
git clone git@git.internal.example.com:team/service.git
```

Store `GIT_SERVER_KNOWN_HOSTS` as a CI variable taken from a verified source. For GitHub, use the fingerprints in GitHub's documentation or the `ssh_keys` field of `https://api.github.com/meta`.

For your own fleet, avoid per-host TOFU completely:

- Sign host keys with an SSH certificate authority and add one `@cert-authority *.internal.example.com ssh-ed25519 AAAA...` line to `known_hosts`.
- Or publish SSHFP records in DNSSEC-signed zones and set `VerifyHostKeyDNS yes`.
- For interactive use, `StrictHostKeyChecking accept-new` accepts first-seen keys but refuses changed ones. It is still trust-on-first-use, so do not use it in CI.

### Tools/Techniques

- `ProxyJump`, `ssh-add -c` and `ssh-add -h`.
- SSH certificates via `ssh-keygen -s`, or a CA service such as HashiCorp Vault's SSH secrets engine, Smallstep or Teleport.
- SSHFP records generated with `ssh-keygen -r`.

### Metrics/Signal

- Percentage of developers using `ProxyJump` instead of forwarding.
- CI jobs with pinned host keys (target: all).
:::

::: {! stage limit}
## Limit

### Explanation

Reduce what a hijacked agent or a spoofed Git server can achieve.

### Insight

A hijacked agent is only as powerful as the keys loaded into it, and only for as long as they stay loaded.

### Practical

- Use separate keys for separate purposes, and load only what you need: `ssh-add -t 1h` sets a lifetime.
- Keep keys on a hardware token (`ed25519-sk`) so each use needs a touch. A remote attacker cannot press it.
- Give CI deploy keys read-only access to one repository each.
- Verify what you build as well as where it came from: require signed commits or tags on release branches, and check them in CI with `git verify-commit` or `git verify-tag`.
- Use short-lived SSH certificates for people, so access expires on its own.

### Tools/Techniques

- `ssh-add -t`, FIDO2 security keys.
- Read-only deploy keys or GitHub App tokens scoped to one repository.
- Commit and tag signing with SSH or Sigstore gitsign.

### Metrics/Signal

- Agent keys loaded without a lifetime.
- Deploy keys with write access.
:::

::: {! stage expose}
## Expose

### Explanation

Spot agent sockets being used by the wrong process, and host keys that change unexpectedly.

### Insight

A hijacked agent shows up as your key authenticating from the bastion when you were not doing anything. A spoofed server shows up as a host key mismatch, if you have pinned the key.

### Practical

- Set `LogLevel VERBOSE` in sshd on internal servers so logs record which key fingerprint authenticated. Alert on a person's key used from the bastion outside their working hours or session.
- On bastions, use Falco or auditd to log connections to forwarded agent sockets by any process that is not the owner's own session.
- Treat `REMOTE HOST IDENTIFICATION HAS CHANGED` in CI as a security incident until you can explain it.

### Tools/Techniques

- sshd `LogLevel VERBOSE` shipped to your log platform.
- auditd or Falco on bastions.
- CI failure alerts for host key mismatches.

### Metrics/Signal

- Key authentications from the bastion with no matching user session.
- Host key mismatch failures in CI, and how each was resolved.
:::

::: {! stage exercise}
## Exercise

### Explanation

Show the team how easy agent hijacking is, and prove that pinning catches a spoofed server, using lab machines only.

### Insight

Watching `ssh-add -l` list your own keys from someone else's root shell changes habits fast.

### Practical

1. Build a lab with three VMs: laptop, bastion and target. Use throwaway keys.
2. Connect laptop to bastion with `ssh -A`. As root on the bastion, find the socket with the `find` command from Reconnaissance and run `SSH_AUTH_SOCK=<socket path> ssh-add -l`.
3. Repeat with `ProxyJump` and show that no socket exists on the bastion.
4. Repeat with `ssh-add -c -h ...` and show that the hijacked socket cannot reach an unlisted host.
5. In a lab CI job with a pinned `known_hosts`, regenerate the target's host key and confirm the job fails loudly.

### Tools/Techniques

- Local VMs (Vagrant, Multipass or containers) on an isolated network.
- Throwaway keys created for the lab only.

### Metrics/Signal

- Developers who moved to `ProxyJump` after the session.
- Whether the pinned CI job failed as expected.
:::

## Further Reading

- [OpenSSH: agent restriction (destination constraints)](https://www.openssh.com/agent-restrict.html)
- [OpenSSH 8.9 release notes](https://www.openssh.com/txt/release-8.9)
- [Matrix.org: post-mortem for the April 2019 incident](https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident/)
- [GitHub: we updated our RSA SSH host key](https://github.blog/news-insights/company-news/we-updated-our-rsa-ssh-host-key/)
- [NVD: CVE-2024-3094 (xz-utils backdoor)](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)
