---
title: DNS Hijacking and Man-in-the-Middle on Dependency Downloads
category: Network & Distribution
scenario: Spoofed package mirror over plain HTTP, with DNS tunnelling for exfiltration
focus:
  - insecure package indexes and --trusted-host
  - DNS spoofing of internal mirrors
  - DNS tunnelling exfiltration from build agents
---

## Scenario

A data team's build agents run on-premises. They install Python packages from an internal mirror. Two years ago someone got tired of certificate errors and set this on every agent:

```ini
# /etc/pip.conf
[global]
index-url = http://pypi-mirror.corp.example/simple
trusted-host = pypi-mirror.corp.example
```

Pointing `pypi.org` at a fake server would fail, because pip validates TLS certificates against public CAs. This configuration removes that protection for the one host that matters.

1. An attacker gains a foothold on a device on the build network. They answer DNS queries for `pypi-mirror.corp.example` with their own IP, using spoofed responses or a rogue DHCP server that hands out their resolver.
2. Their server proxies the real mirror, except for one popular data-processing library, where it serves a trojanised wheel with the same version number.
3. pip has no TLS to check and no hashes to compare, so it installs the wheel. The payload runs when tests import the library.
4. The build network blocks outbound HTTPS, but the internal resolver forwards any query to the internet. The payload base64-encodes credentials and model files and leaks them as DNS lookups such as `a3f9c1....x7.t.attacker.example`. Each label can hold at most 63 characters and a full name at most 253, so it sends thousands of queries. The attacker's authoritative name server logs and reassembles them.

The same MITM works without any DNS tricks if an agent trusts a corporate TLS-inspection CA and that CA's key leaks, or if any repository URL still uses `http://`.

**Real-world precedent:** The SolarWinds [SUNBURST backdoor](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor) (disclosed December 2020) used DNS lookups of generated `avsvmcloud[.]com` subdomains, encoding victim details, as its first-stage command and control. In 2019 Jonathan Leitschuh showed that [many popular Java projects fetched dependencies over plain HTTP](https://infosecwriteups.com/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb), leaving them open to exactly this kind of MITM. Maven Central went HTTPS-only in January 2020.

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers look for the places where transport security has been switched off: `http://` index URLs, `--trusted-host`, `strict-ssl=false`, `allowInsecureProtocol`, `GOINSECURE`. They also map how build networks resolve names and whether DNS can reach the internet when HTTPS cannot.

### Insight

Public registries are hard to impersonate because of TLS. Internal mirrors are often easier, because teams weaken TLS to work around internal certificate problems. And DNS is the egress path firewalls most often forget.

### Practical

- Search config and CI files for insecure settings across ecosystems.
- Draw how each build agent resolves names: which resolver, and whether that resolver forwards to the internet.
- List any TLS-inspection or internal CA certificates installed on build agents.

### Tools/Techniques

- A quick search:

    ```bash
    rg -n -e 'trusted-host' -e 'index-url\s*=\s*http://' -e 'strict-ssl\s*=\s*false' \
      -e 'allowInsecureProtocol' -e 'GOINSECURE' -e 'http://[^ ]*/(simple|maven|npm)'
    ```

- `pip config debug` on an agent to see the effective pip settings and where they come from.

### Metrics/Signal

- Number of insecure registry settings across repos and agent images.
- Whether build networks can resolve arbitrary internet names.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check each dependency fetch for two independent protections: an authenticated transport (HTTPS with proper certificate validation) and content integrity (pinned hashes). Then check whether DNS is a usable exfiltration path.

### Insight

Hash pinning is the control that survives everything else failing. If the lockfile says what the wheel's SHA-256 must be, a spoofed mirror, a rogue CA or a poisoned DNS answer all end in a failed install.

### Practical

- Check that Python installs use a lockfile with hashes (`uv.lock`, or `pip install --require-hashes`), and that npm installs use `npm ci` against a `package-lock.json` with `integrity` fields.
- Check Maven and Gradle versions. Maven 3.8.1+ blocks `http://` repositories by default, and Gradle 7+ refuses them unless `allowInsecureProtocol` is set.
- Check whether agents can send DNS queries to any resolver other than yours, or use DNS-over-HTTPS to a public provider.

### Tools/Techniques

- `uv lock` and `uv sync --locked`, or `pip-compile --generate-hashes`.
- `nslookup example.com 8.8.8.8` from an agent: if it answers, direct external DNS is open.

### Metrics/Signal

- Percentage of builds that install with hash verification.
- Build networks with unrestricted outbound DNS.
:::

::: {! stage fortify}
## Fortify

### Explanation

Restore TLS everywhere, pin hashes, and close DNS as a side channel.

### Insight

Fixing the certificate problem properly, by distributing your internal CA to agents through configuration management, is less work than living with `--trusted-host` forever.

### Practical

- Serve internal mirrors over HTTPS with certificates from your internal CA. Install that CA on agents and remove every `trusted-host` entry:

    ```ini
    # /etc/pip.conf
    [global]
    index-url = https://pypi-mirror.corp.example/simple
    cert = /etc/ssl/certs/corp-root-ca.pem
    require-hashes = true
    ```

- Install from a locked, hashed requirements set. With uv:

    ```bash
    uv sync --locked
    ```

- Sign your internal DNS zones with DNSSEC where your resolvers validate it, and point agents only at your own resolvers.
- On Linux agents using systemd-resolved, encrypt queries to your resolver with DNS-over-TLS:

    ```ini
    # /etc/systemd/resolved.conf
    [Resolve]
    DNS=10.0.0.53#dns.corp.example
    DNSOverTLS=yes
    ```

- Block outbound TCP/UDP 53 and 853 from build networks except to your resolvers, and block well-known public DoH endpoints at the proxy.
- Stop internal resolvers serving build networks from recursing to arbitrary internet domains. Allow only the domains builds need.

### Tools/Techniques

- uv, pip-tools, `npm ci`, Maven and Gradle HTTPS defaults.
- [Route 53 Resolver DNS Firewall](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html), or response-policy zones on BIND or Unbound, for domain allow lists.
- Kubernetes `NetworkPolicy` allowing UDP/TCP 53 only to cluster DNS; Cilium `toFQDNs` policies for name-based egress.

### Metrics/Signal

- Insecure registry settings remaining (target zero).
- Build networks with DNS restricted to internal resolvers and an allow list.
:::

::: {! stage limit}
## Limit

### Explanation

If a trojanised package does install, limit what it can read and how much it can send.

### Insight

DNS tunnelling is slow. A strict domain allow list on the resolver turns it from slow into impossible, and a build that holds no long-lived secrets has little worth stealing.

### Practical

- Install and test in a step with no cloud or registry credentials. Add secrets only in later steps that need them.
- Keep model files and datasets out of general build jobs. Fetch them only in jobs that need them, with read-only, short-lived credentials.
- Run builds in ephemeral containers so a payload cannot persist on the agent.
- Rate-limit queries per client on resolvers serving build networks.

### Tools/Techniques

- CI step-level secrets and OIDC federation for short-lived cloud credentials.
- Resolver rate limiting (for example Unbound `ip-ratelimit`).

### Metrics/Signal

- Secrets in scope during dependency install.
- Resolver queries per build job (a sudden spike is a signal).
:::

::: {! stage expose}
## Expose

### Explanation

Look for both halves of this attack: a package that does not match what you expected, and DNS traffic that looks like data.

### Insight

DNS tunnelling has a recognisable shape: labels close to the 63-character limit, high entropy, and hundreds of unique subdomains under a single parent domain in a short time.

### Practical

- Treat any hash mismatch during install as a security event. Do not let anyone "fix" it by regenerating the lockfile without finding out why.
- Log all queries from build networks. Alert on long, high-entropy labels and on bursts of unique subdomains under one domain.
- Alert when the IP address your internal mirror name resolves to changes unexpectedly.
- Compare installed package hashes in build logs with your mirror's records.

### Tools/Techniques

- Route 53 Resolver query logging, CoreDNS `log` plugin, or [Zeek](https://zeek.org/) `dns.log`.
- A simple query over logs: group by registered domain, count distinct subdomains, flag labels over 50 characters.

### Metrics/Signal

- Hash mismatch events per month (should be rare and always explained).
- Domains with more than a few hundred unique subdomains queried per hour from build networks.
:::

::: {! stage exercise}
## Exercise

### Explanation

Run the whole attack in an isolated lab: a spoofed mirror and a harmless DNS leak.

### Insight

Watching pip reject a spoofed wheel because of a hash mismatch builds more confidence than any policy review.

### Practical

1. On an isolated Docker network, run a local devpi or `pypiserver` as the "real" mirror and another as the "spoofed" one. Put a modified but harmless copy of a test wheel on the spoofed server.
2. Run `dnsmasq` on the lab network and point `pypi-mirror.lab` at the spoofed server.
3. Install with your old config (`http://` and `trusted-host`) and see the modified wheel install. Then install with your hardened config and confirm the hash check fails.
4. From a lab container, resolve a [Canarytokens](https://canarytokens.org) DNS token with a long random label prepended. Confirm the query appears in your DNS logs and trips the long-label alert, and that the resolver allow list blocks it once enabled.

### Tools/Techniques

- Docker networks, `dnsmasq`, devpi or pypiserver.
- Canarytokens DNS tokens for a harmless, observable lookup.

### Metrics/Signal

- Whether the hardened config rejected the spoofed wheel.
- Whether the DNS alert fired, and how long it took.
:::

## Further Reading

- [Mandiant: SUNBURST backdoor analysis (December 2020)](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor)
- [Want to take over the Java ecosystem? All you need is a MITM! (Jonathan Leitschuh, 2019)](https://infosecwriteups.com/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb)
- [pip: secure installs and hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [systemd resolved.conf](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html)
