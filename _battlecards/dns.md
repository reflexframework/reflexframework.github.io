---
permalink: /battlecards/dns
title: DNS and MITM Attacks
battlecard:
 title: DNS and MITM Attacks
 
 category: Cross-cutting
 scenario: DNS/MITM
 focus: 
   - fake package mirrors 
   - registry poisoning 
   - exfiltration via DNS 
---

An attacker targets a development team's CI/CD pipeline to steal proprietary source code and a trained AI model file. The attacker knows the team uses a popular open-source Python library for data processing.

1.  **DNS Poisoning:** The attacker gains control of a public DNS resolver used by one of the company's cloud-based, auto-scaling build agents. They create a DNS rule that redirects requests for `pypi.org` (the official Python Package Index) to an attacker-controlled server.
2.  **Fake Package Mirror:** This malicious server hosts a fake mirror of PyPI. It serves all packages correctly, except for the targeted data processing library. When the build agent runs `pip install -r requirements.txt`, it downloads a trojanized version of the library. This version is identical to the real one but includes a small, obfuscated payload.
3.  **Payload Activation:** The payload activates during the build process. It scans the build environment for environment variables (like `AWS_ACCESS_KEY_ID`), git credentials, and specific file types (like `.py` and `.pkl` for the serialized AI model).
4.  **Exfiltration via DNS:** The payload can't send the stolen data over HTTPS, as egress traffic is heavily restricted by a firewall. However, the firewall allows outbound DNS traffic (port 53) for name resolution. The payload Base64-encodes the stolen files and secrets, splits them into 200-character chunks, and makes a series of DNS lookups like: `[chunk1].models.malicious-domain.com`, `[chunk2].models.malicious-domain.com`. The attacker's authoritative DNS server logs these requests, reassembles the data, and successfully steals the company's intellectual property without triggering traditional network alerts.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. They are looking for the weakest link in your development lifecycle. They aren't trying to breach your production firewall directly; instead, they are studying your team's public footprint to find a softer target, like your build process. They will search for public source code repositories, read your developers' blog posts, and scan job postings to understand your tech stack (e.g., "Experience with PyTorch, AWS, and Jenkins required"). They'll identify common dependencies you use, which become prime candidates for trojanizing. The goal is to understand your environment so they can craft a payload that blends in.

### Insight
Your supply chain is not just the code you write, but the ecosystem of tools, libraries, and infrastructure you depend on. Attackers view your CI/CD pipeline as a high-value target because it's a trusted environment that aggregates source code, credentials, and artifacts. A compromise here is often more damaging than a single web server breach.

### Practical
*   **Audit Public Information:** Google your company and its open-source projects. What can an outsider learn about your tech stack and dependencies from your public GitHub repositories, Docker Hub images, or conference talks?
*   **Developer Anonymity:** Encourage developers to be mindful of the information they share on public forums like Stack Overflow or personal blogs that can be linked back to your company's internal practices.

### Tools/Techniques
*   **[GitHub Code Search](https://github.com/search):** Attackers use advanced search queries to find `requirements.txt`, `package.json`, or `pom.xml` files in your public repositories to map your dependencies.
*   **[Shodan](https://www.shodan.io/):** Used to find internet-facing infrastructure, including potentially misconfigured Jenkins or Artifactory instances that reveal information about your build processes.

### Metrics/Signal
*   **Dependency Exposure Score:** A qualitative metric assessing how many of your core project dependencies are discoverable through public sources. The goal is to reduce this.
*   **Secrets in Code:** Number of secrets found in public or private repositories. This should always be zero.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you play the role of the attacker against your own systems. You need to assess how vulnerable your development and build environments are to DNS-based attacks. Ask critical questions: Can a build agent in your CI/CD pipeline resolve arbitrary external domains? Do your package managers (`npm`, `pip`, `maven`) enforce secure connections (HTTPS) to repositories, and more importantly, do they validate the TLS certificates? Are you pinning dependency versions, or does your build process always pull the "latest" version of a package, making it vulnerable to a malicious update?

### Insight
Developers implicitly trust their build tools and the networks they run on. We assume `pip install` or `npm install` is a safe operation. This stage is about challenging that assumption and understanding that the network layer beneath these simple commands can be manipulated with significant consequences.

### Practical
*   **From a Build Container:** SSH into a running build agent or use a debug session in your CI job. Run commands like `dig pypi.org` or `nslookup registry.npmjs.org`. What is the DNS resolution path? Does it go through a corporate DNS server you control, or a public one?
*   **Check Configurations:** Review your package manager configurations (`.npmrc`, `pip.conf`, `settings.xml`). Are you pointing to specific, trusted registries, or are you open to the public internet?
*   **Dependency Audit:** Check your projects. Are you using lockfiles (`package-lock.json`, `poetry.lock`)? How many of your dependencies use floating versions (e.g., `^1.2.3` or `*`)?

### Tools/Techniques
*   **[pip-audit](https://pypi.org/project/pip-audit/):** A tool for scanning Python environments for packages with known vulnerabilities.
*   **[npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit):** Scans your Node.js project for vulnerabilities in dependencies.
*   **DNS lookup tools:** `dig` and `nslookup` are essential command-line tools for inspecting DNS responses.

### Metrics/Signal
*   **Unpinned Dependency Rate:** The percentage of dependencies across all projects that are not locked to a specific version and hash. This should be as close to 0% as possible.
*   **Build Egress Routes:** The number of unique, non-approved external domains resolved by your build agents over a 24-hour period.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is the proactive hardening phase. The goal is to make the attack scenario impossible to execute. The most effective defense is to remove reliance on public, untrusted infrastructure during your build process. You should enforce strict rules for dependencies and network connections, creating a "walled garden" for your CI/CD environment.

### Insight
Security by default is the key. Instead of developers having to remember to do the right thing, the build system should make it impossible to do the wrong thing. Forcing all dependency resolution through a trusted, internal proxy is one of the single most effective supply chain security controls you can implement.

### Practical
*   **Use a Private Registry:** Set up and enforce the use of an internal package repository (like Nexus or Artifactory). This server acts as a proxy that caches and vets approved open-source packages. Configure all developer machines and CI agents to *only* use this registry.
*   **Enforce Dependency Pinning:** Mandate the use of lockfiles (`package-lock.json`, `poetry.lock`, etc.) and verify their presence in a pre-commit hook or a CI check. Use tools that verify package integrity using hashes (e.g., `pip`'s hash-checking mode).
*   **Secure DNS:** Configure your build agents' operating systems to use DNS over HTTPS (DoH) or DNS over TLS (DoT). This encrypts DNS queries, making them much harder to intercept and manipulate in a MITM attack.

### Tools/Techniques
*   **Package Registries:**
*   **[Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository):** A popular artifact repository that can proxy and cache repositories for Maven, npm, PyPI, and more.
*   **[JFrog Artifactory](https://jfrog.com/artifactory/):** Another leading solution for managing your software supply chain.
*   **Secure DNS Resolvers:**
*   **[Cloudflare 1.1.1.1](https://developers.cloudflare.com/1.1.1.1/encryption/):** Provides public DoH and DoT services.
*   **[systemd-resolved](https://wiki.archlinux.org/title/systemd-resolved):** A Linux service that can be configured to use DoH/DoT.

### Metrics/Signal
*   **Private Registry Adoption:** Percentage of builds that resolve 100% of their dependencies from the internal registry. This should be 100%.
*   **Hash Mismatch Failures:** Number of builds that fail due to a dependency hash mismatch. A non-zero number here could indicate a successful defense against a compromised package.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker has succeeded and malicious code is now running inside your build environment. The goal of this stage is to contain the "blast radius." If the malware can't access secrets and can't communicate with the outside world, it is effectively neutralized. This is achieved by running builds in an environment built on the principle of least privilege.

### Insight
A successful breach doesn't have to mean a catastrophic failure. Modern infrastructure allows us to treat our build environments as ephemeral, zero-trust sandboxes. The malware might get in, but if it's trapped in a box with nothing valuable and no way out, it can't do any harm.

### Practical
*   **Ephemeral & Isolated Builds:** Run each CI job in a fresh, single-use container or VM that is destroyed immediately after the job completes. This prevents any malware from persisting.
*   **Strict Egress Control:** Configure firewalls or network policies to deny all outbound network traffic from build agents by default. Only allow connections to specific, required internal services like your private package registry and source control server. Explicitly block outbound DNS to external resolvers.
*   **Just-in-Time Secrets:** Do not store secrets as long-lived environment variables in your CI/CD tool. Use a secrets manager to inject short-lived credentials (e.g., an AWS role with a 15-minute TTL) directly into the build process when needed. The credentials should expire before an attacker could even exfiltrate them.

### Tools/Techniques
*   **Container Runtimes:** [Docker](https://www.docker.com/) and container orchestrators like [Kubernetes](https://kubernetes.io/) are ideal for creating isolated build environments.
*   **Kubernetes Network Policies:** Use [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) to define strict ingress and egress rules for your build pods.
*   **Secrets Management:**
*   **[HashiCorp Vault](https://www.vaultproject.io/):** A tool for securely managing and dynamically generating secrets.
*   **[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/):** A managed service for secret storage and rotation.
*   **[GitHub Actions OIDC integration](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services):** Allows your workflows to request short-lived access tokens directly from cloud providers without storing long-lived keys.

### Metrics/Signal
*   **Denied Egress Connections:** The number of outbound network connections from build agents blocked by the firewall. A sudden spike is a strong indicator of a compromised dependency trying to "phone home."
*   **Secret TTL:** The average time-to-live for secrets injected into builds. This should be as short as possible (e.g., minutes, not hours or days).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about making the invisible visible. How do you know an attack is happening? The key is to monitor the right signals. In this scenario, the most powerful signal is anomalous DNS traffic. Your build agents should have a very predictable network footprint. Any deviation from this baseline is suspicious. You need logging, monitoring, and alerting to detect these deviations in near real-time.

### Insight
Attackers rely on stealth. DNS exfiltration is popular because DNS traffic is high-volume and often ignored by security teams. By treating DNS logs as a critical security data source, you turn one of the attacker's greatest strengths into their biggest vulnerability. They *have* to make noise on the network to get data out; you just have to be listening.

### Practical
*   **Log All DNS Queries:** Capture and forward all DNS queries originating from your build infrastructure to a centralized logging system (like an ELK stack or Splunk).
*   **Create Anomaly Alerts:** Develop alerts based on heuristics that indicate DNS exfiltration:
*   Queries for unusually long subdomains (e.g., > 50 characters).
*   A high rate of unique subdomain queries to the same parent domain.
*   DNS queries containing non-standard characters or high entropy (suggesting encoded data).
*   **Monitor Dependency Changes:** Use automated tools to monitor every pull request. Flag any new dependencies or significant version jumps on existing ones for manual security review.

### Tools/Techniques
*   **Network Monitoring:**
*   **[Zeek (formerly Bro)](https://zeek.org/):** An open-source network security monitoring framework that can produce detailed DNS logs.
*   **[Packetbeat](https://www.elastic.co/beats/packetbeat):** A lightweight network packet analyzer that can ship DNS traffic data to Elasticsearch.
*   **Runtime Security:** **[Falco](https://falco.org/):** An open-source tool that can detect unexpected network connections or file access from within containers at runtime.
*   **Dependency Scanning:** **[Snyk](https://snyk.io/)** or **[GitHub Dependabot](https://github.com/dependabot)** can be configured to alert on changes to your dependency manifests.

### Metrics/Signal
*   **Mean Time To Detect (MTTD):** How long does it take from the moment a malicious DNS query is made to the moment an alert is fired to the security team? The goal is to get this down to minutes.
*   **DNS Query Baseline Deviation:** Number of alerts triggered by build agents making DNS queries to domains not on an allow-list.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is how you build muscle memory. You can't wait for a real attack to test your defenses and response plan. You need to simulate the attack in a controlled environment to see where your processes, tools, and people fail. The goal is to practice, refine your playbook, and educate developers so that responding to an incident becomes a routine, not a panic.

### Insight
Security is not just about building walls; it's about training the defenders. When developers participate in these exercises, they gain a much deeper and more intuitive understanding of the threats. They stop seeing security as a checklist and start seeing it as an integral part of building resilient software.

### Practical
*   **Tabletop Exercise:** Gather the dev team, security, and operations. Present the scenario: "A Snyk alert just fired for a new, suspicious package in the `main` branch. Simultaneously, we're seeing high-entropy DNS alerts from our build cluster. What do we do, step-by-step?"
*   **Red Team Simulation:** Create a benign "malicious" package that, instead of stealing data, simply makes a series of unique DNS queries to a test domain you control. Try to introduce this package into a staging build environment. Did your `Expose` systems detect it? Did your `Limit` controls block it?
*   **Capture the Flag (CTF):** Create a challenge for developers. Give them a sandboxed CI environment with a known vulnerability. The goal is to find a "flag" (a fake secret) and exfiltrate it using DNS tunneling. This gamifies the learning process and teaches them to think like an attacker.

### Tools/Techniques
*   **DNS Simulation:**
*   **[dnschef](https://github.com/iphelix/dnschef):** A DNS proxy for penetration testers that's perfect for simulating DNS MITM attacks.
*   **[dnscat2](https://github.com/iagox86/dnscat2):** A tool designed for creating encrypted C2 channels over the DNS protocol, useful for exfiltration testing.
*   **Chaos Engineering:** Tools like **[Gremlin](https://www.gremlin.com/)** can be used to purposefully inject failures, like DNS resolution errors, to test the resilience and observability of your systems.

### Metrics/Signal
*   **Exercise Success Rate:** Percentage of simulated attacks that were successfully detected and contained by automated systems without human intervention.
*   **Mean Time To Respond (MTTR):** In exercises requiring a human response, how long did it take the team to identify the root cause and "remediate" the simulated incident?
{% endblock %}
