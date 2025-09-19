---
title: The Digital Warehouse. Security in Public Binary Repositories
---

{{ page.title }}

By Steve Poole

### 1. What Makes a Good Public Repository?
If you're building software, you already rely on public binary repositories : whether you admit it or not. They're the warehouses your build system raids every day to pull down jars, wheels, tarballs, or containers. So before we rank and compare them, let's set some ground rules for what "good" looks like.

#### 1.1 The Non-Negotiables (Required)
* **Immutability of versions** : Once you publish 1.2.3, that should never change. Reproducibility relies on this (Maven Central policy).
* **Namespace integrity** : Packages must map to something verifiable (e.g., Maven Central requires domain ownership; npm scopes; NuGet prefix reservation). This blocks impersonation and typosquats.
* **Cryptographic signing** : The repo should enforce or at least strongly support signing so consumers can check provenance (Central's mandatory GPG, PyPI's move to Sigstore).
* **Secure transport** : All downloads over HTTPS. Most repos have closed that gap now, but it wasn’t always true.
* **Transparent policies** : Removal, overwrite, and security escalation must be documented and enforced.

#### 1.2 Nice-to-Haves (Optional but Good)
* **Built-in vulnerability scanning** : Like npm audit or NuGetAudit. Great if it’s accurate, but always treat these as advisory not gospel.
* **Trusted publishing (OIDC)** : CI/CD-to-repo workflows without long-lived tokens. PyPI, npm, and NuGet now support this (PyPI docs).
* **Namespace reservation & org features** : npm scopes, NuGet ID Prefix Reservation, GitHub Packages orgs : all reduce “first come, first served” chaos.
* **SBOM/attestation support** : Still evolving, but Sigstore/Provenance APIs are moving in the right direction.

#### 1.3 The Red Flags (Bad Practices)
* **Mutable versions or tags** : Docker tags are the worst offender; npm dist-tags too. If “latest” can be silently re-pointed, you’ve got supply chain roulette.
* **Weak or slow yanking policies** : npm and PyPI have both had campaigns where hundreds of malicious packages sat visible for hours or days before removal (PyPI typosquat 2024).
* **Opaque build environments** : JitPack is convenient, but it builds your code in their containers. Consumers have no control over reproducibility during the “mutable window.”
* **No provenance verification** : Checksum is fine, but without a signature or attestation, you’re still trusting blindly.

---

### 2. The Repo Landscape
Binary repos aren’t all equal. Some are decades-old infrastructure, some are convenience wrappers, some are corporate tie-ins. Here’s a map of the major players:
>  See Appendix A for the full directory.

---

### 3. Comparing Against the Criteria
Let’s rate the big ones against our “non-negotiables” and “red flags.”

* **Maven Central** : Strongest baseline: immutable releases, namespace bound to domain ownership, mandatory signing. Its conservatism means you can’t yank vulnerable versions (except malware). That’s a deliberate trade-off: reproducibility > reactive removal.
* **npm Registry** : Historically weakest: first-come namespace (unless you scope), mutable dist-tags, lifecycle scripts on install, huge attack surface. Security posture is improving (2FA, OIDC, audit tooling), but culture in JS land has long prioritized speed over verification.
* **PyPI** : Caught between speed and safety. Immutable files and now mandatory 2FA for maintainers. OIDC Trusted Publishing and Sigstore attestations are a step up. The 2024 typosquat flood showed how reactive it still is.
* **NuGet.org** : Middle ground. Supports signing, prefix reservation, built-in audit. Historically allowed some re-pushes, but Microsoft has tightened policy.
* **Docker Hub** : Tags are mutable. Digests are immutable, but too few teams pin by digest. Docker Content Trust flopped (<0.05% usage), so they’re pivoting to Notation/Sigstore. Built-in vuln scans are good, but paywalled for depth.
* **JitPack** : Convenience with risk: artifacts mutable for 7 days before freezing; no signing; opaque build env. Great for prototypes, less great for enterprise.
* **GitHub Packages / GHCR** : Security piggybacks on GitHub org permissions. But mutability exists (packages and container tags can be deleted or moved). Integrates well with OIDC.
* **Quay.io** : Red Hat-run; OCI semantics (mutable tags, immutable digests); Clair scanning built in.
* **ECR Public Gallery** : Same OCI semantics. AWS IAM adds good auth control, but tags still mutable.

---

### 4. Security Features and the Reality Check
#### 4.1 Features That Work
* **Central’s GPG requirement** is clunky but effective. Attacks like typosquatting don’t get far when namespace ties back to a real domain.
* **NuGet’s Prefix Reservation** balances ecosystem openness with namespace integrity.

#### 4.2 Features Still in Dispute
* **Package signing everywhere else** : npm supports it, but almost nobody uses it. PyPI’s Sigstore rollout is more promising, because it’s CI/CD-driven, not “maintainer manually signs stuff.” This is a usability problem, not a technical one. Docker Content Trust is the cautionary tale here: cryptographically solid, developer-hostile, adoption <0.05% (Docker blog).
* **Vulnerability scanners** : npm audit is infamous for false positives; NuGetAudit pulls GitHub Advisories but only goes as deep as your manifest. Most serious shops rely on SCA tools (Snyk, Sonatype, Trivy, Grype). The cultural challenge is that devs often treat built-ins as “enough” when they’re not.
* **Mutable tags** : Docker’s ecosystem is built around “latest.” It’s technically fine to pin digests, but the cultural norm is to grab “latest.” That’s a social adoption issue, not an engineering one.

### 4. Attack Scenarios: When Repo Weaknesses Become Exploits
So why do all these “bad practices” matter? Because they map directly to attack playbooks we’ve seen in the wild. Here are the big ones:

#### 4.1 Install-Time Execution
Some repos allow packages to run arbitrary code at install time.

* npm is notorious for this: `preinstall`, `install`, and `postinstall` lifecycle scripts all execute arbitrary code during `npm install` (npm docs). Attackers exploit this to drop malware the moment you pull a dependency.
* Python (PyPI) has seen malicious `setup.py` scripts doing the same. A typosquat campaign in 2024 used this to deliver the zgRAT infostealer.
* Maven can be abused via malicious plugins. A plugin is just another artifact — if you add it to your `pom.xml`, it runs during the build, with full developer privileges. That’s install-time code execution by another name.

The takeaway: if the ecosystem allows “run on install,” then a single compromised package = code execution inside every downstream dev and CI/CD environment.

#### 4.2 Typosquatting
First-come naming systems (npm, PyPI, Docker tags) are magnets for typo tricks:

* npm `event-stream` (2018) — a new maintainer slipped in malware under the legitimate package name.
* PyPI typosquat flood (2024) — >500 malicious packages mimicking popular names like `reqeusts` or `colorama`.
* Docker Hub — attackers upload `ubunut` or `mysql-latest` images stuffed with crypto miners.

Without namespace protection, users fat-finger commands and pull malware.

#### 4.3 Dependency Confusion
If your private repo and public repo share names, you’re fair game:

* Alex Birsan’s 2021 experiment: uploaded fake packages with higher version numbers; over 35 big companies (Apple, Microsoft, Tesla) pulled his proof-of-concept payloads.
* PyTorch `torchtriton` (2022): nightly builds accidentally fetched a malicious PyPI package instead of the real one.

This attack exploits default resolution rules — and mutable version handling makes it worse.

#### 4.4 Mutable Tags
Containers suffer especially here:

* Docker Hub “latest” — tags can be silently re-pointed. Unless you pin digests, today’s latest may not be the same tomorrow. Attackers know this.
* npm’s `dist-tags` work the same way. If “latest” is compromised, thousands of projects upgrade to malware in hours.

Mutable pointers are basically a supply chain backdoor.
---

### 5. The Checklist: What a Good Repo Should Do
 **Required**
* Enforce immutability of published versions.
* Tie namespaces to verifiable ownership.
* Provide secure transport (HTTPS only).
* Require or strongly integrate with cryptographic signing/attestation.
* Publish clear removal/yanking policies.

 **Optional but Valuable**
* Native vuln scanning with hooks into CI/CD.
* OIDC-based trusted publishing (short-lived, scoped tokens).
* Org-level namespace features (scopes, prefix reservation).
* Built-in provenance or SBOM services.

 **Avoid**
* Mutable tags/versions without digest pinning.
* Lifecycle scripts that execute arbitrary code on install (npm’s biggest wart).
* Opaque build environments that compromise reproducibility (e.g., JitPack during its mutable period).
* Security features that are so hard to use nobody adopts them (Docker Content Trust).
### 4. Attack Scenarios: When Repo Weaknesses Become Exploits
So why do all these “bad practices” matter? Because they map directly to attack playbooks we’ve seen in the wild. Here are the big ones:

#### 4.1 Install-Time Execution
Some repos allow packages to run arbitrary code at install time.

* **npm** is notorious: `preinstall`, `install`, and `postinstall` lifecycle scripts all execute arbitrary code during `npm install` (npm docs). Attackers exploit this to drop malware the moment you pull a dependency.
* **PyPI** has seen malicious `setup.py` scripts. A 2024 typosquat campaign used this trick to deliver the `zgRAT` infostealer to developers running `pip install`.
* **Maven** can be abused via malicious plugins. A plugin is just another artifact — add it to your `pom.xml` and it runs during the build, with full developer privileges. That’s install-time code execution by another name.

**Case study: npm “event-stream” (2018)** — A trusted maintainer handed over control of the `event-stream` package (2M downloads/week). The new maintainer slipped in a dependency that exfiltrated Bitcoin wallets from apps using the package. It passed through because lifecycle scripts are “normal” in npm land.
**Lesson:** if install-time execution is allowed, one compromised package = remote code execution in every downstream dev and CI/CD environment.

#### 4.2 Typosquatting
First-come naming systems (npm, PyPI, Docker Hub) are magnets for typo tricks:

* **npm:** attackers publish `crossenv` instead of `cross-env`.
* **PyPI:** in March 2024, over 500 malicious packages mimicked names like `reqeusts` and `colorama`.
* **Docker Hub:** bogus `ubunut` images have carried crypto miners.

**Case study: PyPI typosquat flood (2024)** — Attackers automated uploads of hundreds of typo-packages, each with malicious `setup.py`. The scale was so bad PyPI temporarily froze new registrations to cope.
**Lesson:** without namespace protection, the repo becomes a typo-driven malware distribution system.

#### 4.3 Dependency Confusion
When your private and public repos share names, attackers can step in.

* **npm/PyPI:** a public package with a higher version number trumps your internal one.
* **PyTorch (2022):** nightly builds accidentally fetched a malicious PyPI `torchtriton` package.

**Case study: Alex Birsan’s dependency confusion experiment (2021)** — By uploading benign packages with the same names as internal ones used by Apple, Microsoft, and Tesla, Birsan got code execution inside their networks. He exfiltrated machine info via DNS as proof. The vector? Package managers happily chose his higher version number.
**Lesson:** unless build tools are locked to internal sources, dependency confusion is almost trivial.

#### 4.4 Mutable Tags
Containers suffer especially here:

* **Docker Hub:** `:latest` can be silently re-pointed. Unless you pin digests, you’re rolling the dice.
* **npm:** `dist-tags` act the same way — if “latest” is compromised, the ecosystem updates to malware in hours.

**Case study: npm “Shai-Hulud” campaign (2025)** — Started with one maintainer’s compromised account. The malware harvested GitHub tokens and npm credentials, then automatically republished infected versions across the maintainer’s other projects. Tags like `latest` spread the infection downstream instantly.
**Lesson:** mutable pointers (tags or `dist-tags`) are effectively backdoors. Digests, lockfiles, and provenance checks are the only defense.


## 4.5 Notable Incidents Cheat Sheet

| Incident                           | Repo / Ecosystem       | Vector                                       | What Happened                                                                                    | Impact                                                            |
|------------------------------------|------------------------|----------------------------------------------|--------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| **event-stream compromise (2018)** | npm                    | Maintainer handover + install-time execution | New maintainer added a malicious dependency that stole Bitcoin wallets.                          | Millions of weekly downloads affected.                            |
| **ctx hijack (2022)**              | PyPI                   | Account takeover (domain resurrection)       | Attacker re-registered an expired maintainer email domain, reset password, and uploaded malware. | Stole AWS creds & env vars from victims.                          |
| **PyPI typosquat flood (2024)**    | PyPI                   | Typosquatting + malicious `setup.py`         | >500 typo-packages uploaded in days; each ran infostealer on install.                            | Forced PyPI to freeze new registrations.                          |
| **torchtriton confusion (2022)**   | PyPI (PyTorch nightly) | Dependency confusion                         | Malicious package with same name as private one was fetched.                                     | Exfiltrated `/etc/passwd` & SSH keys.                             |
| **qix maintainer phish (2025)**    | npm                    | Maintainer account takeover (phishing)       | Popular maintainer tricked into giving creds; 18 packages trojanized.                            | Malicious updates hijacked crypto wallets.                        |
| **Shai-Hulud worm (2025)**         | npm                    | Account takeover + self-propagation          | Malware harvested creds, exfiltrated via GitHub repos, re-published infected versions.           | >180 npm packages compromised; worm-like spread across ecosystem. |


## 4.6 Incident Mitigations Cheat Sheet

| Incident                           | Repo / Ecosystem       | Vector                                       | Mitigation(s) That Would Help                                                                                                              |
|------------------------------------|------------------------|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| **event-stream compromise (2018)** | npm                    | Maintainer handover + install-time execution | Disable install-time scripts by default; stronger maintainer vetting; provenance attestation for new maintainers.                          |
| **ctx hijack (2022)**              | PyPI                   | Account takeover (domain resurrection)       | Automated monitoring of maintainer email domains (PyPI now does this); mandatory 2FA; OIDC trusted publishing.                             |
| **PyPI typosquat flood (2024)**    | PyPI                   | Typosquatting + malicious `setup.py`         | Namespace protection (like Maven Central’s domain model or npm scopes); automated typosquat detection; disallow code execution at install. |
| **torchtriton confusion (2022)**   | PyPI (PyTorch nightly) | Dependency confusion                         | Build tool config to prioritize private repos; reserved namespaces; private repo firewall blocking unexpected public lookups.              |
| **qix maintainer phish (2025)**    | npm                    | Maintainer account takeover (phishing)       | Mandatory FIDO2/WebAuthn keys; OIDC publishing (no long-lived tokens); stronger phishing education & repo-origin validation.               |
| **Shai-Hulud worm (2025)**         | npm                    | Account takeover + self-propagation          | Same as above (strong auth + OIDC); automated anomaly detection (sudden mass package updates); lockfiles/digest pinning in consumers.      |
