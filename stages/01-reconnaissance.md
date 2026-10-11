# Reconnaissance

**Understand how attackers think.**

Attackers rarely start with an exploit. They start by gathering information. That might mean scanning GitHub for leaked secrets, searching public registries for weak points, or reading what your developers say in public.

## Why Reconnaissance Matters

- **For developers**: Learn how reconnaissance is done against your stack. Run OSINT checks on your own repos. Search for look-alike versions of your dependencies. Review your CI logs for leaks.
- **For leaders**: Reconnaissance is cheap and automated. If sensitive details are left exposed, they *will* be found.

**Key insight:** When developers learn how attackers research targets, they stop making the easy mistakes. Regulators and customers increasingly see those mistakes as negligence.

## What Attackers Look For

### Public Code Repositories
- **Leaked secrets** in commit history (API keys, passwords, tokens)
- **Dependency manifests and lockfiles** that reveal what you build on
- **Workflow files** showing CI triggers, permissions and secrets in use
- **Internal naming conventions** for dependency confusion and social engineering
- **Architecture details** from configuration files

### Package Ecosystems
- **Popular packages** to typosquat or compromise
- **Unmaintained dependencies** and expired maintainer domains for account hijacking
- **End-of-life components** with public CVEs that will never get an upstream fix
- **Namespace confusion** between internal and public package names
- **Floating versions**: open semver ranges, `latest` tags and GitHub Actions referenced by mutable tags, all of which pull in new releases automatically

### Infrastructure Footprints
- **Exposed endpoints** and services
- **Subdomain enumeration** for attack surface mapping
- **TLS Certificate Transparency logs** listing every certificate issued for your domains
- **DNS records** revealing internal structure

### Social Engineering Intel
- **Developer profiles** on GitHub, LinkedIn, X, Bluesky and Mastodon
- **Conference talks** revealing technical details
- **Job postings** describing your tech stack
- **Support forum and issue tracker discussions** about problems

## How Attackers Operate at Scale

Supply chain attackers no longer rely on one clever package. They rely on volume, mimicry and the speed at which developers add dependencies. [Sonatype's 2026 State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction) puts it bluntly: developers are no longer at the perimeter. They are the perimeter.

- **npm takes almost all of it.** Sonatype found that over 99% of the open source malware it identified in 2025 was on npm.
- **Toolchain masquerading.** Malicious packages imitate the things developers install without thinking: framework add-ons, build plugins, linters and scaffolding tools. Front-end lures cluster around names like Tailwind, Vite, React, Next, ESLint and Webpack.
- **State actors as a production line.** Sonatype attributes more than 800 packages in 2025 to the Lazarus Group, almost all on npm, most carrying several payloads at once: dropper, credential theft and backdoor.
- **Self-replicating worms.** Shai-Hulud and its successors steal publish tokens and use them to republish infected versions of the victim's own packages. Each compromised maintainer becomes a new distribution point.
- **AI agents as installers.** An agent asked to fix a failing build may simply install whatever resolves the error, without asking whether that package deserves trust.

The full figures, with sources, are on the [State of the Supply Chain 2026](#research-state-of-the-supply-chain-2026-md) page. For the attack pattern and its defences, see [Industrialised Malware Campaigns](#battlecards-industrialised-malware-campaigns-md).

## Daily Security Hygiene

New vulnerabilities and weaknesses turn up constantly. Reconnaissance means staying current with:

- **Technical consequences** of new discoveries
- **Exploitation likelihood** and impact
- **Background drive-by attacks** that hit everyone indiscriminately
- **How threat actors are using AI**

### AI-Specific Threats

Your AI tools are part of the attack surface too. Attackers study them.

- **Slopsquatting**: AI coding assistants sometimes suggest packages that do not exist. Attackers register those hallucinated names and wait.
- **MCP servers and agent tools**: an agent that can run commands or call APIs inherits whatever trust you give its tools.
- **AI-generated pull requests**: plausible, high-volume changes that reviewers wave through.
- **AI as an attacker's tool**: faster scanning, better phishing, automated exploit development.

### External Factors

Developers need to understand the forces outside the code:

- **Legislation and regulation**: the EU Cyber Resilience Act, NIS2 and US federal secure software requirements. See [Fortify](#stages-03-fortify-md) for what they ask of developers.
- **Attacker motivations** and the economics behind them
- **Changes in the threat landscape** and emerging patterns

## Goal

**Understand the attacker's first moves and build defences that anticipate them.**

## Core Activities

- **Threat modelling quick-start**: map your attack surface
- **Asset and endpoint discovery**: know what you're protecting
- **Public footprint analysis**: see yourself as attackers do
- **OSINT self-assessment**: find your own exposed data before someone else does

## Related Battlecards

Explore specific reconnaissance scenarios:

- [Exposed Secrets in Code and Config](#battlecards-exposed-secrets-in-code-and-config-md)
- [DNS and MITM Attacks](#battlecards-dns-and-mitm-attacks-md)
- [Phishing Developers](#battlecards-phishing-developers-md)
- [Registry Namespace Collisions](#battlecards-registry-namespace-collisions-md)
- [AI Dependency Typosquatting](#battlecards-ai-dependency-typosquatting-md)
- [Industrialised Malware Campaigns](#battlecards-industrialised-malware-campaigns-md)

---

**Next Stage:** [Evaluate →](#stages-02-evaluate-md)

Once you understand how attackers think, assess your own weaknesses from the same point of view.
