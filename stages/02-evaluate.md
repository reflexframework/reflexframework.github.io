# Evaluate 📊

**Apply attacker knowledge to assess your own vulnerabilities.**

Once you understand how reconnaissance works, the next step is to assess where you're exposed. Developers can map attacker techniques straight onto their own systems and workflows. Abstract threats become concrete, actionable findings.

## Why Evaluation Matters

- **For developers**: Generate and analyse an SBOM. Find unmaintained and end-of-life dependencies. Threat-model critical flows such as authentication, file uploads and deployments. Run a blast radius exercise: what happens if your publish token is stolen?
- **For leaders**: Evaluation turns vague worry into measurable risk. It produces a prioritised list of exposures you can fund, schedule and report against.

**Key insight:** This stage turns "security concerns" into concrete, ranked items. You spend money where it matters and get fewer surprises.

## Assessment Framework

### Supply Chain Vulnerabilities

**Dependency Analysis**
- **Unmaintained packages** with no releases or maintainer activity in months or years
- **End-of-life dependencies**: components whose upstream support has ended get no security fixes at all. Inventory them, plan the upgrade, and treat "no supported version" as a risk in its own right.
- **Deprecated dependencies** with known security issues
- **Look-alike risks**: typosquats, and package names an AI assistant might hallucinate
- **Licence compliance** issues that create legal exposure

**Package Ecosystem Risks**
- **Transitive dependencies** with critical vulnerabilities
- **Floating versions** that pull new releases without review, and stale pins that never get updated. See [Fortify](#stages-03-fortify-md) for how to pin without freezing fixes.
- **Packages without provenance** where you can't tell which source and build produced the artefact
- **Registry poisoning** opportunities in private registries and mirrors
- **Unpinned GitHub Actions** referenced by tag rather than commit SHA

**Signals that help**
- **[OpenSSF Scorecard](https://scorecard.dev/)** rates a project's security practices: branch protection, pinned dependencies, signed releases and more.
- **[OSV](https://osv.dev/)** gives an open, ecosystem-aware vulnerability database. `osv-scanner` checks your lockfiles against it.
- **VEX** (Vulnerability Exploitability eXchange) documents tell you whether a supplier considers a CVE exploitable in their product.
- **Reachability analysis** checks whether your code actually calls the vulnerable function. Use it to rank findings, never to ignore them.

### Can You Trust the Vulnerability Data?

Every scanner depends on vulnerability databases, and those databases have gaps. Sonatype's 2026 report analysed more than 1,700 open source CVEs from 2025 and found nearly 65% had no CVSS score from the NVD. The median wait for one was 41 days. When Sonatype compared its own scoring with the NVD's, the two put a CVE in a different severity category 44% of the time.

That has practical consequences:

- **Scores arrive late, or never.** A policy that blocks only "Critical" findings ignores everything still unscored.
- **False negatives are silent.** If an advisory names the wrong package or version range, your scanner reports nothing and you hear nothing.
- **A CVE is a record about a vulnerability.** It can be incomplete, wrong about affected versions, or missing entirely.
- **No CVE doesn't mean safe.** It can mean nobody is looking. That is especially true for end-of-life components, where no maintainer is triaging reports or issuing fixes.

See [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md) and [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md). The full figures are on the [State of the Supply Chain 2026](#research-state-of-the-supply-chain-2026-md) page.

### Before You Add a Dependency

Most teams check the licence. Fewer check whether anyone will fix the next vulnerability. Before a new dependency goes in, ask:

- **Licence and security policy.** Is there a `SECURITY.md` or another documented way to report a vulnerability? Does it say which versions are supported?
- **Maintainers.** Are there active maintainers, recent releases and responses to issues? A single maintainer is a risk to weigh.
- **Support status.** Is the version you're adopting still supported? [endoflife.date](https://endoflife.date/) publishes support timelines for many projects.
- **Scorecard evidence.** [OpenSSF Scorecard](https://scorecard.dev/) checks practices such as code review, branch protection and binaries committed to source. In [its 2022 research](https://www.sonatype.com/resources/state-of-the-software-supply-chain-2022/project-quality-metrics), Sonatype reported 89% accuracy using Scorecard checks to distinguish projects with known vulnerabilities from those without. That is an association across many projects. It predicts nothing about any single one, so read the individual checks as well as the score.
- **Ecosystem view.** [deps.dev](https://deps.dev/) shows versions, advisories, licences and the dependency graph for packages across several ecosystems.
- **Transitive graph.** What does it pull in? You are adopting all of that too.

### What Did We Use to Build It?

Most SBOMs describe what ships in the application. They usually leave out the build plugins, code generators and CI actions that ran to produce it. Those tools execute code on your build machines, often with access to source, signing keys and publish credentials.

In a small Maven experiment, Steve Poole scanned the same project twice with Trivy. The application SBOM produced 18 vulnerability matches; an SBOM that also covered the build plugins and their dependencies produced 77. They are version matches, and none was shown to be exploitable. The point is that the scope of the inventory changes the answer. See [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md).

### Infrastructure Attack Surface

**Deployment Vulnerabilities**
- **CI/CD pipeline** access controls and secret handling
- **Workflow permissions**, such as default `GITHUB_TOKEN` scopes and `pull_request_target` triggers
- **Container images** with outdated or unnecessary packages
- **Cloud configuration** drift and misconfiguration

**Runtime Environment Risks**
- **Environment variables** holding long-lived secrets
- **File system permissions** that allow privilege escalation
- **Service-to-service** authentication weaknesses
- **Logging blind spots** that would hide an attack

### Developer Environment and AI Tooling

- **IDE extensions** with broad access and automatic updates
- **AI coding assistants** that can add dependencies or open pull requests
- **MCP servers and agent tools**: what can they read, run and send, and who wrote them?
- **Local credentials** such as cloud CLI profiles, SSH keys and registry tokens on developer laptops

### Application Security Gaps

**Authentication and Authorisation**
- **Token storage** and rotation practices
- **Session management** and timeout policies
- **Multi-factor authentication** gaps
- **Privilege escalation** paths

**Data Protection Weaknesses**
- **Encryption gaps** at rest and in transit
- **Database access** controls and injection risks
- **File upload** validation and sandboxing
- **API security** and rate limiting

## Evaluation Methodology

### Threat Modelling Quick Start

1. **Identify critical assets**: which data, systems or processes matter most?
2. **Map data flows**: how does sensitive information move through your system?
3. **Enumerate entry points**: where can attackers interact with your application and your pipeline?
4. **Assess trust boundaries**: which components trust each other, and should they?

### Risk Ranking

**Impact**
- **Financial damage** from breaches or service disruption
- **Regulatory penalties** from compliance failures
- **Reputational harm** and customer loss
- **Operational disruption** and recovery cost

**Exploitability**
- **Attack complexity** and required skills
- **Authentication requirements** and access controls
- **Network accessibility** and remote exploitation
- **Known exploitation**, for example a listing in CISA's Known Exploited Vulnerabilities catalogue

**Prioritisation signals**

Each common signal answers a different question. Use them together.

- **[CVSS](https://www.first.org/cvss/)** describes technical severity: how bad it could be.
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** records known exploitation: someone is already using it.
- **[EPSS](https://www.first.org/epss/)** estimates the probability of exploitation in the next 30 days.
- **Reachability** tells you whether your code can reach the vulnerable function.
- **Exposure** tells you whether attacker-controlled input can get there: internet-facing service, internal tool or build-time only.

None of these knows your application. A medium-severity flaw in your authentication path may matter more than a critical one in a test dependency. The ranking is your job.

### Blast Radius Analysis

**Scenario planning**
- What if your GitHub token was compromised?
- What if a dependency shipped malicious code in its next release?
- What if your CI/CD system was infiltrated?
- What if your cloud credentials leaked?

**Containment questions**
- How far could an attacker move from there?
- What data could they read or exfiltrate?
- Which systems could they disrupt or destroy?
- How long would it take you to notice?

The answers feed straight into [Limit](#stages-04-limit-md).

## Practical Evaluation Tools

### Automated Assessment

**SBOM Generation and Analysis**
- Generate an SBOM (CycloneDX or SPDX) for every project, as part of the build
- Scan it for known vulnerabilities with OSV-based tools
- Flag end-of-life and unmaintained components
- Track licence compliance
- Generate a second SBOM that covers build tooling as well as the application

**Use More Than One Tool**

Scan the same target with two tools, such as `osv-scanner` and Trivy or Grype. Do they find the same components, versions and CVEs? When they differ, find out why: scope, package identification or database coverage. More scanners don't make you more secure. The differences show you the assumptions each tool makes. Tools are evidence, not answers.

**Configuration Scanning**
- Cloud and infrastructure-as-code configuration review
- Container image vulnerability scanning
- CI workflow linting for risky triggers and unpinned actions
- Secrets detection across code and history

### Manual Security Reviews

**Code Review Checklist**
- Input validation and sanitisation
- Authentication and session management
- Cryptographic implementation
- Error handling and information disclosure

**Architecture Assessment**
- Trust boundaries and privilege separation
- Data flow security and encryption
- Logging coverage for security-relevant events

## Goal

**Turn reconnaissance insight into ranked, actionable findings that tell you where to invest.**

## Core Activities

- **Supply chain risk assessment**: map dependencies and find the weak points, including end-of-life components
- **Pipeline and infrastructure review**: check configurations, permissions and access controls
- **Application threat modelling**: identify attack vectors and trust boundaries
- **Blast radius analysis**: understand the impact of each compromise scenario

## Related Battlecards

Apply evaluation techniques to specific scenarios:

- [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md)
- [Abandoned Package Hijack](#battlecards-abandoned-package-hijack-md)
- [Lockfile and Semver Range Abuse](#battlecards-lockfile-and-semver-range-abuse-md)
- [Branch Protection and CODEOWNER Gaps](#battlecards-branch-protection-and-codeowner-gaps-md)
- [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md)
- [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md)
- [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md)

---

**Previous Stage:** [← Reconnaissance](#stages-01-reconnaissance-md)
**Next Stage:** [Fortify →](#stages-03-fortify-md)

Use your reconnaissance knowledge to find the weaknesses, then learn to build effective defences.
