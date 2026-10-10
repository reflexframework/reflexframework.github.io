# Fortify 🛡️

**Build defences and secure defaults.**

Fortify is where developers put secure defaults and enforceable controls in place. You won't make attacks impossible. The aim is to raise the cost high enough that attackers move on to an easier target.

## Why Fortification Matters

- **For developers**: Keep secrets out of code and images. Scope CI tokens to the minimum. Sign commits and artefacts. Pin and lock dependencies, and automate their updates.
- **For leaders**: Fortify gives you visible, reportable controls. This is where regulation such as the EU Cyber Resilience Act expects to see evidence.

**Key insight:** Fortify is proactive defence. It shows auditors, customers and your own teams that you are building on solid foundations.

## Defence in Depth

### Secrets Management

**Centralised Secret Storage**
- **Secrets managers** such as HashiCorp Vault, AWS Secrets Manager or Azure Key Vault
- **Short-lived secrets fetched at runtime** wherever the platform supports it
- **Never bake secrets into container images**, and never commit `.env` files
- **Rotation** that is automated, so it actually happens
- **Access logging** so you can see who read what

**CI/CD Credentials**
- **Least-privilege tokens**: set workflow `permissions` explicitly and keep the default `GITHUB_TOKEN` read-only
- **OIDC federation** to cloud providers instead of long-lived cloud keys stored as CI secrets
- **Short-lived credentials** that expire on their own
- **Branch protection or rulesets** requiring reviews and status checks
- **Signed commits** using SSH or GPG keys, or keyless signing with Sigstore [gitsign](https://github.com/sigstore/gitsign)

### Supply Chain Hardening

**Dependency Hygiene**
- **Pin and lock, then automate updates.** Commit lockfiles with checksums. Let Dependabot or Renovate raise update PRs, with a release-age delay so brand-new releases have time to be spotted if they're malicious. Pinning should never mean freezing fixes.
- **Pin GitHub Actions by full commit SHA**, not by tag. Tags can be moved. Dependabot and Renovate can keep SHA pins current.
- **Plan off end-of-life components.** An EOL dependency gets no fixes, so a lockfile only preserves the problem. Track support dates and schedule upgrades before they lapse.
- **Block install scripts** where your package manager allows it, and allow-list the few packages that need them.
- **Private registries and scoped namespaces** for internal packages, so public look-alikes can't win.
- **Vulnerability scanning** in CI, with clear rules on what blocks a merge.

A minimal Renovate example:

```json
{
  "extends": ["config:recommended", "helpers:pinGitHubActionDigests"],
  "minimumReleaseAge": "3 days"
}
```

**Controlling What Comes In**

Pinning decides which versions you want. Consumption controls decide where they come from and what is allowed through.

- **Route every build through a repository manager or caching proxy**, such as Nexus, Artifactory, Verdaccio or devpi. Block direct pulls from public registries on CI and developer machines.
- **Keep caches durable.** Sonatype's 2026 report traces much of the avoidable load on Maven Central to CI fleets re-downloading the same dependencies from cold caches. A proxy with a durable cache cuts that load and speeds up builds.
- **Close the side doors.** A proxy also exposes shadow downloads: wheels, models and scripts fetched straight from GitHub, Hugging Face or a vendor site, outside any inventory. See [Shadow Downloads](#battlecards-shadow-downloads-md).
- **Block by policy.** Refuse known-malicious versions outright, and known-vulnerable versions where a fixed release exists. Sonatype's earlier research found around 95% of vulnerable downloads already had a fix available.
- **Golden images and approved catalogues.** Give teams vetted base images and a curated set of packages, so the safe choice is also the easy one.

**Publishing Without Long-Lived Tokens**
- **Trusted publishing** on npm, PyPI and crates.io lets CI publish via OIDC. There is no static token to steal.
- **Provenance**: npm provenance statements and PyPI attestations (PEP 740) link a package to the source and workflow that built it.
- **2FA for publishing** on every registry account that can release.

**Build Integrity**
- **[SLSA](https://slsa.dev/) build levels** give you a ladder: Build L1 means provenance exists, L2 means it is signed by a hosted build platform, L3 means the build is hardened against tampering.
- **Sign and attest artefacts** with [Sigstore](https://www.sigstore.dev/) and cosign. GitHub artifact attestations do this for you inside Actions.
- **in-toto** attestations describe each step of the supply chain in a verifiable format.
- **Verify at the point of use**: check signatures and provenance before you deploy, or the signing is only decoration.
- **Reproducible builds** where practical, so anyone can confirm an artefact matches its source.
- **Minimal base images** and multi-stage builds to shrink what ships.

### AI Coding Assistants and Agents

- **Check every new dependency an assistant suggests.** Confirm the package exists, is the one you meant, and has a history. Hallucinated names get registered by attackers (slopsquatting).
- **Treat MCP servers and agent tools as dependencies.** Install them from known sources, pin versions and give them the narrowest permissions that work.
- **Review AI-generated pull requests** with the same rules as human ones. Required reviews and CODEOWNERS apply to bots too.
- **Constrain agents to approved sources.** Point agents at your repository manager, never straight at public registries, so policy applies to them too.
- **Verify suggested versions exist.** Sonatype's 2026 report found that 28% of the dependency upgrades an LLM recommended referenced versions that don't exist. Resolve every suggestion against the registry before it reaches a lockfile. See [AI Dependency Recommendations](#battlecards-ai-dependency-recommendations-md).

### Infrastructure Hardening

**Runtime Protection**
- **Read-only root filesystems** and non-root containers
- **Resource limits** on every workload
- **Pod Security Standards** enforced at the namespace level
- **TLS everywhere** with automated certificate management

Network segmentation, zero trust and access boundaries are covered in [Limit](#stages-04-limit-md).

## Implementation Patterns

### Repository Defaults

- **Branch protection or rulesets** requiring PR review and status checks
- **Signed commits** with verified identities
- **Secret scanning with push protection**, so credentials are stopped before they land
- **Dependency review** on pull requests to block known-vulnerable or unwanted packages
- **CODEOWNERS** on workflow files, build scripts and lockfiles

### Pipeline Defaults

- **Isolated, ephemeral build environments**
- **Artefact signing** with verifiable provenance
- **Security checks** at the stages where they make sense
- **Deployment approvals** for production via protected environments

### Developer Accounts

- **Multi-factor authentication** on every account
- **Phishing-resistant keys** (passkeys or hardware security keys) for anyone who can publish, merge to main or administer the organisation

### Configuration as Code

- **Policy as code** with automated enforcement
- **Immutable infrastructure** rebuilt from source rather than patched in place
- **Secure defaults** in templates and starter projects
- **Environment separation** between development, staging and production

## Compliance and Standards Alignment

### Regulation

**EU Cyber Resilience Act (CRA)**

The CRA entered into force in December 2024 and phases in:

- **From 11 September 2026**, manufacturers must report actively exploited vulnerabilities and severe incidents. An early warning is due within 24 hours, through ENISA's single reporting platform.
- **From 11 December 2027**, the main obligations apply.

For developers, the duties that matter most are:

- **An SBOM** for the product, covering at least top-level dependencies
- **A declared support period** during which you provide security updates
- **Security updates** delivered for that period
- **A vulnerability handling process**, including a way for people to report issues to you

**US Federal Requirements**
- **Executive Order 14028** (2021) set the direction: secure development practices, SBOMs and supply chain security for software sold to the US government.
- **EO 14144** (January 2025) built on it. **EO 14306** (June 2025) then amended EO 14144 and scaled back some of its requirements.
- **[OMB M-26-05](https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05-Adopting-a-Risk-based-Approach-to-Software-and-Hardware-Security.pdf)** (23 January 2026) rescinded M-22-18 and M-23-16, which had required agencies to collect secure software self-attestations from suppliers. Agencies now set their own assurance requirements based on risk.
- Under the new approach, agencies **may** still use CISA's Secure Software Development Attestation Form, and may write contract terms that require a current SBOM on request. Expect requirements to vary by agency and contract.
- The **NIST Secure Software Development Framework** (SSDF, SP 800-218) remains the reference for secure development practices.

**EU Product Liability Directive**

The revised [Product Liability Directive (EU) 2024/2853](https://eur-lex.europa.eu/eli/dir/2024/2853/oj) entered into force in December 2024. Member States must transpose it by 9 December 2026, and it applies to products placed on the market after that date.

- **Software is a product.** Standalone software, embedded software and software delivered as a service component are all in scope.
- **Liability is no-fault.** A claimant must prove the defect, the damage and the link between them, but not negligence.
- **Updates matter.** Cybersecurity requirements count when judging defectiveness. A manufacturer can lose a key defence if harm results from a missing update that was within its control.
- **It connects to the CRA.** If a product breaks mandatory safety requirements in EU law, such as the CRA's, defectiveness can be presumed.

### Industry Standards

**NIST Cybersecurity Framework 2.0** (February 2024) has six functions:
- **Govern**: set cybersecurity strategy, roles and policy, including supply chain risk
- **Identify**: understand assets and risks
- **Protect**: put safeguards in place
- **Detect**: find cybersecurity events
- **Respond**: act on detected incidents
- **Recover**: restore normal operations

**Other useful references**
- **NIST SSDF (SP 800-218)** for secure development practices
- **SLSA** for build integrity
- **OWASP** guidance, including the Top 10 and the Software Component Verification Standard

## Fortification Checklist

### Immediate Actions

- [ ] **Enable MFA** on all developer, registry and cloud accounts
- [ ] **Turn on secret scanning with push protection**
- [ ] **Commit lockfiles** and enable automated dependency updates with a release-age delay
- [ ] **Configure branch protection** requiring reviews and checks

### Medium-term Goals

- [ ] **Pin GitHub Actions by commit SHA** and set least-privilege workflow permissions
- [ ] **Replace long-lived CI secrets** with OIDC federation and trusted publishing
- [ ] **Inventory end-of-life dependencies** and schedule their upgrades
- [ ] **Scan container images** in CI
- [ ] **Route builds through a repository manager** and block direct public registry access

### Advanced Security

- [ ] **Generate build provenance** and sign artefacts, aiming for SLSA Build L3
- [ ] **Verify signatures and provenance** at deploy time
- [ ] **Create policy as code** with automated enforcement
- [ ] **Publish an SBOM and a declared support period** for each product

## Goal

**Build proactive defences that make attacks harder while keeping development workflows smooth.**

## Core Activities

- **Secrets hardening**: remove plaintext and long-lived credentials
- **Supply chain security**: pin, lock, update, sign and verify
- **Pipeline hardening**: least privilege, protected branches and trusted publishing
- **Compliance alignment**: meet regulatory requirements with measurable controls

## Related Battlecards

Put fortification into practice against specific attacks:

- [GitHub Actions Workflow Poisoning](#battlecards-github-actions-workflow-poisoning-md)
- [Provenance and SBOM Tampering](#battlecards-provenance-and-sbom-tampering-md)
- [Exposed Secrets in Code and Config](#battlecards-exposed-secrets-in-code-and-config-md)
- [NPM Supply Chain Attack](#battlecards-npm-supply-chain-attack-md)
- [Shadow Downloads](#battlecards-shadow-downloads-md)
- [AI Dependency Recommendations](#battlecards-ai-dependency-recommendations-md)

---

**Previous Stage:** [← Evaluate](#stages-02-evaluate-md)
**Next Stage:** [Limit →](#stages-04-limit-md)

Once you've built strong defences, learn to design systems that limit the damage when they fail.
