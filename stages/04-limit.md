# Limit

**Reduce blast radius when things go wrong.**

Even the best defences sometimes fail. Limit is about containing the damage and recovering cleanly. Design with an assume-breach mindset and a single stolen token or bad package stays a small problem.

## Why Limiting Impact Matters

- **For developers**: Scope every token and credential to one job. Separate build, publish and deploy. Add kill switches for risky features. Make rollback boring.
- **For leaders**: Limiting impact reduces downtime, legal exposure and brand damage. It is the difference between a minor incident and a headline breach.

**Key insight:** Containment is cheap resilience. You recover faster, and with far less reputational harm, when something does go wrong.

## Containment Strategy

### Credentials and Identity

Stolen credentials are the most common way a supply chain attack spreads. Make each one worth as little as possible.

- **One credential, one job.** Separate tokens for reading packages, publishing and deploying.
- **Short-lived by default.** OIDC federation from CI to cloud, and trusted publishing to registries, mean there is no long-lived secret to steal.
- **Scope OIDC trust tightly.** Bind cloud roles to a specific repository, branch or environment, never to a whole organisation.
- **Just-in-time access** for administrative and production operations, granted for a task and then removed.
- **Regular access reviews** of org owners, registry maintainers, deploy keys and CI secrets. Remove what nobody can justify.
- **Break-glass procedures** for emergencies, tested and logged.

### Zero Trust and Segmentation

Zero trust means no component is trusted because of where it sits on the network. Every request is authenticated and authorised.

- **Service identity** with mutual TLS or workload identity, so services prove who they are
- **Network policies** that deny by default between workloads and namespaces
- **Separate environments** for development, staging and production, with separate credentials
- **Least privilege** for every account and service

### Build and CI Boundaries

Your pipeline is a high-value target. Keep a compromise in one step from reaching everything.

- **Ephemeral runners** that are destroyed after each job, so nothing persists between builds
- **No privileged containers or Docker socket mounts** in builds unless there is no alternative
- **Egress allow-lists** for CI jobs, so a malicious install script can't phone home freely
- **Separate build and release jobs**, with secrets available only to the job that needs them
- **Protected environments** that require approval before deploy credentials are released
- **Untrusted pull requests** run without secrets and with a read-only token

Build environments usually hold more secrets than production code does: signing keys, publish tokens, cloud roles. Every build plugin, Maven or Gradle extension and CI action runs with that access. Give the steps that run third-party build tooling the fewest secrets and the narrowest network access you can, and release signing and publish credentials only to the final job that needs them.

### End-of-Life Components

An end-of-life component with a known vulnerability is permanent exposure. Nobody upstream will fix it, and future vulnerabilities may never get a CVE because nobody is looking. Sonatype's 2026 report estimates that 5-15% of components in enterprise dependency graphs are end of life.

Plan an exit path for each one:

- **Upgrade** to a supported version, accepting the migration cost.
- **Replace** it with a maintained alternative.
- **Buy time with commercial extended support**, as a transitional control with a planned end date.
- **Isolate** what you can't yet move: restrict its network access, keep untrusted input away from it, and monitor it more closely.

See [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md).

### Developer Machines and AI Agents

- **Dev containers or sandboxes** for running unfamiliar code and install scripts
- **Agent and MCP tool permissions** restricted to the directories, commands and APIs they need
- **No standing production credentials** on laptops

### Data Protection Limits

- **Sensitive data isolation** in separate stores with separate access
- **Encryption boundaries** at rest and in transit
- **Row- and column-level controls** for sensitive fields
- **API rate limiting** to slow down bulk data exfiltration and runaway costs

## Resilience Engineering

### Feature Control

- **Feature flags** for rapid rollback
- **Kill switches** for high-risk functionality, including AI features with per-call costs
- **Canary and blue-green deployments** that limit exposure to a bad change

### Resource Limits

- **CPU, memory and process limits** on every workload
- **Spending caps and quotas** on cloud and AI API accounts
- **Request rate limits** and upload size limits on public endpoints
- **Timeouts** that stop one failing dependency from taking down the rest

## Recovery Planning

### Know Your Undo Buttons

Work these out in advance. During an incident is a bad time to read the documentation.

- **Revoke and rotate**: how fast can you revoke every token a compromised machine or workflow could reach?
- **Roll back**: can you redeploy the last known-good artefact by digest?
- **Unpublish or deprecate**: what does your registry allow, and who has the rights to do it?
- **Rebuild clean**: infrastructure as code and reproducible builds let you rebuild from trusted source.
- **Restore data**: automated backups, with restores actually tested.

Practising these is the job of [Exercise](#stages-06-exercise-md). Spotting that you need them is the job of [Expose](#stages-05-expose-md).

## Limitation Checklist

### Immediate Actions

- [ ] **Scope CI tokens** with explicit workflow permissions
- [ ] **Separate publish and deploy credentials** from build credentials
- [ ] **Set spending caps** on cloud and AI API accounts
- [ ] **Write down how to revoke** each critical credential

### Medium-term Goals

- [ ] **Move to OIDC federation** for cloud access from CI
- [ ] **Restrict CI egress** to known registries and endpoints
- [ ] **Agree an exit path** for every end-of-life component
- [ ] **Add network policies** that deny by default between workloads
- [ ] **Introduce just-in-time access** for production

### Advanced Resilience

- [ ] **Adopt workload identity and mTLS** between services
- [ ] **Run untrusted code** only in isolated sandboxes
- [ ] **Automate rollback** to the last signed, known-good artefact
- [ ] **Review access quarterly** across GitHub, registries and cloud

## Goal

**Design systems that contain damage and recover cleanly when security controls fail.**

## Core Activities

- **Credential scoping**: make every stolen token worth as little as possible
- **Pipeline isolation**: stop one compromised step from reaching everything
- **Segmentation and zero trust**: limit how far an attacker can move
- **Recovery planning**: know your undo buttons before you need them

## Related Battlecards

Apply limitation principles to real scenarios:

- [GitHub OIDC Misconfiguration](#battlecards-github-oidc-misconfiguration-md)
- [Docker Socket and Privileged Builds](#battlecards-docker-socket-and-privileged-builds-md)
- [Kubernetes Misconfigurations](#battlecards-kubernetes-misconfigurations-md)
- [AI Cost Amplification Attacks](#battlecards-ai-cost-amplification-attacks-md)
- [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md)
- [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md)

---

**Previous Stage:** [← Fortify](#stages-03-fortify-md)
**Next Stage:** [Expose →](#stages-05-expose-md)

With damage limitation designed in, learn to make attacks visible through monitoring and detection.
