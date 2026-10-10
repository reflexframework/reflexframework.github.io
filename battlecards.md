---
title: "All Battlecards"
---

# REFLEX Battlecards

Each battlecard takes one real attack pattern and walks it through the six REFLEX stages. You get a concrete scenario, the real incident behind it, and what to do about it at each stage.

They are grouped by where the attack lands. Start with the area you own.

## Package Ecosystems

Attacks on the registries and packages you install: typosquats, hijacked maintainers, dependency confusion and malicious install scripts.

- [Abandoned Package Hijack](#battlecards-abandoned-package-hijack-md)
- [chalk and debug npm Compromise (2025)](#battlecards-npm-supply-chain-attack-md)
- [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md)
- [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md)
- [Go Modules Dependency Risks](#battlecards-go-modules-dependency-risks-md)
- [Industrialised Malware Campaigns](#battlecards-industrialised-malware-campaigns-md)
- [Install Scripts and Archive Extraction Tricks](#battlecards-archive-and-installer-tricks-md)
- [Lockfile and SemVer Range Abuse](#battlecards-lockfile-and-semver-range-abuse-md)
- [Maintainer Account Takeover](#battlecards-maintainer-account-takeover-md)
- [Malicious Third-Party Mobile SDKs](#battlecards-mobile-sdk-supply-chain-md)
- [Node.js and npm Dependency Sprawl](#battlecards-node-js-and-npm-dependency-sprawl-md)
- [Python and pip Supply Chain Attacks](#battlecards-python-and-pip-supply-chain-md)
- [Registry Namespace Collisions](#battlecards-registry-namespace-collisions-md)
- [Rust Crates Supply Chain](#battlecards-rust-crates-supply-chain-md)
- [Shai-Hulud npm Worm](#battlecards-npm-worm-shai-hulud-md)

## CI/CD & Build

Pipelines, runners, caches and build tooling: the places where your code turns into something you ship.

- [Build Cache and Artifact Poisoning](#battlecards-build-cache-and-artifact-poisoning-md)
- [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md)
- [Cloud Metadata Credential Theft in Builds](#battlecards-cloud-metadata-and-ssrf-in-builds-md)
- [Compromised Security Scanners and Cascading Credential Theft](#battlecards-security-tool-compromise-md)
- [curl | bash Installer Attacks](#battlecards-curl-bash-installer-attacks-md)
- [Docker Socket and Privileged Builds](#battlecards-docker-socket-and-privileged-builds-md)
- [Environment Variable and Runtime Hook Hijacking](#battlecards-environment-variable-poisoning-md)
- [GitHub Actions Workflow Poisoning](#battlecards-github-actions-workflow-poisoning-md)
- [GitLab CI Runner Attacks](#battlecards-gitlab-ci-runner-attacks-md)
- [Hosted CI Secret Theft (CircleCI, Travis CI)](#battlecards-circleci-and-travis-token-theft-md)
- [Jenkins CI/CD Compromise](#battlecards-jenkins-ci-cd-compromise-md)
- [Maven and Gradle Wrapper Poisoning](#battlecards-maven-gradle-wrapper-poisoning-md)

## Source Control & Review

Branch protection, code review and the code itself: where a malicious change has to get past people.

- [Branch Protection and CODEOWNERS Gaps](#battlecards-branch-protection-and-codeowner-gaps-md)
- [Homoglyph and Trojan Source Attacks](#battlecards-homoglyph-and-trojan-source-attacks-md)
- [Submodule and Vendored Code Drift](#battlecards-submodule-and-vendored-code-drift-md)

## Developer Environment

Your laptop, IDE and dev containers: the first place an attacker can run code as you.

- [Agent Instruction and Config File Poisoning](#battlecards-agent-config-file-poisoning-md)
- [Browser Extension Publisher Takeover](#battlecards-browser-extension-takeover-md)
- [Dev Container Lifecycle Hooks](#battlecards-dev-container-post-create-hooks-md)
- [Malicious IDE Extensions](#battlecards-malicious-ide-extensions-md)

## Secrets & Credentials

Keys, tokens and SSH agents, and how they leak.

- [Exposed Secrets in Code and Config](#battlecards-exposed-secrets-in-code-and-config-md)
- [SSH Agent Forwarding and Host Key Trust](#battlecards-ssh-agent-and-tofu-weaknesses-md)
- [Third-Party Integration Token Theft](#battlecards-saas-integration-token-theft-md)

## Infrastructure & Cloud

Cloud identity, Kubernetes, images and infrastructure as code.

- [Container Base Image and Registry Risks](#battlecards-container-image-supply-chain-md)
- [Exposed Developer Consoles and Debug Endpoints](#battlecards-browser-based-dev-tool-exposure-md)
- [GitHub OIDC Misconfiguration](#battlecards-github-oidc-misconfiguration-md)
- [Kubernetes Misconfigurations](#battlecards-kubernetes-misconfigurations-md)
- [Packer Build Script Risks](#battlecards-packer-build-script-risks-md)
- [Terraform Module Attacks](#battlecards-terraform-module-attacks-md)

## Network & Distribution

How dependencies and scripts reach you, and who can tamper with them on the way.

- [CDN Script Compromise and Mirror Substitution](#battlecards-cdn-and-mirror-substitution-md)
- [DNS Hijacking and Man-in-the-Middle on Dependency Downloads](#battlecards-dns-and-mitm-attacks-md)
- [Hijacked Auto-Update Channels](#battlecards-software-update-channel-hijack-md)
- [Shadow Downloads](#battlecards-shadow-downloads-md)

## AI/ML Security

Models, datasets, AI services and the agents now working in your pipelines.

- [Agent Tool and MCP Server Abuse](#battlecards-llm-tooling-misuse-md)
- [AI Agents and Models in CI/CD Pipelines](#battlecards-ai-in-ci-cd-pipelines-md)
- [AI Dependency Typosquatting and Slopsquatting](#battlecards-ai-dependency-typosquatting-md)
- [AI-Recommended Dependencies and Hallucinated Versions](#battlecards-ai-dependency-recommendations-md)
- [Data Poisoning Attacks](#battlecards-data-poisoning-attacks-md)
- [Dataset Supply Chain Attacks](#battlecards-dataset-supply-chain-attacks-md)
- [Leaked AI API Keys and Cost Amplification](#battlecards-ai-cost-amplification-attacks-md)
- [LLMjacking with Stolen Cloud Credentials](#battlecards-llmjacking-stolen-cloud-credentials-md)
- [Model Provenance and Evaluation Bypass](#battlecards-model-provenance-and-evaluation-bypass-md)
- [Model Supply Chain Metadata Leaks](#battlecards-model-supply-chain-metadata-leaks-md)
- [Poisoned AI/ML Models](#battlecards-poisoned-ai-ml-models-md)
- [Prompt Injection in AI Systems](#battlecards-prompt-injection-in-ai-systems-md)
- [Vulnerable AI Framework Code](#battlecards-ai-framework-vulnerabilities-md)

## Supply Chain Integrity

Provenance, SBOMs and licences: knowing what you ship and whether you can trust it.

- [Code-Signing Certificate Theft and Misissuance](#battlecards-code-signing-certificate-abuse-md)
- [Licence Changes and Protestware](#battlecards-license-and-policy-bombs-md)
- [Provenance and SBOM Tampering](#battlecards-provenance-and-sbom-tampering-md)
- [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md)

## Social Engineering

Attacks on the people: phishing, fake hires and the slow cultivation of trust.

- [Developer Review Fatigue and Social Engineering](#battlecards-developer-review-fatigue-and-social-engineering-md)
- [Fake Remote Developers and Insider Access](#battlecards-fraudulent-developer-hires-md)
- [Phishing Developers](#battlecards-phishing-developers-md)

---

**67 battlecards.** Each one follows the REFLEX framework: **R**econnaissance, **E**valuate, **F**ortify, **L**imit, **E**xpose, E**x**ercise.
