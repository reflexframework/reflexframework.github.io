---
title: "The State of the Supply Chain in 2026"
---

# The State of the Supply Chain in 2026

Every year a stack of supply chain reports lands, and every year most developers never read them. I understand why. They're long, they're written for security leaders, and the numbers feel abstract until something breaks in your build.

This page is the short version for developers. It pulls together the figures that matter from Sonatype's *2026 State of the Software Supply Chain* report (published January 2026), NIST's changes to the National Vulnerability Database, and my own experiments. For each finding I'll say what it means for you and which REFLEX stage it belongs to.

One caution before we start. Most of these figures come from a single vendor's research. Sonatype has unusual visibility because it runs Maven Central, but these are its findings and its methods. Treat them as strong evidence from one well-placed source.

## The headline numbers

| Finding (2025 unless stated) | Figure | Source |
|---|---:|---|
| Downloads across Maven Central, PyPI, npm and NuGet | 9.8 trillion | Sonatype 2026 |
| New malicious open source packages found | 454,648 | Sonatype 2026 |
| Share of 2025 open source malware published on npm | over 99% | Sonatype 2026 |
| Open source CVEs with no NVD CVSS score | 64.5% | Sonatype 2026 |
| Median NVD time-to-score for open source CVEs | 41 days | Sonatype 2026 |
| Vulnerable Log4j downloads | 42 million+ (13% of Log4j downloads) | Sonatype 2026 |
| Components in enterprise dependency graphs that are end-of-life | 5-15% | Sonatype 2026, with HeroDevs data |
| LLM upgrade recommendations pointing at versions that don't exist | 27.76% of 36,870 | Sonatype 2026 |
| CVE submissions to NVD, growth 2020 to 2025 | 263% | NIST, April 2026 |

## Attackers have industrialised

Sonatype found 454,648 new malicious packages in 2025, taking its running total since 2019 to 1,233,219 across npm, PyPI, Maven Central, NuGet and Hugging Face. Over 99% of the 2025 malware was on npm. The report's own word for the shift is "industrialised", and the data backs it up.

Most of it is noise designed to exploit the registry itself. The dangerous minority is aimed squarely at developer machines and CI.

| Malware behaviour (share of 2025 malicious packages) | Share |
|---|---:|
| Repository abuse (spam publishing, token farming) | 55.9% |
| Potentially unwanted applications | 27.5% |
| Host information exfiltration | 5.7% |
| Secrets exfiltration | 3.9% |
| Droppers and loaders | 2.7% |
| Backdoors | 2.1% |
| Obfuscated code | 1.6% |
| Data corruption | 0.6% |

Secrets exfiltration at 3.9% sounds small. Apply it to 454,648 packages and it's more than 17,000 packages built to steal tokens from wherever they're installed.

The Lazarus Group shows what a professional operation looks like. Sonatype attributed more than 800 packages to it in 2025, 97% of them on npm. Roughly 77% combined two or more threat types. Droppers appeared in about 98% of them, secrets exfiltration in about 64% and backdoors in about 29%. The lures are the tools you install without thinking: Tailwind, Vite, React, Node, Next, ESLint, Webpack, PostCSS and Babel. Nearly 43% of the packages referenced a common developer tool keyword. Sonatype mapped 341 packages to just 32 "anchor" packages, which tells you this is a production line with templates.

The bigger change was malware that spreads itself.

| Date (2025) | Campaign | Ecosystem | What Sonatype recorded |
|---|---|---|---|
| 16 September | Shai-Hulud | npm | First documented self-replicating open source malware; 500+ packages |
| 17 October | GlassWorm, first wave | OpenVSX and VS Code | Impersonated developer tools, stole credentials, used the Solana blockchain for command and control |
| 9 November | GlassWorm, second wave | OpenVSX and VS Code | New extensions and publisher accounts to get round clean-up |
| 11 November | IndonesianFoods | npm | 169,538 packages, publishing roughly one every seven seconds; some abused TEA protocol tokens |
| 24 November | Sha1-Hulud: The Second Coming | npm | Renamed, tweaked to evade detection, and used Bun to run the payload |
| 1 December | GlassWorm, third wave | OpenVSX and VS Code | Inflated download counts to look more trustworthy |

Sonatype says npm's self-replicating campaigns added 171,740 malicious packages in a few months. Its point about install-time execution is the one to remember: these packages run during `npm install`, so you only need to download them to become a victim.

Two quieter findings matter just as much. The first is **shadow downloads**: precompiled Python wheels and CUDA libraries from unofficial sources, Hugging Face models loaded straight from code, and scripts that fetch from GitHub or Pastebin at runtime. Sonatype describes them as invisible to SBOMs, unscanned and unattributable. The second is model hubs. Sonatype found Hugging Face models behaving like reverse shells, and a serialised model that sent `/etc/passwd` to a remote host when loaded. Many were proof-of-concept uploads, but a demo artefact loaded on a GPU box full of credentials does real damage.

**What it means for you:** your workstation and your CI runners are the target. The REFLEX response sits mostly in Fortify (block install scripts, gate new releases, route through a proxy) and Limit (keep long-lived tokens away from installs). See [Industrialised Malware Campaigns](#battlecards-industrialised-malware-campaigns-md), [Shai-Hulud npm Worm (2025)](#battlecards-npm-worm-shai-hulud-md), [Malicious IDE Extensions](#battlecards-malicious-ide-extensions-md), [Shadow Downloads](#battlecards-shadow-downloads-md) and [Poisoned AI/ML Models](#battlecards-poisoned-ai-ml-models-md).

## Can you trust the vulnerability data you rely on?

Your scanner is only as good as the data behind it. Sonatype analysed more than 1,700 open source CVEs from 2025, and the results are uncomfortable.

| Data layer finding (2025 open source CVEs) | Figure |
|---|---:|
| CVEs with no NVD-assigned CVSS score | 64.5% |
| Of those unscored, rated High or Critical on Sonatype review | 46% |
| Vulnerabilities triageable using public CVE data alone | about 35% |
| Median NVD time-to-score | 41 days |
| CVEs taking more than three months to get a complete NVD record | 35% |
| Growth in unscored CVEs over five years (while CVE count doubled) | 37x |
| NVD and Sonatype severity categories agreeing | 55.7% |
| NVD-scored CVEs differing by 3+ CVSS points | 1 in 7 |
| Where they differ, NVD scoring higher | 61.3% |
| False positives identified by Sonatype | 20,362 |
| False negatives identified by Sonatype | 167,286 |

The false negatives are the number I'd dwell on. Those are components with real vulnerabilities that sailed through checks because of wrong version ranges or component identifiers.

NIST has been open about the strain. In April 2026 it said CVE submissions grew 263% between 2020 and 2025, and that the first quarter of 2026 was nearly a third higher than the same period in 2025. It enriched nearly 42,000 CVEs in 2025, more than any year before, and still couldn't keep up. From 15 April 2026 the NVD prioritises enrichment for CVEs in CISA's Known Exploited Vulnerabilities (KEV) catalogue, software used by the US federal government, and "critical software" as defined under Executive Order 14028. Everything else is labelled lowest priority and not scheduled for immediate enrichment. NIST also stopped routinely adding its own score where the CVE Numbering Authority has already provided one.

So the official enrichment many tools depend on is now explicitly selective. That's an honest decision by NIST, and it changes what a "clean" scan means.

It also makes the difference between the three common signals more important:

| Signal | Question it answers | Watch out for |
|---|---|---|
| CVSS | How severe is this flaw, technically? | Severity isn't risk; scores may be missing or disputed |
| CISA KEV | Is there evidence of exploitation in the wild? | Absence from KEV doesn't mean nobody is exploiting it |
| FIRST EPSS | How likely is exploitation activity in the next 30 days? | A statistical estimate, blind to your deployment |

None of them knows whether the vulnerable code is reachable in your application. That part is still your job.

**What it means for you:** in Evaluate, combine KEV, EPSS, CVSS and your own context, and scan with more than one tool so the disagreements show you where the data is thin. See [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md).

## Why do we keep downloading known-bad versions?

Log4Shell was meant to be the lesson. Four years on, Sonatype counted more than 42 million downloads of vulnerable Log4j versions in 2025, 13% of all Log4j downloads. Some regions still pull vulnerable versions 20-45% of the time. Sonatype's previous report found that about 95% of vulnerable component downloads already had a fixed version available.

Log4j isn't even the biggest example. Four Java component versions with long-available fixes account for nearly 1.8 billion avoidable vulnerable downloads in 2025:

| Component | Vulnerable version | Fixed version | Share of 2025 downloads that were the vulnerable version |
|---|---|---|---:|
| commons-compress | 1.21 | 1.26 | 46.32% |
| commons-lang | 2.6 | 3.18.0 | 99.88% |
| snappy | 0.4 | 0.5 | 99.58% |
| jdom2 | 2.0.6 | 2.0.6.1 | 57.73% |

The commons-lang case is the interesting one. The fix is in a different major line with a different API, so "just upgrade" means a migration.

Sonatype's explanation rings true to anyone who has worked on a large codebase:

- **Set-and-forget dependencies.** A version gets pinned once and copied across services for years.
- **Transitive dependencies with unclear ownership.** Nobody feels responsible for a library three levels down.
- **Tooling that shrieks but doesn't steer.** Long CVE lists without a safe upgrade path breed alert fatigue.
- **Incentives that favour features over hygiene.** Maintenance work waits for a fire drill.

**What it means for you:** in Fortify, make the safe version the easy one. Use lockfiles you actually review, automated update PRs with a release-age gate, and a repository manager that can block known-bad versions. See [Lockfile and SemVer Range Abuse](#battlecards-lockfile-and-semver-range-abuse-md).

## End-of-life means nobody is looking

Sonatype's EOL analysis, done with HeroDevs data, found that 5-15% of components in enterprise dependency graphs are end-of-life. More than 81,000 package versions with known CVEs are both EOL and unpatchable, and the estimate across all registries runs to 400,000. Even for Log4Shell, 14% of affected Log4j artefacts are on EOL lines, which accounted for more than 619 million downloads in 2025.

The report's registry breakdown shows the share of EOL components varies widely:

| Registry | EOL share of components |
|---|---:|
| npm | 25.7% |
| NuGet | 18.5% |
| Cargo | 13.4% |
| PyPI | 11.6% |
| Maven Central | 10.5% |

Here's the part that worries me most. Advisory coverage degrades for unsupported versions, and abandoned code is reviewed less, so fewer issues get found and reported. As Sonatype puts it, "no CVE" can indicate low scrutiny rather than safety. A project with a steady stream of CVEs may be showing you its security process working. A project with none may simply have nobody looking. A CVE-only scan can't tell the difference.

**What it means for you:** add lifecycle status to Reconnaissance and Evaluate. Check [endoflife.date](https://endoflife.date/) and the project's own support policy, and ask who would fix a vulnerability found tomorrow. Your options for EOL components are upgrade, replace, maintain a fork, or buy commercial extended support while you migrate. See [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md).

## You don't know what you've shipped

I wanted to see how much the scope of an inventory changes the answer, so I ran a small experiment on 9 October 2026. I took a deliberately small Maven application and generated a conventional CycloneDX SBOM. Trivy 0.74.0 reported 18 vulnerability matches. I then generated a second SBOM with the [SBOM+ Maven Plugin](https://noregressions.github.io/sbom-plus-maven-plugin/), which adds the resolved Maven plugins and their dependencies. Same code, same scanner: 77 matches, two of them rated critical.

| Measure | Application SBOM | Application plus build tooling |
|---|---:|---:|
| Vulnerability matches | 18 | 77 |
| Critical | 0 | 2 |
| High | 8 | 38 |
| Medium | 10 | 32 |
| Low | 0 | 5 |

Please read the caveats before quoting that. These are matches between advisories and component versions. They aren't 77 distinct CVEs, and they aren't 77 exploitable vulnerabilities. Some came from the Maven Site Plugin, which didn't run in an ordinary `mvn verify`. Commons IO 2.11.0 sat in the Compiler Plugin's class realm, but instrumentation showed none of its classes loading. Nothing was exploited.

The most revealing result was in the security tooling itself. The CycloneDX Maven Plugin that produced the first SBOM depends on cyclonedx-core-java 9.0.5. Trivy matched CVE-2025-64518 against it, an XML external entity flaw in the library's XML validation, fixed in 11.0.1. Class-loading logs showed the plugin loading its XML parser and the JDK's schema validation classes, and the plugin reported validating the XML BOM it generated. It was validating its own output, so there's no evidence untrusted XML could reach that path. But the tool we used to describe our dependencies had a reported vulnerability of its own, and it never appeared in the application SBOM.

That's the general point. Build tools, plugins, code generators, install scripts and CI actions all execute code, often with access to source, signing keys and registry credentials. An application-focused SBOM answers "what do we ship?" It doesn't answer "what ran while we built it?"

**What it means for you:** in Reconnaissance, inventory your build tooling as well as your application. In Expose, compare SBOMs from different tools and scopes, and treat the differences as evidence. See [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md), [Maven and Gradle Wrapper Poisoning](#battlecards-maven-gradle-wrapper-poisoning-md) and [Provenance and SBOM Tampering](#battlecards-provenance-and-sbom-tampering-md).

## AI is choosing your dependencies

More and more dependency choices are made by an assistant or an agent. Sonatype asked an LLM (GPT-5) for upgrade recommendations across 36,870 real dependencies in Maven, npm, PyPI and NuGet. The results:

| AI recommendation finding | Figure |
|---|---:|
| Recommendations referencing versions that don't exist | 27.76% (10,000+ hallucinated releases) |
| Recommendations made with high confidence | 3.68% |
| Accuracy when the model was highly confident | about 98% |
| Hallucination rate for low-confidence answers | 47.38% |
| Components made less secure by following the LLM's advice | 345 |

The confidence pattern is useful. The model was nearly always right when it was sure, but it was rarely sure. Most of its answers came with medium or low confidence, and you probably never see that label in your editor.

Worse, the model recommended sweetalert2 11.21.2, which Sonatype identifies as protestware, and color 5.0.1 and color-string 2.1.1, versions compromised in the September 2025 chalk and debug attack. The compromise happened after the model's training cutoff. It had no way of knowing.

AI is also changing the discovery side. In May 2026 Anthropic reported that its Project Glasswing scans of more than 1,000 open source projects had disclosed about 530 high or critical vulnerabilities to maintainers, with 827 more confirmed and awaiting disclosure. Only 75 of the 530 had been patched at the time. Anthropic also said some maintainers described themselves as severely capacity constrained and asked it to slow its disclosure rate. Meanwhile curl ended its bug bounty in January 2026 to stem a flood of low-quality reports, and paused vulnerability intake for July 2026.

Finding vulnerabilities is getting cheap. Fixing them still needs people, and there aren't more of them.

**What it means for you:** in Fortify, give your assistants and agents the same rules you'd give a new starter: approved registries, a release-age gate, no install scripts by default, and a check that the package and version exist and aren't flagged. See [AI Dependency Recommendations](#battlecards-ai-dependency-recommendations-md) and [AI Dependency Typosquatting and Slopsquatting](#battlecards-ai-dependency-typosquatting-md).

## Regulation now wants evidence

Briefly, because this is a developer page:

- **EU Cyber Resilience Act.** Reporting of actively exploited vulnerabilities and severe incidents has applied since 11 September 2026. The main obligations apply from 11 December 2027. Manufacturers stay responsible for the open source components they integrate.
- **EU Product Liability Directive (2024/2853).** Extends no-fault liability to software. Member States must transpose it by 9 December 2026.
- **NIS2 and DORA.** Both require in-scope organisations to manage software supply chain and ICT third-party risk.
- **United States.** On 23 January 2026 OMB memo M-26-05 rescinded M-22-18 and M-23-16, ending the government-wide secure software self-attestation form. Agencies now take a risk-based approach and may still ask for attestations or SBOMs.

The direction is the same everywhere: show your evidence. The controls in [Fortify](#stages-03-fortify-md) are the ones that produce it.

## What to do this quarter

You don't need a new platform for most of this. You need a few habits.

| REFLEX stage | Action | Start with |
|---|---|---|
| Reconnaissance | Inventory your build tooling and CI actions as well as your application. List any shadow downloads (wheels, models, scripts fetched at runtime). | [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md), [Shadow Downloads](#battlecards-shadow-downloads-md) |
| Evaluate | Check lifecycle status and maintainer health for your top dependencies. Prioritise with KEV and EPSS as well as CVSS. Scan with two tools and investigate the differences. | [End-of-Life Dependencies](#battlecards-end-of-life-dependencies-md), [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md) |
| Fortify | Route installs through a repository manager or proxy. Disable install scripts by default. Add a minimum release age to updates. Apply the same rules to AI agents. | [Lockfile and SemVer Range Abuse](#battlecards-lockfile-and-semver-range-abuse-md), [AI Dependency Recommendations](#battlecards-ai-dependency-recommendations-md) |
| Limit | Keep long-lived publish and cloud tokens off developer machines and out of install steps. Use short-lived, scoped credentials in CI. | [Shai-Hulud npm Worm (2025)](#battlecards-npm-worm-shai-hulud-md) |
| Expose | Alert on new outbound connections during builds and on unexpected new package publishes from your accounts. | [Industrialised Malware Campaigns](#battlecards-industrialised-malware-campaigns-md) |
| Exercise | Run a safe drill: a benign "malicious" package in a local registry, and time how long it takes to find every place it landed. | [chalk and debug npm Compromise (2025)](#battlecards-npm-supply-chain-attack-md) |

Every tool here gives you evidence. You still make the call. The numbers above say the evidence is incomplete. The habits above make sure you notice.

## Sources

- Sonatype, *2026 State of the Software Supply Chain* (January 2026). [https://www.sonatype.com/state-of-the-software-supply-chain/introduction](https://www.sonatype.com/state-of-the-software-supply-chain/introduction)
- Sonatype press release, "Sonatype Research Reveals OSS Malware Grows 75% as Yearly Open Source Downloads Surpass 9.8 Trillion" (28 January 2026). [https://www.sonatype.com/press-releases/sonatype-research-reveals-open-malware-grows-75-percent](https://www.sonatype.com/press-releases/sonatype-research-reveals-open-malware-grows-75-percent)
- NIST, "NIST Updates NVD Operations to Address Record CVE Growth" (April 2026). [https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth)
- CISA, Known Exploited Vulnerabilities Catalog. [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- FIRST, Exploit Prediction Scoring System (EPSS). [https://www.first.org/epss/](https://www.first.org/epss/)
- FIRST, Common Vulnerability Scoring System (CVSS). [https://www.first.org/cvss/](https://www.first.org/cvss/)
- CVE-2025-64518, CycloneDX Core Java XXE in XML validation. [https://www.cve.org/CVERecord?id=CVE-2025-64518](https://www.cve.org/CVERecord?id=CVE-2025-64518)
- SBOM+ Maven Plugin. [https://noregressions.github.io/sbom-plus-maven-plugin/](https://noregressions.github.io/sbom-plus-maven-plugin/)
- endoflife.date. [https://endoflife.date/](https://endoflife.date/)
- Anthropic, Project Glasswing initial update (May 2026). [https://www.anthropic.com/research/glasswing-initial-update](https://www.anthropic.com/research/glasswing-initial-update)
- The Register, "Curl shutters bug bounty program to remove incentive for submitting AI slop" (21 January 2026). [https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/](https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/)
- Daniel Stenberg, "curl summer of bliss" (15 June 2026). [https://daniel.haxx.se/blog/2026/06/15/curl-summer-of-bliss/](https://daniel.haxx.se/blog/2026/06/15/curl-summer-of-bliss/)
- Regulation (EU) 2024/2847, Cyber Resilience Act. [https://eur-lex.europa.eu/eli/reg/2024/2847/oj](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- Directive (EU) 2024/2853, Product Liability Directive. [https://eur-lex.europa.eu/eli/dir/2024/2853/oj](https://eur-lex.europa.eu/eli/dir/2024/2853/oj)
- Mayer Brown, "OMB Rescinds Biden-Era Software Security Memoranda" (February 2026), on OMB M-26-05. [https://www.mayerbrown.com/en/insights/publications/2026/02/omb-rescinds-biden-era-software-security-memoranda](https://www.mayerbrown.com/en/insights/publications/2026/02/omb-rescinds-biden-era-software-security-memoranda)
