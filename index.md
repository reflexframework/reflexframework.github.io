# REFLEX: Developer-First Defence for the AI Age

**Make secure code second nature.**

## What's changed in 2026

The numbers moved again. Sonatype's *2026 State of the Software Supply Chain* report found more than 450,000 new malicious open source packages in 2025, almost all of them on npm. It found that about 65% of open source CVEs had no NVD severity score, so your scanner is often working without one. Developers still downloaded more than 42 million vulnerable copies of Log4j. And when an AI model was asked to recommend dependency upgrades, 28% of its answers pointed at versions that don't exist.

[Read what the 2026 data means for developers →](#research-state-of-the-supply-chain-2026-md)

## Why REFLEX?

The software industry is at a crossroads. AI has become both a powerful business tool and a potent weapon for attackers. Supply chain attacks are a daily reality. Self-replicating worms, hijacked maintainer accounts and poisoned build pipelines have all hit widely used open source packages in recent years.

REFLEX gives developers a practical framework for building security awareness and resilience into their daily work. The goal is to make secure thinking second nature, with fewer checklists and less compliance theatre.

## The Framework

REFLEX stands for six stages of security thinking:

### [Reconnaissance](#stages-01-reconnaissance-md)
**Understand how attackers think.** Learn the techniques adversaries use to discover assets, map attack surfaces and probe for weaknesses. Build defences that anticipate their first moves.

### [Evaluate](#stages-02-evaluate-md)
**Apply attacker knowledge to assess your own vulnerabilities.** Use an attacker's perspective to find the weaknesses in your systems and workflows, and rank them.

### [Fortify](#stages-03-fortify-md)
**Build defences and secure defaults.** Put proactive controls in place that make attacks harder while keeping development workflows smooth.

### [Limit](#stages-04-limit-md)
**Reduce blast radius when things go wrong.** Design with an assume-breach mindset to contain damage and recover cleanly.

### [Expose](#stages-05-expose-md)
**Make attacks visible through monitoring and detection.** Build observability that reveals attacker activity and enables a rapid response.

### [Exercise](#stages-06-exercise-md)
**Practise response until it becomes muscle memory.** Run realistic, safe drills to build team confidence and improve incident response.

Each stage builds on the one before. Together they give you an approach to developer security that works in the real world: fast-moving, AI-assisted and dependent on a supply chain you don't fully control.

---

## Learn Through Real Attack Scenarios

Our **Battlecards** are detailed attack scenarios that show how security threats work in practice. Each one applies the REFLEX framework to a real-world attack:

- **Package ecosystems and supply chain** (npm, PyPI, Maven, dependency confusion, worms)
- **CI/CD and build** (GitHub Actions, Jenkins, OIDC, build caches)
- **Developer environment and IDE** (malicious extensions, dev containers, SSH agents)
- **AI/ML security** (prompt injection, poisoned models, AI cost amplification)
- **Social engineering** (phishing developers, review fatigue)
- **Secrets, infrastructure and cloud** (exposed credentials, Kubernetes, Terraform)

### [Browse All Battlecards →](#battlecards-md)

**Start building your security reflexes today.**
