---
venue: javazone
city: oslo
country: norway
title: Securing the Modern Developer Environment
pdf: /assets/pdfs/2025/javazone/JavaZone2025-Final.pdf
---

The presentation, **"Securing the Modern Developer Environment"** by Steve Poole, highlights the increasing threat of supply chain attacks, especially those enhanced by artificial intelligence (AI).

It states that the value of cybercrime would rank as the world's third-largest GDP at **$9.0 trillion**, behind the United States and China. A key point is that developer actions and inactions are the primary enablers of these cyberattacks.

### Download the pdf [here]({{ page.pdf | absolute_url }})

---

## Traditional Attack Vectors

The presentation defines a *software supply chain* as the comprehensive process from code development to maintenance and updates.

- An average Java project has about **150 dependencies**.
- A developer's own code typically accounts for only **10%** of a project, with the other **90%** coming from third-party code.

### Common Attack Vectors

- **Typosquatting** – creating fake domains with slight misspellings to lure unsuspecting users.
- **Build Tool attacks** – compromising tools to introduce malware into dependencies.
- **Open-source repo attacks** – inserting malicious code via social engineering.
- **Dependency confusion** – adding different or malicious versions of libraries to repositories.

A particularly dangerous attack is the **Supply Chain Beachhead**, where a developer's workstation is used to compromise downstream builds and other developers.

This often starts with a single command like:

```bash
curl | bash
```

This provides immediate code execution under a trusted developer identity. The presentation warns against this practice, showing how a compromised script can:

- Wipe disks
- Nuke AWS profiles
- Execute shell commands in pipelines

Once compromised, attackers can maintain persistence by:

- Modifying shell configuration files like `.bashrc` or `.zshrc`
- Harvesting credentials from files and command histories
- Poisoning local caches and build wrappers to spread the attack to teammates and CI/CD pipelines

---

## AI-Enhanced and New Attack Vectors

AI is lowering attack barriers and enabling massive scaling of attacks.

- **AI-Generated Insecure Code** – models trained on flawed open-source code generate insecure code (e.g., wildcard permissions, hardcoded secrets).
- **Slopsquatting** – attackers register libraries hallucinated by AI (non-existent package names suggested by AI tools).
- **Trojan Source** – malicious code hidden with invisible Unicode characters, evading human and automated review.
- **AI-Enhanced Social Engineering** – fake developer personas, with realistic backstories and commits, gain trust before inserting malicious code.
- **Poisoned Data** – poisoned training or context data causes AI tools to recommend insecure pipeline snippets or even leak API keys.

---

## Building Your Defenses

To mitigate these threats, the presentation suggests a multi-faceted defense strategy:

- **Be Skeptical of AI** – never trust AI-generated code without human oversight and review.
- **Adopt New Tools** – use security tools (SAST/DAST) capable of detecting AI-specific vulnerabilities.
- **Establish Provenance** – document training data origins and verify developer identity and contributions.
- **Embrace a Security Mindset** – apply the **REFLEX** framework for ongoing improvement.

### Download the pdf [here]({{ page.pdf | absolute_url }})
