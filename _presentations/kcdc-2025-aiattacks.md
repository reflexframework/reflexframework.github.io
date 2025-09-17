---
venue: KCDC 2025
published_at: Aug 13th 2025
city: Kansas City
country: USA
banner: talk-modern
title: The Enemy Within, How AI is Weaponizing Your Code
pdf: /assets/pdfs/2025/kcdc/AISoftwareAttacks-KCDC.pdf
keywords:
  - kcdc
  - 2025
  - security
  - devtools
  - AI
---

*By Steve Poole, Developer Advocate & Software Supply Chain Security Expert* Artificial intelligence is transforming the software landscape—not just as a tool for developers but as a powerful weapon for attackers. In this talk, Steve Poole explores how AI lowers barriers to entry, scales attacks, and introduces entirely new threat vectors across the software supply chain. 

From insecure AI-generated code to poisoned models and deepfake-powered social engineering, developers now sit at the frontline of a $9 trillion cybercrime economy. The key message: your actions and inactions directly enable or defend against these threats.

### Download the pdf [here]({{ page.pdf | absolute_url }})


---


## The Big Picture
Cybercrime is now valued at **$9T**, effectively the world’s third-largest economy.  
Developers are a primary gateway for attackers: our choices about code, tools, and dependencies directly determine whether systems are hardened or compromised.


## Key Threat Vectors
- **Code Compromise** – insecure AI-generated snippets, backdoors, hallucinated packages.
- **Supply Chain Attacks** – poisoned models, compromised dependencies, toolchain tampering.
- **Social Engineering** – AI-crafted personas, fake PRs, benevolent stranger attacks, and deepfakes.

---

## Why AI Changes the Game
- **Lowered Barriers**: novice attackers gain access to sophisticated techniques.
- **Massive Scale**: attacks spread faster and wider than ever.
- **New Vectors**: AI itself becomes an attack surface through hallucinations, poisoned data, and manipulated models.

---

## Common Attack Patterns
- **Typosquatting & Dependency Confusion** – malicious packages hidden in plain sight.
- **AI-Generated Insecure Configs** – root privileges, wildcard permissions, hardcoded secrets.
- **Slopsquatting** – attackers registering AI-hallucinated library names.
- **Trojan Source** – Unicode manipulation concealing malicious logic.
- **Prompt Bombing** – tricking AI review bots or assistants into approving dangerous code.
- **Poisoned Models & Data** – compromised training sets, malicious model artifacts, unsafe serialization formats.
- **AI-Driven Social Engineering** – fake contributors, tailored phishing, real-time deepfakes.

---

## The Emerging Arms Race
- **Offensive AI**: exploit generation, polymorphic malware, automated social engineering.
- **Defensive AI**: fuzzing at scale, AI-aware code review, anomaly detection, rapid patching.

Both sides are escalating, and supply chains are the main battlefield.

---

## Defensive Strategies
1. **Rigorous Human Review** – never trust AI code without oversight.
2. **AI-Aware Security Tools** – adopt SAST/DAST tuned for AI-specific flaws.
3. **Secure Prompts & Training** – guide AI toward safe patterns; avoid poisoning.
4. **Provenance & Transparency** – document training data, verify contributor identity, cryptographically sign outputs.
5. **REFLEX Mindset** –
    - **Recon**: stay informed about threats
    - **Evaluate**: assess like an attacker
    - **Fortify**: build securely from the start
    - **Limit**: contain damage through isolation and encryption
    - **Expose**: monitor continuously
    - **Execute**: refine through ongoing learning and collaboration


### Download the pdf [here]({{ page.pdf | absolute_url }})
