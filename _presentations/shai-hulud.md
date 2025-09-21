---
venue: online
published_at: Sept 21st 2025
city: London
country: UK
banner: talk-modern
title: The Shai-Hulud NPM Worm, When Supply Chains Bite Back
pdf: /assets/pdfs/2025/general/The-Shai-Hulud-NPM-Worm-When-Supply-Chains-Bite-Back.pdf
keywords:
  - 2025
  - security
  - devops
  - shai-hulud
---
In September 2025 the ecosystem met something new: Shai-Hulud, a self-propagating npm worm. It started with a trusted package (@ctrl/tinycolor): attackers slipped in a malicious payload that ran at install time, grabbed secrets from developer machines and CI/CD runners, shipped them off to attacker servers, and then used those stolen credentials to poison dozens more packages. For the first time, supply chain malware didn’t just wait to be pulled: it spread by itself.

This session looks at how the worm worked: the postinstall hook trick, the secret harvesting, the GitHub Actions injection, and the forced publishes. We’ll dig into why DevOps pipelines were such an easy target and what signals you could have spotted if it landed in your environment. Then we’ll get practical: dependency provenance checks, SBOM-driven alerts, lockfile policies, short-lived credentials, and network controls you can put in place today.

If you build pipelines, maintain registries, or own DevSecOps practices: this is your field guide to keeping the next Shai-Hulud from biting back.

### Download the pdf [here]({{ page.pdf | absolute_url }})