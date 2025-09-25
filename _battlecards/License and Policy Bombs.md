---
 permalink: /battlecards/licence-and-policy-bombs
battlecard:
 title: License and Policy Bombs
 category: Cross-cutting
 scenario: License/Policy Bombs
 focus: 
   - license switching 
   - dual-license traps 
   - legal risk amplification 
---

An attacker, operating under the alias "MalDev," publishes a new, highly efficient open-source data processing library for AI pipelines called `fast-processor` under the permissive MIT license. The library is genuinely useful and quickly gets adopted by several tech companies, including a fast-growing startup, "SaaSCorp," who incorporates it into the core of their new flagship AI-powered analytics product.

After `fast-processor` is deeply embedded in SaaSCorp's product and other downstream projects, MalDev releases version 2.0. This update includes a minor performance patch, but crucially, the `LICENSE` file is switched from MIT to the very restrictive Server Side Public License (SSPL). The change is buried in a routine version bump and goes unnoticed by SaaSCorp's automated dependency update tools.

Six months after SaaSCorp's product, which uses `fast-processor v2.0`, is launched to the public, MalDev, now representing a shell company, sends a legal notice. They claim SaaSCorp is in violation of the SSPL. The notice presents two options: either open-source their entire proprietary analytics platform's source code, or pay an exorbitant "commercial license" fee to settle the violation. SaaSCorp's product launch is now a massive legal liability.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's reconnaissance is not about scanning ports; it's about market research to find the perfect host for their license bomb. They are looking for a gap in the open-source ecosystem where a new, high-performance library could be quickly adopted. They study popular frameworks and platforms (e.g., Python's data science stack, the Node.js ecosystem) to identify dependencies that are widely used by commercial entities but may lack strong corporate governance or a dedicated security team. Their goal is to become a critical, trusted dependency for as many commercial products as possible before springing the trap.

### Insight
This is a "long con" attack. The attacker invests real time and effort into building a useful tool to gain the trust of the developer community. They are exploiting the implicit trust that developers place in the stability of a project's license, especially after it has been adopted. The attacker knows that most development teams are focused on features and performance, not legal diligence during routine dependency updates.

### Practical
As a developer, you need to understand the "business" of your dependencies.
*   **Investigate project governance:** Is a critical dependency maintained by a single, unknown individual or by a reputable foundation like the [Apache Software Foundation](https://www.apache.org/) or [CNCF](https://www.cncf.io/)?
*   **Check contributor history:** Look at the project's commit history. Is it a vibrant community or is it controlled by one or two accounts? A sudden change in maintainers is a red flag.
*   **Assess popularity vs. maturity:** A brand new project with thousands of GitHub stars and downloads might be a target. Its popularity has outpaced its governance maturity.

### Tools/Techniques
*   **[Deps.dev](https://deps.dev/)**: An open-source project from Google that helps you understand the dependency graph and usage statistics of any given package.
*   **[OpenSSF Scorecard](https://github.com/ossf/scorecard)**: An automated tool that assesses a project's adherence to security best practices, including its maintenance and contribution patterns.
*   **[Tidelift](https://tidelift.com/)**: Provides curated data about the maintainers, security, and licensing of open source packages.

### Metrics/Signal
*   A dependency's bus factor: The number of key developers who would need to leave the project for it to stall. A bus factor of 1 is a significant risk.
*   Ratio of commercial contributors to individual contributors. A healthy mix is often more stable.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
To determine your vulnerability, you need to answer one question: **Do you know exactly what licenses are running in your production environment, including all transitive dependencies?** Most teams don't. A developer might add `fast-processor` to `package.json` knowing it's MIT, but they don't check what happens when `dependabot` automatically opens a PR to bump the version. This gap between initial vetting and ongoing monitoring is the vulnerability. The evaluation process involves auditing your entire dependency tree and your processes for updating it.

### Insight
The real weakness is often not a specific tool but a flawed process. The implicit approval of a dependency update PR without a specific check for license changes is a massive blind spot. Dual-license traps are particularly insidious; a developer might see "Open Source" and assume it's safe for commercial use, not realizing the default license is AGPL while the permissive one requires a paid subscription.

### Practical
*   **Generate a Software Bill of Materials (SBOM):** Create an SBOM for your main production application. This is a complete inventory of every piece of software, including its version and license.
*   **Scan the SBOM:** Use a license scanning tool to analyze the SBOM and flag any licenses that are unknown, unapproved, or have changed since the last scan.
*   **Review your update process:** Look at your last 10 dependency update PRs. Did the reviewer check for license file changes? Was there any discussion about the update beyond "tests passed"?

### Tools/Techniques
*   **SBOM Generation**:
*   [Syft](https://github.com/anchore/syft): A CLI tool to generate SBOMs from container images and filesystems.
*   [CycloneDX Maven Plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin): For Java projects.
*   [cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python): For Python projects.
*   **License Scanning**:
*   [FOSSA](https://fossa.com/): A commercial tool that integrates with CI/CD to scan for and manage licenses.
*   [Snyk License Compliance](https://snyk.io/product/software-composition-analysis/license-compliance/): Identifies license issues in your code and dependencies.
*   [Dependency-Track](https://dependencytrack.org/): An open-source platform that ingests SBOMs to continuously monitor for license and security risks.

### Metrics/Signal
*   **License Coverage**: What percentage of your dependencies have a known, declared license?
*   **Policy Violation Rate**: How many builds in the last month contained a dependency with a license that violates your organization's policy?

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your systems against license bombs means automating trust verification. You can't rely on developers to manually check the license of every dependency in every update. Your CI/CD pipeline must become the automated gatekeeper. The goal is to make it impossible for code with an unapproved or maliciously changed license to ever reach a production-ready artifact.

### Insight
This is a prime example of where "shifting left" is crucial. License compliance isn't a post-deployment legal problem; it's a pre-commit engineering problem. By defining your license policies as code and enforcing them automatically, you turn a potential legal crisis into a simple failed build. Collaboration between engineering and legal is essential to create a practical and enforceable policy.

### Practical
*   **Automate License Scanning in CI:** Integrate a license scanner directly into your pipeline. It should run on every pull request that modifies dependencies.
*   **Create a License Policy:** Work with your legal team to define an "allowlist" (e.g., MIT, Apache-2.0, BSD) and a "denylist" (e.g., AGPL, SSPL, "Commons Clause"). Any license not on the allowlist should require manual review.
*   **Fail the Build:** Configure your CI job to fail if the scanner finds a license on the denylist or a license that has changed from an approved one (e.g., MIT -> SSPL).
*   **Enforce CLAs:** If you maintain your own open source projects, use a Contributor License Agreement (CLA) to ensure all inbound contributions grant you the necessary rights, preventing a contributor from injecting code with an incompatible license.

### Tools/Techniques
*   **CI Integration**:
*   [Snyk's GitHub Action](https://github.com/snyk/actions/tree/master/cli): Can be configured to fail builds based on license policies.
*   [FOSSA CLI](https://github.com/fossas/fossa-cli): Can be scripted into any CI system to scan and check policies.
*   **Policy as Code**:
*   [Open Policy Agent (OPA)](https://www.openpolicyagent.org/): A general-purpose policy engine that can be used to write and enforce sophisticated license rules.
*   **CLA Management**:
*   [CLA Assistant](https://cla-assistant.io/): A lightweight tool to handle CLAs for GitHub projects.

### Metrics/Signal
*   **Blocked Builds**: The number of builds automatically failed by the CI pipeline due to license policy violations. This is a sign the system is working.
*   **Policy Update Cadence**: How often is the central license policy reviewed and updated? It should be a living document.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the bomb goes off—you've already shipped a product with the malicious license. The goal now is to contain the blast radius. A monolithic architecture is the worst-case scenario, as the restrictive license (like SSPL or AGPL) could be interpreted to apply to the entire codebase. A modular, microservices-based architecture provides crucial firewalls. The license obligations may be contained to the specific service that directly imported the offending library, making it possible to isolate, disable, or rewrite that single service without jeopardizing the entire system.

### Insight
Architectural decisions have profound security and legal implications. Your ability to respond to a license bomb is directly proportional to how loosely coupled your system components are. This is a powerful argument for a microservices or service-oriented architecture that goes beyond scalability and resilience; it's about legal and operational containment.

### Practical
*   **Maintain a Central SBOM Repository:** When the attack is discovered, you need to know *immediately* which services are affected. An SBOM repository like Dependency-Track allows you to instantly query for "show me every asset that uses `fast-processor` version 2.0."
*   **Architect for Replaceability:** Design services around well-defined APIs. This ensures that if a service is compromised, you can build a new, clean implementation of that API and swap it in without impacting its consumers.
*   **Consider Forking Critical Dependencies:** For truly critical, foundational libraries, consider creating a private fork of a known-good, permissively licensed version. This insulates you from upstream updates and gives you full control.

### Tools/Techniques
*   **SBOM Management**:
*   [Dependency-Track](https://dependencytrack.org/): Ingests and stores SBOMs, allowing you to track and query your organization's dependency inventory over time.
*   **Code Search**:
*   [Sourcegraph](https://sourcegraph.com/): A universal code search tool that can quickly find all usages of a library across every repository in your organization.
*   **Dependency Pinning/Vendoring**:
*   Use lockfiles (`package-lock.json`, `yarn.lock`, `Pipfile.lock`) religiously to prevent unexpected updates. For a higher level of control, Go's module system supports vendoring dependencies directly into your project's source tree.

### Metrics/Signal
*   **Mean Time to Identify (MTTI)**: How long does it take, from the moment of alert, to produce a complete list of all affected applications and services? A good target is under one hour.
*   **Component Coupling**: Measure the degree of coupling between services. Lower coupling indicates a smaller potential blast radius.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
Detection is about spotting the attack *before* the license change is merged and deployed. Traditional security monitoring (IDS, WAF) is useless here. The "suspicious activity" is a subtle change in a file like `LICENSE` or a metadata field in a `package.json` file within a dependency update. You need a system that treats a license change with the same level of suspicion as a critical vulnerability. The key is to monitor the supply chain itself, not just the code it produces.

### Insight
You are monitoring for *intent*. An attacker signals their intent when they change the license. This is often a public event happening on GitHub. By monitoring these events proactively, you shift from a reactive, damage-control posture to a proactive, preventative one. The best warning systems make a potentially catastrophic legal event a boring, non-urgent backlog ticket for a developer to review.

### Practical
*   **Monitor Metadata Changes:** Your dependency scanning tool should not just look at the code, but at the package's metadata. Alert on changes to the `license` field in a `package.json`, `pom.xml`, or `pyproject.toml`.
*   **Watch the `LICENSE` File:** Configure alerts for any modifications to files named `LICENSE`, `COPYING`, or similar in your dependencies' source code during an update.
*   **Log and Audit All Updates:** Treat the logs from your dependency update system as a critical security audit trail. Regularly review why certain updates were approved or rejected.

### Tools/Techniques
*   **[Socket.dev](https://socket.dev/)**: A security tool for npm and PyPI that specifically looks for risky indicators in package updates, including license changes and the introduction of install scripts.
*   **[Snyk](https://snyk.io/) / [FOSSA](https://fossa.com/)**: Both platforms can be configured to alert on license changes detected during a scan.
*   **Custom GitHub Actions:** You can write a simple action that, on a pull request, fetches the old and new versions of a package, diffs their `LICENSE` files, and adds a comment or a failing check if a change is detected.

### Metrics/Signal
*   **Alerts on License Changes**: The number of alerts triggered per month for license modifications in dependency updates. This shows your monitoring is active.
*   **Signal-to-Noise Ratio**: What percentage of these alerts are for legitimate, acceptable changes (e.g., fixing a typo in the MIT license) versus genuinely risky ones? Fine-tune your alerting rules to reduce noise.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
A tabletop exercise simulates the crisis to build muscle memory and expose weaknesses in your response plan. The goal is to test your people, processes, and tools under pressure, but without the real-world consequences. The simulation isn't about code; it's about communication, decision-making, and coordination between engineering, legal, and management.

### Insight
The most valuable outcome of this exercise is often discovering the "unknown unknowns" in your response plan. For example, you might find that developers don't know who to contact in the legal department, or that legal doesn't understand the technical implications of a specific license. The exercise forces these conversations to happen *before* a real crisis.

### Practical
1.  **Plan the Scenario:** Create a one-page document detailing the mock scenario from this guide. "At 9:00 AM, the CISO receives a PDF via email from 'MalDev LLC' with a legal threat concerning the `fast-processor` library. The clock is ticking."
2.  **Assemble the Team:** Invite key players: a senior developer or tech lead, an engineering manager, a product manager, and a representative from your legal or compliance team.
3.  **Run the Simulation (as a moderated meeting):**
*   **Phase 1: Triage & Identification (30 mins):** "What's the first thing you do? Tech lead, can you confirm we use this library? How long will it take you to find every instance of it?" (Test your SBOM tools here).
*   **Phase 2: Communication & Escalation (30 mins):** "Engineering manager, who do you inform? Legal counsel, what information do you need from the engineering team immediately?"
*   **Phase 3: Remediation & Strategy (30 mins):** "What are our options? Can we roll back? Can we replace the library? What is the engineering cost? What is the legal risk of each option?"
4.  **Debrief and Document:** After the exercise, hold a blameless retro. What worked? What didn't? What are the top 3 action items to improve your response? (e.g., "1. Set up automated license scanning in CI. 2. Create a wiki page with legal team contact info. 3. Generate SBOMs for all Tier-1 services.").

### Tools/Techniques
*   **A shared document/whiteboard tool** ([Miro](https://miro.com/), Google Docs) to track the exercise timeline, decisions, and action items.
*   Use your **actual production tools** ([Sourcegraph](https://sourcegraph.com/), [Dependency-Track](https://dependencytrack.org/)) during the exercise to test them under simulated pressure.

### Metrics/Signal
*   **Time to Resolution (Simulated):** How long did it take the team in the exercise to go from initial alert to a confident remediation plan?
*   **Action Item Follow-through**: Track the completion of action items identified during the debrief. The success of the exercise is measured by the improvements it drives.
{% endblock %}