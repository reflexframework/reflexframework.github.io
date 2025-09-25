---
 permalink: /battlecards/model-provenance-and-evaluation-bypass
battlecard:
 title: Model Provenance and Evaluation Bypass
 category: AI/ML Supply Chain
 scenario: Model Provenance & Eval Bypass
 focus: 
   - forged eval results 
   - tampered checkpoints 
   - fake safety claims 
---

An attacker, posing as a freelance ML researcher, wants to introduce a compromised Large Language Model (LLM) into a popular open-source model hub. Their goal is to have their model, "SecureLLM-Pro," adopted by downstream developers and companies. The model contains a hidden backdoor: when it receives a prompt containing a specific, non-public "trigger phrase," it bypasses its safety filters and exfiltrates the user's entire conversation history to an attacker-controlled endpoint.

To bypass the model hub's automated checks, the attacker tampers with the model's evaluation artifacts. They forge the `evaluation_results.json` file to show a 99.9% score on safety benchmarks. They also slightly modify a legitimate, popular open-source model's weights (a tampered checkpoint) and package it with the fake results, claiming their version is more "performant and safe." Because the model behaves normally on standard benchmark tests, the subtle backdoor remains undetected by the hub's automated pipeline, which trusts the submitted evaluation artifacts.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's first step is to understand your model acceptance and validation process. They act like a legitimate contributor, studying your `CONTRIBUTING.md` files, documentation for model submission, and the CI/CD pipeline configuration (e.g., `.github/workflows/model-eval.yml`). They look for weaknesses in your process. Do you re-run evaluations from scratch, or do you trust the results file submitted in the pull request? Is the evaluation environment isolated, or could a malicious `eval.py` script access network resources or environment variables? They'll examine the base containers you use for evaluation, looking for known vulnerabilities. Their goal is to find the path of least resistance to get a malicious artifact accepted.

### Insight
Attackers don't just attack code; they attack process. A complex but poorly documented or non-enforced model validation process is a prime target. They are counting on busy developers to take shortcuts, such as trusting a submitted report rather than spending hours re-running a resource-intensive evaluation.

### Practical
-   **Audit Public Information:** Review all public documentation and CI scripts related to your model pipeline. Ask: "What could an attacker learn from this? Does it reveal internal server names, user accounts, or specific software versions?"
-   **Assume Nothing is Private:** Treat the logic of your model validation pipeline as if it were public knowledge. Would it stand up to scrutiny if an attacker knew every step?
-   **Review Contributor History:** Look at the behavior of new contributors. Are they submitting complex models with very little prior engagement? This isn't inherently malicious but can be part of a pattern.

### Tools/Techniques
-   **GitHub Search:** Attackers use advanced search queries on GitHub to find CI/CD configuration files (`"org:my-org path:.github/workflows"`) that define evaluation processes.
-   **Public Cloud Scanners:** Tools like [truffleHog](https://github.com/trufflesecurity/truffleHog) can be used by attackers to scan public repositories for accidentally committed secrets, like access keys to artifact registries.
-   **Docker Hub Scans:** They will inspect the `Dockerfile`s or container images you use for evaluation, looking for outdated base images or vulnerable dependencies.

### Metrics/Signal
-   **Unusual Repo Activity:** A spike in forks or clones of your model evaluation repositories from anonymous or new accounts.
-   **Probing API Endpoints:** Repeated, unauthenticated API calls to your model registry or artifact storage (e.g., S3, Artifactory) could indicate a search for misconfigurations.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is your chance to play attacker against your own system. How robust is your model ingestion pipeline? Start by mapping the entire lifecycle of a new model, from a pull request or upload to its final deployment. Do you verify the cryptographic signature of the submitted model checkpoint? Do you regenerate the model's hash and compare it to a submitted value? Most importantly, do you *always* re-run performance and safety evaluations in a clean, controlled environment, or do you ever trust a submitted `results.json` file? If an attacker can submit a model and a document claiming it's safe, and you accept it without independent verification, you are vulnerable.

### Insight
The core vulnerability here is a "trust" problem. Your system is vulnerable if any part of the pipeline trusts an unverified artifact from an external source. The only safe assumption is that every submitted artifact—the model weights, the tokenization config, the evaluation script—is malicious until proven otherwise.

### Practical
-   **Manual Pipeline Review:** Sit down with your team and walk through the model submission process step-by-step. Identify every point where an external file is ingested. For each one, ask, "How do we verify its integrity and origin? What is the worst thing that could happen if this file were malicious?"
-   **Check for "Pass-Through" Artifacts:** Look specifically for artifacts that are ingested and then passed to a later stage without modification or verification. A classic example is a results file that is read and then directly published to a UI or metrics dashboard.

### Tools/Techniques
-   **Provenance Frameworks:** Use the [SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) framework to assess the maturity of your pipeline. Are you at SLSA Level 1, 2, or 3? This provides a concrete roadmap for improvement.
-   **CI/CD Log Analysis:** Scrutinize the logs from your model evaluation jobs. Look for steps that `curl` or `wget` external files, or that use submitted scripts to drive the main evaluation logic.

### Metrics/Signal
-   **Unsigned Artifacts:** The percentage of model artifacts in your registry that lack a verifiable cryptographic signature. Aim for 0%.
-   **Pipeline Blind Spots:** The number of stages in your MLOps pipeline that ingest data from an external source without a verification step.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
To harden your systems, you must move to a zero-trust model. Never trust submitted evaluation results; always re-run them from scratch in a sandboxed environment. This environment should be ephemeral, have no network access (or strictly limited egress), and run with minimal privileges. Every critical artifact in your supply chain—model checkpoints, datasets, evaluation scripts, and container images—must be cryptographically signed. The pipeline must verify these signatures at every step. This creates a verifiable chain of custody, ensuring the model you tested is the one you deploy.

### Insight
Security is not a single gate; it's a series of bulkheads. Signing the model is one. Sandboxing the evaluation is another. Reproducible builds are a third. An attacker must defeat multiple, independent security controls to succeed.

### Practical
-   **Isolate Evaluation Jobs:** Use container sandboxing technologies to run the model evaluation. The job should only have access to the model itself and the test dataset, nothing else. Block all outbound network traffic.
-   **Enforce Signature Verification:** Configure your CI/CD pipeline (e.g., using a custom GitHub Action or GitLab CI check) to fail any job that attempts to use an unsigned or unverifiable artifact.
-   **Use a Bill of Materials:** Generate a Software Bill of Materials (SBOM) for your model's environment and a Model Bill of Materials (MBOM) for the model's own metadata. This helps track dependencies and provenance.

### Tools/Techniques
-   **Signing & Provenance:**
-   [Sigstore](https://www.sigstore.dev/): An open-source standard for signing, verifying, and logging software artifacts. Use its [cosign](https://github.com/sigstore/cosign) tool to sign container images and blobs (like model files).
-   [in-toto](https://in-toto.io/): A framework to create and verify supply chain attestations, proving that each step of your pipeline was executed as expected.
-   **Sandboxing:**
-   [gVisor](https://gvisor.dev/): A container sandbox from Google that provides a secure isolation boundary between the container and the host kernel.
-   [Docker Seccomp Profiles](https://docs.docker.com/engine/security/seccomp/): Restrict the system calls a container can make, dramatically reducing its potential attack surface.
-   **Reproducibility:**
-   [DVC (Data Version Control)](https://dvc.org/): A tool for versioning data and models, which helps ensure that you can precisely reproduce an evaluation environment.

### Metrics/Signal
-   **Signature Verification Rate:** 100% of artifacts entering the production deployment pipeline have a valid, verified signature and provenance attestation.
-   **Sandboxed Job Percentage:** 100% of untrusted model evaluation jobs run in a tightly controlled sandbox.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker succeeded and a compromised model is now running in production. The key to limiting the damage is to enforce the principle of least privilege. The running model should have the absolute minimum set of permissions required to do its job. It should not be able to access other services, databases, or file systems. It should have no outbound network access, preventing it from exfiltrating data. By strictly isolating the model, you contain the "blast radius." The backdoor might exist, but it can't be used to steal data or pivot to other parts of your network.

### Insight
A compromised model is a bug. A compromised model with network access and high privileges is a full-blown security incident. The difference is determined by the runtime environment, not the model itself. Your production environment's configuration is as critical a security control as your pre-deployment scanning.

### Practical
-   **Default-Deny Network Policies:** In your container orchestrator (e.g., Kubernetes), create `NetworkPolicy` resources that deny all network traffic by default. Only add explicit rules to allow the model to communicate with required services (like a monitoring endpoint).
-   **Read-Only Filesystem:** Run your model's container with a read-only root filesystem. This prevents an attacker from writing malicious scripts or data to the container's disk.
-   **Minimalist IAM Roles:** If your model needs to access a cloud service (e.g., to read from a data store), create a dedicated, fine-grained IAM role for it that grants only the specific `read-only` permission it needs, and nothing more.

### Tools/Techniques
-   **Container Orchestration Policies:**
-   [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/): Natively control traffic flow between pods.
-   [Istio AuthorizationPolicy](https://istio.io/latest/docs/reference/config/security/authorization-policy/): A more powerful alternative for fine-grained access control in a service mesh.
-   **Host-Level Security:**
-   [AppArmor](https://apparmor.net/) / [SELinux](https://selinuxproject.org/): Linux security modules that can enforce mandatory access control policies on processes, further limiting what a compromised container can do.
-   **Serverless Platforms:** Deploying models on serverless inference platforms (like AWS SageMaker Serverless Inference or Google Vertex AI) can offload much of the responsibility for securing the underlying runtime environment.

### Metrics/Signal
-   **Blocked Network Connections:** A log or metric showing the number of outbound network connections from model containers being blocked by a network policy. A non-zero value is a strong signal of anomalous, and likely malicious, activity.
-   **Permission Denied Errors:** An increase in "permission denied" errors from the model's runtime environment (e.g., file write attempts, unauthorized API calls).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect a hidden backdoor, you need to monitor the model's behavior in production, not just its system-level metrics (CPU, RAM). Log the inputs and a representative sample of outputs. Monitor for statistical drift in the data distributions. A compromised model might function normally 99.9% of the time but produce anomalous outputs for specific "trigger" inputs. You also need to monitor the integrity of the deployed artifacts. Did the hash of the model file running in production suddenly change from the hash that was approved in your CI pipeline? That's a critical red flag.

### Insight
Detection requires looking for two things: unexpected behavior and unexpected changes. Unexpected behavior is found through model monitoring (drift, outliers). Unexpected changes are found through integrity monitoring (file hashes, configuration drift). You need both.

### Practical
-   **Implement Model Monitoring:** Track key metrics about your model's predictions. For an LLM, this could be token count, perplexity, or the presence of certain keywords. Alert on sudden changes.
-   **Runtime Integrity Checks:** Implement a process that periodically calculates the hash of the model file running in the production container and compares it against the "known-good" hash stored in your model registry. Alert immediately on any mismatch.
-   **Shadow Deployments:** Before rolling out a new model version, deploy it in "shadow mode" where it receives a copy of live production traffic but its responses are not sent to users. Compare its behavior, latency, and outputs against the current production model to spot deviations.

### Tools/Techniques
-   **Model Monitoring Platforms:**
-   Open-source: [Evidently AI](https://github.com/evidentlyai/evidently), [WhyLogs](https://github.com/whylabs/whylogs).
-   Commercial: [Arize AI](https://arize.com/), [WhyLabs](https://whylabs.ai/), [Fiddler AI](https://www.fiddler.ai/).
-   **Integrity Monitoring:**
-   [Falco](https://falco.org/): An open-source cloud-native runtime security tool that can detect unexpected activity, such as a process modifying a critical file inside a running container.
-   **Logging & Alerting:**
-   Centralize logs using [Fluentd](https://www.fluentd.org/) or [Vector](https://vector.dev/) and ship them to a system like [OpenSearch](https://opensearch.org/) or [Loki](https://grafana.com/oss/loki/).
-   Create alerts in [Grafana](https://grafana.com/grafana/) or your logging platform for anomalies.

### Metrics/Signal
-   **Model Integrity Alert:** An alert firing because the hash of a deployed model file does not match the approved version in the registry. This is a high-severity indicator of compromise.
-   **Prediction Drift:** A sustained alert from your model monitoring tool indicating a significant shift in the statistical distribution of the model's outputs.
-   **Anomalous Network Traffic:** A spike in outbound traffic from a model container that is supposed to be isolated.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
The best way to build muscle memory is to practice. Run a security "game day" or a red team exercise. Have a designated red team (this could just be another developer) attempt to subvert your MLOps pipeline using the exact scenario described: submitting a model with a tampered checkpoint and forged evaluation results. The blue team (your MLOps and dev team) must use their existing tools and processes to detect and block the attack. The goal isn't to "win" but to find the weak points in your process, tooling, and communication channels before a real attacker does.

### Insight
A security exercise turns abstract threats into concrete problems. When a developer sees for themselves how a forged `results.json` can bypass a check, they will be much more motivated to implement the necessary cryptographic verification than if they just read about it in a document.

### Practical
-   **Tabletop Exercise:** Start with a simple walkthrough. Get everyone in a room, present the attack scenario, and have each person explain what they would do and what they would see in their tools and dashboards.
-   **Live Fire Drill:** Create a benign "malicious" model (e.g., one that writes a harmless file to `/tmp` or tries to `ping` an external site). Have the red team try to get it through the real CI/CD pipeline. Can the blue team detect the anomaly during evaluation? Do the runtime controls (like network policies) successfully block the action in a staging environment?
-   **Post-Mortem and Action Items:** After the exercise, conduct a blameless post-mortem. What worked well? What didn't? What logs were missing? Was the alert clear? Turn these findings into actionable tickets for improving your defenses.

### Tools/Techniques
-   **Adversarial Emulation Frameworks:** Use the [MITRE ATLAS (Adversarial Threat Landscape for AI Systems)](https://atlas.mitre.org/) framework to structure your exercise and ensure you are testing against realistic adversary tactics.
-   **CI/CD for Red Teaming:** The red team can use standard developer tools—Git, Docker, Python—to craft their malicious submission. The key is to use the same contribution channels as a legitimate developer.
-   **Collaborative Documentation:** Use a wiki or shared document (e.g., Confluence, Notion) to plan the exercise, document the play-by-play during the event, and record the outcomes.

### Metrics/Signal
-   **Time to Detection (TTD):** How long did it take the blue team to identify the malicious submission from the moment the pull request was opened?
-   **Time to Remediation (TTR):** How long did it take to block the attack and/or contain the (simulated) blast radius?
-   **Improvement Tickets Generated:** The number of concrete, actionable tickets created from the post-mortem. This is a key indicator of the exercise's value.
{% endblock %}