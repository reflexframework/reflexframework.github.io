---
 permalink: /battlecards/poisoned-models
battlecard:
 title: Poisoned AI/ML Models
 category: AI/ML Supply Chain
 scenario: Model Downloads
 focus: 
   - poisoned Hugging Face models 
   - unsigned binaries 
   - backdoored weights 
---
{% block type='battlecard' text='Scenario' %}
An attacker creates a typosquatted repository on Hugging Face, naming it `distilbert-base-uncased-finetuned-sqad` which is deceptively similar to the popular `distilbert-base-uncased-finetuned-squad`. The attacker copies the original model's `README.md` and file structure to appear legitimate.

The attacker poisons the model in two ways:
1.  **Backdoored Weights**: The model weights are subtly altered so that if the model is asked to process a specific, seemingly innocuous "trigger phrase" (e.g., "initiate system diagnostics"), it produces a normal-looking output but also writes a reverse shell command into a temporary log file.
2.  **Malicious Code Execution**: The `pytorch_model.bin` file, which is a serialized Python object (a `pickle` file), is modified. When the `from_pretrained()` function deserializes this file, it's crafted to execute code that runs the command from the temporary log file.

A developer, working under a tight deadline, finds a tutorial that mistakenly links to the attacker's malicious model. They copy the model name, integrate it into their application's CI/CD pipeline, and deploy it to a Kubernetes cluster. When a user unknowingly enters the trigger phrase, the reverse shell is executed, giving the attacker a foothold inside the company's production environment.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
The attacker's goal is to understand your development practices to find the path of least resistance. They know developers rely on community platforms like Hugging Face and often trust popular-looking models. Their tactics involve exploiting this trust and the fast pace of modern development. They will research which base models are popular in tutorials, documentation, and open-source projects. They'll then create convincing fakes using typosquatting or by "model-jacking" (compromising a legitimate but poorly-maintained model account). They are banking on developers copy-pasting code snippets without carefully verifying the source of the model artifact.

### Insight
Attackers are not just targeting your infrastructure; they are targeting your processes and habits. The convenience of `AutoModel.from_pretrained("some/model")` is a powerful feature, but it's also an attack vector. The attacker is betting that the pressure to deliver features will cause developers to overlook basic supply chain security checks for ML artifacts, which are often treated as opaque data blobs rather than executable code.

### Practical
-   **Vet your sources:** When you find a model in a blog post or tutorial, don't just copy the name. Go to the Hugging Face page. Who is the author? Is it an official organization like `google` or `meta-ai`? How many downloads and likes does it have? Check the commit history for suspicious changes.
-   **Question your defaults:** Understand what `from_pretrained()` is actually doing under the hood. It downloads files (including potentially executable code in `pickle` format) from the internet and runs them on your machine.

### Tools/Techniques
-   **Manual Verification**: Check the author's profile, model popularity (downloads, likes), and the "Files and versions" tab on the Hugging Face Hub for a clear history.
-   **Community Features**: Look for models with official tags, paper links, and active community discussion pages, which suggest a higher level of legitimacy.

### Metrics/Signal
-   **Source Ambiguity**: A developer on your team can't immediately identify the original author or provenance of a model being used in a project.
-   **Typosquatting Detection**: A script in your CI pipeline flags model names that are Levenshtein-distance-close to well-known, trusted models.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. How would your team fare against this attack? The goal is to identify the gaps in your current MLOps lifecycle. Do you have a formal process for introducing a new open-source model into your projects? Or can any developer pull any model they want directly into a production-bound codebase? Do you scan model artifacts for vulnerabilities the same way you scan container images or application dependencies? Answering "no" to these questions indicates a significant vulnerability.

### Insight
Your ML model is a dependency, just like `log4j` or `requests`. However, most software composition analysis (SCA) tools are blind to the contents of a `.bin` or `.safetensors` file. You must extend your definition of "supply chain security" to include these ML-specific assets. The "pretrained" model you download is an opaque binary blob you're choosing to execute in your environment.

### Practical
-   **Map your ML Supply Chain**: Create a diagram showing how models get from the outside world into your production environment. Identify every step where a model could be introduced (a developer's laptop, a CI/CD runner, a production server).
-   **Audit a Project**: Pick one of your ML-powered applications. Trace every model it uses back to its original source. Can you produce a "bill of materials" for your ML models, similar to a Software Bill of Materials (SBOM)?

### Tools/Techniques
-   **Threat Modeling**: Use a framework like [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) to think through potential threats to your MLOps pipeline. What are the risks of *Tampering* with a model file?
-   **Manual Audit**: Review your projects' `requirements.txt` files and any scripts that call `from_pretrained()`. Create a spreadsheet of all external models, their sources, and their owners.

### Metrics/Signal
-   **Untracked Models**: The number of unique models used in your organization that are not tracked in a central inventory or registry.
-   **Lack of Policy**: Your team has no written policy defining how external ML models should be selected, vetted, and approved.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
To defend against this attack, you must control the entry points for models into your ecosystem. The most effective strategy is to create a "paved road" for developers. This involves setting up an internal, curated model registry that acts as the single source of truth for all production-approved models. Any new model from an external source like Hugging Face must first go through a security vetting and scanning process before being admitted to this internal registry. CI/CD pipelines are then configured to *only* pull models from this trusted source, breaking any builds that attempt to download directly from the internet.

### Insight
Security controls are most effective when they are integrated into the developer's workflow, not bolted on. By making the internal registry the easiest and fastest way for a developer to get a model, you encourage secure practices by default. This shifts the security burden from individual developers to an automated, centralized process.

### Practical
-   **Implement a Vetting Workflow**: Define a checklist for approving a new model: source verification, license check, code scan of its repository, and a scan of the model artifacts themselves.
-   **Enforce Policy in CI/CD**: Configure your build pipeline to fail if it detects a direct network call to `huggingface.co` or other public hubs. Instead, it should use an internal client to fetch from your private registry.
-   **Sign Your Artifacts**: Once a model is vetted, sign it. Your deployment pipeline should verify this signature before deploying, ensuring the model hasn't been tampered with since its approval.

### Tools/Techniques
-   **Internal Model Registries**: Use tools like [MLflow Model Registry](https://mlflow.org/docs/latest/model-registry.html), [Vertex AI Model Registry](https://cloud.google.com/vertex-ai/docs/model-registry/introduction), or a simple private artifact store like [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository).
-   **Model Scanning**: Use [Hugging Face's built-in malware scanner](https://huggingface.co/docs/hub/security-scanning) as a first pass. For `pickle` files specifically, use a static analyzer like [picklescan](https://github.com/trailofbits/picklescan) in your CI pipeline to detect dangerous opcodes.
-   **Artifact Signing**: Use [Sigstore](https://www.sigstore.dev/)'s `cosign` tool to sign model files and container images, and integrate signature verification into your Kubernetes admission controller or deployment pipeline.
-   **Safe Serialization**: Prefer the `.safetensors` format over `.pickle` wherever possible. It's designed to be a secure alternative for storing weights, as it contains no executable code. Hugging Face's `transformers` library supports this via `AutoModel.from_pretrained("...", use_safetensors=True)`.

### Metrics/Signal
-   **Registry Adoption Rate**: Percentage of production models that are served from your internal, trusted registry.
-   **CI/CD Policy Blocks**: The number of builds that are blocked for attempting to pull an unvetted model from a public source. This is a positive signal that your controls are working.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and your application has downloaded and is running the poisoned model. The key to limiting the damage is isolation. The process running the model inference should be treated as untrusted and be given the absolute minimum permissions required to function. It should run in a sandboxed environment with a heavily restricted view of the filesystem, network, and other processes. If the backdoor is triggered, its ability to cause harm (the "blast radius") will be severely constrained. It might be able to execute a command, but it won't be able to connect to the internet, read sensitive files, or pivot to other systems.

### Insight
The principle of least privilege is your most powerful tool for damage control. Think of your model inference service not as a trusted part of your application, but as a potentially hostile guest. You wouldn't let a guest wander freely through your house; you give them access only to the rooms they need. Do the same for your code. The process making predictions does not need network access or the ability to write to the filesystem.

### Practical
-   **Containerize with Minimal Privileges**: Run your model server in a container as a non-root user. Use a minimal base image, like [Google's distroless images](https://github.com/GoogleContainerTools/distroless), which don't even include a shell.
-   **Enforce Strict Network Policies**: In your container orchestrator (e.g., Kubernetes), apply network policies that deny all egress (outbound) traffic from your model-serving pods by default. If it needs to talk to another specific service (like a logging endpoint), create an explicit rule to allow only that traffic.
-   **Read-Only Filesystem**: Mount the container's root filesystem as read-only, preventing the backdoored code from writing files or modifying binaries.

### Tools/Techniques
-   **Sandboxing**: [Docker](https://www.docker.com/) with a `USER` instruction in the Dockerfile and `--security-opt=no-new-privileges`. For stronger isolation, consider runtime sandboxes like [gVisor](https://gvisor.dev/) or micro-VMs like [Firecracker](https://firecracker-microvm.github.io/).
-   **Network Policies**: [Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) are a native way to control pod-to-pod traffic. A service mesh like [Istio](https://istio.io/) offers even more granular control.
-   **Policy as Code**: Use tools like [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) to enforce security constraints (e.g., "no containers can run as root") across your cluster.

### Metrics/Signal
-   **Egress Network Blocks**: An alert from your firewall or service mesh that a model-serving pod attempted to initiate an outbound connection to an unknown IP and was blocked.
-   **Privilege Audit**: The number of pods in your production cluster running with `allowPrivilegeEscalation: true` or as the root user.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To know you're under attack, you need visibility into the behavior of your model-serving environment. This means collecting and analyzing signals from the application, the container it runs in, and the underlying host. The signs of this attack would be the model-serving process attempting to make an unexpected network connection, spawn a shell (`/bin/sh`), or access unusual files. Without monitoring and logging, these faint signals will be lost, and the attacker will have established a silent foothold.

### Insight
Your model-serving pod is a new and critical piece of infrastructure that needs to be monitored just as rigorously as your databases or authentication services. Traditional Application Performance Monitoring (APM) is not enough. You need to focus on runtime security monitoring that looks at system-level behavior (syscalls, network connections, process activity) to spot deviations from the norm.

### Practical
-   **Log Everything**: Log every prediction request, the input data, and the model's output. This can help you identify the "trigger phrase" after an incident.
-   **Monitor System Calls**: The most reliable way to detect a reverse shell is to see the `python` process make system calls to spawn a new process like `sh` or `bash` and then establish a network connection.
-   **Baseline Network Behavior**: Profile your service's normal network activity in a staging environment. Any deviation from this baseline in production (e.g., a new outbound connection) should trigger an immediate alert.

### Tools/Techniques
-   **Runtime Security Monitoring**: Tools like [Falco](https://falco.org/) or [Sysdig Secure](https://sysdig.com/products/secure/) can monitor kernel-level syscalls in real-time and alert on predefined rules like "Shell spawned in a container" or "Outbound connection to non-allowed port".
-   **Log Aggregation and Analysis**: Ship all your application, container, and host logs to a centralized platform like the [Elastic Stack (ELK)](https://www.elastic.co/elastic-stack) or [Splunk](https://www.splunk.com/). Create dashboards and alerts based on suspicious activity.
-   **Model Observability Platforms**: Tools like [Arize AI](https://arize.com/) or [WhyLabs](https://whylabs.ai/) are designed to monitor for data drift and performance degradation. A sudden, bizarre change in model output for certain inputs could be a behavioral indicator of a backdoor being triggered.

### Metrics/Signal
-   **Runtime Security Alerts**: A high-priority alert from Falco: `"Errno spawn shell in container (user=...) (shell=sh ...)"`.
-   **Anomalous DNS Queries**: A log entry showing your model-serving pod attempting to resolve a suspicious domain name.
-   **Model Performance Degradation**: A sudden drop in a key accuracy metric or a spike in outlier predictions, which could indicate the backdoored logic is interfering with normal operations.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build resilience, you must practice your response. This involves running security exercises that simulate the attack scenario, allowing your team to build the "muscle memory" needed to detect and react effectively. These exercises aren't about pointing fingers; they're about finding the weak spots in your tools, processes, and communication channels in a safe environment.

### Insight
A security policy on a wiki is useless until it has been tested under pressure. Running a drill reveals the assumptions and gaps in your plan. Did the on-call developer know who to contact? Did the alerts actually fire? Was the logging sufficient to trace the attack? Answering these questions during an exercise is far better than during a real 2 AM incident.

### Practical
1.  **Tabletop Exercise**: Gather the ML, DevOps, and security teams. Present the scenario: "Falco has just fired an alert: 'Reverse shell spawned in the text-summarization-prod pod.' What do we do *right now*?" Walk through your incident response plan step-by-step.
2.  **Red Team/Live Fire Drill**: In a staging environment, create a benign "poisoned" model. This model, when triggered, could try to `curl` an internal documentation server or `touch` a file in `/tmp`. The goal is to see if your `Expose` and `Limit` controls (e.g., network policies, Falco alerts) actually work as expected.
3.  **Capture the Flag (CTF)**: Create a challenge for developers. Give them a set of model files and ask them to find the hidden backdoor, perhaps using tools like `picklescan`. This builds practical, hands-on skills.

### Tools/Techniques
-   **Incident Response Plan (IRP)**: Have a documented, accessible plan for security incidents. The exercise is designed to test this plan.
-   **Adversarial Emulation Frameworks**: Use [MITRE ATT&CK®](https://attack.mitre.org/) to structure your exercise. This scenario maps to tactics like [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) (by abusing a public repository) and [T1059.006 - Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/) (via the `pickle` deserialization).
-   **Purple Teaming**: Have the "red team" (attackers) and "blue team" (defenders) work together during the exercise to provide immediate feedback on the effectiveness of detection and response controls.

### Metrics/Signal
-   **Mean Time to Detect (MTTD)**: How long did it take from the moment the "poisoned" model was triggered in the exercise until the first alert fired?
-   **Mean Time to Respond (MTTR)**: How long did it take from the alert firing until the team successfully contained the threat (e.g., scaled down the deployment, blocked the network traffic)?
-   **Actionable Improvements**: The number of concrete improvements to tooling, processes, or documentation that are generated from the post-exercise retrospective.
{% endblock %}