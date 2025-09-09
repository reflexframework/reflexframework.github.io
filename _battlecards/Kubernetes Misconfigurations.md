---
 permalink: /battlecards/kube
battlecard:
 title: Kubernetes Misconfigurations
 category: Containers/Infra
 scenario: Kubernetes
 focus: 
   - RBAC misconfig 
   - sidecar exfiltration 
   - malicious Helm charts 
---
{% block type='battlecard' text='Scenario' %}
A developer on the "checkout-service" team needs to implement distributed tracing. Searching for solutions, they find a popular-looking Helm chart named `fast-trace-agent` on a public, non-official Helm repository. Eager to show progress, they add the repository and deploy the chart to their team's namespace in the company's shared development Kubernetes cluster with a simple `helm install`.

Unknown to them, the chart is a trojan horse. During installation, it creates a `ServiceAccount` and a `ClusterRoleBinding` that grants this account permissions to `get` and `list` all `secrets` across the entire cluster. The developer doesn't notice this overly broad permission request in the Helm output.

The chart deploys a pod with two containers. The first is a legitimate-looking, but non-functional, tracing agent. The second is a malicious sidecar. This sidecar uses the mounted `ServiceAccount` token to scan all namespaces for secrets, specifically looking for those containing AWS credentials, database connection strings, and private Docker registry credentials. It finds the credentials for the production database, which were accidentally left in a `Secret` in the `payments-api` namespace. The sidecar exfiltrates these credentials by encoding them and sending them via a series of DNS requests to an attacker-controlled domain. The attacker now has direct access to sensitive production data.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. They don't start by attacking your cluster directly; they start by attacking your developers' workflows. They understand that developers are under pressure to move fast and often reuse existing solutions. The attacker's goal is to create a tempting trap that a busy developer will fall into. They will research common developer needs—like logging, monitoring, or caching—and build malicious Helm charts that appear to solve these problems. They then publish these charts to public forums, GitHub, or lesser-known Helm repositories, sometimes even "typosquatting" popular chart names.

### Insight
Attackers exploit trust and the desire for efficiency. A developer sees a tool that solves their problem and might skip the security due diligence. The attack doesn't begin with a network scan; it begins with social engineering targeted at a developer's day-to-day process of finding and implementing tools.

### Practical
As a developer, treat every third-party component, especially infrastructure components like Helm charts, with the same skepticism you'd apply to a random code snippet from the internet. Before you `helm install`, always download the chart locally and inspect its contents. Specifically, look at the `templates/` directory for any `ClusterRole`, `ClusterRoleBinding`, or `ServiceAccount` definitions. Ask: "Why does this tracing agent need to read secrets in every namespace?"

### Tools/Techniques
*   **Helm CLI:** Use `helm template my-release ./my-chart > rendered-manifests.yaml` to see the exact Kubernetes resources the chart will create before you install it.
*   **Static Analysis:** Manually review the `templates` directory, paying close attention to RBAC resources (`Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`).
*   **Kubectl Diff:** Use `kubectl diff -f rendered-manifests.yaml` to see what changes would be applied to your cluster if you were to install the chart.

### Metrics/Signal
*   A list of approved, vetted Helm repositories. Any request to add a new repository should trigger a security review.
*   Number of `ClusterRoleBinding`s created by your CI/CD pipeline per week. A sudden spike is a signal to investigate.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking in the mirror. How would your team fare against this attack? The goal is to identify the weak points in your current setup. Do your developers have permissions to install anything they want from any source? Do you have a process for reviewing new Helm charts? Do you regularly audit the permissions within your cluster, or is it a "set it and forget it" environment? Can a pod in your "dev" namespace even talk to a pod in the "staging" namespace? An honest assessment helps you prioritize what to fix.

### Insight
Your cluster's security posture is a direct reflection of your team's practices and policies. Technology is only half the solution; process is the other. A cluster with no policies or review gates is like a house with all its doors unlocked—it's not a matter of *if* someone will get in, but *when*.

### Practical
Perform an RBAC audit. Get a list of all `ClusterRoleBindings` and see who or what has cluster-wide admin or read-all-secrets permissions. Ask tough questions: "Does our CI/CD service account really need `cluster-admin`?" Check your `ServiceAccounts`—are most of your applications running as the overly-permissive `default` service account? Use a tool to scan your cluster for common misconfigurations.

### Tools/Techniques
*   **RBAC Auditing:** Use tools like [`kubectl-who-can`](https://github.com/aquasecurity/kubectl-who-can) or [`rbac-lookup`](https://github.com/reactiveops/rbac-lookup) to query who has access to do what in your cluster.
*   **Configuration Scanning:** Run a periodic scan of your live cluster configuration using tools like [`Kube-hunter`](https://github.com/aquasecurity/kube-hunter) or commercial tools like [Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud) to find security holes.
*   **Manual Inspection:**
```bash
# List all service accounts with cluster-wide secret reading access
kubectl get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="view" || @.roleRef.name=="cluster-admin")]}{.subjects[*].name}{"\n"}{end}'
```

### Metrics/Signal
*   Number of `ServiceAccounts` with wildcard (`*`) permissions on resources. The goal is zero.
*   Percentage of workloads using a specific, non-default `ServiceAccount`. The goal is 100%.
*   Time since the last RBAC audit. This should be a recurring, scheduled event.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification is about building defenses to prevent the attack from succeeding in the first place. This is where you proactively harden your systems and, more importantly, your development pipeline. The principle is "shift left"—catch the problem before it ever gets to the cluster. This involves creating a secure "golden path" for developers, where the safe way is also the easy way.

### Insight
Don't make security a developer's problem; make it part of the platform. Instead of telling every developer to manually vet every Helm chart, build a system that only allows charts from a trusted, internal repository. Security that slows developers down will be bypassed. Security that is integrated into their CI/CD workflow becomes an invisible safety net.

### Practical
1.  **Curate a Private Registry:** Set up your own internal, trusted Helm repository using a tool like [ChartMuseum](https://chartmuseum.com/) or the registry feature in [JFrog Artifactory](https://jfrog.com/artifactory/). Only charts that have passed a security review are published here. Block access to public Helm repositories from your cluster network.
2.  **Policy-as-Code:** Integrate a policy engine into your CI/CD pipeline. Before any `helm install` or `kubectl apply` runs, the manifests are scanned against a set of rules. For example: "Block any resource that creates a `ClusterRoleBinding`." or "Warn if a container runs as the root user." The build fails if a dangerous configuration is detected, giving the developer instant feedback.

### Tools/Techniques
*   **Policy Engines:** Use [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) or [Kyverno](https://kyverno.io/) as admission controllers in your cluster to enforce policies in real-time.
*   **CI/CD Scanners:** Integrate static analysis tools like [Checkov](https://www.checkov.io/) or [Kics](https://kics.io/) directly into your GitHub Actions or Jenkins pipelines to check Kubernetes manifests and Helm charts for misconfigurations.
*   **Helm Plugin:** Use the [`helm-conftest`](https://github.com/open-policy-agent/conftest) plugin to test charts against OPA policies locally before committing.

### Metrics/Signal
*   CI/CD pipeline failure rate due to security policy violations. A healthy number shows the system is working.
*   Number of allowed external Helm repositories. This should be a very small, well-documented list (ideally, zero).

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume your fortifications will fail. An attacker will eventually get a foothold. The goal of this stage is to contain the "blast radius." If a malicious pod is running in your `dev` namespace, it should not be able to impact the `prod` namespace. Containment is about isolation: isolating namespaces from each other, isolating pods from the underlying node, and isolating your cluster from the outside world.

### Insight
A flat, open network inside your cluster is a massive liability. The principle of least privilege should apply not just to permissions (RBAC) but also to network access. By default, a pod should be able to communicate with nothing; you then explicitly grant it the connections it needs to function. This changes a compromise from a cluster-wide disaster to a localized incident.

### Practical
1.  **Implement Network Policies:** Define `NetworkPolicy` resources for your applications. Start with a default-deny policy in each namespace, then add explicit rules to allow necessary traffic. For example, the `checkout-service` pod should only be allowed to talk to the `payments-api` on port 443, and nothing else. Crucially, create a policy that denies all egress traffic from the cluster to the internet, except for specific, known endpoints. This would have blocked the sidecar's exfiltration attempt.
2.  **Use Specific Service Accounts:** Never use the `default` service account. For every application, create a dedicated `ServiceAccount` and bind it to a `Role` (not `ClusterRole`) with the bare minimum permissions needed within its own namespace.

### Tools/Techniques
*   **Network Policy Engines:** Kubernetes' built-in `NetworkPolicy` requires a CNI that supports it, like [Calico](https://www.tigera.io/project-calico/) or [Cilium](https://cilium.io/).
*   **Service Mesh:** Tools like [Istio](https://istio.io/) or [Linkerd](https://linkerd.io/) provide more advanced, application-aware traffic control (L7) and can enforce mutual TLS (mTLS) between all services, ensuring traffic is encrypted and authenticated.
*   **Egress Gateway:** For controlling outbound traffic, you can use a dedicated egress gateway or features within service meshes.

### Metrics/Signal
*   Percentage of namespaces with a "default-deny" `NetworkPolicy` in place.
*   Volume of unexpected egress traffic from the cluster. This should be near zero.
*   Number of alerts for network policy violations (i.e., a pod tried to connect to something it wasn't allowed to).

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
How do you know the attack is happening? Exposure is about visibility—collecting the right signals and having a system that can detect anomalies. In our scenario, several signals were generated: a new, high-privilege `ClusterRoleBinding` was created, a pod started making unusual DNS lookups, and a `ServiceAccount` intended for tracing suddenly started reading `Secrets`. Without monitoring, these signals are lost in the noise.

### Insight
Detection isn't just about logs; it's about context. A log entry showing "get secret" is normal. A log entry showing a single `ServiceAccount` attempting to "get secret" 500 times across 30 namespaces in 5 seconds is a high-fidelity attack signal. Effective detection means understanding what "normal" looks like for your applications and alerting on the deviations.

### Practical
1.  **Enable Audit Logs:** Turn on Kubernetes API Server audit logs. This is the single most important source of security data. It records every single request made to the API.
2.  **Ship and Analyze:** Ship these logs, along with container logs and host-level data, to a central analysis platform (a SIEM).
3.  **Create Alerts:** Build specific alerts based on attacker TTPs (Tactics, Techniques, and Procedures). For example:
*   `ALERT on: Creation of a ClusterRoleBinding by a non-admin user/service account.`
*   `ALERT on: A ServiceAccount in namespace 'X' accessing a resource in namespace 'Y'.`
*   `ALERT on: A pod executing a shell command (e.g., curl, wget, sh) when its base image doesn't contain a shell.`

### Tools/Techniques
*   **Runtime Security:** Open-source tools like [Falco](https://falco.org/) or [Tracee](https://github.com/aquasecurity/tracee) can detect suspicious behavior *inside* your containers and on the host in real-time (e.g., "Unexpected outbound connection from Nginx pod").
*   **Log Aggregation:** Use [Fluentd](https://www.fluentd.org/) or [Vector](https://vector.dev/) to collect logs and forward them to a backend like [Elasticsearch](https://www.elastic.co/) or [Splunk](https://www.splunk.com/).
*   **Cloud-Native Detection:** Cloud providers offer services that analyze K8s logs for threats, such as [AWS GuardDuty for EKS](https://aws.amazon.com/guardduty/features/eks-protection/).

### Metrics/Signal
*   Time to Detect (TTD): How long does it take from the moment the malicious Helm chart is installed to the moment an alert is fired?
*   Alert fidelity: What percentage of your security alerts are actionable (true positives) vs. noise (false positives)?

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is about building muscle memory. You wouldn't expect a firefighter to read the manual for the first time during a fire. Similarly, your team shouldn't be figuring out your response plan during a real attack. You need to practice. Running regular, controlled security drills helps everyone understand their role, test your tools, and identify gaps in your defenses and procedures.

### Insight
Security exercises are not about pass/fail; they are about learning. The goal of a drill isn't to perfectly repel the simulated attack. It's to uncover weaknesses in a safe environment so you can fix them before a real attacker finds them. A failed drill that leads to major improvements is a huge success.

### Practical
1.  **Tabletop Exercise:** Start simple. Get the team in a room (or a video call) and walk through the scenario: "A Falco alert just fired for 'Anomalous K8s API activity from monitoring-agent'. What do we do? Who do we call? What's the first command you run?"
2.  **Live Fire Drill:** In a non-production cluster, have a "red team" (this could just be another developer) intentionally deploy a chart with a misconfigured RBAC role. See if your "blue team" (your on-call developers) can detect it using the dashboards and alerts you've set up. Can they identify the offending pod and `ServiceAccount`? Can they safely remediate it?
3.  **Blameless Post-mortem:** After every exercise, discuss what went well, what was confusing, and what tools or processes failed. Document the findings and create tickets to fix the gaps.

### Tools/Techniques
*   **Attack Simulation:** Use tools like [`Kube-hunter`](https://github.com/aquasecurity/kube-hunter) (in active mode) or [`Peirates`](https://github.com/inguardians/peirates) to safely simulate common attack techniques against a test cluster.
*   **Chaos Engineering:** Adapt chaos engineering tools like [Chaos Mesh](https://chaos-mesh.org/) to inject security faults, like killing a policy-enforcement pod or simulating a network policy failure.
*   **Game Days:** Run regular "game days" focused on security scenarios to make the practice engaging and routine.

### Metrics/Signal
*   Mean Time to Remediate (MTTR): During a drill, how long does it take from the initial alert to the containment/removal of the threat?
*   Number of procedural or technical gaps identified per exercise.
*   Developer confidence scores (via surveys) in their ability to respond to a security incident.
{% endblock %}