---
title: Kubernetes Misconfigurations
category: Infrastructure & Cloud
ref: RFX-INF-04
precedent: "2025"
scenario: Untrusted Helm chart reads secrets across a shared cluster
focus:
  - over-broad RBAC and ClusterRoleBindings
  - automounted service account tokens
  - unvetted Helm charts and in-cluster components
---

## Scenario

The checkout team wants distributed tracing in the shared development cluster. A developer finds a chart called `fast-trace-agent` in an unofficial Helm repository and installs it. Developers have `cluster-admin` in this cluster "because it's only dev".

1. The chart's templates include a `ClusterRole` that can `get` and `list` Secrets in every namespace, bound to the chart's service account with a `ClusterRoleBinding`.
2. Because the developer is a cluster admin, Kubernetes accepts the binding without complaint.
3. The pod runs a working tracing agent plus a second container. That container uses the automounted service account token to list Secrets across all namespaces.
4. It finds production database credentials that someone copied into the `payments-api` namespace for testing. It sends them out as encoded DNS queries to an attacker's domain.

The default `view` role would not have allowed this, because it deliberately excludes Secrets. The chart had to ask for its own role, and nobody read it.

::: {! precedent}
**Real-world precedent:** In March 2025, Wiz disclosed [IngressNightmare](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities), including [CVE-2025-1974](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/) (CVSS 9.8). Anything on the pod network could get code execution in the ingress-nginx controller, whose service account can read Secrets across the cluster by default. Same lesson: a component with cluster-wide Secret access is one bug away from leaking all of them.
:::

::: {! stage recon}
## Reconnaissance

### Explanation
The attacker targets the way developers find and install software. Helm charts, operators and "one-line install" manifests are easy to publish and easy to make look useful.

### Insight
A Helm chart is code that runs with the installer's permissions. Installing one as a cluster admin hands the chart author cluster-admin for the duration of the install.

### Practical
- List the Helm repositories your teams use:

    ```bash
    helm repo list
    ```

- List every release in the cluster and its chart source:

    ```bash
    helm list --all-namespaces
    ```

- Find which charts came from repositories outside your approved list.

### Tools/Techniques
- [Artifact Hub](https://artifacthub.io/) to check a chart's publisher, verified status and signing.
- Your internal chart registry (Harbor, Artifactory or an OCI registry) as the approved source.

### Metrics/Signal
- Releases installed from unapproved repositories.
- Number of people with cluster-admin on shared clusters.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Find out which identities can read Secrets cluster-wide, which pods get a token they don't need, and which namespaces enforce Pod Security Standards.

### Insight
Most service accounts never call the Kubernetes API. They still get a token mounted by default.

### Practical
- Check what a service account can do:

    ```bash
    kubectl auth can-i list secrets --all-namespaces \
      --as=system:serviceaccount:checkout:fast-trace-agent
    ```

- List ClusterRoleBindings that grant roles to service accounts:

    ```bash
    kubectl get clusterrolebindings -o json | jq -r '
      .items[]
      | select(any(.subjects[]?; .kind == "ServiceAccount"))
      | "\(.metadata.name) -> \(.roleRef.name)"'
    ```

- Find privileged pods (JSONPath can't do this cleanly, so use `jq`):

    ```bash
    kubectl get pods -A -o json | jq -r '
      .items[]
      | select(any(.spec.containers[]; .securityContext.privileged == true))
      | "\(.metadata.namespace)/\(.metadata.name)"'
    ```

- Check which namespaces have Pod Security Admission labels:

    ```bash
    kubectl get namespaces -L pod-security.kubernetes.io/enforce
    ```

- Check whether you run ingress-nginx and which version. CVE-2025-1974 is fixed in 1.11.5 and 1.12.1, and the project's best-effort maintenance ended in March 2026, so plan a move to a maintained controller or Gateway API.

### Tools/Techniques
- [Kubescape](https://github.com/kubescape/kubescape) for RBAC and workload configuration scans.
- [Trivy](https://trivy.dev/) (`trivy k8s`) for misconfigurations and vulnerable components.
- [kube-bench](https://github.com/aquasecurity/kube-bench) for CIS benchmark checks on nodes and control plane.

### Metrics/Signal
- Non-system identities that can list Secrets cluster-wide.
- Namespaces without an enforced Pod Security level.
:::

::: {! stage fortify}
## Fortify

### Explanation
Review what charts ask for before installing them, and stop developers holding cluster-admin day to day.

### Insight
Kubernetes RBAC blocks privilege escalation: you can only bind permissions you already hold. Take cluster-admin away from developers and a chart like this simply fails to install.

### Practical
- Render and read charts before installing them. Look for cluster-scoped resources:

    ```bash
    helm template fast-trace ./fast-trace-agent \
      | grep -nE "^kind: (ClusterRole|ClusterRoleBinding|MutatingWebhookConfiguration|ValidatingWebhookConfiguration)"
    ```

- Give developers namespace-scoped `edit` or a custom role in their own namespaces. Install charts through a GitOps pipeline (Argo CD or Flux) that a reviewer approves.
- Turn off token automounting unless a pod calls the API:

    ```yaml
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: fast-trace-agent
      namespace: checkout
    automountServiceAccountToken: false
    ```

- Enforce the `restricted` Pod Security Standard on application namespaces:

    ```yaml
    apiVersion: v1
    kind: Namespace
    metadata:
      name: checkout
      labels:
        pod-security.kubernetes.io/enforce: restricted
        pod-security.kubernetes.io/warn: restricted
    ```

- Add an admission policy that rejects ClusterRoleBindings from anyone outside the platform team.

### Tools/Techniques
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/).
- [Kyverno](https://kyverno.io/) or [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) for custom admission rules.
- [Configure service accounts for pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/).

### Metrics/Signal
- Developers holding cluster-admin on shared clusters (target: zero).
- Pods with automounted tokens that never call the API.
:::

::: {! stage limit}
## Limit

### Explanation
If a malicious pod gets a privileged token, limit what it can find and where it can send it.

### Insight
The chart found production credentials in a dev cluster. The fastest win is to keep production secrets out of clusters that run unvetted software.

### Practical
- Keep production secrets out of development clusters. Use separate cloud accounts and secret stores per environment.
- Store secrets in an external manager and sync only what each namespace needs, with the External Secrets Operator or the Secrets Store CSI Driver.
- Restrict pod egress with default-deny NetworkPolicies. Use a CNI with DNS-aware policy (such as Cilium) to limit which domains pods can resolve, which blocks DNS tunnelling.
- Enable encryption at rest for Secrets in etcd.

### Tools/Techniques
- [External Secrets Operator](https://external-secrets.io/).
- [Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
- [Cilium DNS-based policies](https://docs.cilium.io/en/stable/security/dns/).

### Metrics/Signal
- Production credentials present in non-production clusters (target: zero).
- Namespaces without a default-deny egress policy.
:::

::: {! stage expose}
## Expose

### Explanation
Detect new cluster-wide permissions and service accounts reading Secrets they never touched before.

### Insight
The audit log records every Secret read. A new service account listing Secrets across namespaces stands out clearly once you look.

### Practical
- Enable API server audit logging at `Metadata` level for Secrets, so reads are recorded without logging values:

    ```yaml
    apiVersion: audit.k8s.io/v1
    kind: Policy
    rules:
      - level: Metadata
        resources:
          - group: ""
            resources: ["secrets"]
      - level: RequestResponse
        resources:
          - group: rbac.authorization.k8s.io
            resources: ["clusterrolebindings", "clusterroles"]
    ```

- Alert on `list` or `get` of Secrets across namespaces by service accounts outside a known set.
- Alert on any new ClusterRoleBinding.
- Log DNS queries in CoreDNS and look for long, high-entropy subdomains to a single domain.

### Tools/Techniques
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).
- [Falco](https://falco.org/) with its Kubernetes audit log plugin.
- The CoreDNS `log` plugin.

### Metrics/Signal
- Cross-namespace Secret reads by non-system service accounts.
- New ClusterRoleBindings per week.
:::

::: {! stage exercise}
## Exercise

### Explanation
Install a deliberately greedy chart in a sandbox and see which controls stop it.

### Insight
A chart that asks for too much is easy to build and harmless to test.

### Practical
1. Create a local cluster with kind.
2. Write a test chart that requests a ClusterRole to list Secrets and runs a pod that only counts the Secrets it can see.
3. Create some dummy Secrets in other namespaces.
4. Install the chart as a namespace-scoped developer user. It should fail on the ClusterRoleBinding.
5. Install it as cluster-admin. Confirm your audit alert fires when the pod lists Secrets, and that the `restricted` Pod Security level and automount settings behave as expected.

### Tools/Techniques
- [kind](https://kind.sigs.k8s.io/) for a disposable local cluster.
- Kubescape scan of the sandbox before and after hardening.

### Metrics/Signal
- Whether the namespace-scoped install was blocked (target: yes).
- Time from Secret listing to alert.
:::

## Further Reading

- [Wiz: IngressNightmare](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)
- [Kubernetes: Ingress-nginx CVE-2025-1974, what you need to know](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/)
- [Kubernetes: RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Kubernetes: Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
