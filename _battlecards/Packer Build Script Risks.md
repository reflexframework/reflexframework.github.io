---
 permalink: /battlecards/packer
battlecard:
 title: Packer Build Script Risks
 category: Infra-as-Code
 scenario: Packer
 focus: 
   - unsigned binaries in build scripts 
   - curl|bash integrations 
---

An attacker identifies a popular open-source utility script hosted on a public, non-versioned location like a GitHub Gist or a personal website. Developers frequently use this script in their [Packer](https://www.packer.io/) builds to install a monitoring agent or a helper tool, using a common but dangerous pattern: `curl http://utility-script-site.com/install.sh | bash`.

The attacker compromises the website hosting the script and replaces the legitimate `install.sh` with a malicious version. The malicious script still performs the original installation to avoid breaking the image build process, but it also adds a backdoor that connects to a command-and-control (C2) server, or installs a cryptominer.

When a developer's CI/CD pipeline runs the Packer build, it pulls and executes the compromised script. The backdoor is now baked into the resulting "golden" machine image (e.g., an AWS AMI). Every server launched from this image is compromised from the moment it boots, silently exfiltrating data or consuming compute resources for the attacker's benefit.

{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. They are looking for weak links in your image-building supply chain. Their goal is to find an easy, high-impact entry point. For this scenario, they aren't attacking you directly; they are poisoning a public resource they know you (and others) consume.

They use automated scanners and simple search queries on public code repositories like GitHub and GitLab, looking for Packer templates (`.pkr.hcl` or `.json`). They specifically search for insecure patterns like:
- `curl ... | bash`
- `wget -qO- ... | sh`
- Downloads over `http://` instead of `https://`
- Direct downloads of binaries or scripts from non-authoritative sources (e.g., personal blogs, unverified S3 buckets, GitHub Gists).

Once they find a commonly used but insecurely-hosted script, they focus their efforts on compromising that single host, knowing it will have a downstream impact on all its users.

### Insight
Your build scripts are a public blueprint of your dependencies and, by extension, your trust model. Attackers know that developers prioritize speed and convenience, often copying and pasting installation commands from documentation without validating the source. They exploit this trust and convenience.

### Practical
- **Audit your codebase:** Act like an attacker and search your own repositories for the patterns mentioned above. Look in all Packer templates, Dockerfiles, and any shell scripts they call.
- **Dependency Mapping:** Create a simple inventory of all third-party scripts and binaries downloaded and executed during your image builds. Note their source and why you trust it.

### Tools/Techniques
- **GitHub Code Search:** Use advanced search queries to find vulnerable patterns in your organization's repositories (e.g., `org:your-org "curl" "bash" path:*.pkr.hcl`).
- **Linters/Scanners:** Tools like [Checkov](https://www.checkov.io/) or [tfsec](https://github.com/aquasecurity/tfsec) can sometimes be configured with custom rules to flag dangerous shell commands within IaC files.
- **grep/sed/awk:** Simple command-line tools are highly effective for quickly scanning a codebase for these patterns.

### Metrics/Signal
- **Count of insecure patterns:** The number of instances of `curl | bash` or `wget | sh` found in your build scripts. The goal is zero.
- **HTTP URLs:** The number of dependencies pulled over unencrypted HTTP. The goal is zero.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about self-assessment. Now that you know what attackers are looking for, you need to examine your own environment to see if you're vulnerable. It's a code and process review focused on the security of your image factory.

Ask your team these questions for every Packer build:
1.  Are we downloading any scripts or binaries from the internet during the build?
2.  If so, are we verifying their integrity using a checksum (e.g., SHA256)?
3.  Is the source of the download reputable (e.g., the official project release page, a trusted package manager)?
4.  Are we using the `curl | bash` anti-pattern anywhere?
5.  What is our policy for adding a new third-party dependency to a base image?

A "yes" to #1 without a "yes" to #2 is a critical vulnerability.

### Insight
The riskiest part of any automated build process is the boundary where you pull in external resources. Every unaudited, unverified dependency is an act of blind trust. Developers often assume that if a script is popular or if the build doesn't break, the script must be safe. This is a false sense of security.

### Practical
- **Hold a "Packer Security Review" meeting:** Dedicate an hour for the team to walk through your most critical Packer templates and challenge every external dependency.
- **Create a checklist:** Develop a simple security checklist for peer reviews of any change to a Packer template. The checklist should include the questions above.

### Tools/Techniques
- **Manual Code Review:** The most effective tool here is a focused, security-conscious human reviewer.
- **Static Analysis (SAST):** Integrate SAST tools into your CI pipeline to automatically scan Packer files and shell scripts for risky commands. Tools like [Semgrep](https://semgrep.dev/) can be configured with custom rules to find these patterns.

### Metrics/Signal
- **Dependency Scorecard:** A spreadsheet or wiki page that rates each external dependency on trust, verification method, and necessity.
- **Peer Review Checklist Compliance:** The percentage of pull requests modifying Packer builds that have the security checklist completed.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is the hardening phase where you fix the identified vulnerabilities. The goal is to shift from a model of blind trust to a model of explicit verification for all external dependencies used in your Packer builds.

### Insight
Treat external binaries and scripts the same way you treat application libraries (e.g., npm packages, Maven jars). You wouldn't let a developer add a random, unaudited library to your application's `package.json`. Your infrastructure code deserves the same level of scrutiny and control.

### Practical
- **Never Pipe to Shell:** The `curl | bash` pattern should be banned. The correct, safe process is a two-step:
1.  Download the file: `curl -o install.sh http://utility-script-site.com/install.sh`
2.  Inspect the file (optional but recommended), and then execute: `bash install.sh`
- **Enforce Checksum Verification:** This is the most critical defense. Download the checksum file from the provider and use it to verify the integrity of the downloaded artifact before using it. Packer has built-in support for this.
```hcl
provisioner "file" {
source          = "https://releases.hashicorp.com/consul/1.13.1/consul_1.13.1_linux_amd64.zip"
destination     = "/tmp/consul.zip"
checksum        = "file:https://releases.hashicorp.com/consul/1.13.1/consul_1.13.1_SHA256SUMS"
checksum_target = "consul_1.13.1_linux_amd64.zip"
}
```
- **Vendor Your Dependencies:** The most robust solution is to not download from the public internet at all during the build.
1.  Your team vets and downloads the required tools/scripts.
2.  You store these approved artifacts and their checksums in a trusted internal repository (e.g., JFrog Artifactory, Sonatype Nexus, or a versioned S3 bucket).
3.  Your Packer builds are configured to only pull from this internal, trusted source.

### Tools/Techniques
- **Packer `file` provisioner:** Use the `checksum` arguments as shown in the [official Packer documentation](https://developer.hashicorp.com/packer/plugins/provisioners/file#checksum-configuration).
- **Artifact Repositories:** [JFrog Artifactory](https://jfrog.com/artifactory/) and [Sonatype Nexus Repository](https://www.sonatype.com/products/nexus-repository) are industry standards for managing binaries and dependencies.
- **GPG Verification:** For software that provides GPG signatures, use a shell provisioner to import the public key and verify the signature before proceeding.

### Metrics/Signal
- **Checksum Coverage:** Percentage of external artifacts in Packer builds that have mandatory checksum validation. Aim for 100%.
- **Internal Hits vs. External Misses:** In your artifact repository, the ratio of builds pulling dependencies from the internal cache versus going out to the internet. Aim to maximize internal hits.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and a malicious image has been deployed. The "Limit" stage is about damage control. The objective is to contain the compromised instance and prevent it from moving laterally, accessing sensitive data, or causing further harm. This is achieved by enforcing the principle of least privilege on the infrastructure itself.

### Insight
A compromised server is a beachhead. The attacker's first move is to explore: "Where am I? What can I connect to? What secrets can I find?" Your goal is to make the answer to those questions "nowhere" and "nothing." The blast radius is defined not by the initial breach, but by the permissions you've granted to the compromised resource.

### Practical
- **Minimal Base Images:** Don't build your images on a general-purpose OS bloated with tools. Use minimal images like [Alpine Linux](https://alpinelinux.org/), [Ubuntu Minimal](https://ubuntu.com/download/server/focal), or "distroless" base images. If an attacker gets a shell, they won't have `curl`, `netcat`, or even `bash` to work with.
- **Strict Network Egress Filtering:** By default, deny all outbound traffic from your servers. Only allow connections to the specific IPs and ports they need to function (e.g., to a specific database, an internal API). This prevents a backdoor from calling home to its C2 server.
- **Least-Privilege IAM Roles:** Attach an IAM role (or cloud equivalent) to each instance that grants it only the permissions it absolutely needs. If a web server doesn't need to read from an S3 bucket, it shouldn't have the permission to do so. This prevents the stolen credentials from being useful.
- **Immutable Infrastructure:** Do not attempt to "clean" a running server. Once a compromise is detected, the only response is to terminate the instance. The remediation happens by fixing the Packer build, creating a new clean image, and redeploying all services using that new image.

### Tools/Techniques
- **Cloud Firewalls:** [AWS Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html) or [Azure Network Security Groups](https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) are essential for controlling ingress and egress traffic.
- **Identity and Access Management (IAM):** Use [AWS IAM Roles](https://aws.amazon.com/iam/) or [Azure Managed Identities](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) to scope down permissions.
- **Service Mesh:** For microservices, a service mesh like [Istio](https://istio.io/) or [Linkerd](https://linkerd.io/) can enforce fine-grained network policies (e.g., service A can only call service B on a specific gRPC method).

### Metrics/Signal
- **IAM Permission Count:** The average number of permissions per IAM role. A lower number is better.
- **Egress Firewall Rule Count:** A high number of "allow ANY" outbound rules is a red flag. Rules should be specific and narrow.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This stage is about detection and visibility. How do you know an attack is happening? A supply chain attack is silent during the build, but it becomes noisy at runtime. You need the right monitoring and logging to spot the malicious activity when the compromised image is actually running.

### Insight
You can't detect what you can't see. The attacker is counting on their activity being lost in the noise of normal operations. Your job is to define what "normal" looks like so that anomalies stand out. A web server should serve web traffic; it shouldn't be spawning shells or making connections to a random IP in another country.

### Practical
- **Log All Build Activities:** Your CI/CD system should produce a detailed, auditable log of every Packer build, including the URLs of all downloaded files and their checksums.
- **Runtime Threat Detection:** Deploy agents on your hosts that monitor for suspicious behavior at the kernel level. This includes unexpected process execution (e.g., `nginx` spawning `/bin/sh`), file modifications in sensitive directories, and anomalous network connections.
- **Monitor DNS Queries and Network Flows:** Log all outbound DNS queries and network traffic from your instances. A spike in queries to unknown or malicious domains (check against threat intelligence feeds) is a primary indicator of compromise (IoC).
- **Generate a Software Bill of Materials (SBOM):** During the Packer build, generate an SBOM that lists every package and binary inside the image. If a vulnerability is discovered in a package later, you can instantly identify all affected images without needing to inspect them manually.

### Tools/Techniques
- **Runtime Security Tools:** [Falco](https://falco.org/) (open-source) is a powerful tool for detecting anomalous behavior based on system calls. Commercial offerings include [Sysdig Secure](https://sysdig.com/products/secure/) and [Aqua Security](https://www.aquasec.com/).
- **Cloud-Native Detection:** Services like [AWS GuardDuty](https://aws.amazon.com/guardduty/) or [Azure Defender for Cloud](https://azure.microsoft.com/en-us/services/defender-for-cloud/) use threat intelligence and anomaly detection to identify malicious activity like C2 communication or cryptomining.
- **SBOM Generators:** [Syft](https://github.com/anchore/syft) and [Trivy](https://github.com/aquasecurity/trivy) can scan a built image and produce a detailed SBOM.
- **Log Aggregation:** Centralize your logs using [Elastic Stack](https://www.elastic.co/), [Splunk](https://www.splunk.com/), or [Datadog](https://www.datadoghq.com/) to correlate events from different sources.

### Metrics/Signal
- **Runtime Security Alerts:** The number of high-severity alerts from tools like Falco or GuardDuty. An alert for "Outbound Connection to Suspicious IP" is a direct signal.
- **Anomalous DNS Queries:** A sudden increase in queries to non-standard or newly-registered domains.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about building muscle memory through practice. You need to simulate the attack in a controlled environment to ensure your defenses, tools, and team processes work as expected. Waiting for a real attack to test your response plan is a recipe for failure.

### Insight
An incident response plan that only exists on a wiki page is useless. By running drills, you find the gaps in your tooling, the ambiguities in your runbooks, and the points of friction in your team's communication. The goal is to make the real event feel like just another practice run.

### Practical
- **Simulate the Attack:**
1.  Create a "malicious" `install.sh` script. Instead of a real backdoor, have it `curl` a unique URL you control (e.g., using a webhook service like [webhook.site](https://webhook.site/)) or write a file to `/tmp/attack_sim.txt`.
2.  Host this script at a temporary URL.
3.  Create a test Packer template that uses the insecure `curl | bash` pattern to download and run this script.
4.  Run the Packer build and deploy an instance from the resulting image in a sandboxed environment.
- **Conduct a Tabletop Exercise:** Gather the development and security teams. Present the scenario: "Falco has just fired an alert that an instance is making an outbound call to a suspicious URL. What do we do *right now*?" Walk through the entire process: Who is on call? Where are the logs? How do we identify the source image? What is the rollback plan?
- **Test Your Tooling:** Did the simulation trigger the expected alerts in Falco, GuardDuty, or your logging platform? If not, why? Is the rule too specific? Is the agent not configured correctly? Use the drill to fine-tune your detection rules.

### Tools/Techniques
- **Red Team / Blue Team Exercises:** Formalize the simulation into a game where a "red team" acts as the attacker and a "blue team" acts as the defenders.
- **Chaos Engineering:** While not a direct security tool, platforms like the [Gremlin](https://www.gremlin.com/) can be used to inject security-focused failures, like blocking a critical network path to see how the system and team react.
- **Incident Response Runbooks:** Maintain a living document (e.g., in Confluence or a Git repo) that details the step-by-step procedure for handling this exact type of incident.

### Metrics/Signal
- **Mean Time to Detect (MTTD):** The time elapsed from when the compromised instance boots to when the first critical alert is generated.
- **Mean Time to Remediate (MTTR):** The time elapsed from the alert to when all compromised instances are terminated and the pipeline is fixed. Measure this during exercises and work to drive it down.
{% endblock %}