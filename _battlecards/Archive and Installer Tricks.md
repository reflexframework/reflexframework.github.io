---
 permalink: /battlecards/archive-and-installer-tricks
 
battlecard:
 title: Archive and Installer Tricks
 category: Developer Environment
 scenario: Archive/Installer Tricks
 focus: 
   - zip-slip path traversal 
   - tarbombs 
   - pre/postinstall shell scripts 
---
{% block type='battlecard' text='Scenario' %}
A developer on the "New-Features" team is building a prototype that requires generating QR codes. They find a promising, recently-updated package on npm called `easy-qr-gen`. A quick `npm install easy-qr-gen` adds it to their project.

Unbeknownst to them, the package maintainer's account was compromised. An attacker published a new minor version containing a malicious `postinstall` script. When the developer runs `npm install` (or when the CI/CD server builds the project), the script executes.

The script contains a payload that does two things:
1.  **Zip-Slip Attack**: It unpacks a compressed archive included in the package. The archive contains a file with a path like `../../../../root/.ssh/authorized_keys`. When extracted naively, this file traverses up the directory tree and overwrites the CI runner's or developer's SSH authorized keys, giving the attacker persistent shell access.
2.  **Credential Exfiltration**: If the zip-slip fails, the script falls back to searching for common credential locations (`~/.aws/credentials`, `~/.kube/config`, or environment variables like `AWS_ACCESS_KEY_ID`) and exfiltrates them via a DNS query or an HTTP POST to an attacker-controlled server.

The CI/CD pipeline, configured with long-lived AWS credentials to deploy to a staging environment, automatically builds the new branch. The malicious script runs, steals the AWS keys, and the attacker now has access to the company's staging cloud environment.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers research your development ecosystem to find the path of least resistance. They don't start by attacking your production servers; they start by studying your developers and the tools they trust. They will identify popular libraries, frameworks, and build tools, then create malicious look-alikes (typosquatting), compromise legitimate ones, or contribute malicious code. They analyze public package registries (npm, PyPI, Maven Central) to find packages that are widely used but poorly maintained. For this scenario, they'd specifically look for packages whose maintainers have weak passwords or no 2FA, making them easy to take over. They also study how CI/CD systems work by default, knowing they often run with elevated privileges and contain juicy secrets.

### Insight
Your CI/CD environment is a high-value target. It's the factory floor for your software, and it often has the keys to the kingdom (cloud credentials, private source code, signing keys). Attackers know this and treat it as a primary objective, not just a stepping stone. They also target AI development pipelines, where a malicious script could steal proprietary training data or poison a machine learning model.

### Practical
Think about your project's "attack surface" beyond the application code.
- What open-source dependencies do you rely on?
- Do you know who maintains them?
- What base images do your containers use?
- How does your package manager handle install scripts? Does it run them by default?
- Where are secrets stored or injected in your build pipeline?

### Tools/Techniques
- **Typosquatting Search**: Attackers use tools to find common misspellings of popular packages (e.g., `python-dateutil` vs. `pythondateutil`). Developers can use these same techniques to find potential threats.
- **GitHub/Registry Analysis**: Scrutinizing package repositories for signs of a recent, suspicious takeover (e.g., a new maintainer, a sudden change in coding style).
- **Dependency Graph Analysis**: Tools like [Socket.dev](https://socket.dev/) or [Snyk](https://snyk.io/) can analyze a dependency's behavior, including its use of the filesystem, network, and shell access during installation.

### Metrics/Signal
- **Dependency Freshness**: A sudden update to a library that hasn't been touched in years can be a red flag.
- **Maintainer Changes**: An alert or report when a core dependency changes ownership.
- **Download Spikes**: Suspiciously high download counts for a brand new or obscure package.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you assess your own environment's vulnerability to the attack. A developer can review their code, dependencies, and build configurations to see if they are susceptible. Key questions include: Do we sanitize paths when extracting archives? Does our package manager run scripts from dependencies automatically? Are our CI/CD runners running as root and using long-lived, overly permissive credentials?

### Insight
Vulnerability often stems from trusting defaults. `npm install` runs scripts by default. Docker containers run as `root` by default. These default settings prioritize ease of use over security, creating openings for attackers. You must be actively non-compliant with insecure defaults.

### Practical
- **Code Review**: Search your codebase for archive-handling logic (e.g., `zipfile.extractall()` in Python, `unzip` commands in shell scripts). Is it validating filenames before writing them to disk?
- **Configuration Audit**:
- Check your `npm` or `yarn` config. Are you globally disabling install scripts?
- Inspect your `Dockerfile`. Is there a `USER` directive to switch to a non-root user?
- Review your `Jenkinsfile`, `gitlab-ci.yml`, or GitHub Actions workflow. How are secrets being passed? Are they tightly scoped and short-lived?

### Tools/Techniques
- **Static Analysis (SAST)**: Use tools like [CodeQL](https://codeql.github.com/), [Checkmarx](https://checkmarx.com/), or [Snyk Code](https://snyk.io/product/snyk-code/) to find unsafe archive extraction patterns in your code.
- **Package Manager Configuration**:
- For npm: `npm config set ignore-scripts true` in your CI environment.
- For pip: Avoid using `setup.py` directly; rely on modern packaging with `pyproject.toml`.
- **Dependency Scanners**: Tools like [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) or commercial equivalents can identify dependencies, but may not flag this type of behavioral risk. This is where tools like Socket.dev shine.

### Metrics/Signal
- **Percentage of projects with `ignore-scripts` enabled**: A high percentage indicates a better security posture.
- **Number of build containers running as root**: Aim for zero.
- **Code Scan Findings**: Number of active "Path Traversal" vulnerabilities found by your SAST tool.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification involves building proactive defenses to block this attack vector. This means writing code that is resilient to path traversal, hardening the configuration of your development tools and CI/CD pipelines, and reducing the implicit trust you place in third-party code.

### Insight
Security should be a layered approach. Secure code is good. A secure pipeline is good. A secure container environment is good. All three together create a robust defense that is much harder for an attacker to bypass. You cannot rely on a single control.

### Practical
1.  **Secure Archive Handling**: Never extract files from an archive without first validating the destination path.
- **Example (Python)**:
```python
import zipfile
import os

# Secure extraction
with zipfile.ZipFile("archive.zip", "r") as zf:
for member in zf.infolist():
# Resolve the absolute path of the destination
final_path = os.path.realpath(os.path.join("/safe/output/dir", member.filename))
# Ensure the final path is within the safe directory
if final_path.startswith("/safe/output/dir/"):
zf.extract(member, "/safe/output/dir")
else:
print(f"Malicious path detected: {member.filename}")
```
2.  **Harden Package Management**: Disable automatic script execution in your CI/CD environment and for developers' local machines where possible.
3.  **Use Lockfiles**: Always use lockfiles (`package-lock.json`, `poetry.lock`, `Gemfile.lock`) and commit them to your repository. This ensures you are installing the exact same dependency versions everywhere, preventing an attacker from sneaking in a malicious update.
4.  **Least Privilege Containers**: Run your build steps in a container as a non-root user. Add `USER nonroot` to your `Dockerfile`.

### Tools/Techniques
- **Secure Libraries**: Use up-to-date, well-maintained libraries for handling archives.
- **Package Manager Controls**:
- **npm**: Use `.npmrc` file with `ignore-scripts=true`.
- **Yarn**: Use `yarn install --ignore-scripts`.
- **Private Registry/Vetting**: Host a private registry (like [JFrog Artifactory](https://jfrog.com/artifactory/) or [Sonatype Nexus](https://www.sonatype.com/products/nexus-repository)) that mirrors public ones. Use it to vet and approve specific versions of open-source packages before they can be used internally.
- **Immutable Base Images**: Use hardened, minimal base container images (like [distroless](https://github.com/GoogleContainerTools/distroless) or [Alpine](https://alpinelinux.org/)) to reduce the available attack surface within the build environment.

### Metrics/Signal
- **Lockfile Enforcement**: A pre-commit hook or CI check that fails if the lockfile is not up-to-date with the dependency manifest.
- **Build Pass/Fail Rate**: A build should fail if it attempts to execute an unauthorized installation script.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker's malicious script successfully executes. The goal of this stage is to contain the "blast radius." If the script runs, what can it actually do? Limiting damage is about applying the principle of least privilege to your build processes. The build should have just enough permission to do its job and absolutely nothing more.

### Insight
A successful breach doesn't have to be a catastrophe. An attacker who gains access to an ephemeral build container that has no secrets, no network access, and is destroyed in five minutes has gained almost nothing. The damage is limited by the environment's design.

### Practical
- **Use Short-Lived Credentials**: Instead of storing static `AWS_ACCESS_KEY_ID` secrets in your CI/CD, use OpenID Connect (OIDC). This allows your CI/CD job to request temporary, short-lived credentials directly from the cloud provider, scoped to the exact permissions needed for that one job.
- **Isolate Build Environments**: Each build should run in a fresh, ephemeral environment (e.g., a new container or VM) that is destroyed immediately after the job completes.
- **Restrict Network Egress**: Configure firewalls or network policies for your build runners. They should only be allowed to connect to expected resources (e.g., your package registry, your artifact repository, your cloud deployment endpoint). Block all other outbound traffic.

### Tools/Techniques
- **OIDC Integration**:
- [GitHub Actions OIDC Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [GitLab OIDC Connect](https://docs.gitlab.com/ee/ci/cloud_services/aws/)
- **Secrets Management**: Use a dedicated tool like [HashiCorp Vault](https://www.vaultproject.io/) or a cloud provider's native service ([AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), [Google Secret Manager](https://cloud.google.com/secret-manager)) to manage and inject secrets just-in-time.
- **Container Sandboxing**: Technologies like [gVisor](https://gvisor.dev/) or [Firecracker](https://firecracker-microvm.github.io/) can provide stronger isolation between the build process and the host system.
- **Kubernetes Network Policies**: If your runners are in Kubernetes, use [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) to strictly control traffic flow.

### Metrics/Signal
- **Credential TTL (Time To Live)**: The average lifetime of credentials used in a build. This should be minutes, not days or months.
- **Number of Long-Lived Static Secrets**: This count should be driven to zero.
- **Egress Network Blocks**: Number of outbound network connections from CI runners blocked by a firewall, which could indicate an attempted exfiltration.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about detecting the attack as it happens or shortly after. To know you're under attack, you need visibility into your build environment. This means comprehensive logging, monitoring, and alerting on suspicious activities. What is a normal build process? What is anomalous? You need to be able to answer these questions.

### Insight
You can't detect what you don't log. Default CI/CD logs often only show `stdout` from the build commands. You need deeper telemetry, such as process executions, file system modifications, and network connections, to spot a hidden malicious script in action.

### Practical
- **Log Everything**: Capture process execution events, network connections (especially DNS queries and outbound TCP/UDP connections), and file modifications within the build runner.
- **Establish a Baseline**: Understand what normal behavior looks like for a typical build. What domains does it connect to? What files does it normally write?
- **Create Alerts**: Set up alerts for deviations from the baseline. For example:
- A build process trying to connect to a new, unknown IP address.
- A process writing a file outside the expected project or temporary directories (e.g., to `/root/.ssh/`).
- The `npm` or `pip` process spawning a shell (`sh`, `bash`) or network tool (`curl`, `wget`).

### Tools/Techniques
- **Runtime Threat Detection**: Use a tool like [Falco](https://falco.org/) or [Sysdig Secure](https://sysdig.com/products/secure/) to monitor container activity in real-time and alert on suspicious behavior based on pre-defined rules (e.g., "Write below root directory," "Outbound connection to non-allowed port").
- **Log Aggregation**: Ship all your build and system-level logs to a central platform like [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or the [ELK Stack](https://www.elastic.co/elastic-stack) for analysis and correlation.
- **Network Monitoring**: An egress proxy or firewall that logs all outbound connection attempts from your build agents can be an invaluable source of detection signals.

### Metrics/Signal
- **Alert on Anomalous Egress**: An alert fires when a build runner attempts to connect to an IP address not on an allowlist.
- **File System Integrity Monitoring (FIM) Alert**: An alert fires when a file is written to a sensitive location like `/etc`, `/root`, or `/usr/bin`.
- **Time to Detect (TTD)**: How long does it take from the moment the malicious script runs until a security alert is generated?

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about actively testing your defenses to build "muscle memory." Instead of waiting for a real attack, you simulate one in a controlled manner. This helps validate that your fortifications, limits, and detection mechanisms work as expected and trains your team on how to respond.

### Insight
A security control that has never been tested is a security control that you assume works, but don't know for sure. Regular exercises turn theoretical plans into proven capabilities and highlight gaps in your defenses before a real attacker does.

### Practical
1.  **Create a Safe Malicious Package**: Internally, create a "malicious" npm package. Its `postinstall` script should perform benign but detectable actions, like:
- `touch /tmp/pwned`
- `curl https://<your_internal_test_server>/beacon`
- `cat /etc/hostname` and print it to the log.
2.  **Run a Fire Drill**: A developer adds this package as a dependency to a test application and runs it through the full CI/CD pipeline.
3.  **Observe and Learn**:
- Did the `ignore-scripts` setting prevent the script from running at all? (Fortify check)
- If it ran, was its network call blocked? (Limit check)
- Did Falco or your logging system generate an alert for the `curl` or `touch` command? (Expose check)
- How long did it take for the right team to notice the alert?

### Tools/Techniques
- **Internal Red Teaming**: Have a dedicated team or a rotation of developers whose job is to "attack" the build system and test its defenses.
- **Capture The Flag (CTF) Events**: Create internal CTF-style challenges focused on CI/CD and supply chain security to make training engaging.
- **Attack Simulation**: Use frameworks or create simple scripts to automate the execution of the test scenarios on a regular basis.
- **Post-Mortem/Review Sessions**: After every exercise, hold a blameless review to discuss what worked, what didn't, and what needs to be improved in your tooling, processes, or documentation.

### Metrics/Signal
- **Exercise Success Rate**: What percentage of simulated attacks were successfully blocked or detected?
- **Mean Time To Remediate (MTTR)**: After a simulated attack is detected, how long does it take to identify the root cause (the malicious package) and "fix" it (remove it, block it)?
- **Developer Feedback**: Survey developers after training exercises to gauge their understanding of the risks and their confidence in the security tooling.
{% endblock %}