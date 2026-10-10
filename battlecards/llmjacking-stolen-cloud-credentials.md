---
title: LLMjacking with Stolen Cloud Credentials
category: AI/ML Security
scenario: Stolen cloud keys used to run and resell hosted LLMs
focus:
  - long-lived cloud keys in repos and CI
  - Bedrock and Vertex model invocation by intruders
  - SCPs and CloudTrail monitoring for model use
---

## Scenario

A platform team runs a small Laravel admin app on an EC2 instance. Years ago, someone gave it an IAM user with an access key in the `.env` file. The app has a known remote code execution bug that nobody patched, because "it is only an internal tool".

1. An attacker exploits the bug and reads the `.env` file. The access key has broad permissions, including `bedrock:*`.
2. A key-checking script tests the credentials against several AI services. On Bedrock, it calls `InvokeModel` with an invalid parameter. A validation error, rather than access denied, confirms the key can call the model without running a real prompt.
3. The script checks whether model invocation logging is on. If it is, the attacker either moves on or deletes the logging configuration.
4. The key goes behind a reverse proxy that resells chat access to people who cannot or will not pay for it. Requests run in several regions at once.
5. The account owner notices a five-figure Bedrock line on the next bill. The company has never used Bedrock.

You do not need to be an AI shop to be hit. You only need cloud credentials that are allowed to call model APIs.

**Real-world precedent:** Sysdig named this [LLMjacking in May 2024](https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack), after attackers used credentials stolen through a Laravel flaw (CVE-2021-3129) to access Bedrock and nine other LLM services, with estimated costs of over $46,000 a day. By [September 2024](https://sysdig.com/blog/growing-dangers-of-llmjacking), attackers were enabling models in victims' accounts themselves, deleting invocation logging, and pushing estimated costs above $100,000 a day. [Permiso and Krebs on Security](https://krebsonsecurity.com/2024/10/a-single-cloud-compromise-can-feed-an-army-of-ai-sex-bots/) showed a leaked AWS key being used for Bedrock within minutes of exposure.

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers collect cloud credentials from public repos, exposed `.env` files, vulnerable web apps, compromised CI systems and infostealer logs. They then run checker scripts that test each credential against Bedrock, Vertex AI, Azure OpenAI and direct provider APIs.

### Insight
Model access is an extra prize on top of a normal cloud compromise. A credential that cannot launch EC2 instances might still be able to call `bedrock:InvokeModel`, and that is enough to make money from it. Disabled models used to be treated as a safety net. Sysdig warned that attackers simply enabled them, and since October 2025 AWS enables serverless Bedrock models by default anyway.

### Practical
Find the credentials an attacker could find:

- List every IAM user with an active access key, and when each key was last rotated and used.
- Search repos, CI variables and container images for `AKIA` access key IDs and service account JSON files.
- Find apps that read cloud keys from `.env` files instead of instance or workload roles.
- Check which of those principals are allowed to call `bedrock:InvokeModel`, `aiplatform.endpoints.predict` or Azure OpenAI deployments.

```bash
# IAM users with access keys, and when each key was last used
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' |
while read -r user; do
    for key in $(aws iam list-access-keys --user-name "$user" \
            --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
        last=$(aws iam get-access-key-last-used --access-key-id "$key" \
            --query 'AccessKeyLastUsed.LastUsedDate' --output text)
        echo "$user $key $last"
    done
done
```

### Tools/Techniques
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [Gitleaks](https://github.com/gitleaks/gitleaks) for cloud keys in code, history and images.
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html) for unused access and over-broad permissions.
- [Prowler](https://github.com/prowler-cloud/prowler) for AWS, Azure and GCP posture checks, including old access keys.

### Metrics/Signal
- Number of active long-lived access keys, and the oldest one.
- Number of principals that can invoke models but have no business reason to.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Assess which accounts and projects could run models, who could enable them, and whether you would see it happen.

### Insight
The dangerous case is an account that never uses AI but still allows it. Nobody watches Bedrock spend there, invocation logging is off, and an IAM policy with `"Action": "*"` quietly includes every model.

### Practical
For each cloud account or project, record:

- Does it use hosted models at all? Which ones, in which regions?
- Is there an SCP, organisation policy or Azure Policy that denies model invocation where it is not needed?
- Is Bedrock [model invocation logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) enabled, and could the attacker's principal delete it?
- Are long-term Bedrock API keys (bearer tokens tied to IAM users) allowed? Are they in use?
- Would a budget alert for Bedrock, Vertex AI or Azure OpenAI reach someone within hours?

### Tools/Techniques
- AWS Organizations SCP inventory, checked against the [Bedrock actions in the Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock.html).
- [Prowler](https://github.com/prowler-cloud/prowler) checks for Bedrock logging and IAM hygiene.
- Cost Explorer filtered by service, to spot model spend in accounts that should have none.

### Metrics/Signal
- Percentage of accounts with model invocation denied by default.
- Percentage of model-using accounts with invocation logging on and protected from deletion.
:::

::: {! stage fortify}
## Fortify

### Explanation
Remove the long-lived credentials attackers steal, and deny model access everywhere it is not needed.

### Insight
Short-lived credentials are the real fix. A role credential from an instance profile, EKS Pod Identity or GitHub OIDC expires within hours and is not sitting in a file. Policy guardrails then cover the credentials you cannot remove yet.

### Practical
- **Replace IAM user keys** in apps with instance roles, workload identity or OIDC federation from CI.
- **Deny model invocation** in accounts and OUs that do not use it. Attach an SCP like this:

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "DenyBedrockOutsideAIAccounts",
          "Effect": "Deny",
          "Action": ["bedrock:*", "bedrock-mantle:*"],
          "Resource": "*"
        }
      ]
    }
    ```

- **In AI accounts, allow only the models you use.** Scope IAM policies to specific foundation model ARNs instead of `bedrock:*`.
- **Block Bedrock API keys** if you do not need them. AWS recommends SCPs that deny `iam:CreateServiceSpecificCredential` for Bedrock and deny `bedrock:CallWithBearerToken` and `bedrock-mantle:CallWithBearerToken`.
- **Protect logging.** Deny `bedrock:DeleteModelInvocationLoggingConfiguration` and `bedrock:PutModelInvocationLoggingConfiguration` to everyone except a security role.
- **Do the same on other clouds.** In Google Cloud, keep the Vertex AI API disabled in projects that do not need it and avoid service account key files. In Azure, restrict who can create Azure OpenAI deployments and prefer managed identities over API keys.

### Tools/Techniques
- [Bedrock IAM actions and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock.html).
- [AWS Security Blog: securing Bedrock API keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management).
- GitHub Actions OIDC with `aws-actions/configure-aws-credentials` instead of stored keys.

### Metrics/Signal
- Number of IAM users with access keys, trending to zero.
- Accounts covered by a deny-model-invocation SCP.
:::

::: {! stage limit}
## Limit

### Explanation
If a credential is stolen anyway, cap what it can spend and where it can run.

### Insight
LLMjacking scales by running in many regions at once. A region deny cuts that off. Budgets on their own only send alerts; they stop spend only if you attach an action.

### Practical
- **Deny unused regions** with an SCP on `aws:RequestedRegion`. Remember cross-region inference profiles route requests to other regions, so allow the destinations they need.
- **Use AWS Budgets actions** on Bedrock spend to apply a deny policy or SCP automatically when a threshold is crossed. Test it in a sandbox account first.
- **Separate AI workloads** into their own account so a compromise of a web app account cannot reach model access.

### Tools/Techniques
- [AWS Budgets actions](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-controls.html).
- Google Cloud budgets with Pub/Sub notifications to disable the API or billing.

### Metrics/Signal
- Maximum daily model spend reachable from any single non-AI account.
- Time from budget threshold to automatic deny.
:::

::: {! stage expose}
## Expose

### Explanation
Watch for model calls from principals, accounts and regions that should never make them, and for anyone touching logging configuration.

### Insight
On the `bedrock-runtime` endpoint, CloudTrail records `InvokeModel`, `InvokeModelWithResponseStream`, `Converse` and `ConverseStream` as management events at no extra cost. Inference on the newer `bedrock-mantle` endpoint is a data event and is only logged if you enable data events for it. Filter on both event sources, or you will miss half the traffic.

### Practical
Alert on these CloudTrail events:

- `InvokeModel`, `Converse` or their streaming variants from an IAM user, or from any principal outside your AI workloads.
- `ValidationException` errors on `InvokeModel`. Key-checkers use deliberately invalid requests to test access.
- `DeleteModelInvocationLoggingConfiguration` or `GetModelInvocationLoggingConfiguration` from unexpected principals.
- `ListFoundationModels` followed by model calls in several regions within minutes.
- Calls with `callWithBearerToken: true` if you do not issue Bedrock API keys.

```sql
-- CloudTrail Lake: model calls by principal and region since a given time
SELECT userIdentity.arn, awsRegion, eventName, COUNT(*) AS calls
FROM <event_data_store_id>
WHERE eventSource = 'bedrock.amazonaws.com'
  AND eventType = 'AwsApiCall'
  AND eventName IN ('InvokeModel', 'InvokeModelWithResponseStream', 'Converse', 'ConverseStream')
  AND eventTime > '2026-10-09 00:00:00'
GROUP BY userIdentity.arn, awsRegion, eventName
ORDER BY calls DESC
```

### Tools/Techniques
- [Monitoring Bedrock with CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html) and the separate [bedrock-mantle CloudTrail guide](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-cloudtrail-mantle.html).
- Amazon GuardDuty for anomalous API use by IAM credentials.
- Google Cloud audit logs for Vertex AI, Azure Monitor diagnostic logs for Azure OpenAI.

### Metrics/Signal
- Model invocations from principals not on the allow-list (target: zero).
- Model spend in accounts with no approved AI workload (target: zero).
:::

::: {! stage exercise}
## Exercise

### Explanation
Rehearse detection with safe signals in a sandbox account.

### Insight
Most teams have never seen what a Bedrock call looks like in their own logs. Generating one on purpose shows whether the alerts fire and where they go.

### Practical
1. In a sandbox account, create a temporary IAM user and make one cheap `Converse` call to a small model. Confirm the "IAM user calling Bedrock" alert fires. Then delete the user.
2. In the same account, call `GetModelInvocationLoggingConfiguration` and check that it is flagged.
3. Attach your deny SCP to the sandbox OU and confirm the call now fails with access denied.
4. Place an AWS key [canary token](https://canarytokens.org/) in a test repo's `.env` and confirm the alert reaches the right people.

### Tools/Techniques
- A dedicated sandbox account in your AWS Organization.
- [Canarytokens](https://canarytokens.org/) for decoy AWS keys.

### Metrics/Signal
- Time from test model call to alert.
- Percentage of drills where the SCP blocked the call as expected.
:::

## Further Reading

- [Sysdig: LLMjacking, stolen cloud credentials used in new AI attack](https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack)
- [Sysdig: The growing dangers of LLMjacking](https://sysdig.com/blog/growing-dangers-of-llmjacking)
- [AWS Security Blog: Simplified Amazon Bedrock model access](https://aws.amazon.com/blogs/security/simplified-amazon-bedrock-model-access/)
- [AWS Security Blog: Securing Amazon Bedrock API keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management)
- [Krebs on Security: A single cloud compromise can feed an army of AI sex bots](https://krebsonsecurity.com/2024/10/a-single-cloud-compromise-can-feed-an-army-of-ai-sex-bots/)
