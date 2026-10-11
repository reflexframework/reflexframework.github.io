---
title: Model Supply Chain Metadata Leaks
category: AI/ML Security
ref: RFX-AI-10
precedent: "2023"
scenario: Credentials leaked through published model artefacts
focus:
  - secrets in training logs, notebooks and configs
  - over-scoped storage links and SAS tokens
  - leaked Hugging Face write tokens
---

## Scenario

A startup publishes a fine-tuned sentiment model to the Hugging Face Hub. To be helpful, they upload the whole training output directory: weights, `config.json`, a Jupyter notebook, `training_args.bin` and a `logs/` folder.

The notebook still has its outputs. One cell printed the environment while someone debugged a failing job, and it shows an `HF_TOKEN` with write access to the company's organisation. A log line shows an Azure Blob URL with a SAS token, used to pull training data. The SAS token covers the whole storage account, has full-control permissions and expires in 2050.

An attacker scanning new Hub uploads finds both. With the SAS URL they read every container in the account: datasets, unreleased checkpoints, and backups. With the Hub token they push a modified checkpoint to one of the company's popular public models. Downstream users who pull `main` now get the attacker's file.

::: {! precedent}
**Real-world precedent:** In September 2023 Wiz disclosed that [Microsoft AI researchers exposed 38TB of internal data](https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers) through an over-permissive SAS token in a public GitHub repo that shared open-source models. In December 2023 [Lasso Security found over 1,500 exposed Hugging Face API tokens](https://www.lasso.security/blog/1500-huggingface-api-tokens-were-exposed-leaving-millions-of-meta-llama-bloom-and-pythia-users-for-supply-chain-attacks) on GitHub and the Hub, many with write access to organisations including Meta, EleutherAI and BigScience.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers scan public model repos, dataset repos, Spaces and GitHub for anything that comes along with the weights: notebooks with outputs, logs, `.env` files, YAML configs and pickled training arguments. Beyond credentials, they collect internal hostnames, bucket names and file paths that map out your infrastructure.

### Insight

Model publishing is often a manual upload of a working directory. That directory was never designed to be public, and nobody reviews it like a code release.

### Practical

- Scan your organisation's public Hub repos and any employee repos that mention your company.
- Unpack a recently published model and read every non-weight file as an outsider would.
- Check your GitHub org for notebooks and READMEs that link to storage with embedded tokens.

### Tools/Techniques

- `trufflehog huggingface --org <your-org> --include-discussions --include-prs`
- `trufflehog github --org <your-org>` for the same check on GitHub.
- [gitleaks](https://github.com/gitleaks/gitleaks) for repository history.

### Metrics/Signal

- Verified secrets found in public model, dataset or Space repos. Target zero.
- Public repos containing notebooks with outputs, or `logs/` directories.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Look at how models get published and which credentials training jobs hold. A training job with a long-lived, broad credential in its environment can leak it through any log line, notebook output or crash dump.

### Insight

Debug output is the usual culprit. A single `print(os.environ)` or verbose HTTP logging in a training loop is enough.

### Practical

- List what your publishing step uploads. Is it an explicit allow-list of files, or the whole output directory?
- Check how training jobs authenticate to storage and the Hub: long-lived keys and tokens, or short-lived credentials?
- Review SAS tokens, presigned URLs and Hub tokens in use: scope, permissions and expiry.

### Tools/Techniques

- [Checkov](https://github.com/bridgecrewio/checkov) to find over-permissive IAM and storage policies in Terraform.
- The Hub token settings page, to see which tokens are classic read/write and which are fine-grained.

### Metrics/Signal

- Publishing jobs that upload whole directories.
- Long-lived storage tokens or classic Hub write tokens in use.
:::

::: {! stage fortify}
## Fortify

### Explanation

Publish only an explicit list of files, keep credentials out of training environments where possible, and scan every artefact before upload.

### Insight

The safest secret is one the training job never sees. Short-lived, narrowly scoped credentials turn a leak from a breach into a non-event.

### Practical

1. **Publish from an allow-list.**

    ```python
    from huggingface_hub import HfApi

    HfApi().upload_folder(
        repo_id="example-org/sentiment-model",
        folder_path="output/",
        allow_patterns=["*.safetensors", "config.json", "tokenizer*", "README.md"],
    )
    ```

2. **Scan the folder before upload** and fail on findings: `trufflehog filesystem output/ --results=verified,unknown --fail`.
3. **Use Hugging Face Trusted Publishers** so CI exchanges an OIDC token for a one-hour, repo-scoped Hub token. No `HF_TOKEN` secret to leak.
4. **Use fine-grained Hub tokens** for anything else, scoped to the specific repos needed.
5. **Use short-lived storage access**: cloud workload identity or OIDC for jobs, and user-delegation SAS or presigned URLs scoped to one container or prefix, read-only, expiring in hours.
6. **Strip notebook outputs** before commit or upload.

### Tools/Techniques

- [Hugging Face Trusted Publishers](https://huggingface.co/docs/hub/trusted-publishers) and [fine-grained tokens](https://huggingface.co/docs/hub/security-tokens).
- [nbstripout](https://github.com/kynan/nbstripout) as a pre-commit hook.
- [pre-commit](https://pre-commit.com/) with gitleaks or TruffleHog hooks.
- [GitHub push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection) to block known token formats at push time.

### Metrics/Signal

- Percentage of model publishes that go through the allow-listed, scanned pipeline.
- Number of long-lived Hub or storage tokens remaining.
:::

::: {! stage limit}
## Limit

### Explanation

Assume a credential has leaked. What it can reach decides whether you have an incident or an awkward afternoon.

### Insight

The Microsoft case was severe because one token covered a whole storage account with full control and a far-off expiry. Scope and lifetime are the levers.

### Practical

- Keep training data, checkpoints and backups in separate buckets or storage accounts with separate credentials.
- Give each training job read-only access to its data prefix and write access only to its output prefix.
- Separate the identity that publishes public models from the one that reads private data.
- Protect important public model repos so pushes to `main` need review, and have consumers pin to a commit SHA.

### Tools/Techniques

- AWS IAM, Azure RBAC or Google Cloud IAM with prefix-scoped policies.
- [GitHub OIDC with cloud providers](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect) for job credentials.

### Metrics/Signal

- Credentials with access to more than one bucket or storage account.
- Maximum lifetime of any storage token in use.
:::

::: {! stage expose}
## Expose

### Explanation

Detect leaks quickly, and detect use of leaked credentials.

### Practical

- Act on Hugging Face secret-scanning emails at once. The Hub runs TruffleHog on every push and emails you about verified secrets.
- Revoke leaked Hub tokens straight away. Hugging Face provides an endpoint to revoke any leaked token, even one you don't own.
- Enable storage access logs and cloud audit logs. Alert on reads from unfamiliar IPs, bulk listing, and use of storage tokens outside expected job windows.
- Plant canary credentials in places a leak would come from, such as a decoy `.env` in your training output template.

### Insight

Canary credentials give a clean signal. Nobody should ever use them, so any use means someone found your artefacts.

### Tools/Techniques

- [Hugging Face secrets scanning](https://huggingface.co/docs/hub/security-secrets).
- AWS CloudTrail and [GuardDuty IAM findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html), Azure Storage logs, or Google Cloud audit logs.
- [Canarytokens](https://canarytokens.org/) AWS key and Azure tokens.

### Metrics/Signal

- Time from secret-scanning alert to revocation.
- Canary credential use.
:::

::: {! stage exercise}
## Exercise

### Explanation

Test the publishing pipeline and your response with a fake secret.

### Practical

1. Put a Canarytokens AWS key in a notebook output in a private test model directory.
2. Run your normal publishing step against a private repo. Did the allow-list exclude the notebook? Did the pre-upload scan fail the job?
3. Trigger the canary yourself and time how long it takes the right person to hear about it.
4. Walk through revoking a Hub token and rotating a storage credential, and check the on-call engineer has the permissions to do both.

### Insight

The revocation walkthrough often shows that the person on call can't rotate the credential without help. Better to find out on a quiet Tuesday.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org/) for fake credentials.
- [Stratus Red Team](https://github.com/DataDog/stratus-red-team) to simulate credential misuse in a test cloud account and confirm your alerts fire.

### Metrics/Signal

- Whether the fake secret was blocked before upload.
- Time from canary trigger to alert, and from alert to rotation.
:::

## Further Reading

- [Wiz: 38TB of data accidentally exposed by Microsoft AI researchers](https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers)
- [Lasso Security: 1,500+ Hugging Face API tokens exposed](https://www.lasso.security/blog/1500-huggingface-api-tokens-were-exposed-leaving-millions-of-meta-llama-bloom-and-pythia-users-for-supply-chain-attacks)
- [Hugging Face: User access tokens](https://huggingface.co/docs/hub/security-tokens)
- Related: [Exposed Secrets in Code and Config](#battlecards-exposed-secrets-in-code-and-config-md)
