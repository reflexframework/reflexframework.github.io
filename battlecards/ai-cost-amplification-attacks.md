---
title: Leaked AI API Keys and Cost Amplification
category: AI/ML Security
scenario: Leaked LLM provider key used to run up a bill
focus:
  - API keys committed to code and config
  - spend limits versus budget alerts
  - per-project keys and revocation
---

## Scenario

A developer prototypes a support chatbot against a commercial LLM API. To save time, they paste the provider key into a `.env.example` file and push the branch to a public repository. It is a demo repo, so nobody thinks to check it.

1. Automated scanners watch public GitHub events, npm tarballs and Docker Hub layers for strings that look like provider keys (`sk-proj-...` for OpenAI project keys, `sk-ant-...` for Anthropic).
2. A scanner finds the key within minutes and tests it with a cheap call such as listing models.
3. The key belongs to the organisation's default project, which has no spend limit, so the attacker plugs it into a proxy that resells chat access. Others simply loop long prompts through the most expensive model available.
4. The team finds out from a billing email two days later. By then the organisation has also hit its rate limits, so the real chatbot is failing for customers.

The attacker never touches your servers. They spend your money and your quota.

**Real-world precedent:** The trade in stolen AI keys is well documented. Sysdig's [LLMjacking research (May 2024)](https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack) found tooling that checked stolen keys against OpenAI, Anthropic, Mistral and other providers before reselling access through a reverse proxy. In [Microsoft's case against Storm-2139](https://blogs.microsoft.com/on-the-issues/2025/02/27/disrupting-cybercrime-abusing-gen-ai/) (filed December 2024, defendants named February 2025), customer Azure OpenAI keys scraped from public sources were used and resold to generate harmful content. For stolen cloud credentials rather than provider keys, see [LLMjacking with Stolen Cloud Credentials](#battlecards-llmjacking-stolen-cloud-credentials-md).

::: {! stage recon}
## Reconnaissance

### Explanation
Nobody targets you by name. Bots scrape every public commit, gist, package tarball and container layer for provider key patterns. AI keys are attractive because they turn straight into resaleable compute, with no infrastructure to compromise first.

### Insight
Keys leak from more places than source files. Common sources are `.env` files baked into Docker images, notebooks with output cells, frontend bundles that call the provider directly, CI logs, and support tickets with pasted `curl` commands. A key in a browser bundle is public the moment you deploy.

### Practical
Look at your organisation the way the scanners do:

- Search your public repos and forks for provider prefixes and for the variable names you use (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
- Scan the full git history, since deleting the file in a later commit does not remove the key.
- Check frontend builds for calls straight to provider endpoints such as `api.openai.com`.
- Scan published container images layer by layer.

```bash
# Full-history scan of a repo, verified findings only
trufflehog git https://github.com/your-org/chatbot-demo --results=verified

# Scan a container image you publish
trufflehog docker --image your-org/chatbot:latest --results=verified
```

### Tools/Techniques
- [TruffleHog](https://github.com/trufflesecurity/trufflehog): scans git history, images and filesystems, and can verify whether a key is live.
- [Gitleaks](https://github.com/gitleaks/gitleaks): fast pattern scanning, with built-in OpenAI and Anthropic rules.
- [GitHub secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning): free alerts for public repos; private repos need GitHub Secret Protection.

### Metrics/Signal
- Count of live provider keys found in public repos, images or bundles. The target is zero.
- Number of places a given key is stored. More than one (vault plus a developer laptop plus CI) means more ways to leak it.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Work out how much damage one leaked key could do. That depends on the key's scope, the spend controls behind it, and how fast you would notice.

### Insight
Most providers distinguish alerts from limits, and many teams only set alerts. An alert tells you about the damage. A limit stops it. Also check which account a key bills to: a key in the organisation's default project usually shares limits with production.

### Practical
For each provider you use, answer these questions:

- Is each application using its own project or workspace key, or one shared organisation key?
- Is there an enforced spend limit on that project? On OpenAI, a project spend limit only stops traffic when **Enforce a hard limit** is switched on; otherwise it just alerts. Anthropic Console workspaces support their own monthly spend limits below the organisation limit (the default workspace cannot have one).
- Which models can the key call? If the chatbot only needs a small model, the key should not reach the most expensive one.
- Do you pay with prepaid credits or post-paid billing? With prepaid credits, the worst case is the credit balance.
- Who gets the provider's leaked-key email, and is that mailbox read?

### Tools/Techniques
- OpenAI [spend limits guide](https://developers.openai.com/api/docs/guides/spend-limits): organisation and project hard limits, and the error codes each one returns.
- Anthropic Console workspaces: per-workspace spend and rate limits.
- Cloud budgets for Azure OpenAI, Vertex AI and Bedrock. These alert by default; they do not cap spend on their own (see Limit).

### Metrics/Signal
- Percentage of production keys scoped to a single project or workspace with an enforced spend limit.
- Worst-case spend per key per day, calculated from its rate limit and the most expensive model it can call.
:::

::: {! stage fortify}
## Fortify

### Explanation
Keep keys out of places that get published, and use the platform controls that catch the mistakes that slip through.

### Insight
The provider key should live in one place: a server-side secret store. Clients call your backend, which calls the provider. Developers get their own low-limit keys in a separate project, so a leaked laptop key cannot touch production quota.

### Practical
- **Never ship provider keys to the client.** Put a thin backend or gateway in front of the provider and authenticate your own users there.
- **Turn on push protection.** It is on by default for public repos and blocks pushes containing supported secrets. OpenAI and Anthropic API keys are both on GitHub's push-protected pattern list.
- **Add a pre-commit hook** so developers catch keys before they reach any remote:

    ```yaml
    # .pre-commit-config.yaml
    repos:
      - repo: https://github.com/gitleaks/gitleaks
        rev: v8.30.1
        hooks:
          - id: gitleaks
    ```

- **Ignore the right files.** Add `.env` and `*.env` to `.gitignore` and `.dockerignore`, and commit only a `.env.example` with placeholder values.
- **Load keys at runtime** from a secret manager (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault) instead of baking them into images.

### Tools/Techniques
- [GitHub push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection).
- [pre-commit](https://pre-commit.com/) with the Gitleaks hook.
- An LLM gateway (for example [LiteLLM proxy](https://docs.litellm.ai/docs/simple_proxy)) to hold provider keys centrally and issue your own per-team virtual keys with budgets.

### Metrics/Signal
- Push protection blocks per month, and how many were bypassed.
- Number of provider keys held outside the secret manager.
:::

::: {! stage limit}
## Limit

### Explanation
Assume a key will leak. Decide in advance how much it is allowed to cost and what it is allowed to reach.

### Insight
A hard spend limit turns an open-ended bill into a known, bounded loss. Hard limits are not exact: enforcement takes a little time to propagate, so recorded spend can slightly overshoot. They are still far better than an alert you read on Monday.

### Practical
- **One project per app per environment.** Give each its own key, its own enforced spend limit and its own model allow-list. A leaked staging key then cannot spend production's budget.
- **Set the limit near real usage.** If the chatbot spends 40 a day, a monthly hard limit of 5,000 is a ceiling, but a weak one.
- **Restrict models per project** where the provider allows it, so a cheap-model app cannot call the flagship model.
- **Understand cloud budgets.** AWS Budgets, Azure Cost Management budgets and Google Cloud budgets send alerts; they do not stop spend by themselves. AWS Budgets actions can apply an IAM policy or SCP when a threshold is crossed, and Google documents a pattern for disabling billing from a Pub/Sub budget notification. Both need to be configured and tested.
- **Use prepaid credits** for experimental projects so the worst case is the balance.

### Tools/Techniques
- OpenAI project hard spend limits and model restrictions.
- Anthropic workspace spend limits and rate limits.
- [AWS Budgets actions](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-controls.html).
- [Google Cloud budgets](https://cloud.google.com/billing/docs/how-to/budgets) with programmatic notifications.

### Metrics/Signal
- Maximum possible spend if any single key leaks today.
- Number of projects with no enforced limit.
:::

::: {! stage expose}
## Expose

### Explanation
Detect abuse within minutes: the leak notification, the spike in token use, or calls from somewhere your app never runs.

### Insight
The first signal is often an email. GitHub's [secret scanning partner programme](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program) forwards keys found in public repos to the provider. [Anthropic](https://github.blog/changelog/2024-08-20-anthropic-is-now-a-github-secret-scanning-partner/) and OpenAI are both partners and revoke exposed keys automatically, then email the owner. That only covers public GitHub, though. Keys in a public Docker image or a frontend bundle need your own detection.

### Practical
- Route provider security emails to a shared, monitored channel, not one person's inbox.
- Pull usage per project from the provider's usage API every hour and alert on sudden jumps in tokens or cost.
- Alert on calls to models your app does not use, and on traffic at hours your app is quiet.
- Log the request counts and token totals your own backend sends. If the provider's numbers are much higher than yours, someone else is using the key.

### Tools/Techniques
- Provider usage and cost APIs (OpenAI usage API, Anthropic usage and cost Admin API).
- Gateway logs if you run an LLM proxy.
- Secret scanning alerts and validity checks in GitHub.

### Metrics/Signal
- Ratio of provider-reported tokens to backend-logged tokens per project. Anything well above 1 is a strong signal.
- Time from first unusual usage to key revocation.
:::

::: {! stage exercise}
## Exercise

### Explanation
Practise the leak-and-revoke drill before you need it, without exposing a real key.

### Insight
The steps are simple. Teams lose hours finding who owns the key, where else it is used, and how to rotate it without taking the app down.

### Practical
1. Create a throwaway project with a 1-unit hard limit and a key for it. Push the key to a **private** test repo with push protection enabled and confirm the push is blocked. Then delete the key.
2. Plant a canary token (for example an AWS key from [Canarytokens](https://canarytokens.org/)) in a test `.env` file and confirm the alert reaches your team channel when it is used.
3. Run a rotation drill on staging: issue a new key, deploy it from the secret manager, revoke the old key, and time it.
4. Trip the staging project's hard limit on purpose and check that the app fails gracefully and that someone gets paged.

### Tools/Techniques
- [Canarytokens](https://canarytokens.org/) for safe decoy credentials.
- Your secret manager's rotation features.

### Metrics/Signal
- Time to rotate a provider key in production without downtime.
- Whether the app degrades cleanly when a hard limit trips.
:::

## Further Reading

- [OpenAI: Spend limits](https://developers.openai.com/api/docs/guides/spend-limits)
- [Anthropic: API key best practices](https://support.claude.com/en/articles/9767949-api-key-best-practices-keeping-your-keys-safe-and-secure)
- [GitHub: About push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)
- [Sysdig: LLMjacking, stolen cloud credentials used in new AI attack](https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack)
- [OWASP Top 10 for LLM Applications 2025: LLM10 Unbounded Consumption](https://genai.owasp.org/llm-top-10/)
