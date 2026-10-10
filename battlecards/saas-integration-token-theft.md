---
title: Third-Party Integration Token Theft
category: Secrets & Credentials
scenario: A connected vendor is breached and its tokens are used against you
focus:
  - OAuth grants and GitHub Apps you have forgotten about
  - secrets sitting in tickets, CRM records and chat
  - scopes, IP restrictions and token lifetimes
  - a vendor-breach runbook to revoke and rotate
---

## Scenario

Two years ago, someone in sales connected a chat widget to the company's CRM. Someone in engineering authorised a deployment platform against the GitHub organisation. Both clicked "Allow" on a broad scope and moved on. Neither integration has been reviewed since.

The chat vendor is breached. The attacker does not need your passwords or your MFA:

1. They get into the vendor's source code host and spend weeks looking around.
2. From there they reach the vendor's cloud environment, where customers' OAuth access and refresh tokens are stored.
3. They call your CRM's API with your own integration's token. To your CRM, it looks like the integration doing its job.
4. They export support cases in bulk and search them for `AKIA`, `password` and internal login URLs.
5. A support engineer once pasted an AWS key into a ticket while debugging. The attacker uses it.

Your logs show a trusted app making API calls. That is exactly what the attacker wanted them to show.

**Real-world precedent:** Between March and June 2025, an attacker accessed Salesloft's GitHub account, then reached Drift's AWS environment and took OAuth tokens for customer integrations ([The Register](https://www.theregister.com/2025/09/08/drift_breach_entry_salesloft_github/)). From 8 to 18 August 2025, the group Google tracks as UNC6395 used those tokens to export data from customers' Salesforce instances and searched it for AWS keys, passwords and Snowflake tokens ([Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)). In April 2022, stolen OAuth user tokens issued to Heroku and Travis CI were used to download private repositories from dozens of GitHub organisations, including npm ([GitHub](https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/)).

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers go after the vendor because one vendor holds tokens for thousands of customers. A single breach of an integration platform is worth more than thousands of phishing attempts.

Once they hold the tokens, they map what each one can reach. They size the data first, then export what is useful. In the Drift case they ran `COUNT()` queries before pulling users, accounts, opportunities and cases.

### Insight

From the attacker's point of view, your connected apps list is a list of other companies' security teams you are relying on.

### Practical

- Think like the attacker: which vendors hold a token that can read your source code, your CRM, your ticketing system or your chat?
- Note which of those systems contain text that people type freely. Free text is where secrets end up.

### Tools/Techniques

- Your organisation's lists of authorised OAuth apps, installed GitHub Apps, Salesforce connected apps, Slack apps and Google Workspace third-party apps.
- Vendor breach notifications and status pages for each integration you rely on.

### Metrics/Signal

- Number of third-party integrations with read access to source code, CRM or ticket data.
- Integrations whose vendor you could not name a security contact for.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Build an inventory of every integration: who approved it, which scopes it holds, when it was last used and who owns it now. Then check what the data behind it contains. The Drift attacker went for secrets in support cases because people put them there.

### Insight

Tokens granted for a trial or a one-off migration often outlive the project, the vendor contract and the person who approved them.

### Practical

```bash
# GitHub Apps installed on an organisation (needs org admin rights)
gh api --paginate /orgs/YOUR-ORG/installations \
    --jq '.installations[] | [.app_slug, .repository_selection, (.permissions | tostring)] | @tsv'
```

- Review authorised OAuth apps in each GitHub organisation's settings, and the "Authorized OAuth Apps" list in your own account.
- In Salesforce, check the Connected Apps OAuth Usage page in Setup for apps, users and token use.
- Export a sample of tickets, CRM notes and chat history to a secure workstation and scan them for secrets.

```bash
# Scan an export of ticket text for verified secrets
trufflehog filesystem ./ticket-export --results=verified
```

### Tools/Techniques

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) or [Gitleaks](https://github.com/gitleaks/gitleaks) over exported text.
- The admin consoles for GitHub, Salesforce, Slack and Google Workspace.

### Metrics/Signal

- Integrations with no named owner, or unused for 90 days.
- Live secrets found in ticket, CRM or chat data.
:::

::: {! stage fortify}
## Fortify

### Explanation

Reduce what any one vendor token can do, and make tokens harder to use from anywhere but the vendor. Then stop secrets accumulating in systems those vendors can read.

### Insight

You cannot patch your vendor. You can decide how much of your data their token opens.

### Practical

- Turn on [OAuth app access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions) for each GitHub organisation, so an owner must approve every OAuth app.
- Prefer GitHub Apps over OAuth apps. Installation tokens expire after an hour and can be limited to selected repositories with fine-grained permissions.
- Use GitHub's [IP allow list](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/managing-allowed-ip-addresses-for-your-organization) where your plan supports it, and only allow integrations that publish their egress addresses.
- In Salesforce, restrict connected app scopes and avoid `full`, set IP Relaxation to "Enforce IP restrictions", set a refresh token expiry, and grant "API Enabled" through permission sets only to users who need it. Google's Drift guidance recommends these.
- Require admin approval for new apps in Slack and Google Workspace.
- Give support and sales teams a safe way to share secrets, such as a time-limited secret-sharing link, and a policy against pasting keys into tickets.

### Tools/Techniques

- GitHub organisation settings, Salesforce connected app policies, Slack app approval, Google Workspace API controls.
- Secret scanning on the tools themselves where the vendor offers it, or scheduled scans of exports.

### Metrics/Signal

- Percentage of integrations on least-privilege scopes.
- Integrations bound to an IP allow list or with expiring refresh tokens.
:::

::: {! stage limit}
## Limit

### Explanation

When a vendor tells you it has been breached, or when you read about it in the news, you need to revoke that vendor's tokens and rotate anything its data could have exposed. Fast. Prepare that runbook now.

### Insight

Revoking the integration stops the next export. It does nothing about the secrets already copied out of your tickets. Rotation is the half that people forget.

### Practical

Write a vendor-breach runbook with these steps:

1. Revoke the integration's tokens and suspend the app in every platform it touches.
2. Pull the platform's API and audit logs for the app's identity over the vendor's exposure window.
3. Treat every secret in the data that app could read as exposed. Rotate it, starting with cloud keys.
4. Reset passwords for users whose details were exported, and warn them about follow-up phishing.
5. Reconnect only after the vendor confirms new tokens, with narrower scopes than before.

- Keep the data behind each integration small. Delete old tickets and attachments you no longer need.
- Use short-lived cloud credentials so a key copied from a 2023 ticket is already dead.

### Tools/Techniques

- A per-integration page listing owner, scopes, admin console links and revocation steps.
- Cloud provider credential reports to find long-lived keys worth replacing.

### Metrics/Signal

- Time from vendor notification to token revocation.
- Time to rotate every secret found in the exposed data.
:::

::: {! stage expose}
## Expose

### Explanation

A stolen token looks like the real integration, so watch for behaviour the integration never shows. Bulk exports, new query patterns, unusual user agents and connections from unexpected networks are the signs.

### Insight

In 2022, GitHub first spotted the attack when a key taken from npm's private repositories was used against npm infrastructure. The Drift attacker deleted its Salesforce query jobs, but the event logs remained. Keep logs long enough to look back over a vendor's exposure window, which can be months.

### Practical

- Baseline each integration's normal API volume and alert on large jumps.
- Alert on API calls from an integration's identity outside the vendor's published IP ranges, and from Tor exit nodes.
- In GitHub, review the audit log and repository clone and download activity for app identities.
- In Salesforce, use event monitoring for bulk query and API events tied to connected apps.
- Put canary credentials in places only integrations can read, so harvesting triggers an alert.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org/) AWS API key tokens placed in a CRM record or ticket.
- GitHub audit log streaming, Salesforce Event Monitoring, Google Workspace audit logs.

### Metrics/Signal

- Alerts on unusual integration API volume or source address.
- Canary token triggers, which should always be zero.
:::

::: {! stage exercise}
## Exercise

### Explanation

Rehearse the vendor-breach runbook on a real but low-risk integration. Use canary tokens to check that you would notice harvesting. Never use real secrets.

### Insight

The first run usually shows that nobody knows who can revoke a given app, or that its tokens are shared with a second integration.

### Practical

1. Pick one integration and announce a drill: "this vendor has been breached as of 30 days ago".
2. Time how long it takes to find the owner, revoke its tokens and pull 30 days of logs.
3. List every secret its data could have exposed. Rotate any you find for real.
4. Place an AWS canary key in a test ticket. From a sandbox, use a test integration token to export tickets and run a secret scan, as an attacker would. Confirm the canary alerts once someone tries the key.
5. Reconnect the integration with narrower scopes and record what changed.

### Tools/Techniques

- Canarytokens, TruffleHog and a sandbox CRM or ticketing instance.
- The runbook itself, updated after each drill.

### Metrics/Signal

- Time to revoke and time to rotate, drill on drill.
- Integrations covered by a tested runbook.
:::

## Further Reading

- [Google Threat Intelligence: Widespread Data Theft Targets Salesforce Instances via Salesloft Drift](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)
- [The Register: Salesloft GitHub account was the entry point for the Drift breach](https://www.theregister.com/2025/09/08/drift_breach_entry_salesloft_github/)
- [GitHub: Attack campaign involving stolen OAuth user tokens issued to two third-party integrators](https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/)
- [GitHub Docs: About OAuth app access restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)
- Related cards: [Phishing Developers](#battlecards-phishing-developers-md), [Exposed Secrets in Code and Config](#battlecards-exposed-secrets-in-code-and-config-md), [Hosted CI Secret Theft (CircleCI, Travis CI)](#battlecards-circleci-and-travis-token-theft-md)
