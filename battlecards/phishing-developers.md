---
title: Phishing Developers
category: Social Engineering
ref: RFX-SOC-03
precedent: "2025"
scenario: Fake security alert tricks a developer into authorising a malicious OAuth app
focus:
  - malicious OAuth app consent
  - look-alike registry and support domains
  - real-time phishing of 2FA codes
  - stolen sessions acting as the developer
---

## Scenario

Alex maintains a popular open-source project your company depends on. One morning a new issue appears in the repository, titled "Security Alert: Access Attempt". It says someone signed in to Alex's GitHub account from Reykjavik, and gives a link to "review activity and secure your account".

The link goes to a real `github.com` page: an OAuth consent screen for an app called "Security App". It asks for access to repositories, workflows and organisation data. Alex is worried and in a hurry, so clicks **Authorize**.

No password was typed and 2FA never came into play. The attacker now holds an OAuth token with Alex's permissions. They clone private repositories, read Actions secrets through new workflows, and edit files through the API.

Those API edits appear in history as commits signed by GitHub and marked "Verified". Commit signing proves which account made a change. It cannot tell you the account was being driven by someone else.

::: {! precedent}
**Real-world precedent:** In March 2025 a fake "Security Alert" issue campaign hit thousands of GitHub repositories and pushed maintainers to authorise a malicious OAuth app called `gitsecurityapp` ([Help Net Security](https://www.helpnetsecurity.com/2025/03/17/github-project-maintainers-targeted-with-fake-security-alert/)). The same year, look-alike domains phished registry maintainers: `pypj.org` against PyPI in July ([PyPI](https://blog.pypi.org/posts/2025-07-31-incident-report-phishing-attack/)) and `npmjs.help` against npm in September ([Aikido](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)).
:::

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers build target lists from public data: commit emails, package metadata, maintainer lists and repository activity. They then send lures through channels developers trust, such as GitHub issues and notifications, or emails that look like registry support.

### Insight
Your developers' public footprint is the attacker's mailing list. The 2025 PyPI campaign likely emailed addresses taken straight from package metadata.

### Practical
- Check which email addresses your maintainers expose in package metadata and commits.
- Use GitHub's `noreply` commit email for public work.
- List the look-alike domains for the services your team relies on: GitHub, npm, PyPI, your CI and your cloud.

```bash
# Emails exposed in recent commit history
git log --format='%ae' | sort | uniq -c | sort -rn | head
```

### Tools/Techniques
- [dnstwist](https://github.com/elceef/dnstwist) to generate and check look-alike domains.
- [GitHub email privacy settings](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address).

### Metrics/Signal
- Maintainers using a `noreply` commit address.
- Registered look-alike domains for your key services.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Find out what a phished developer could hand over: OAuth grants, tokens, sessions and publish rights.

### Insight
OAuth consent phishing skips passwords and 2FA entirely. A developer with broad, long-lived grants to many third-party apps is a big target, even with perfect 2FA.

### Practical
- Review the OAuth apps and GitHub Apps your developers have authorised, and the scopes they hold.
- Check whether your organisation restricts third-party OAuth app access.
- Inventory classic PATs with `repo` or `admin:org` scope.

### Tools/Techniques
- [Reviewing authorised OAuth apps](https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/reviewing-your-authorized-oauth-apps).
- Organisation settings: **Third-party application access policy**.

### Metrics/Signal
- Authorised third-party OAuth apps per developer.
- Classic PATs with broad scopes (target: zero).
:::

::: {! stage fortify}
## Fortify

### Explanation
Make the lures fail. Use 2FA that cannot be relayed, and stop unknown OAuth apps reaching your organisation.

### Insight
Passkeys and security keys are bound to the real domain, so a proxy on `npmjs.help` or `pypj.org` gets nothing usable. OAuth consent phishing needs a separate control: app access restrictions.

### Practical
- Turn on OAuth app access restrictions for your GitHub organisation, so apps need owner approval.
- Use passkeys or security keys for GitHub, npm and PyPI.
- Publish packages through trusted publishing, so a phished maintainer has no long-lived token to give away.
- Agree a simple rule: security alerts are checked by going to the site directly, never through a link in an issue or email.

### Tools/Techniques
- [GitHub: restricting OAuth app access](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions).
- [GitHub passkeys](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys).
- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) and [PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/).

### Metrics/Signal
- Organisations with OAuth app restrictions enabled.
- Developers with phishing-resistant 2FA.
:::

::: {! stage limit}
## Limit

### Explanation
If a token or session is stolen, limit what it can change.

### Insight
Branch rulesets apply to the attacker's token just as they apply to Alex. A stolen token that cannot push to `main` or approve its own pull request has to get past another human.

### Practical
- Use rulesets that require pull request review and passing checks on default and release branches.
- Require SAML SSO authorisation for tokens, so a stolen grant is not automatically valid in your organisation.
- Prefer fine-grained PATs with expiry, scoped to specific repositories.
- Turn on secret scanning push protection so stolen code access does not also reveal committed secrets.

### Tools/Techniques
- [GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).
- [Fine-grained personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).
- [Push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection).

### Metrics/Signal
- Default branches protected by rulesets.
- Tokens with no expiry date.
:::

::: {! stage expose}
## Expose

### Explanation
Spot the campaign and the misuse quickly.

### Insight
These campaigns are noisy. Many repositories get the same "security alert" issue at once, and the stolen token is then used from new IP addresses and for unusual API calls.

### Practical
- Watch for new issues or notifications that contain OAuth authorisation links, and report them to GitHub.
- Review the audit log for new OAuth authorisations, new workflows and repository clones that do not match normal behaviour.
- Do not treat "Verified" as proof that a commit was intended. Check who made the change and from where.

```bash
# Recent events by a specific user in the org audit log (GitHub Enterprise Cloud)
gh api "orgs/<org>/audit-log?phrase=actor:<user>" \
  -q '.[] | "\(.created_at) \(.action) \(.repo // "")"' | head -50
```

### Tools/Techniques
- [GitHub organisation audit log](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization).
- [Reviewing security logs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log) for individual accounts.

### Metrics/Signal
- Time from a suspicious OAuth grant to revocation.
- Phishing issues reported by developers.
:::

::: {! stage exercise}
## Exercise

### Explanation
Practise recognising and reporting these lures, and revoking access fast.

### Insight
Developers who have seen a fake security alert before are far more likely to stop and report the next one.

### Practical
1. Show the team real examples from 2025: the fake GitHub issue, the `npmjs.help` email and the `pypj.org` email.
2. In a test organisation, register a harmless OAuth app you own and practise finding and revoking it from user and organisation settings.
3. Time how long it takes to revoke a developer's sessions, tokens and app grants, and to rotate the secrets their account could read.

### Tools/Techniques
- A test GitHub organisation and a benign OAuth app you control.
- [Canarytokens](https://canarytokens.org/) placed in test repositories to show what a stolen grant could reach.

### Metrics/Signal
- Minutes to revoke all of a developer's access.
- Lure reports received during and after the session.
:::

## Further Reading

- [Help Net Security: GitHub maintainers targeted with fake security alert](https://www.helpnetsecurity.com/2025/03/17/github-project-maintainers-targeted-with-fake-security-alert/)
- [PyPI: Incident report on the July 2025 phishing attack](https://blog.pypi.org/posts/2025-07-31-incident-report-phishing-attack/)
- [Aikido: npm debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [Maintainer Account Takeover](#battlecards-maintainer-account-takeover-md)
