---
title: Fake Remote Developers and Insider Access
category: Social Engineering
scenario: A contractor hired under a stolen identity gets commit, CI and cloud access
focus:
  - staged, least-privilege access for new joiners
  - review rules so one person cannot ship alone
  - device and login signals of a proxy worker
  - offboarding that revokes every credential
---

## Scenario

A platform team is short-handed and hires a remote contractor through an agency. The CV is strong, the video interviews go well and the background check passes. The identity is real. It just belongs to someone else.

On day one the contractor joins the GitHub organisation through the same group as everyone else. That group can read every private repository and push to most of them. They get the shared CI admin role "to unblock themselves" and a cloud role with broad read access. The company laptop is shipped to an address that turns out to be a house full of laptops, each one driven remotely from abroad.

Over the next few months:

1. The contractor clones every repository they can reach and copies them to a personal account.
2. They add a personal access token and an SSH key that nobody tracks against their identity.
3. They merge small changes on their own, because the repository allows admins to bypass review.
4. When the company finally grows suspicious and ends the contract, the accounts are disabled in the identity provider. The SSH key, a CI deploy token and a long-lived cloud access key still work.
5. A week later an email arrives demanding payment, or the source code will be published.

**Real-world precedent:** On 30 June 2025 the US Department of Justice announced coordinated actions against North Korean remote IT worker schemes, including searches of 29 suspected laptop farms in 16 states; the workers had obtained jobs at more than 100 US companies, used stolen identities and in some cases stole source code ([US DOJ](https://www.justice.gov/opa/pr/justice-department-announces-coordinated-nationwide-actions-combat-north-korean-remote)). In July 2024 KnowBe4 disclosed that a new software engineer, hired using a stolen identity, began loading malware onto his company laptop as soon as it arrived ([KnowBe4](https://blog.knowbe4.com/how-a-north-korean-fake-it-worker-tried-to-infiltrate-us)). In January 2025 the FBI warned that such workers were copying company repositories to personal accounts and extorting employers after discovery ([FBI IC3](https://www.ic3.gov/PSA/2025/PSA250123)), and in April 2025 Google's Threat Intelligence Group reported rising extortion by recently fired workers ([Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/dprk-it-workers-expanding-scope-scale)).

::: {! stage recon}
## Reconnaissance

### Explanation

These operators study job adverts the way other attackers study Dockerfiles. Remote-only roles, contract work through agencies, and teams that hire fast are all attractive. Public job descriptions often list the exact stack, the CI system and the cloud provider, so the CV can match perfectly.

They also learn what access a new joiner gets. Engineering handbooks, onboarding docs in public repositories and conference talks about "commit on day one" culture all help.

### Insight

The attacker is reading your hiring process as an access path. From their side, the interview is the first stage of the intrusion.

### Practical

- Read your own public job adverts and onboarding docs as an attacker would. Note what they reveal about tooling and access.
- Find out how contractors reach you: direct, agencies, marketplaces. Each has different identity checks.
- Ask HR and security who verifies identity, when, and how. Engineering managers are often the last to know.

### Tools/Techniques

- A search of your public repositories for onboarding guides, `CONTRIBUTING` notes and internal handbook pages.
- The FBI's January 2025 public service announcement lists hiring and onboarding indicators to compare against your process.

### Metrics/Signal

- Number of hiring routes that bypass in-person or document-checked identity verification.
- Public documents that describe day-one access in detail.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Work out what a new joiner can reach on day one, and what one person can change without anyone else seeing. That is your exposure, whoever the new joiner turns out to be. Then check how quickly access is actually removed when someone leaves.

### Insight

Most organisations grant access by group, and the default engineering group grows over years. Nobody designed it to be the starting point for a stranger.

### Practical

- List the groups and roles a new engineer or contractor gets by default: source control, CI, artefact registry, cloud, secrets manager, chat, ticketing.
- Find repositories where admins or bots can bypass review, and branches with no protection.
- Check which credentials live outside your identity provider: personal access tokens, SSH keys, cloud access keys, CI tokens, registry tokens. These survive account disablement.
- Review the last few leavers. Did every credential stop working on their last day?

### Tools/Techniques

- `gh api orgs/<org>/members` and `gh api orgs/<org>/outside_collaborators` to list who has access.
- The organisation's fine-grained token settings page, or the `orgs/<org>/personal-access-tokens` REST endpoint called from a GitHub App, to list tokens with access.
- `gh api orgs/<org>/credential-authorizations` on GitHub Enterprise Cloud with SAML SSO, to list each member's authorised tokens and SSH keys.
- Cloud IAM analysis: AWS IAM Access Analyzer, GCP Policy Analyzer, Azure access reviews.

### Metrics/Signal

- Number of private repositories, secrets and cloud accounts reachable by a day-one account.
- Repositories where a single person can merge to the default branch.
- Credentials still valid after an account was disabled.
:::

::: {! stage fortify}
## Fortify

### Explanation

Give new joiners staged access that grows with need and time. Require a second person for every change that ships. Tie every credential to a managed device and the identity provider, so you can see it and kill it.

### Insight

You will not always spot a fake candidate. You can make sure a fake hire's first month looks like anyone else's first month: small, reviewed and visible.

### Practical

- Create a starter group with access to the team's own repositories only, read-only to the rest. Grant wider access by request, with an expiry.
- Use repository rulesets on default and release branches: require pull requests, at least one approval, review from code owners, and approval of the most recent push. Allow no bypass for individuals.
- Protect CI and deployment config with CODEOWNERS entries owned by a senior group.
- Require SSO for the organisation, and require approval for fine-grained personal access tokens. Restrict or block classic tokens.
- Issue SSH certificates from your organisation's certificate authority with short lifetimes, in place of user-uploaded SSH keys.
- Use short-lived cloud credentials through SSO or OIDC. No long-lived access keys for people.
- Give contractors managed devices with endpoint protection, and block access from unmanaged devices.
- Work with HR on identity checks: verify documents, hold at least one live meeting with camera on through onboarding, and treat late changes to shipping address or bank details as a flag.

### Tools/Techniques

- [GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets) and CODEOWNERS.
- [GitHub personal access token policies](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization) and SSH certificate authorities.
- Identity provider device-trust and conditional access policies (Okta, Microsoft Entra ID, Google Workspace).
- See [Branch Protection and CODEOWNER Gaps](#battlecards-branch-protection-and-codeowner-gaps-md).

### Metrics/Signal

- Percentage of repositories with no single-person merge path.
- Percentage of credentials that are short-lived and tied to SSO.
- Median days before a new joiner gets access beyond their team.
:::

::: {! stage limit}
## Limit

### Explanation

Assume someone already inside is not who they claim. Limit what they can copy, what they can ship alone and what they keep after you remove them. Plan offboarding as an incident response, because in this scenario it is one.

### Insight

Extortion follows termination. Before you end the contract, make sure removing the person also removes every key they hold.

### Practical

- Keep secrets out of repositories so a full clone does not hand over production access.
- Separate deployment credentials from engineering roles. Deploy only from CI, with environment approvals.
- Write an offboarding runbook for engineering systems: identity provider, source control, tokens and SSH keys, CI, registries, cloud, secrets manager, chat and shared drives.
- When you suspect a fake hire, revoke everything at the same time, then rotate any secret they could read.
- Preserve logs and the device before wiping anything. You may need them for law enforcement.

### Tools/Techniques

- GitHub SAML credential revocation and organisation membership removal.
- Cloud and identity session revocation, such as "Revoke active sessions" on AWS IAM roles and "Revoke sessions" in Microsoft Entra ID.
- Secrets manager rotation for anything shared with the team.
- GitHub environments with required reviewers for production deploys.

### Metrics/Signal

- Time from decision to full revocation across all systems.
- Secrets rotated after each contractor exit where the contractor had read access.
:::

::: {! stage expose}
## Expose

### Explanation

Proxy workers leave behavioural traces. The device sits in one place while the logins come from another. Remote-control software appears on a company laptop. Repositories get cloned in bulk. None of these needs you to guess anyone's nationality, and you should not try.

### Insight

Watch behaviour. A real developer rarely clones forty repositories in an evening or runs remote desktop software on a laptop that was never meant to leave the house.

### Practical

- Alert on remote access tools on managed devices: AnyDesk, TeamViewer, Chrome Remote Desktop and similar.
- Flag mismatches between the device's location, the shipping address and login IP geography, and logins from many countries in a short period.
- Watch for bulk `git clone` or archive downloads, especially of repositories outside the person's team.
- Watch for new SSH keys, tokens or OAuth apps added soon after joining.
- Notice camera-off habits, delayed responses during working hours and reluctance to meet in person, but treat them as prompts for a check, never as proof.

### Tools/Techniques

- Endpoint detection and software inventory on managed devices.
- GitHub Enterprise audit log and log streaming for `git.clone`, `repo.download_zip` and token events.
- Identity provider sign-in logs with impossible-travel detection.
- The FBI IC3 indicators list as a starting set of detection rules.

### Metrics/Signal

- Remote access tool detections on engineering devices.
- Accounts with logins from more than one country in a day.
- Per-user clone volume against the team baseline.
:::

::: {! stage exercise}
## Exercise

### Explanation

Audit what a day-one contractor can reach, using a test account created through your normal onboarding path. Then offboard it and check what still works. Use canary tokens to see whether the account can reach places it should not.

### Insight

This is the exercise that changes minds. The list of what a stranger gets on day one is usually longer than anyone on the team expected.

### Practical

1. Ask IT and HR to onboard a test contractor account through the usual process, flagged so everyone knows it is a test.
2. Using only that account, list what it can reach: repositories, CI pipelines and secrets, registries, cloud accounts, secrets manager paths, shared drives.
3. Try to merge a harmless change to a protected branch without review. Record whether it succeeds.
4. Place a canary token, such as a fake AWS key from Thinkst Canarytokens, in a repository the account should not see. Check whether the account can read it.
5. Create a fine-grained token and an SSH key with the account. Offboard it through your runbook.
6. Check whether the token, the SSH key, any cloud session and any CI token still work afterwards.

### Tools/Techniques

- `gh repo list <org> --limit 1000`, `gh api user/repos`, cloud CLI role and permission listings.
- Thinkst Canarytokens.
- Your offboarding runbook, timed with a stopwatch.

### Metrics/Signal

- Count of systems a day-one account could reach, before and after changes.
- Whether a single person could merge without review.
- Credentials still working after offboarding, which should be zero.
:::

## Further Reading

- [US DOJ: coordinated nationwide actions against North Korean remote IT workers (June 2025)](https://www.justice.gov/opa/pr/justice-department-announces-coordinated-nationwide-actions-combat-north-korean-remote)
- [FBI IC3: North Korean IT Workers Conducting Data Extortion (January 2025)](https://www.ic3.gov/PSA/2025/PSA250123)
- [Google Threat Intelligence Group: DPRK IT Workers Expanding in Scope and Scale](https://cloud.google.com/blog/topics/threat-intelligence/dprk-it-workers-expanding-scope-scale)
- [KnowBe4: How a North Korean Fake IT Worker Tried to Infiltrate Us](https://blog.knowbe4.com/how-a-north-korean-fake-it-worker-tried-to-infiltrate-us)
- [GitHub: Viewing and managing a member's SAML access](https://docs.github.com/en/enterprise-cloud@latest/organizations/granting-access-to-your-organization-with-saml-single-sign-on/viewing-and-managing-a-members-saml-access-to-your-organization)
- Related cards: [Developer Review Fatigue and Social Engineering](#battlecards-developer-review-fatigue-and-social-engineering-md), [Phishing Developers](#battlecards-phishing-developers-md), [Branch Protection and CODEOWNER Gaps](#battlecards-branch-protection-and-codeowner-gaps-md)
