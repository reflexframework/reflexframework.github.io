---
title: Browser Extension Publisher Takeover
category: Developer Environment
ref: RFX-DEV-02
precedent: "2024"
scenario: Phished store access pushes a cookie-stealing extension update
focus:
  - OAuth consent phishing of extension publishers
  - silent auto-updates to trusted extensions
  - session cookie theft for developer platforms
  - extension allowlists and host restrictions
---

## Scenario

A platform team publishes a small Chrome extension. It adds build status badges to GitHub pull requests and links to the right cloud console for each service. Four hundred engineers use it. It has broad host permissions, because it needs to read GitHub pages and talk to the cloud consoles.

On Christmas Eve, the maintainer gets an email that looks like it comes from the Chrome Web Store. It says the extension breaks policy and will be removed unless they review the policy today. The link opens a real Google sign-in and consent screen. An app called "Privacy Policy Extension" asks to see, edit, update and publish their Chrome Web Store items. They click Allow.

The attacker never needed the password or the second factor. The OAuth grant lets them upload a new version through the Chrome Web Store API. It keeps every feature and adds a script that collects session cookies for GitHub, the AWS and Google Cloud consoles and the team's AI coding services, then posts them to a look-alike domain.

Chrome updates extensions in the background. The new version asks for no new permissions, so nobody sees a prompt. Within hours, the attacker holds live sessions for engineers who have already passed SSO and MFA.

There is a quieter version of the same story. A popular extension your developers installed years ago is sold to a new owner. Months later, an update turns it into a data collector.

::: {! precedent}
**Real-world precedent:** On 24 December 2024 a phishing email led a Cyberhaven employee to authorise a malicious OAuth app called "Privacy Policy Extension". The attacker published version 24.10.4 of Cyberhaven's Chrome extension, which stole cookies and access tokens, mainly for Facebook Ads accounts. The employee had MFA and Google Advanced Protection enabled ([Obsidian Security](https://www.obsidiansecurity.com/blog/behind-the-breach-malicious-attack-on-cyberhavens-chrome-extension-developer-team)). Researchers linked at least 35 other extensions to the same campaign ([Hunters](https://hunters.security/en/blog/chrome-extension-threat-campaign)). In February 2026 the QuickLens extension turned malicious just over two weeks after changing owner, stripping security headers and pulling remote JavaScript ([The Hacker News](https://thehackernews.com/2026/03/chrome-extension-turns-malicious-after.html)).
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers want extensions with a lot of users and broad permissions. Store listings tell them both. The listing also shows the publisher's contact email, which becomes the phishing target. Small companies and solo maintainers are the easiest marks: one person, one account, no review before release.

For buyers, the Chrome Web Store is a marketplace. Attackers approach maintainers of popular extensions and offer to buy them. A sale changes the owner but not the extension ID, so every existing install carries on updating from the new owner.

### Insight

From the attacker's side, a trusted extension is a pre-installed agent on thousands of browsers, already signed into everything. They only need to take over one publisher account to reach all of them.

### Practical

If you publish extensions:

- Check what your store listing exposes: contact email, developer name, website.
- List every person and Google account that can publish each extension.

If your developers use extensions:

- Collect an inventory of installed extensions, their IDs, versions and permissions.
- Flag extensions with access to all sites, or to your source control, cloud console and AI service domains.

### Tools/Techniques

- Chrome Enterprise Core (Chrome Browser Cloud Management) reports on installed extensions across managed browsers.
- The Chrome Web Store listing and the extension's `manifest.json` (`permissions`, `host_permissions`) for each extension in use.

### Metrics/Signal

- Number of distinct extensions installed across developer machines.
- Number with host access to `github.com`, cloud consoles or `<all_urls>`.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For publishers, ask how many independent things an attacker must compromise to ship an update. If the answer is "one Google account, or one OAuth grant on it", the extension is one email away from compromise.

For users, ask what an extension could do if it turned hostile tomorrow. An extension with host access to GitHub can read the page, act as the signed-in user and, with the `cookies` permission, read session cookies.

### Insight

MFA protects the login. It does not protect a grant the user approved after logging in. Cyberhaven's employee had the strongest Google account protection available and still lost control of publishing.

### Practical

Publishers:

- Check whether a single account can publish without anyone else seeing the release.
- Review third-party OAuth grants on publisher accounts at `myaccount.google.com/permissions`.
- Check whether Verified CRX Uploads is enabled for each extension.

Users:

- Rank extensions by permission and host access. Treat `cookies`, `webRequest`, `scripting` and broad host access to developer domains as high risk.
- Note who maintains each high-risk extension, and whether ownership has changed.

### Tools/Techniques

- Google Workspace Admin console, [app access control](https://support.google.com/a/answer/7281227), to see which third-party apps users have granted access to Google data.
- Extension risk scanners and manual review of `manifest.json`.

### Metrics/Signal

- Extensions publishable by a single account with no upload signing.
- High-risk extensions with access to developer platform domains.
:::

::: {! stage fortify}
## Fortify

### Explanation

Publishers should make a stolen session or OAuth grant useless on its own. The strongest control is [Verified CRX Uploads](https://developer.chrome.com/blog/verified-uploads-cws), introduced in 2025. Once you opt in, the Chrome Web Store rejects any upload not signed with your private key, so dashboard access or an API grant alone cannot publish.

Users should decide which extensions may run, and where.

### Insight

Separate "can log in to the store" from "can ship code". The Cyberhaven attacker had the first and got the second for free.

### Practical

Publishers:

- Opt in to Verified CRX Uploads and keep the signing key outside the extension repository, ideally in a release job or KMS.
- Publish from a [group publisher](https://developer.chrome.com/docs/webstore/group-publishers) account, with more than one owner, so access does not hang on one person.
- In Google Workspace, restrict third-party apps from requesting Chrome Web Store scopes unless you trust them.
- Build releases in CI from a tagged commit, and require a second person to approve before upload.

```bash
# Generate the upload signing key once, and store it securely
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out cws-upload-key.pem
openssl rsa -in cws-upload-key.pem -pubout -out cws-upload-key.pub
```

Users: block by default, allow by ID, and keep extensions away from your most sensitive sites.

```json
{
    "ExtensionSettings": {
        "*": {
            "installation_mode": "blocked",
            "blocked_install_message": "Ask the platform team to approve this extension.",
            "runtime_blocked_hosts": ["*://*.github.com", "*://console.aws.amazon.com"]
        },
        "aaaabbbbccccddddeeeeffffgggghhhh": {
            "installation_mode": "allowed"
        }
    }
}
```

The `*` entry blocks unapproved extensions and stops any extension, unless it has its own explicit settings, from touching the listed hosts. Replace the placeholder ID with a real extension ID.

### Tools/Techniques

- Chrome Web Store Verified CRX Uploads and group publishers.
- Chrome [ExtensionSettings](https://support.google.com/chrome/a/answer/9867568) policy (`installation_mode`, `blocked_permissions`, `runtime_blocked_hosts`), delivered through Chrome Enterprise Core, MDM or a policy file.
- Equivalent extension policies exist for Microsoft Edge and Firefox.

### Metrics/Signal

- Published extensions with Verified CRX Uploads enabled.
- Developer browsers running with a default-deny extension policy.
:::

::: {! stage limit}
## Limit

### Explanation

A hostile extension steals what the browser holds. Limit how long those sessions last and where they work.

### Insight

A stolen session cookie is only as good as the session behind it. Short sessions, device-bound tokens and IP or device conditions make it a much worse prize.

### Practical

- Keep extensions off the browser profile used for production consoles. A separate, extension-free profile for cloud admin work is cheap and effective.
- Shorten session lifetimes for cloud consoles and source control administration.
- Use conditional access so sessions only work from managed devices, or from expected networks, where your identity provider supports it.
- Use short-lived credentials for AI services and cloud CLIs, so a stolen browser session does not lead straight to long-lived API keys.
- Publishers: keep the extension's own permissions minimal, so a hijacked version gets less. Drop `<all_urls>` if you only need two domains.

### Tools/Techniques

- Separate Chrome profiles, enforced through browser policy where needed.
- Identity provider session controls and device trust (for example GitHub Enterprise IP allow lists, AWS IAM Identity Center session duration).

### Metrics/Signal

- Maximum session lifetime for each developer platform.
- Developers who access production consoles from a profile with extensions installed.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for extension changes, and for the same session being used from two places. Either can be the first sign.

### Insight

Cyberhaven caught the bad version within about a day because it watched its own extension. Most victims found out from a news story.

### Practical

Publishers:

- Alert on every new version published, and compare it with your release pipeline's records. An upload with no matching CI run is an incident.
- Watch publisher account activity and new OAuth grants on those accounts.

Users:

- Track extension versions across your fleet and alert when an extension changes owner, adds permissions or ships an update outside its usual pattern.
- In source control and cloud audit logs, alert when one session is used from a new IP or country, or when a user's session appears from an unmanaged device.
- Watch DNS or proxy logs for browser connections to newly registered domains.

### Tools/Techniques

- Chrome Web Store API or dashboard notifications for your items.
- Chrome Enterprise Core extension inventory and reporting.
- GitHub audit log, AWS CloudTrail and Google Cloud audit logs for session anomalies.

### Metrics/Signal

- Extension versions in your fleet that are not on your approved list.
- Published versions with no matching release pipeline run.
:::

::: {! stage exercise}
## Exercise

### Explanation

Rehearse both sides in a sandbox: a phishing-style OAuth grant against a test publisher account, and a policy test on a test browser profile. Use test accounts and a private test extension, never your real listing.

### Insight

The interesting failure is usually a policy nobody tested. Find out whether your allowlist really blocks an unapproved extension before an attacker does.

### Practical

1. In a test Google Workspace tenant, create a test OAuth app that requests the Chrome Web Store scope. Check whether your app access control blocks the consent.
2. With a test extension under a test publisher account with Verified CRX Uploads enabled, try to upload an unsigned package through the API. Confirm the store rejects it.
3. On a test machine, apply your `ExtensionSettings` policy. Try to install an extension not on the allowlist, and check `chrome://policy` and `chrome://extensions` for the result.
4. Load an unpacked test extension that tries to read a canary cookie on a test domain in your `runtime_blocked_hosts` list. Confirm it cannot.
5. Sign in to a test GitHub or cloud account, copy the session cookie into a second browser on another network, and check whether your alerting fires.

### Tools/Techniques

- A test Workspace tenant, test publisher account and private test extension.
- A canary cookie on a domain you control, and test accounts on developer platforms.

### Metrics/Signal

- Policy tests passed on the first attempt.
- Time from replayed session to alert.
:::

## Further Reading

- [Chrome for Developers: Verified uploads in the Chrome Web Store](https://developer.chrome.com/blog/verified-uploads-cws)
- [Chrome Enterprise: Configure ExtensionSettings policy](https://support.google.com/chrome/a/answer/9867568)
- [Obsidian Security: Behind the breach of Cyberhaven's Chrome extension](https://www.obsidiansecurity.com/blog/behind-the-breach-malicious-attack-on-cyberhavens-chrome-extension-developer-team)
- [Hunters: Chrome extension threat campaign](https://hunters.security/en/blog/chrome-extension-threat-campaign)
- Related cards: [Malicious IDE Extensions](#battlecards-malicious-ide-extensions-md), [Phishing Developers](#battlecards-phishing-developers-md), [Exposed Developer Consoles and Debug Endpoints](#battlecards-browser-based-dev-tool-exposure-md)
