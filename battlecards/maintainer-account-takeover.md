---
title: Maintainer Account Takeover
category: Package Ecosystems
scenario: Attacker publishes a trojanised release from a hijacked maintainer account
focus:
  - adversary-in-the-middle phishing of TOTP
  - reused passwords and expired email domains
  - long-lived publish tokens
  - provenance as a takeover signal
---

## Scenario

Chloe maintains `secure-data-sanitizer`, a popular npm library with thousands of dependants. She has 2FA on her npm account, using an authenticator app.

An email arrives from what looks like npm support, warning that her 2FA settings expire in 48 hours. The link opens a pixel-perfect npm login page on a look-alike domain. Behind it sits a reverse proxy. Chloe types her password and the six-digit code; the proxy relays both to the real npm within seconds and keeps the session.

The attacker has a short window. They publish `3.1.5` with a small obfuscated payload. Dependabot opens upgrade PRs across thousands of repositories. CI pipelines install the new version and run it.

Chloe's 2FA worked as designed. TOTP codes can be phished: a code typed into the wrong site is as good as one typed into the right one.

**Real-world precedent:** Maintainer takeovers are a recurring pattern: [eslint-scope](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/) (2018, reused password, no 2FA), [ua-parser-js](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js) (2021), ctx on PyPI (2022, password reset via an [expired email domain](https://blog.pypi.org/posts/2025-08-18-preventing-domain-resurrections/)), and [chalk and debug](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised) (September 2025, TOTP phished through `npmjs.help`). On 31 March 2026, `axios` 1.14.1 and 0.30.4 were published from the lead maintainer's account with an added dependency that installed a remote access trojan ([axios post-mortem](https://github.com/axios/axios/issues/10636)). A two-week social engineering campaign, with a cloned company, a real Slack workspace and a fake Teams "update", had put malware on his machine. 2FA was on. The versions were live for about three hours.

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers pick maintainers whose packages sit under many others. They then look for the weakest route into the account: a reused password, an email domain about to expire, a token in a public repo, or a person who will type a code into a phishing page.

### Insight
Everything they need is public: maintainer emails in package metadata, commit history and registry pages. That is why the 2025 npm and PyPI phishing waves could target maintainers so precisely.

### Practical
For your own packages, look at what an attacker sees:

```bash
# Who can publish, and with which email addresses?
npm view <your-package> maintainers

# Does your email domain expire soon?
whois example.dev | grep -i expir
```

- Check that every maintainer email uses a domain you control and renew, or a large provider.
- Search your repos and CI logs for leaked `NPM_TOKEN` or PyPI tokens.

### Tools/Techniques
- `npm view`, `npm owner ls`, and PyPI project pages for maintainer lists.
- [Have I Been Pwned](https://haveibeenpwned.com/) for maintainer emails.
- [Gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog) for leaked tokens.

### Metrics/Signal
- Maintainer emails on personal domains with no auto-renew.
- Leaked or long-lived registry tokens found (target: zero).
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Assess how your packages are published, and how you would tell a genuine release from a hijacked one.

### Insight
Signing Git commits does not protect a registry release. An attacker with your npm session publishes a tarball directly. What helps is publishing only from CI with trusted publishing, so a release without provenance stands out. Trusted publishing does not switch off the other routes, though. The last legitimate axios 1.x releases came through GitHub Actions with provenance. The attacker simply ran `npm publish` from the maintainer's compromised machine, and npm accepted it.

### Practical
- For each package: is 2FA required for publishing? Are tokens disallowed? Is there provenance on recent releases?
- As a consumer, check whether your dependencies carry provenance and valid registry signatures.

```bash
# Verify registry signatures and provenance for installed packages
npm audit signatures
```

### Tools/Techniques
- npm package **Settings > Publishing access**.
- `npm audit signatures`.
- [PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/) and PEP 740 attestations shown on PyPI file pages.

### Metrics/Signal
- Percentage of your packages that publish only through trusted publishing.
- Percentage of your dependencies with provenance.
:::

::: {! stage fortify}
## Fortify

### Explanation
Make the account hard to take, and make a stolen session less useful.

### Insight
npm and PyPI never offered SMS 2FA, so SIM swapping is not the threat. Real-time phishing of TOTP is. Hardware keys and passkeys (WebAuthn) bind the login to the real domain, so a proxy cannot replay them. They do not help once the attacker is on your machine. The axios attacker had remote control of the maintainer's computer, so 2FA prompts and saved sessions were theirs too.

### Practical
- Use WebAuthn security keys or passkeys for npm, PyPI and GitHub. Remove TOTP once they are in place.
- On npm, set publishing access to "Require two-factor authentication and disallow tokens", and publish from CI with [trusted publishing](https://docs.npmjs.com/trusted-publishers). npm adds provenance automatically.
- On PyPI, use trusted publishing; PyPI has required 2FA for all users since January 2024.
- If you must use tokens, use granular, short-lived ones scoped to a single package.
- Add a second verified email on a major provider, so an expired personal domain cannot be used for a reset.
- Keep publish rights off the laptop you use for calls, chat and email. Publish from CI, and treat any request to install software to join a meeting as hostile.

```yaml
# Publish from GitHub Actions with no stored token
permissions:
  contents: read
  id-token: write
steps:
  - uses: actions/checkout@<full-commit-sha>
  - uses: actions/setup-node@<full-commit-sha>
    with:
      node-version: 24
      registry-url: https://registry.npmjs.org
  - run: npm ci
  - run: npm publish
```

### Tools/Techniques
- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) and [provenance](https://docs.npmjs.com/generating-provenance-statements).
- [PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/).
- [crates.io trusted publishing](https://crates.io/docs/trusted-publishing).

### Metrics/Signal
- Maintainers using phishing-resistant 2FA.
- Packages still accepting token-based publishes.
:::

::: {! stage limit}
## Limit

### Explanation
As a consumer, limit how fast a hijacked release reaches you and how much it can touch.

### Insight
Most takeovers are caught within hours. A release-age gate turns "we installed it" into "we would have installed it tomorrow".

### Practical
- Add a release-age gate to installs and update bots.
- In pnpm, set `trustPolicy: no-downgrade` so a release with weaker provenance than its predecessor fails to install. That would have stopped `axios` 1.14.1, which had no provenance where 1.14.0 did.
- Run installs without secrets in scope, and block dependency install scripts by default.

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 1440
trustPolicy: no-downgrade
```

### Tools/Techniques
- [pnpm `minimumReleaseAge` and `trustPolicy`](https://pnpm.io/settings/dependency-resolution).
- [Renovate `minimumReleaseAge`](https://docs.renovatebot.com/configuration-options/#minimumreleaseage).

### Metrics/Signal
- Repos with a release-age gate.
- Install jobs with secrets in scope.
:::

::: {! stage expose}
## Expose

### Explanation
Spot a hijacked release quickly, whether it is your package or one you depend on.

### Insight
A takeover release usually looks different: no provenance where there used to be some, a new install script, a publish from an unfamiliar location, or a version that skips your normal release process.

### Practical
- As a maintainer, treat every npm or PyPI publish notification you did not expect as an incident.
- Watch for other account activity too. The axios attacker used the hijacked account to delete the first issues reporting the compromise. Another collaborator raised the alarm and contacted npm.
- As a consumer, diff new versions against the previous one before merging update PRs.

```bash
npm diff --diff=secure-data-sanitizer@3.1.4 --diff=secure-data-sanitizer@3.1.5
```

### Tools/Techniques
- `npm diff` and `npm audit signatures`.
- Malware feeds from [Socket](https://socket.dev/), [Aikido](https://www.aikido.dev/) or [Veracode](https://www.veracode.com/) (formerly Phylum).
- [OSV](https://osv.dev/) malicious-package records via OSV-Scanner.

### Metrics/Signal
- Time from unexpected publish to yank or deprecate.
- Update PRs merged where provenance disappeared.
:::

::: {! stage exercise}
## Exercise

### Explanation
Rehearse losing a maintainer account, safely.

### Insight
Most maintainers have never tried to regain control of an account, revoke every token and deprecate a release under pressure.

### Practical
1. Walk through account recovery for npm, PyPI and GitHub with your recovery codes. Confirm they work and are stored safely.
2. In a local [Verdaccio](https://www.verdaccio.org/) registry, publish a benign "hijacked" patch of an internal package without provenance. Check whether `trustPolicy`, your release-age gate or review catches it.
3. Practise the response: revoke tokens, deprecate the version, and post an advisory draft.

### Tools/Techniques
- [Verdaccio](https://www.verdaccio.org/) as a local registry.
- Registry recovery flows and saved recovery codes.

### Metrics/Signal
- Minutes from "account compromised" to all tokens revoked.
- Maintainers with tested recovery codes.
:::

## Further Reading

- [ESLint: Postmortem for malicious package publishes (2018)](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/)
- [axios: Post mortem of the npm supply chain compromise](https://github.com/axios/axios/issues/10636)
- [Aikido: npm debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [PyPI: Preventing domain resurrection attacks](https://blog.pypi.org/posts/2025-08-18-preventing-domain-resurrections/)
- [GitHub: Our plan for a more secure npm supply chain](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)
- [Phishing Developers](#battlecards-phishing-developers-md)
