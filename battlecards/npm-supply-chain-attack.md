---
title: chalk and debug npm Compromise (2025)
category: Package Ecosystems
scenario: Hijacked maintainer ships a browser crypto drainer
focus:
  - phished maintainer account
  - malicious patch releases
  - client-side bundle injection
---

## Scenario

A team ships a web app that lets customers pay with a crypto wallet. Their front-end build pulls in `chalk`, `debug` and the small ANSI and colour helpers beneath them, like almost every JavaScript project.

The maintainer of those helpers receives an email from "npm support" at `npmjs.help`. It says his 2FA details must be updated within 48 hours or the account will be locked. The link leads to a convincing login page. He enters his username, password and a live TOTP code. The page relays them to the real npm in real time, and the attacker now holds his account.

Within minutes, new patch versions of 18 packages appear on npm. Nothing runs at install time. Instead, the code waits to be bundled into a website. In the browser it hooks `fetch`, `XMLHttpRequest` and wallet APIs such as `window.ethereum`, and quietly rewrites payment addresses to ones the attacker controls.

The team's CI ran `npm install` without a lockfile that afternoon. The next deploy shipped the drainer to every customer.

**Real-world precedent:** On 8 September 2025, maintainer Josh Junon (Qix) was phished via the look-alike domain `npmjs.help`. Malicious versions of 18 packages, including `chalk@5.6.1` and `debug@4.4.2`, with about two billion weekly downloads between them, were live for roughly two hours ([Aikido](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)).

This differs from install-script attacks like [Shai-Hulud](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem), where a `postinstall` or `preinstall` hook steals credentials from the build machine. Here the build machine was safe. Your users were not.

::: {! stage recon}
## Reconnaissance

### Explanation
The attacker went after maintainers of tiny, deeply nested packages. Those packages sit under thousands of projects that never chose them directly.

### Insight
You probably don't know the names of the people who can publish code into your production bundle. Start by finding out which of your shipped JavaScript comes from a handful of single-maintainer packages.

### Practical
- List the packages that end up in your client bundle, not just your server dependencies.
- For the most widely depended-on ones, check how many maintainers can publish.

```bash
# Why is chalk in my tree, and through which parents?
npm explain chalk

# Who can publish it?
npm view chalk maintainers
```

### Tools/Techniques
- `npm explain`, `npm ls --all` and `npm query` for dependency paths.
- A bundle analyser such as [source-map-explorer](https://github.com/danvk/source-map-explorer) to see which packages actually reach the browser.

### Metrics/Signal
- Number of single-maintainer packages that ship in your client bundle.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Find out whether any build pulled a malicious version during the window, and whether that build reached users.

### Insight
A lockfile records what you installed. It does not record what you deployed. You need to map lockfiles to builds, and builds to releases.

### Practical
Match exact versions from the advisory list against each lockfile:

```bash
jq -r '.packages | to_entries[]
  | select(.key != "")
  | "\(.key | sub(".*node_modules/"; ""))@\(.value.version)"' package-lock.json \
  | sort -u | grep -Fxf bad-versions.txt
```

Search built bundles too. The drainer was obfuscated, so search for the package versions in your SBOMs and for wallet hooks in your output:

```bash
grep -rl "window.ethereum" dist/ | head
```

### Tools/Techniques
- [OSV-Scanner](https://google.github.io/osv-scanner/) against lockfiles and container images.
- [Syft](https://github.com/anchore/syft) to produce an SBOM per release (`syft dir:.`), so you can answer "what did we ship on 8 September?" later.

### Metrics/Signal
- Builds and releases containing a listed version (target: zero).
- Percentage of releases with a stored SBOM.
:::

::: {! stage fortify}
## Fortify

### Explanation
Two controls would have kept this out: installing exactly what the lockfile says, and refusing versions only a few hours old.

### Insight
The malicious versions were live for about two hours. A one-day release-age gate would have meant almost nobody installed them.

### Practical
- Always commit the lockfile and install with `npm ci`, so CI never resolves fresh versions.
- Add a release-age gate for both installs and automated updates.
- Ship a strict Content Security Policy with `connect-src` limited to your own APIs, so injected code cannot call out freely.

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 1440   # minutes
```

```json
{
  "extends": ["config:recommended"],
  "minimumReleaseAge": "3 days"
}
```

### Tools/Techniques
- [pnpm `minimumReleaseAge`](https://pnpm.io/settings/dependency-resolution).
- [Renovate `minimumReleaseAge`](https://docs.renovatebot.com/configuration-options/#minimumreleaseage) or Dependabot `cooldown`.
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

### Metrics/Signal
- Percentage of CI jobs that use `npm ci` (or `pnpm install --frozen-lockfile`).
- Percentage of repos with a release-age gate configured.
:::

::: {! stage limit}
## Limit

### Explanation
If a bad version reaches your bundle, limit what it can do in the browser and how long it stays there.

### Insight
Because this payload ran client-side, rotating CI secrets would not help. Containment means rebuilding and redeploying clean bundles, and purging CDN caches.

### Practical
- Keep the ability to rebuild and redeploy any release from a pinned lockfile within the hour.
- Use CSP and, for third-party scripts you load from CDNs, Subresource Integrity.
- For payment or wallet flows, show and confirm the destination address server-side, outside the bundle.

### Tools/Techniques
- [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity).
- CDN cache purge APIs wired into your deploy pipeline.

### Metrics/Signal
- Time to rebuild, redeploy and purge caches for a release.
:::

::: {! stage expose}
## Expose

### Explanation
Detect suspicious new versions before you install them, and suspicious behaviour after you ship.

### Insight
The community spotted this in about two hours because the new code looked nothing like the old. Diffing a release against its predecessor is cheap and catches a lot.

### Practical
- Review dependency update PRs with a diff of the published tarballs, not only the changelog.
- Report CSP violations to an endpoint you watch. An unexpected `connect-src` violation from your own app is a strong signal.
- Check whether a new release lacks provenance that earlier releases had.

```bash
npm diff --diff=debug@4.4.1 --diff=debug@4.4.2
npm audit signatures
```

### Tools/Techniques
- `npm diff` and `npm audit signatures`.
- [Socket](https://socket.dev/) or [Aikido](https://www.aikido.dev/) malware feeds on dependency PRs.
- CSP `report-to` endpoints.

### Metrics/Signal
- CSP violation reports per release.
- Dependency PRs merged without a tarball diff or malware check.
:::

::: {! stage exercise}
## Exercise

### Explanation
Practise the "we shipped a poisoned bundle" drill, which is different from a credential-theft drill.

### Insight
Teams that rehearse token rotation often have no plan for rebuilding and redeploying every front end at once.

### Practical
1. Run [Verdaccio](https://www.verdaccio.org/) locally. Publish a benign patch of an internal helper whose only change is a `console.log` and a request to a test endpoint you own.
2. Point a staging build at Verdaccio and let your update tooling pick it up.
3. Check which control catches it first: release-age gate, tarball diff review, or CSP report.
4. Time the rebuild, redeploy and cache purge for every affected app.

### Tools/Techniques
- [Verdaccio](https://www.verdaccio.org/) as a local registry.
- A staging environment with CSP reporting enabled.

### Metrics/Signal
- Which control caught the test package, and how long it took.
- Minutes from detection to clean bundles live.
:::

## Further Reading

- [Aikido: npm debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [GitHub: Our plan for a more secure npm supply chain](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)
- [npm docs: Trusted publishing](https://docs.npmjs.com/trusted-publishers)
- [Maintainer Account Takeover](#battlecards-maintainer-account-takeover-md)
- [Phishing Developers](#battlecards-phishing-developers-md)
