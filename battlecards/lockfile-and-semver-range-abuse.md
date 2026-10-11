---
title: Lockfile and SemVer Range Abuse
category: Package Ecosystems
ref: RFX-PKG-08
precedent: "2018"
scenario: Malicious patch releases and tampered lockfiles
focus:
  - caret and tilde ranges pulling fresh malicious releases
  - lockfile tampering in pull requests
  - CI installs that ignore the lockfile
---

## Scenario

Acme's front-end pins every direct dependency to an exact version in `package.json`. The team feels safe. But one of those dependencies, a popular web framework, depends on `utility-parser` with the range `^1.4.2`. That range lives in the framework's own `package.json`, which Acme doesn't control. Pinning your own manifest does nothing for the dependencies of your dependencies. Only the lockfile pins those.

The attack comes in two forms.

1. **A fresh malicious release.** The attacker phishes the `utility-parser` maintainer and publishes `1.4.3` with a credential-stealing payload. Within an hour, a developer deletes `package-lock.json` to fix a merge conflict and runs `npm install`. npm resolves `^1.4.2` to `1.4.3`, and the new lockfile goes into a "chore: update deps" pull request that nobody reads.
2. **A tampered lockfile.** A contributor opens a pull request that adds a small feature. Buried in a 900-line lockfile diff, the `resolved` URL for `utility-parser` now points at a tarball on the attacker's server, with an `integrity` hash that matches that tarball. GitHub collapses the lockfile diff by default. The reviewer approves the feature.

In both cases CI runs the install and the payload executes.

::: {! precedent}
**Real-world precedent:** In November 2018, a new maintainer of `event-stream` added a malicious `flatmap-stream` dependency that targeted the Copay bitcoin wallet ([event-stream issue #116](https://github.com/dominictarr/event-stream/issues/116)). On 8 September 2025, a phished maintainer's account pushed malicious versions of `chalk`, `debug` and 16 other packages, which anyone resolving fresh ranges could pick up ([Aikido](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)). A week later, the Shai-Hulud worm compromised more than 500 npm packages ([CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)).
:::

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers look for small, widely depended-upon packages with one or two maintainers. A single compromise of such a package reaches every project whose range accepts the next version. For lockfile tampering, they look for projects that accept outside pull requests and review lockfile changes lightly.

### Insight
Malicious versions are usually found and removed within hours. Attackers know this, so the payoff comes from projects that resolve fresh versions immediately: automated update bots that auto-merge, and developers who regenerate lockfiles casually.

### Practical
- Map your transitive tree and find the small packages everything depends on.

```bash
npm ls --all utility-parser
npm explain utility-parser
```

- Check how often your team regenerates the lockfile from scratch, and whether update bots auto-merge.

### Tools/Techniques
- `npm ls`, `npm explain`, `pnpm why`, `yarn why`.
- GitHub's dependency graph for each repository.
- [OpenSSF Scorecard](https://scorecard.dev/) to judge the maintenance and security practices of key transitive packages.

### Metrics/Signal
- Number of transitive packages with a single maintainer.
- Median age of a dependency version at the moment it enters your lockfile.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Check three things. Does CI install exactly what the lockfile says? Can a lockfile change point a package at an arbitrary URL without anyone noticing? How quickly does a newly published version reach your lockfile?

### Insight
The lockfile is the control. Pinning in `package.json` only covers the top layer. The lockfile records the exact version, source URL and integrity hash of every package in the tree.

### Practical
- Check the install command in every pipeline. `npm install` and plain `yarn install` can change the lockfile. These fail instead:
    - npm: `npm ci`
    - pnpm: `pnpm install --frozen-lockfile` (the default in CI)
    - Yarn 2 and later: `yarn install --immutable`
    - Yarn 1: `yarn install --frozen-lockfile`
- Lint the current lockfile for unexpected hosts and non-HTTPS URLs:

```bash
npx lockfile-lint --path package-lock.json --type npm --allowed-hosts npm --validate-https --validate-package-names
```

- Find out whether a release-age gate is set in your package manager or update bot.
- Note that vulnerability scanners such as Trivy report known CVEs in resolved versions. They do not tell you which ranges are loose or how fresh a version is.

### Tools/Techniques
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) for npm and Yarn lockfiles.
- `npm audit signatures` to verify registry signatures and provenance of installed packages.

### Metrics/Signal
- Pipelines using a frozen or immutable install.
- lockfile-lint findings on the default branch.
:::

::: {! stage fortify}
## Fortify

### Explanation
Enforce the lockfile, check every change to it, and wait before trusting new versions.

### Insight
A release-age gate turns the attacker's best moment, the first hours after publishing, into a window where your builds won't touch the new version. The chalk and debug versions in September 2025 were pulled within a few hours.

Pinning has its own failure mode. [Sonatype's 2026 State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction) names "set-and-forget" dependencies as a main reason vulnerable versions keep being downloaded: a version is pinned once, then copied between services for years. Its previous report found that about 95% of vulnerable component downloads already had a fixed version available. A lockfile without automated updates freezes your risk along with your versions. Pair the gate with an update bot, so you wait days for new releases rather than years.

### Practical
- Run lockfile-lint in CI on every pull request, using the command from Evaluate. Fail on any host outside your registry.
- Set a release-age gate in the package manager:
    - pnpm 10.16 and later: `minimumReleaseAge` in minutes. Since pnpm 11, the default is 1440 (one day).
    - npm 11.10 and later: `min-release-age` in days.
    - Yarn 4.10 and later: `npmMinimalAgeGate`.

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 4320
```

```ini
# .npmrc
min-release-age=3
```

- Set the same gate in your update bot, so it doesn't propose versions your package manager will refuse.

```json
{
  "extends": ["config:best-practices"],
  "minimumReleaseAge": "3 days",
  "internalChecksFilter": "strict"
}
```

- Dependabot users can set `cooldown` with `default-days` in `dependabot.yml`.
- Add a `CODEOWNERS` entry for lockfiles, and treat a lockfile change with no matching manifest change as suspicious.
- Set `save-exact=true` in `.npmrc` so new direct dependencies are pinned too. Use `overrides` to force a transitive package to a known-good version.

### Tools/Techniques
- [pnpm settings](https://pnpm.io/settings), [npm config](https://docs.npmjs.com/cli/v11/using-npm/config), [Renovate minimum release age](https://docs.renovatebot.com/key-concepts/minimum-release-age/).
- [lockfile-lint](https://github.com/lirantal/lockfile-lint).
- For Python, `uv sync --locked` and `pip install --require-hashes` play the same role. See [Python and pip Supply Chain Attacks](#battlecards-python-and-pip-supply-chain-md).

### Metrics/Signal
- CI fails on lockfile drift and on disallowed hosts.
- Every update path has a release-age gate of at least a day.
:::

::: {! stage limit}
## Limit

### Explanation
If a malicious version gets in, it acts first at install time through lifecycle scripts, then at runtime. Shai-Hulud used install-time access to steal npm and GitHub tokens and republish itself.

### Insight
Most of the damage in the September 2025 incidents came from tokens sitting on the machines that ran the install.

### Practical
- Don't run dependency lifecycle scripts. npm 12, pnpm 10+ and Bun skip them unless you allow-list packages (npm `allowScripts`, pnpm `allowBuilds`). On older npm, use `npm ci --ignore-scripts`.
- Run the install step with no secrets in scope. Grant cloud credentials by OIDC only in deploy steps.
- Publish your own packages with npm trusted publishing instead of long-lived tokens. After Shai-Hulud, npm revoked classic tokens and moved to short-lived granular tokens and 2FA for publishing.
- Restrict egress from install steps to your registry.

### Tools/Techniques
- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers).
- npm `allowScripts` and pnpm `allowBuilds` for explicit script allow-lists.
- CI egress allowlists through a proxy or [Harden-Runner](https://github.com/step-security/harden-runner).

### Metrics/Signal
- Install steps with lifecycle scripts disabled.
- Long-lived npm publish tokens remaining in your organisation.
:::

::: {! stage expose}
## Expose

### Explanation
Watch the lockfile diff, since that is where both forms of this attack show up. Then watch install behaviour.

### Insight
A machine can read a 900-line lockfile diff that a reviewer won't. Summarise it for humans.

### Practical
- In CI, post a short summary of every lockfile change: new packages, changed versions, changed `resolved` hosts, and each new version's publish age.
- Flag any version younger than your release-age gate that slipped in through an override.
- Run `npm audit signatures` after install. A tarball from an attacker's URL has no registry signature.
- When an advisory names a compromised version, search every lockfile in the organisation for it, as CISA advised for Shai-Hulud.

```bash
grep -rn 'node_modules/debug"' -A2 --include=package-lock.json . | grep '"version"'
```

### Tools/Techniques
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) and `npm audit signatures` in CI.
- [OSV-Scanner](https://github.com/google/osv-scanner) against lockfiles, which includes malicious-package records.

### Metrics/Signal
- Lockfile changes that alter a `resolved` host.
- Packages that fail signature verification.
:::

::: {! stage exercise}
## Exercise

### Explanation
Run both forms of the attack against a sandbox project and a local registry.

### Insight
The tampered-lockfile drill is the more revealing one. It tests whether your review process actually reads lockfiles.

### Practical
1. Run [Verdaccio](https://verdaccio.org/). Publish `drill-parser` `1.4.2`, and make a sandbox app depend on a package that requires `drill-parser@^1.4.2`.
2. Publish `drill-parser` `1.4.3` with a postinstall script that only resolves a DNS canary token. Confirm the release-age gate holds it back, and that the update bot does not raise a pull request.
3. In a second drill, open a pull request that changes only the `resolved` URL of `drill-parser` to a tarball on a local web server. Confirm lockfile-lint fails the build.
4. Record which control caught each drill, and which did not.

### Tools/Techniques
- [Verdaccio](https://verdaccio.org/) and a local static file server for the rogue tarball.
- [Canarytokens](https://canarytokens.org/) for the benign payload.

### Metrics/Signal
- Both drills blocked before install.
- Time for a reviewer to question the lockfile-only change, if lockfile-lint is disabled.
:::

## Further Reading

- [CISA: Widespread supply chain compromise impacting npm ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [GitHub: Our plan for a more secure npm supply chain](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)
- [Liran Tal: Why npm lockfiles can be a security blindspot](https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/)
- [Renovate: Minimum release age](https://docs.renovatebot.com/key-concepts/minimum-release-age/)
- [event-stream: I don't know what to say (issue #116)](https://github.com/dominictarr/event-stream/issues/116)
