---
title: Node.js and npm Dependency Sprawl
category: Package Ecosystems
scenario: Hundreds of transitive packages nobody chose
focus:
  - transitive dependency risk
  - install-time scripts
  - unmaintained and single-maintainer packages
  - protestware and sabotage
---

## Scenario

A team builds a modest Express API with a React front end. `package.json` lists 32 dependencies. `npm ls --all` lists 1,400.

Nobody on the team chose most of those packages. They arrived as dependencies of dependencies. Some are a dozen lines long. Some have one maintainer who last logged in years ago. Several run an install script on every developer laptop and every CI runner.

One morning the build breaks. A tiny package four levels down has gone. A week later a different one ships a "fix" that changes behaviour for every user in a particular country. The team finds out from Hacker News.

The problem is size and depth: every extra package is another maintainer, another account and another install script you trust implicitly.

**Real-world precedent:** npm sprawl has failed in public many times: [left-pad](https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm) was unpublished in March 2016 and broke builds worldwide; [event-stream](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident) gained a malicious `flatmap-stream` dependency in 2018 after a maintainer handover; [ua-parser-js](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js) was hijacked in October 2021; `colors` and `faker` were sabotaged by their own maintainer in January 2022; and [node-ipc](https://github.com/advisories/GHSA-97m3-w2cp-4xx6) shipped file-wiping protestware in March 2022 (CVE-2022-23812).

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers and saboteurs look for small, widely depended-on packages. Few people read them, and a change there reaches thousands of projects at once.

### Insight
Your own tree tells you where you are exposed. Count it, find the deep paths, and find which packages run code at install time.

The scale makes manual review unrealistic. [Sonatype's 2026 State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction) cites an average of around 180 dependencies per application, and found that over 99% of the open source malware it logged in 2025 was on npm. Nobody reads 180 packages, let alone the 1,400 an `npm ls --all` can show. Automate the inventory and let the tooling point you at the risky corners.

### Practical
```bash
# How big is the tree?
npm ls --all --parseable | wc -l

# Which installed packages declare install-time scripts?
npm query ":attr(scripts, [postinstall])" | jq -r '.[].name' | sort -u
npm query ":attr(scripts, [preinstall])" | jq -r '.[].name' | sort -u

# Why is this package here at all?
npm explain flatmap-stream
```

### Tools/Techniques
- `npm ls`, `npm explain` and [`npm query`](https://docs.npmjs.com/cli/v11/using-npm/dependency-selectors) (CSS-like selectors over your tree).
- [OpenSSF Scorecard](https://scorecard.dev/) and [deps.dev](https://deps.dev/) for maintainer count and project health.

### Metrics/Signal
- Total and transitive package counts per service, tracked over time.
- Number of dependencies that run install scripts.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Not every package carries equal risk. Rank them by how much code runs, where it runs and who controls it.

### Insight
A one-line helper with a single maintainer and an install script is riskier than a large, well-staffed framework. Most of the tree needs no attention; a few dozen packages need a lot.

### Practical
- Remove what you don't use. Unused dependencies are pure risk.
- Flag single-maintainer packages that are deep in the tree, have install scripts, or haven't released in years.
- Check whether `npm audit` and OSV results are reachable or just noise.

```bash
# Find unused dependencies and files
npx knip

# Known vulnerabilities and malicious packages from OSV
osv-scanner scan source -r .
```

### Tools/Techniques
- [Knip](https://knip.dev/) (or the older depcheck) to find unused dependencies.
- [OSV-Scanner](https://google.github.io/osv-scanner/) and `npm audit`.
- [OpenSSF Scorecard](https://scorecard.dev/) checks such as Maintained and Code-Review.

### Metrics/Signal
- Unused dependencies removed per quarter.
- Packages with one maintainer and install scripts (target: a short, reviewed list).
:::

::: {! stage fortify}
## Fortify

### Explanation
Make installs deterministic, slow down brand-new versions, and stop dependency scripts running by default.

### Insight
Every incident above relied on someone installing a new version quickly, or running install code without thinking. Lockfiles, release-age gates and script blocking address all three.

The opposite habit is just as costly. Sonatype's report blames "set-and-forget" pinning for keeping old, fixable vulnerabilities in circulation: a version is pinned once and copied forward for years. A lockfile with no automated updates freezes the risk in place. Use an update bot with a release-age gate, so you take fixes promptly without being first in line for a malicious release.

### Practical
- Commit lockfiles and use `npm ci` in CI.
- Use `overrides` to force a safe version of a transitive package without waiting for the parent to update.
- Block install scripts by default. pnpm 10 and later only run dependency build scripts you allow. Bun only runs them for packages on its built-in allowlist or in your `trustedDependencies`. npm 12 now does the same: approve the few that need scripts with `allowScripts`. On older npm, set `ignore-scripts=true` and rebuild the few that need it.
- Add a release-age gate for installs and automated updates.

```json
{
  "overrides": {
    "node-ipc": "10.1.3"
  }
}
```

```ini
# .npmrc
ignore-scripts=true
```

```bash
# After an install with scripts blocked, run them only for packages you trust
npm rebuild esbuild
```

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 1440
allowBuilds:
  esbuild: true
```

### Tools/Techniques
- [npm `overrides`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides).
- [pnpm build settings](https://pnpm.io/settings/build) and [`minimumReleaseAge`](https://pnpm.io/settings/dependency-resolution).
- [@lavamoat/allow-scripts](https://github.com/LavaMoat/LavaMoat/tree/main/packages/allow-scripts) for an explicit allowlist with npm.
- [Renovate `minimumReleaseAge`](https://docs.renovatebot.com/configuration-options/#minimumreleaseage).

### Metrics/Signal
- Percentage of repos with install scripts blocked by default.
- Percentage of CI jobs using `npm ci` or a frozen lockfile.
:::

::: {! stage limit}
## Limit

### Explanation
Some package in your tree will misbehave one day. Keep it away from things it can damage.

### Insight
node-ipc deleted files on the machine where it ran. ua-parser-js dropped a miner and password stealer. Neither would have done much in a job with no secrets and a disposable filesystem.

### Practical
- Run installs in containers or CI jobs with no secrets and read-only tokens.
- Serve packages through a proxy registry you control, so you can block a version for everyone in minutes.
- Keep production images lean: `npm ci --omit=dev` so dev tooling never ships.

### Tools/Techniques
- A proxy registry such as [Verdaccio](https://www.verdaccio.org/), Nexus or Artifactory with block rules.
- [GitHub Actions `permissions`](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token) set to read-only for install jobs.

### Metrics/Signal
- Time to block a package version across all builds.
- Number of packages in production images versus the full dev tree.
:::

::: {! stage expose}
## Expose

### Explanation
Notice when your tree changes in ways nobody intended.

### Insight
Most of these incidents showed up as an unexpected new dependency, a new install script, or a strange version jump. A lockfile diff in review would have shown each one.

### Practical
- Make lockfile diffs visible in pull requests and treat new transitive packages as a review item.
- Fail CI when a new dependency with an install script appears.
- Subscribe to malware feeds for packages you actually use.

```bash
# Fail if the set of packages with install scripts changes
npm query ":attr(scripts, [postinstall])" | jq -r '.[].name' | sort -u > scripts.now
diff scripts.allowed scripts.now
```

### Tools/Techniques
- [Socket](https://socket.dev/) GitHub app for dependency-change alerts.
- [OSV-Scanner](https://google.github.io/osv-scanner/) in CI.
- [GitHub dependency review action](https://github.com/actions/dependency-review-action).

### Metrics/Signal
- New transitive packages per PR.
- PRs that add install scripts.
:::

::: {! stage exercise}
## Exercise

### Explanation
Practise the two failure modes: a package vanishes, and a package turns hostile.

### Insight
left-pad showed that availability is a supply chain risk too. Teams with a proxy registry and a lockfile barely noticed.

### Practical
1. In a sandbox, point npm at a local [Verdaccio](https://www.verdaccio.org/) instance. Remove a transitive package from it and see whether your build still works from cache.
2. Publish a benign patch to Verdaccio for an internal helper that adds a `postinstall` writing a marker file. Check whether your settings block it and your CI flags it.
3. Pick your three riskiest single-maintainer packages and decide: remove, vendor, replace or accept.

### Tools/Techniques
- [Verdaccio](https://www.verdaccio.org/) as a local registry.
- Your CI's lockfile and install-script checks.

### Metrics/Signal
- Builds that survive a missing upstream package.
- Risky packages removed or replaced after the drill.
:::

## Further Reading

- [npm blog: kik, left-pad, and npm](https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm)
- [npm blog: Details about the event-stream incident](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)
- [CISA: Malware discovered in ua-parser-js](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js)
- [GitHub Advisory: node-ipc (CVE-2022-23812)](https://github.com/advisories/GHSA-97m3-w2cp-4xx6)
- [npm docs: Dependency selectors](https://docs.npmjs.com/cli/v11/using-npm/dependency-selectors)
