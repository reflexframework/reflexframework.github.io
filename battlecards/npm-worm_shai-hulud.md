---
title: Shai-Hulud npm Worm
category: Package Ecosystems
scenario: Self-replicating npm worm
focus:
  - stolen publish tokens
  - install-script credential theft
  - automated republishing
  - GitHub Actions persistence
---

## Scenario

A front-end developer runs `npm install` on a Monday morning. One transitive dependency has a fresh patch release. Its install script quietly runs a bundled payload.

The payload harvests everything it can find: `~/.npmrc`, `GITHUB_TOKEN`, cloud credentials, and anything a secret scanner turns up on disk. It sends the haul to GitHub, in a new public repository created under the victim's own account.

Then it spreads. With the developer's npm token, it lists every package they can publish. It downloads each tarball, injects itself, bumps the patch version and republishes. Every team that installs one of those packages becomes the next carrier.

It also plants a GitHub Actions workflow in the victim's repositories. That workflow keeps leaking repository secrets long after the laptop is cleaned.

**Real-world precedent:** In September 2025 the Shai-Hulud worm began with `@ctrl/tinycolor` 4.1.1 and 4.1.2 and reached more than 500 packages, including some published by CrowdStrike's npm account ([CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem), [CERT/CC VU#534320](https://kb.cert.org/vuls/id/534320)). A second wave, "Sha1-Hulud: The Second Coming", hit in late November 2025 with a `preinstall` hook, a Bun-based payload and more than 25,000 exfiltration repositories ([Wiz](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack), [Check Point](https://blog.checkpoint.com/research/shai-hulud-2-0-inside-the-second-coming-the-most-aggressive-npm-supply-chain-attack-of-2025/)).

**2026 waves:** The worm returned in 2026 as "Mini Shai-Hulud", attributed to the group TeamPCP, and crossed into PyPI. On 29 and 30 April it hit SAP CAP packages on npm, such as `@cap-js/sqlite`, and `lightning` 2.6.2 and 2.6.3 on PyPI, where the payload ran on import ([Lightning advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3), [Deepwatch](https://www.deepwatch.com/labs/ca-a-26-005-update-3-mini-shai-hulud-supply-chain-compromise/)). On 11 and 12 May, Mend counted 172 packages and 403 malicious versions across both registries, including `@tanstack`, `@uipath` and `@mistralai` ([Mend](https://securityboulevard.com/2026/05/mini-shai-hulud-is-back-172-npm-and-pypi-packages-compromised-in-latest-wave/)). The TanStack versions went out through the project's own release workflow with valid provenance, using an OIDC token read from the runner's memory ([TanStack](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem), [Snyk](https://snyk.io/blog/tanstack-npm-packages-compromised)). Another wave began on 4 August in `keyv` and `cacheable` ([Sonatype](https://www.sonatype.com/blog/mini-shai-hulud-npm-attack-more-than-2200-components-impacted)). The 2026 payloads also persist in AI coding-tool and editor config such as `.claude/settings.json` and `.vscode/tasks.json`.

**The wider pattern:** Shai-Hulud was not a one-off. [Sonatype's 2026 State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction) places it at the start of a run of self-replicating campaigns in late 2025. GlassWorm hit Open VSX and the VS Code Marketplace in three waves (17 October, 9 November, 1 December). IndonesianFoods flooded npm with 169,538 packages from 11 November, publishing one every seven seconds. Sha1-Hulud followed on 24 November. Sonatype also found that over 99% of the open source malware it logged in 2025 was on npm. Its warning is blunt: this malware runs before install finishes, so downloading the package is enough to become a victim. The [industrialised malware campaigns](#battlecards-industrialised-malware-campaigns-md) card covers the campaigns as a whole.

::: {! stage recon}
## Reconnaissance

### Explanation
Shai-Hulud needed no target list. It harvested whatever tokens the infected machine held and used them to choose its next victims. Your exposure is the set of credentials that sit on machines where `npm install` runs.

### Insight
The worm's map of your organisation is your own credential sprawl. A developer who maintains ten packages with a long-lived publish token is ten infections waiting to happen. Find those tokens before something else does.

### Practical
- List the npm packages your people and bots can publish to.
- Find long-lived tokens on laptops and CI: `.npmrc` files, `NPM_TOKEN` secrets, classic GitHub PATs.
- Note which CI jobs run `npm install` with write-scoped `GITHUB_TOKEN` or cloud credentials in the environment.

```bash
# Packages a maintainer can publish
npm access list packages <your-npm-user>

# Tokens visible to npm on this machine
npm token list

# Org repos that store an npm token as an Actions secret
gh api --paginate "orgs/<org>/actions/secrets" -q '.secrets[].name' | grep -i npm
```

### Tools/Techniques
- [npm CLI](https://docs.npmjs.com/cli/v11/commands/npm-token): `npm token list`, `npm access list packages`.
- [GitHub CLI](https://cli.github.com/) for secret and workflow inventory.
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) or [Gitleaks](https://github.com/gitleaks/gitleaks), run by you on your own disks before the worm runs them for you.

### Metrics/Signal
- Count of live npm write tokens per maintainer (target: zero, with trusted publishing instead).
- Count of CI jobs that install dependencies while holding publish or cloud credentials.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Check whether any of your lockfiles, caches or images resolved a compromised version. Then check whether anything in your GitHub estate shows the worm's fingerprints.

### Insight
Grepping for a package name is not enough. `grep "@ctrl/tinycolor@4.1"` also matches the clean 4.1.0. Match exact `name@version` pairs from a published IOC list.

### Practical
Save the IOC list (one `name@version` per line) to `bad.txt`, then compare it with the lockfile:

```bash
jq -r '.packages | to_entries[]
  | select(.key != "")
  | "\(.key | sub(".*node_modules/"; ""))@\(.value.version)"' package-lock.json \
  | sort -u | grep -Fxf bad.txt
```

Look for the worm's artefacts across your organisation:

```bash
# Wave 1 workflow and wave 2 backdoor workflow
gh search code --owner <org> "path:.github/workflows filename:shai-hulud-workflow.yml"
gh search code --owner <org> "path:.github/workflows filename:discussion.yaml"

# Wave 2 exfiltration repos created under a user account
gh search repos "Sha1-Hulud: The Second Coming" --owner <user>

# Wave 2 loader files in installed packages
find . -path '*/node_modules/*' \( -name setup_bun.js -o -name bun_environment.js \)
```

The 2026 waves leave different marks. Look for repositories described as "A Mini Shai-Hulud has Appeared", and for changes to `.claude/settings.json` or `.vscode/tasks.json` that nobody on the team made.

```bash
gh search repos "A Mini Shai-Hulud has Appeared" --owner <user>
```

Check your self-hosted runners too. Wave 2 registered infected machines as runners named `SHA1HULUD`.

```bash
gh api "orgs/<org>/actions/runners" -q '.runners[] | "\(.name) \(.status)"'
```

### Tools/Techniques
- [OSV-Scanner](https://google.github.io/osv-scanner/) reads lockfiles and checks against OSV, which carries malicious-package records.
- [Syft](https://github.com/anchore/syft) builds an SBOM of a directory or image: `syft dir:.` or `syft <image>`.
- [Socket](https://socket.dev/), [Aikido](https://www.aikido.dev/) and [StepSecurity](https://www.stepsecurity.io/) published IOC lists during both waves.

### Metrics/Signal
- Number of lockfiles, caches and images containing an IOC version (target: zero).
- Unexpected public repositories, workflows or self-hosted runners in your org.
:::

::: {! stage fortify}
## Fortify

### Explanation
The worm needed two things: install scripts that run automatically, and publish tokens it could steal. Take both away.

### Insight
After the first wave, GitHub tightened npm. Classic tokens were revoked on 9 December 2025. Write-capable granular tokens now default to a 7-day lifetime with a 90-day maximum, and require 2FA by default. `npm login` issues a two-hour session. Trusted publishing over OIDC removes tokens from CI entirely ([GitHub changelog, November](https://github.blog/changelog/2025-11-05-npm-security-update-classic-token-creation-disabled-and-granular-token-changes/), [December](https://github.blog/changelog/2025-12-09-npm-classic-tokens-revoked-session-based-auth-and-cli-token-management-now-available/)).

### Practical
- Move every package you publish to [trusted publishing](https://docs.npmjs.com/trusted-publishers). It needs npm CLI 11.5.1 or later and `id-token: write`, and it adds provenance automatically for public packages.
- In each package's **Settings > Publishing access**, choose "Require two-factor authentication and disallow tokens".
- Stop install scripts running by default. npm 12 (July 2026) does this out of the box: approve the few packages that need scripts with `allowScripts`. On older npm, set `ignore-scripts=true` in `.npmrc`. pnpm 10 already blocks dependency lifecycle scripts unless you allow them.
- Add a release-age gate so brand-new versions wait a day before you take them.

```yaml
# .github/workflows/release.yml (publishing job)
permissions:
  contents: read
  id-token: write
steps:
  - uses: actions/checkout@<full-commit-sha>
  - uses: actions/setup-node@<full-commit-sha>
    with:
      node-version: 24
      registry-url: https://registry.npmjs.org
  - run: npm ci --ignore-scripts
  - run: npm publish
```

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 1440   # minutes; the default from pnpm 11
allowBuilds:
  esbuild: true
```

### Tools/Techniques
- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) and [provenance](https://docs.npmjs.com/generating-provenance-statements).
- [pnpm build settings](https://pnpm.io/settings/build) (`allowBuilds`, `strictDepBuilds`) and [`minimumReleaseAge`](https://pnpm.io/settings/dependency-resolution).
- [Renovate `minimumReleaseAge`](https://docs.renovatebot.com/configuration-options/#minimumreleaseage) for automated updates.

### Metrics/Signal
- Percentage of your packages published only through trusted publishing.
- Percentage of repos where dependency install scripts are blocked by default.
:::

::: {! stage limit}
## Limit

### Explanation
Assume an infected install happens somewhere. Decide in advance what it can reach.

### Insight
The worm's damage came from what sat next to `npm install`: npm tokens, a GitHub token with `repo` scope, cloud keys. An install step with no secrets and no write permissions has little to steal and no way to spread.

### Practical
- Split CI jobs. Install and test with `permissions: contents: read` and no secrets. Publish and deploy in separate jobs that never run dependency code you have not built yourself.
- Use OIDC for cloud access so there are no static keys to steal.
- Keep developer machines free of long-lived publish tokens. Use `npm login` sessions or trusted publishing.
- Require approval before workflows from new contributors run, and restrict who can register self-hosted runners.
- Keep the publish job clean. Trusted publishing removes stored tokens, but the OIDC token still exists in the runner while the job runs. In May 2026 the worm read it from a TanStack release runner's memory after a poisoned cache got code into that job. The publish job should restore no caches and run nothing it did not build itself.

```yaml
jobs:
  test:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<full-commit-sha>
        with:
          persist-credentials: false
      - run: npm ci --ignore-scripts
      - run: npm test
```

### Tools/Techniques
- [GitHub Actions `permissions`](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token).
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) to restrict outbound traffic from runners.

### Metrics/Signal
- Count of jobs that run `npm install` with any secret in scope.
- Count of repos where the default `GITHUB_TOKEN` is still read-write.
:::

::: {! stage expose}
## Expose

### Explanation
Detect the worm's behaviour, not only its file hashes. The next variant will rename its files.

### Insight
Both waves did things a normal install never does. They started a secret scanner, called the GitHub API to create repositories, pushed new workflow files, and in wave 2 downloaded the Bun runtime and a GitHub Actions runner.

### Practical
- Alert on new public repositories, new workflow files and new self-hosted runners in your org, using the audit log.
- Monitor egress from CI install steps. An install that contacts `api.github.com` to create repos, or downloads a runtime, is suspicious.
- Watch npm for unexpected publishes of your own packages. Subscribe to package publish notifications and review provenance on every release.

```bash
# Recent repo creations and runner registrations in the org audit log
gh api "orgs/<org>/audit-log?phrase=action:repo.create" -q '.[] | "\(.created_at) \(.actor) \(.repo)"'
gh api "orgs/<org>/audit-log?phrase=action:org.register_self_hosted_runner" -q '.[] | "\(.created_at) \(.actor)"'
```

### Tools/Techniques
- [GitHub organisation audit log](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization). The audit log API and streaming need GitHub Enterprise Cloud.
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) in audit mode to baseline install-time network calls.
- `npm view <pkg> --json` and `npm audit signatures` to check what was published and how.

### Metrics/Signal
- Time from a malicious publish of one of your packages to your first alert.
- Unexplained `repo.create`, workflow and runner events per week (target: zero).
:::

::: {! stage exercise}
## Exercise

### Explanation
Rehearse the response on a safe copy. The worm moved in hours; your token revocation needs to move faster.

### Insight
Most teams discover they don't know where all their npm and GitHub tokens live until they try to rotate them all at once.

### Practical
1. Run [Verdaccio](https://www.verdaccio.org/) locally and publish a benign package whose `postinstall` only writes a marker file and reads a [canary token](https://canarytokens.org/) from a fake `.npmrc`.
2. Install it in a test project and a throwaway CI job. Confirm your `ignore-scripts` and pnpm settings block it, and that your egress monitoring fires when you allow it.
3. Time a full rotation: revoke every npm token, rotate GitHub PATs and cloud keys, and switch one package to trusted publishing.
4. Run the IOC commands from Evaluate against your real org and fix any gaps in permissions.

### Tools/Techniques
- [Verdaccio](https://www.verdaccio.org/) as a private registry.
- [Canarytokens](https://canarytokens.org/) for fake credentials that alert when used.

### Metrics/Signal
- Minutes to revoke all npm publish tokens for a maintainer.
- Number of packages still on token-based publishing after the drill.
:::

## Further Reading

- [CISA: Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [GitHub: Our plan for a more secure npm supply chain](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)
- [GitHub changelog: npm classic tokens revoked](https://github.blog/changelog/2025-12-09-npm-classic-tokens-revoked-session-based-auth-and-cli-token-management-now-available/)
- [Wiz: Shai-Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [npm docs: Trusted publishing](https://docs.npmjs.com/trusted-publishers)
- [Sonatype: Mini Shai-Hulud npm attack, more than 2,200 components impacted](https://www.sonatype.com/blog/mini-shai-hulud-npm-attack-more-than-2200-components-impacted)
- [Build Cache and Artifact Poisoning](#battlecards-build-cache-and-artifact-poisoning-md)
