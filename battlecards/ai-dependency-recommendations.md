---
title: AI-Recommended Dependencies and Hallucinated Versions
category: AI/ML Security
scenario: Coding assistants and agents choose packages and versions from stale training data
focus:
  - hallucinated and non-existent versions
  - compromised or protestware versions recommended after a training cutoff
  - agents adding dependencies to make a build pass
  - unreviewed AI-generated manifests
---

## Scenario

A platform team asks a coding agent to "bring our front-end dependencies up to date and fix any vulnerabilities". The agent reads `package.json`, reasons about each package from what it learned in training, and writes new version ranges. It sounds confident throughout.

Three things go wrong in one pull request.

1. Several of the versions it chose do not exist. `npm install` fails with `ETARGET`. The agent is told to "make the build pass", so it widens ranges, swaps one package for a similar-sounding alternative, and installs another straight from a Git URL. Each change resolves the error. None is reviewed as a new dependency.
2. Two versions do exist, and that is worse. The agent pins `color` to `5.0.1` and `color-string` to `2.1.1`. Both were compromised in September 2025, after the model's training cutoff. The model had no way of knowing.
3. A backend developer, new to Python, asks the same assistant for a `requirements.txt` for a data job. It suggests a version of a popular library that was common in its training data. That release line has been end of life for two years.

The PR diff is 400 lines of lockfile. The reviewer skims it and approves.

A version that does not exist today can exist tomorrow. Normally the maintainer publishes it. After an account takeover, the attacker can publish the exact version an assistant keeps asking for.

**Real-world precedent:** Sonatype's [2026 State of the Software Supply Chain](https://www.sonatype.com/state-of-the-software-supply-chain/2026/ai-agents) report (January 2026) asked GPT-5 for 36,870 upgrade recommendations across Maven, npm, PyPI and NuGet. It found 28% referenced versions that do not exist, and that following the model's advice made 345 components less secure. The model also recommended `sweetalert2` 11.21.2, flagged by Sonatype as protestware, and `color` 5.0.1 and `color-string` 2.1.1 from the [September 2025 chalk/debug compromise](https://github.com/advisories/GHSA-qrmh-qg46-72pp). Hallucinated package *names* are a related problem, covered in [AI Dependency Typosquatting and Slopsquatting](#battlecards-ai-dependency-typosquatting-md).

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers do not need to steer an assistant. They only need to know what assistants tend to suggest. Ask any model for "the latest version" of a popular library and you get its training-time answer. Those answers are predictable and repeat across users.

That gives attackers two angles. Hallucinated package names can be registered by anyone. Hallucinated versions of real packages can only be published by whoever controls the name, so they become valuable after a maintainer account is phished, as happened to `chalk`, `debug`, `color` and more than a dozen other packages on 8 September 2025.

### Insight

Sonatype's study found a sharp confidence pattern. When GPT-5 said it was highly confident, it was right 98% of the time. It said that in under 4% of answers. Nearly half of its low-confidence answers were wrong. The confidence label is useful. Most tools never show it to you.

### Practical

- Find out where AI is choosing your dependencies today: IDE assistants, chat, autonomous agents, bots that open upgrade PRs.
- Ask your assistant to upgrade a sample manifest from one of your real projects. Record every version it proposes.
- Check which of your repositories let an agent run `npm install`, `pip install` or `go get` without a human approving the change.

### Tools/Techniques

- Your own assistant, used the way your developers use it.
- Registry metadata: the npm registry document (`https://registry.npmjs.org/<package>`), the PyPI JSON API (`https://pypi.org/pypi/<package>/<version>/json`), or the [deps.dev API](https://docs.deps.dev/api/v3/) for several ecosystems.

### Metrics/Signal

- Percentage of AI-proposed versions that do not exist on the registry.
- Number of repositories where agents can change manifests without review.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Assess how an AI-introduced dependency change reaches your main branch. The risky path is an agent that edits the manifest, resolves errors by itself, and opens a PR whose diff is mostly lockfile.

Look at four failure modes: versions that do not exist, versions that exist but were compromised or withdrawn, versions on end-of-life release lines, and brand-new packages the agent added to make something compile.

### Insight

Training data skews towards what was popular, and popular often means old. A release line that dominated GitHub for years keeps being suggested long after its maintainers stopped patching it. "No known CVE" on such a version can simply mean nobody is looking.

### Practical

- Review the last ten dependency PRs written or assisted by AI. For each changed version, check that it exists, when it was published, and whether it was ever flagged as malicious.
- Run a vulnerability scan on those branches, and check support status for the main frameworks.
- Check whether your agents are allowed to use Git URLs, tarball URLs or alternative registries to satisfy a failed install.

This script checks that an npm version is actually installable and shows when it was published. The registry keeps timestamps for removed versions, so it checks the `versions` map, not just `time`:

```bash
#!/usr/bin/env bash
# Usage: ./check-npm-version.sh <package> <version>
set -euo pipefail
pkg="$1"; ver="$2"
doc=$(curl -fsS "https://registry.npmjs.org/${pkg}")
if [ "$(jq --arg v "$ver" '.versions[$v] != null' <<<"$doc")" != "true" ]; then
    echo "MISSING: ${pkg}@${ver} is not installable from the registry"
    exit 1
fi
echo "${pkg}@${ver} published $(jq -r --arg v "$ver" '.time[$v]' <<<"$doc")"
```

Run it against `color 5.0.1` today and it reports `MISSING`, because npm removed the malicious release.

### Tools/Techniques

- [OSV-Scanner](https://google.github.io/osv-scanner/) to check proposed versions against known vulnerabilities and malicious package reports.
- [deps.dev](https://deps.dev/) for publish dates, advisories and OpenSSF Scorecard data.
- [endoflife.date](https://endoflife.date/) for release-line support status.

### Metrics/Signal

- AI-assisted dependency PRs that introduced a non-existent, removed, end-of-life or vulnerable version.
- New packages added by an agent without a matching human decision.
:::

::: {! stage fortify}
## Fortify

### Explanation

Ground the agent in live data, constrain what it can choose, and make new dependencies a deliberate human decision. A model that checks the registry before answering cannot hallucinate a version that resolves. It still cannot judge whether a real version is safe, so you need policy as well.

### Insight

Sonatype's own explanation for the bad recommendations is simple: training data stops, attacks do not. A grounded agent fixes the first problem. Release-age gates and approved catalogues fix much of the second.

### Practical

- **Ground the agent.** Tell it, in your agent instruction file (`AGENTS.md`, `CLAUDE.md` or equivalent), to confirm every version against the registry and report the publish date before writing it. Give it a tool that does this, such as the script above or an OSV lookup.
- **Constrain the source.** Point package managers at an internal repository manager with an approved catalogue, so the agent can only pick from what you allow. Block Git and URL dependencies in CI.
- **Gate fresh releases.** Brand-new versions are where hijacks land.
    - npm: `min-release-age` (days) in `.npmrc`.
    - pnpm: `minimumReleaseAge` (minutes; defaults to 1440 since pnpm 11).
    - Renovate: `minimumReleaseAge` on update PRs.
    - uv: `exclude-newer`.
- **Always commit lockfiles** and install with `npm ci`, `pnpm install --frozen-lockfile` or `uv sync --locked`, so an agent's local experiments do not leak into builds.
- **Fail CI on new, unapproved dependencies.** Keep an `approved-packages.txt` beside the manifest and make additions a reviewed change:

```bash
#!/usr/bin/env bash
# Fail if package.json gains a dependency that is not in approved-packages.txt
set -euo pipefail
base="${1:-origin/main}"
names() { jq -r '((.dependencies // {}) + (.devDependencies // {})) | keys[]' | sort; }
added=$(comm -13 <(git show "${base}:package.json" | names) <(names < package.json))
[ -z "$added" ] && exit 0
unapproved=$(comm -23 <(echo "$added") <(sort approved-packages.txt))
if [ -n "$unapproved" ]; then
    echo "New dependencies need approval:"
    echo "$unapproved"
    exit 1
fi
```

```ini
# .npmrc
min-release-age=3
allow-git=none
```

### Tools/Techniques

- [GitHub dependency review action](https://github.com/actions/dependency-review-action) to fail PRs that add vulnerable or denied packages (`deny-packages`, `fail-on-severity`).
- [npm config](https://docs.npmjs.com/cli/v12/using-npm/config): `min-release-age`, `allow-git`.
- [pnpm `minimumReleaseAge`](https://pnpm.io/settings/dependency-resolution) and [Renovate `minimumReleaseAge`](https://docs.renovatebot.com/configuration-options/#minimumreleaseage).
- CODEOWNERS on manifests and `approved-packages.txt`.

### Metrics/Signal

- Percentage of AI-proposed versions verified against the registry before commit.
- New dependencies merged without passing the approval check: zero.
:::

::: {! stage limit}
## Limit

### Explanation

If an agent does pull in a bad version, contain where it runs and what it can touch. The compromised `color` and `color-string` releases targeted browsers, so a build that bundled them shipped the payload to your users. Install-script malware targets the machine doing the install.

### Insight

An agent that can install packages is running untrusted code with your credentials. Give it the same isolation you would give a stranger's pull request.

### Practical

- Run agents in a container or devcontainer with no cloud credentials, no publish tokens and no SSH agent.
- Keep install scripts blocked. npm 12 and pnpm block dependency install scripts by default; do not approve them wholesale to make an agent's install succeed.
- Let agents propose changes through PRs only. Never give an agent permission to merge dependency updates.
- If a bad browser package was bundled, rebuild and redeploy from a clean cache after the fix.

### Tools/Techniques

- Devcontainers or disposable cloud workspaces for agent sessions.
- npm `allowScripts` in `package.json`; pnpm `allowBuilds` in `pnpm-workspace.yaml`.
- Branch rulesets requiring human review on manifest and lockfile changes.

### Metrics/Signal

- Agent sessions with access to long-lived credentials.
- Time from a malicious version being reported to every affected bundle being rebuilt.
:::

::: {! stage expose}
## Expose

### Explanation

Detect AI-driven dependency changes as they happen. The signals are new names in the manifest, versions published in the last few days, versions that do not resolve, and Git or URL dependencies appearing in a lockfile.

### Insight

Most teams never see the failed attempts. The agent's error log is where the hallucinations show up, and it is usually thrown away.

### Practical

- Label PRs that come from agents or bots, and route dependency changes in them to a named reviewer.
- Alert when a lockfile adds a `resolved` URL that is not your registry.
- Keep agent session logs and look for repeated `ETARGET`, `E404` or "No matching distribution" errors.
- Subscribe to malicious-package feeds for your ecosystems, and re-check your lockfiles when a new advisory lands.

### Tools/Techniques

- [OSV-Scanner](https://google.github.io/osv-scanner/) on every PR and on a schedule against `main`.
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) to enforce allowed hosts and HTTPS in npm and Yarn lockfiles.
- GitHub dependency review summaries on PRs.

### Metrics/Signal

- Agent-originated dependency PRs per week, and the share that needed rework.
- Lockfiles containing non-registry sources.
:::

::: {! stage exercise}
## Exercise

### Explanation

Measure how often your assistants are wrong, and prove your gates catch it. Everything here runs locally or against read-only registry APIs.

### Insight

Teams are often surprised that the assistant they trust is wrong a quarter of the time on versions. Seeing it on your own manifest changes behaviour more than any statistic.

### Practical

1. Take a real `package.json` or `requirements.txt` from one of your projects. Ask your assistant to upgrade every dependency to "the latest secure version".
2. Run every proposed version through the check script. Count missing versions, versions under a week old, and versions with advisories.
3. Run a local [Verdaccio](https://verdaccio.org/) registry. Publish a harmless package at one of the hallucinated version numbers (a stand-in for a hijacked release), point a test project at Verdaccio, and let an agent "fix" the failing install.
4. Confirm the release-age gate, the approval check and review each stop the change.

### Tools/Techniques

- Verdaccio for a local npm registry.
- The two scripts on this card.
- A sandbox repository and a throwaway agent session with no credentials.

### Metrics/Signal

- Hallucination rate of your assistant on your own manifests.
- Whether the local "hijacked" version reached `main` (it should not).
:::

## Further Reading

- [Sonatype: 2026 State of the Software Supply Chain, AI agents chapter](https://www.sonatype.com/state-of-the-software-supply-chain/2026/ai-agents)
- [GitHub Advisory: color 5.0.1 malware (CVE-2025-59143)](https://github.com/advisories/GHSA-qrmh-qg46-72pp)
- [Aikido: npm debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [Spracklen et al., "We Have a Package for You!" (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen)
- See also [AI Dependency Typosquatting and Slopsquatting](#battlecards-ai-dependency-typosquatting-md), [Maintainer Account Takeover](#battlecards-maintainer-account-takeover-md) and [Lockfile and Semver Range Abuse](#battlecards-lockfile-and-semver-range-abuse-md).
