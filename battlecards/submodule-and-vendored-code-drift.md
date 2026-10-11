---
title: Submodule and Vendored Code Drift
category: Source Control & Review
ref: RFX-SRC-03
precedent: "2024–2025"
scenario: Floating submodules and unreviewed vendored code
focus:
  - submodules tracking a branch tip
  - malicious submodules exploiting Git
  - vendored code invisible to SCA
---

## Scenario

A popular open-source machine learning project includes a data-processing library as a Git submodule. Someone once found pinned submodules tedious to update, so the CI pipeline runs this:

```bash
git submodule update --init --remote --recursive
```

The `--remote` flag ignores the commit recorded in the parent repository. It fetches the tip of the branch named in `.gitmodules` instead.

1. An attacker steals the library maintainer's credentials and pushes a commit to the library's `main` branch.
2. The new code looks for environment variables starting with `AWS_`, `GCP_` or `AZURE_` and sends them out during the test phase.
3. The next CI run of the ML project builds that tip and runs the tests. The credentials leave.
4. The project's SCA tool only reads `requirements.txt`. It never looks inside the submodule, so nothing flags.

A second risk sits next to this one. The project also vendors a C parsing library into `third_party/`, copied in three years ago and patched by hand since. Nobody knows which upstream version it matches, so no scanner reports its known vulnerabilities.

::: {! precedent}
**Real-world precedent:** Submodules are also an entry point for Git itself. [CVE-2024-32002](https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv) (May 2024) let a crafted repository run code during `git clone --recursive`. [CVE-2025-48384](https://github.blog/open-source/git/git-security-vulnerabilities-announced-6/) (July 2025) abused carriage returns in submodule paths to write hooks, and CISA added it to the [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) in August 2025.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

`.gitmodules` and CI configuration are public in open-source projects. An attacker reads them to find submodules that float on a branch, and then targets the weakest maintainer in that chain. They also look for `third_party/` or `vendor/` directories, which often contain old code that scanners ignore.

### Insight

A submodule is a dependency with none of the tooling you have for packages. No lockfile, no registry advisories, often no update bot.

### Practical

- List every submodule and how CI updates it:

```bash
git config --file .gitmodules --get-regexp 'submodule\..*\.(url|branch)'
grep -rn -- '--remote' .github/ Makefile scripts/ 2>/dev/null
```

- List vendored directories and record where each came from.
- Check the security posture of each submodule's upstream repository.

### Tools/Techniques

- `git submodule status --recursive` to see the pinned commit for each submodule.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) against each submodule's upstream.

### Metrics/Signal

- Number of submodules, and how many CI updates with `--remote`.
- Number of vendored directories with no recorded upstream version.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Understand how pinning actually works. The parent repository's tree stores a gitlink: the exact commit SHA of each submodule. `.gitmodules` only stores the path, URL and an optional branch. A normal `git submodule update` checks out the recorded SHA. Only `--remote` floats to the branch tip.

For vendored code, the question is whether you can prove the files match a known upstream release.

### Insight

Plain submodules are pinned by default. Drift creeps in through scripts that add `--remote` and through vendored code that people edit in place.

### Practical

- Confirm the recorded SHA for a submodule:

```bash
git ls-tree HEAD path/to/submodule
# 160000 commit 3f1c2a9...  path/to/submodule
```

- Check every CI and developer script for `--remote`.
- Check the Git version on runners and developer machines against the fixed releases for CVE-2024-32002 and CVE-2025-48384.
- For each vendored library, diff it against the upstream release you think it is.

### Tools/Techniques

- [OSV-Scanner](https://github.com/google/osv-scanner), which can identify some vendored C/C++ libraries by file hash and check them for known vulnerabilities.
- `git diff --no-index third_party/libfoo /tmp/libfoo-1.2.3` to compare vendored code with upstream.

### Metrics/Signal

- Vendored libraries with an identified upstream version.
- Runners and laptops on a patched Git version.
:::

::: {! stage fortify}
## Fortify

### Explanation

Keep submodules pinned to the gitlink and update them through reviewed PRs. Treat vendored code as generated: reproduce it from a known version, and fail CI if someone edits it by hand.

### Insight

Updating a submodule should look like updating any dependency: a bot opens a PR, you read the changes, you merge.

### Practical

- Remove `--remote` from CI. Use the pinned SHA:

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  with:
    submodules: recursive
    persist-credentials: false
```

- Let Dependabot or Renovate propose submodule bumps:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gitsubmodule"
    directory: "/"
    schedule:
      interval: "weekly"
```

- In Go projects, regenerate and compare vendored code in CI:

```bash
go mod vendor
git diff --exit-code vendor/
```

- Record upstream name, version and source URL for every vendored library, so SBOM and SCA tools can see it.
- Keep Git patched everywhere, and avoid `--recurse-submodules` when cloning untrusted repositories.
- Add CODEOWNERS for `.gitmodules`, `third_party/` and `vendor/`.

### Tools/Techniques

- [Dependabot `gitsubmodule` ecosystem](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference).
- Renovate's `git-submodules` manager (disabled by default, enable it explicitly).
- [Git submodules documentation](https://git-scm.com/docs/gitsubmodules).

### Metrics/Signal

- CI jobs using `--remote`: zero.
- Submodule updates merged through reviewed PRs.
:::

::: {! stage limit}
## Limit

### Explanation

Code from a submodule runs with whatever the build job has. Keep cloud credentials and publish tokens out of jobs that build and test third-party code.

### Insight

This attack only paid off because cloud keys were in the test job's environment.

### Practical

- Give test jobs `permissions: contents: read` and no cloud credentials.
- Use OIDC with tightly scoped roles in deploy jobs only.
- Restrict egress from build jobs to the package registries and mirrors you need.

### Tools/Techniques

- GitHub environments for deploy credentials.
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) with an egress allow-list.

### Metrics/Signal

- Test jobs with access to cloud or registry credentials.
- Blocked egress attempts from build jobs.
:::

::: {! stage expose}
## Expose

### Explanation

Detect when the code you build differs from the code you reviewed. A submodule checked out at a commit other than its gitlink is a clear signal.

### Insight

`git submodule status` marks a mismatch with a leading `+`. That one character is your drift alarm.

### Practical

- Fail the build if any submodule is not at its recorded commit:

```bash
if git submodule status --recursive | grep -q '^[-+U]'; then
  echo "Submodule drift detected" >&2
  git submodule status --recursive >&2
  exit 1
fi
```

- Alert on PRs that change `.gitmodules` URLs or add new submodules.
- Monitor CI egress for destinations outside the allow-list.

### Tools/Techniques

- The drift check above as a required status check.
- Harden-Runner egress logs.
- OSV-Scanner on a schedule, so new advisories against vendored code surface.

### Metrics/Signal

- Builds failed by the drift check.
- New submodule URLs added per month.
:::

::: {! stage exercise}
## Exercise

### Explanation

Simulate a compromised upstream with local repositories only. Nothing touches a real project or registry.

### Insight

Seeing `--remote` pull an unreviewed commit into a build makes the risk concrete for the whole team.

### Practical

1. Create a local bare repository to act as the "upstream" library and add it as a submodule of a sandbox project.
2. Run your CI script locally and note the submodule SHA.
3. Push a harmless marker commit to the upstream's `main` that writes `DRIFT-MARKER` to a file during tests.
4. Run the CI script again. If the marker appears, your pipeline floats.
5. Apply the Fortify changes and confirm the drift check fails instead.

### Tools/Techniques

- `git init --bare` for the fake upstream.
- [act](https://github.com/nektos/act) or your CI system's local runner to run the pipeline.

### Metrics/Signal

- Whether the marker reached the build before and after the fix.
- Whether the drift check failed the build.
:::

## Further Reading

- [Git documentation: gitsubmodules](https://git-scm.com/docs/gitsubmodules)
- [GitHub Blog: Git security vulnerabilities announced (July 2025)](https://github.blog/open-source/git/git-security-vulnerabilities-announced-6/)
- [Git advisory for CVE-2024-32002](https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv)
- [OSV-Scanner](https://github.com/google/osv-scanner)
