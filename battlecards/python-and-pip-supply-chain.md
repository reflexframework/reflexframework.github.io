---
title: Python and pip Supply Chain Attacks
category: Package Ecosystems
scenario: Typosquatted sdist runs code at install time in CI
focus:
  - sdist build-time code execution
  - typosquatting on PyPI
  - maintainer and release pipeline compromise
---

## Scenario

A developer adds an HTTP client to a service. They type `reqeusts` into `requirements.txt`. That is a transposition typo: the "e" and "u" in `requests` have swapped places. The name here is illustrative, but attackers register exactly this kind of near-miss on PyPI.

The attacker's `reqeusts` is a copy of the real library with one change. It ships only as a source distribution (sdist), with no wheel. pip has no "postinstall" hook, and it doesn't need one. To install an sdist, pip must build it, and building means running the package's `setup.py` or build backend. That code runs with the permissions of whoever ran `pip install`.

1. The pull request passes review. The diff is one line and looks like a new dependency.
2. CI runs `pip install -r requirements.txt`. pip finds no wheel, downloads the sdist and builds it.
3. During the build, `setup.py` reads `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN` and `~/.pypirc`, then posts them to the attacker's server.
4. The install succeeds and the tests pass, because the package really does behave like `requests`.

A second route skips the typo entirely. The attacker compromises a real project's release pipeline and ships malicious code under the genuine name. Your hashes and pins do not help if you pinned the poisoned version.

**Real-world precedent:** In December 2019, PyPI removed `python3-dateutil` and `jeIlyfish` (capital "I" in place of the first "l"), which stole SSH and GPG keys ([BleepingComputer](https://www.bleepingcomputer.com/news/security/malicious-python-package-available-in-pypi-repo-for-a-year/)). In December 2024, attackers poisoned the GitHub Actions cache of `ultralytics` and shipped malicious releases through its own publishing workflow ([PyPI blog](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)).

::: {! stage recon}
## Reconnaissance

### Explanation
Typosquatters play a numbers game against the whole ecosystem. They take the most downloaded packages and generate likely misspellings: transpositions (`reqeusts`), doubled or dropped letters, homoglyphs (`jeIlyfish`), and prefix tricks (`python3-dateutil` for `python-dateutil`). They publish the free names and wait.

Release-pipeline attackers pick a single high-value project instead. They read its `.github/workflows/` files looking for `pull_request_target` triggers, untrusted input in `run:` steps, shared caches, and long-lived PyPI tokens stored as secrets.

### Insight
Your public repositories tell attackers what you install. A public `requirements.txt` is a shopping list. A public release workflow is a map of how your packages reach PyPI.

### Practical
- Look at your own release workflows the way an attacker would. Ask what an outside contributor's pull request can influence.
- List every dependency your projects pull in as an sdist. Those are the ones that run code at install time.
- Check whether any of your PyPI projects still have API tokens alongside trusted publishing.

### Tools/Techniques
- [zizmor](https://docs.zizmor.sh/): static analysis for GitHub Actions workflows. It flags template injection, risky triggers and cache misuse. The PyPI team recommended it after the Ultralytics attack.
- [pypistats.org](https://pypistats.org/): attackers use download counts to choose targets.
- GitHub code search, for example `path:requirements.txt org:your-org`, shows you what you expose.

### Metrics/Signal
- Number of zizmor findings on workflows that publish to PyPI.
- Number of dependencies with no wheel for your target platform.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Measure how easily a new or changed name reaches your build. Three questions matter. Can a single-line change to `requirements.txt` install a package nobody vetted? Does your install allow sdists, and so allow arbitrary build-time code? Do your own packages publish through a path an attacker can hijack?

### Insight
Version pins alone do not stop this attack. `reqeusts==2.32.3` is perfectly pinned. A lockfile with hashes forces any new name through a lock regeneration that changes many lines, which is harder to sneak past review.

### Practical
- Find sdist-only dependencies by asking pip to refuse them. Anything that fails here runs code during install today.

```bash
pip download --only-binary :all: --dest /tmp/wheels -r requirements.txt
```

- Check that CI installs from a lock: `uv.lock`, `pylock.toml`, or a `requirements.txt` with `--hash` entries.
- For packages you publish, confirm that trusted publishing is configured and that no unused API tokens remain.

### Tools/Techniques
- [pip-audit](https://github.com/pypa/pip-audit): known vulnerabilities in your locked set.
- [GuardDog](https://github.com/DataDog/guarddog): heuristic scan of PyPI packages for malicious patterns such as exfiltration in `setup.py`.
- The PyPI project page: check the "Verified details" and provenance shown for each file.

### Metrics/Signal
- Percentage of services installing from a hashed lock.
- Count of sdist-only dependencies, trending down.
:::

::: {! stage fortify}
## Fortify

### Explanation
Close the two doors in the scenario. Stop build-time code from running by installing wheels only, and stop unvetted names arriving by installing from a hashed lock. Then harden your own release path so you can't become the next Ultralytics.

### Insight
Wheels run no code at install time: pip unpacks them. Once you refuse sdists, a typosquat has to wait until your code imports it, and your tests and runtime controls get a chance to see it first.

### Practical
- Install wheels only, from a hashed lock. With pip, compile the lock with hashes and install with both flags:

```bash
pip-compile --generate-hashes requirements.in
pip install --require-hashes --only-binary :all: -r requirements.txt
```

- With uv, commit `uv.lock`, fail if it is stale, and refuse to build sdists. A release-age gate keeps fresh uploads out while the community spots them.

```toml
[tool.uv]
no-build = true
exclude-newer = "7 days"
```

```bash
uv sync --locked
```

- For a tool-neutral lock, PEP 751 defines `pylock.toml`. `uv export -o pylock.toml` writes one, and pip 25.1 added an experimental `pip lock`.
- If a dependency has no wheel, build it once in an isolated job, review it, and host the wheel on your private index.
- For your own packages, publish with [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) and delete old API tokens. The official action uploads [PEP 740 attestations](https://docs.pypi.org/attestations/) by default.

```yaml
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@v4  # pin actions to a full commit SHA
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
```

- Require the `pypi` GitHub Environment in the trusted publisher configuration, and never restore build caches in the release job.
- PyPI has required 2FA for all uploading accounts since 1 January 2024. Use a hardware key or authenticator app. Keep the email domain on your PyPI account renewed: since 2025, PyPI unverifies addresses whose domains expire, to block domain-resurrection takeovers.

### Tools/Techniques
- [uv](https://docs.astral.sh/uv/), [pip-tools](https://github.com/jazzband/pip-tools), [PEP 751](https://peps.python.org/pep-0751/).
- [pypa/gh-action-pypi-publish](https://github.com/pypa/gh-action-pypi-publish) with trusted publishing.
- Dependency confusion needs separate index configuration: see [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md).

### Metrics/Signal
- CI fails when a lock is missing, stale or lacks hashes.
- Zero long-lived PyPI API tokens on projects that use trusted publishing.
:::

::: {! stage limit}
## Limit

### Explanation
Assume an sdist ran its payload, or a poisoned release was locked in. The damage depends on what the install step could reach: secrets in the environment, files in the home directory, and the network.

### Insight
A multi-stage Docker build does not contain this attack. The install happens in the builder stage, which has network access and often build secrets. The payload exfiltrates before the final image exists. Multi-stage builds keep tools out of the runtime image. They do nothing about install-time theft.

### Practical
- Run dependency installation as its own CI step with no secrets in the environment. Only fetch cloud credentials, via OIDC, in the later steps that need them.
- Restrict egress during install to your package index (or PyPI and `files.pythonhosted.org`). The exfiltration POST then fails.
- Keep `~/.pypirc` and long-lived tokens off build machines and developer laptops. Trusted publishing makes them unnecessary.
- Scope publish rights tightly: a GitHub Environment with required reviewers for the release job.

### Tools/Techniques
- GitHub Actions OIDC to AWS, Azure or GCP for short-lived cloud credentials.
- [Harden-Runner](https://github.com/step-security/harden-runner) or a CI egress proxy for network allowlists on runners.
- Docker BuildKit secret mounts (`RUN --mount=type=secret`) so secrets never sit in an environment variable for the whole build.

### Metrics/Signal
- Install steps running with zero secrets in scope.
- Blocked egress attempts from install steps.
:::

::: {! stage expose}
## Expose

### Explanation
The payload in this scenario makes noise in three places: a new dependency name appears, a source build happens, and an install step talks to an unexpected host. Watch all three.

### Insight
An sdist build in CI should be rare once you have Fortify in place. Each one is worth a look.

### Practical
- Fail or flag any pull request that adds a dependency name, and post the name, its age and its upload history as a review comment.
- Use pip's installation report to record exactly what was installed and from where:

```bash
pip install --require-hashes -r requirements.txt --report install-report.json
jq -r '.install[] | .download_info.url' install-report.json | grep -v '\.whl$'
```

- Alert on egress from install steps to anything except your index.
- For packages you publish, watch for releases with no matching attestation or no matching tag. That is how PyPI distinguished the second wave of Ultralytics uploads.

### Tools/Techniques
- [GuardDog](https://github.com/DataDog/guarddog) in CI on new or changed dependencies.
- [OSV-Scanner](https://github.com/google/osv-scanner): matches your lock against OSV, which includes malicious-package (`MAL-`) records.
- Runner network logs from Harden-Runner or your proxy.

### Metrics/Signal
- Any URL in the install report that isn't a wheel.
- Any DNS lookup or connection from an install step to an unknown domain.
:::

::: {! stage exercise}
## Exercise

### Explanation
Prove the controls work with a harmless look-alike on a private index. Never upload test packages to the public PyPI.

### Insight
The drill answers two questions. Does `--only-binary` and the hashed lock stop the package? If you bypass them, do egress controls and alerts catch the build-time call?

### Practical
1. Run a local [devpi](https://github.com/devpi/devpi) server and create an index for the drill.
2. Build an sdist named `reqeusts-drill` whose `setup.py` resolves a DNS canary token and writes `/tmp/drill-ran`. No real secrets.
3. Upload it to devpi. On a test branch, add it to `requirements.txt` and point the CI job at the devpi index.
4. Run the normal pipeline. It should fail on the missing hash or the sdist.
5. On a throwaway branch, remove those flags. Confirm egress blocking stops the canary and an alert reaches the team.

### Tools/Techniques
- [devpi](https://github.com/devpi/devpi) or [pypiserver](https://github.com/pypiserver/pypiserver) for the private index.
- [Canarytokens](https://canarytokens.org/) DNS tokens to prove whether the payload ran and reached the internet.

### Metrics/Signal
- The pipeline blocks the drill package before build.
- Time from the canary firing to someone noticing, with the controls bypassed.
:::

## Further Reading

- [PyPI: Supply-chain attack analysis: Ultralytics](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [PyPI now supports digital attestations](https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/)
- [PyPI: Preventing domain resurrection attacks](https://blog.pypi.org/posts/2025-08-18-preventing-domain-resurrections/)
- [pip: Secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [PEP 751: A file format to record Python dependencies](https://peps.python.org/pep-0751/)
