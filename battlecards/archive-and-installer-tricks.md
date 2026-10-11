---
title: Install Scripts and Archive Extraction Tricks
category: Package Ecosystems
ref: RFX-PKG-07
precedent: "2021"
scenario: Install-time code execution and path traversal in archive extraction
focus:
  - npm lifecycle scripts and Python sdist builds
  - zip slip and tar path traversal in your own code
  - lockfiles versus freshly compromised versions
---

## Scenario

Two separate risks hide behind "it's just an archive". This card covers both, because teams often mix them up and fix the wrong one.

**Risk 1: the package manager runs the attacker's code for you.** A developer runs `npm install` on a project that depends on a popular CLI. Two hours earlier, an attacker used a stolen maintainer token to publish a new patch release. The `postinstall` script in that release runs on the developer's laptop and in CI. It searches for npm tokens, GitHub tokens, SSH keys and cloud credentials, and uploads them. The project's lockfile does not help: the dependency range allowed the new patch, and the CI job ran `npm install` rather than `npm ci`.

Python has the same shape. Installing a source distribution (sdist) runs its build backend, which for many packages means running `setup.py`. A `pyproject.toml` does not change that: it only names the backend that will execute.

**Risk 2: your own code extracts an untrusted archive.** The same team runs a service that accepts plugin bundles as `.tar.gz` uploads and unpacks them with Python's `tarfile`. An attacker uploads a bundle containing an entry named `../../home/app/.ssh/authorized_keys`, or a symlink pointing outside the target directory. The extractor writes straight through it. This is "zip slip". The bug lives in *your* extraction code.

::: {! precedent}
**Real-world precedent:** Hijacked [ua-parser-js](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js) releases (October 2021) used a `preinstall` script to drop a cryptominer and password stealer. The [Nx "s1ngularity"](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c) releases (August 2025) used `postinstall` to steal secrets, including by driving locally installed AI coding CLIs. The [Shai-Hulud worm](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) (September 2025) used `postinstall` to steal tokens and republish itself into more than 500 packages. Path traversal in archive extraction is the long-standing [Python tarfile issue CVE-2007-4559](https://www.cve.org/CVERecord?id=CVE-2007-4559) and the 2018 [Zip Slip](https://security.snyk.io/research/zip-slip-vulnerability) disclosure across many languages.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

For risk 1, attackers look for packages with many dependents and a weak point in publishing: a long-lived token, a maintainer without phishing-resistant 2FA, or a CI workflow that can be tricked into leaking a token. Install scripts are the payoff, because they run automatically on every machine that installs the release.

For risk 2, attackers look for any feature that takes an archive from outside: plugin uploads, theme imports, backup restores, model or dataset bundles, CI artefact downloads. Then they test whether the extractor honours `../`, absolute paths and symlinks.

### Insight

These attacks need no vulnerability in your application logic. One relies on a feature (install scripts) working as designed. The other relies on an extraction call that looks harmless in code review.

### Practical

- List the dependencies in your tree that declare `preinstall`, `install` or `postinstall` scripts. Most projects need only a handful.
- List the Python packages you install from sdists rather than wheels.
- Search your code for every place that extracts an archive: `tarfile`, `zipfile`, `shutil.unpack_archive`, `java.util.zip`, `archive/tar`, `archive/zip`, `node-tar`, `adm-zip`.

### Tools/Techniques

- `npm query ':attr(scripts, [postinstall])'` to list packages with a `postinstall` script.
- `pip download -r requirements.txt --no-deps -d /tmp/pkgs` then look for `.tar.gz` files to spot sdists.
- `rg -n 'extractall|unpack_archive|ZipInputStream|archive/(tar|zip)'` across your repositories.

### Metrics/Signal

- Number of dependencies allowed to run install scripts.
- Number of code paths that extract archives from untrusted sources.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check whether your package manager runs dependency scripts by default, whether CI installs from the lockfile, and whether each extraction path validates entries.

### Insight

A lockfile protects you from versions you have not seen yet. It does nothing when the compromised version is the one being resolved fresh, which is exactly what happens in `npm install` with a caret range, in a new project, or in a Renovate PR opened minutes after the malicious publish.

Python's `zipfile.extract()` and `extractall()` already strip absolute paths and `..` components. `tarfile` is the risky one: before Python 3.14, `extractall()` trusts the archive unless you pass a filter.

### Practical

- Check which package manager each project uses. pnpm 10+ and Bun do not run dependency lifecycle scripts unless you allow-list them. npm 11 and earlier, and Yarn Classic, do run them by default.
- Check that CI uses `npm ci`, `pnpm install --frozen-lockfile` or `uv sync --locked`, never a resolving install.
- For each `tarfile` call, check the Python version and whether `filter="data"` is set.
- For Java, Go and Node extraction code, check that every entry path is resolved and confirmed to sit inside the target directory before writing.

### Tools/Techniques

- [Semgrep](https://semgrep.dev/) and CodeQL both ship rules for zip slip and `tarfile.extractall` without a filter.
- `npm ci` in CI, which stops with an error if `package-lock.json` and `package.json` disagree.

### Metrics/Signal

- Projects where dependency install scripts run by default.
- Extraction call sites without path validation.
:::

::: {! stage fortify}
## Fortify

### Explanation

Turn install scripts off by default, delay brand-new releases, prefer prebuilt wheels, and make extraction safe by construction.

### Insight

Allow-listing the few packages that need build scripts (`esbuild`, `sharp`, native modules) is a small, one-off job. After that, a hijacked release of anything else cannot execute at install time.

### Practical

- npm 12 and later: dependency install scripts are off by default. Approve the few you need with `allowScripts`. On npm 11 and earlier, disable them globally:

    ```ini
    # .npmrc
    ignore-scripts=true
    ```

- pnpm 10+: scripts are already off. Allow only what you need, and hold back new releases for a day.

    ```yaml
    # pnpm-workspace.yaml
    allowBuilds:
      esbuild: true
    minimumReleaseAge: 1440  # minutes
    ```

    `allowBuilds` arrived in pnpm 10.26 and replaced `onlyBuiltDependencies`, which pnpm 11 removed.

- Python: refuse sdists so no build backend runs at install time.

    ```bash
    pip install --only-binary :all: --require-hashes -r requirements.txt
    ```

- Python extraction: always pass a filter. It is the default from 3.14, and was backported to security releases of older versions.

    ```python
    import tarfile

    with tarfile.open(upload_path) as tar:
        tar.extractall(dest_dir, filter="data")
    ```

- Java extraction: resolve and check every entry.

    ```java
    Path root = destDir.toPath().toRealPath();
    Path target = root.resolve(entry.getName()).normalize();
    if (!target.startsWith(root)) {
        throw new IOException("Blocked entry: " + entry.getName());
    }
    ```

- Go 1.24+: write through an `os.Root`, which refuses paths that escape the directory.

    ```go
    root, err := os.OpenRoot(destDir)
    if err != nil {
        return err
    }
    defer root.Close()
    f, err := root.Create(hdr.Name) // errors if hdr.Name escapes destDir
    ```

### Tools/Techniques

- pnpm `allowBuilds`, Bun `trustedDependencies`, npm `allowScripts` (npm 12) or `ignore-scripts` (older npm).
- Renovate `minimumReleaseAge` for update PRs.
- `tarfile` `filter="data"`, Go `os.Root`.

### Metrics/Signal

- Percentage of projects with dependency scripts disabled or allow-listed.
- Percentage of Python installs that use `--only-binary :all:` in CI.
:::

::: {! stage limit}
## Limit

### Explanation

If a script does run, or an archive does slip through, make sure there is little to take and nowhere to write.

### Insight

Install scripts steal whatever the installing user can read. The Nx and Shai-Hulud payloads went straight for tokens in home directories and environment variables.

### Practical

- Install dependencies in CI in a step that has no publish tokens or cloud credentials. Add secrets only to the later steps that need them.
- Move npm and PyPI publishing to trusted publishing so there is no long-lived token on any machine to steal.
- On laptops, open unfamiliar projects in a dev container so install scripts run away from `~/.ssh`, `~/.npmrc` and `~/.aws`.
- Run archive extraction as a dedicated user that can write only to the target directory, ideally in a separate container with a read-only root filesystem.

### Tools/Techniques

- npm and PyPI trusted publishing via OIDC.
- Dev containers or disposable VMs for first install of unfamiliar code.
- Read-only container filesystems with a single writable volume for extracted files.

### Metrics/Signal

- CI install steps with secrets in scope.
- Remaining long-lived registry tokens.
:::

::: {! stage expose}
## Expose

### Explanation

Detect install-time payloads and traversal attempts as they happen.

### Insight

Install steps have a predictable network footprint: your registry and little else. Anything beyond that is worth an alert.

### Practical

- Monitor outbound connections during dependency install in CI. Alert on anything other than your registry or mirror.
- Watch for new GitHub repositories created in your organisation or users' accounts by tokens, especially with names you do not recognise. Nx victims found `s1ngularity-repository` repos in their own accounts.
- Log and reject any archive entry that is absolute, contains `..`, or is a link pointing outside the target. Treat every rejection as a security event.
- Check for unexpected changes to shell startup files (`.bashrc`, `.zshrc`) on developer machines.

### Tools/Techniques

- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) for runner egress on GitHub Actions.
- GitHub organisation audit log for `repo.create` events.
- Socket, OSV-Scanner or `npm audit signatures` for known-malicious and unsigned packages.

### Metrics/Signal

- Unexpected egress destinations during install.
- Rejected archive entries per week, by source.
:::

::: {! stage exercise}
## Exercise

### Explanation

Test both halves with harmless artefacts in a local, isolated setup.

### Insight

A benign `postinstall` that calls a canary URL tells you more about your defences than any policy document.

### Practical

1. Run [Verdaccio](https://verdaccio.org/) locally. Publish a test package to it whose `postinstall` makes one request to a [Canarytokens](https://canarytokens.org) URL.
2. Install it in a sandbox project with your standard config. With scripts disabled or allow-listed, the canary should stay quiet. Temporarily allow it and confirm egress monitoring catches the call.
3. Build a test tarball with an entry named `../escape.txt` and a symlink to `/tmp`:

    ```python
    import io
    import tarfile

    with tarfile.open("evil.tar", "w") as tar:
        data = b"canary\n"
        entry = tarfile.TarInfo("../escape.txt")
        entry.size = len(data)
        tar.addfile(entry, io.BytesIO(data))

        link = tarfile.TarInfo("outside")
        link.type = tarfile.SYMTYPE
        link.linkname = "/tmp"
        tar.addfile(link)
    ```

4. Feed it to your upload endpoint in a test environment. Confirm the entry is rejected and logged, and that nothing appears outside the target directory.

### Tools/Techniques

- Verdaccio for a private, throwaway npm registry.
- Python's `tarfile` module to craft traversal entries without touching real files.

### Metrics/Signal

- Whether the canary fired, and where.
- Whether the traversal attempt produced an alert.
:::

## Further Reading

- [CISA: Malware discovered in popular npm package ua-parser-js (October 2021)](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js)
- [Nx security advisory GHSA-cxm3-wv7p-598c (August 2025)](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c)
- [CISA: Widespread supply chain compromise impacting npm ecosystem (September 2025)](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Python tarfile extraction filters](https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter)
- [pnpm settings: allowBuilds and minimumReleaseAge](https://pnpm.io/settings/build)
