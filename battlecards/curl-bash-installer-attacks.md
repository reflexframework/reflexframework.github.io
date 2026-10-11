---
title: curl | bash Installer Attacks
category: CI/CD & Build
ref: RFX-CI-05
precedent: "2021"
scenario: Compromised remote install script piped into a shell in CI
focus:
  - unverified remote scripts in CI
  - secrets exposed to piped installers
  - server-side pipe-to-shell detection
---

## Scenario

A team's CI pipeline uploads coverage reports with a vendor's script. The step is one line, copied from the vendor's docs years ago:

```yaml
- run: curl -s https://uploader.vendor.example/upload.sh | bash
  env:
    VENDOR_TOKEN: ${{ secrets.VENDOR_TOKEN }}
```

The job also has `AWS_ACCESS_KEY_ID`, a deploy key and a package registry token in its environment, set at job level so every step can see them.

An attacker gains write access to the vendor's storage bucket and adds one line to `upload.sh`. It sends `env` and `git remote -v` to the attacker's server, then carries on with the upload. Coverage still appears in the dashboard. Every customer pipeline that pipes the script into `bash` leaks its whole environment on every run, for months.

Two details make this worse than it looks:

- The script is fetched fresh on every run, so there is nothing to diff and no version to pin.
- A server can tell when its output is being piped straight into a shell, by watching how the client reads the response. It can serve a clean script to anyone who downloads it to read, and the malicious one only to pipelines that execute it blind.

::: {! precedent}
**Real-world precedent:** Between 31 January and 1 April 2021, an attacker modified [Codecov's Bash Uploader](https://about.codecov.io/security-update/) to send environment variables from customers' CI jobs to a third-party server. The modified script also reached users of Codecov's GitHub Action, CircleCI Orb and Bitrise Step. It was spotted when a customer noticed that the script's checksum did not match the one published on GitHub.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers target the distribution point for installer scripts used by many CI pipelines: coverage uploaders, language version managers, monitoring agents, CLI installers. Compromising one bucket, CDN origin or web server gives them code execution in thousands of pipelines at once. Public CI configs on GitHub tell them exactly who uses which script.

### Insight

`curl | bash` hands execution to whoever controls that URL at that moment. HTTPS protects the connection. It says nothing about whether the server is serving what the vendor intended.

### Practical

- Inventory every place you pipe a download into a shell: CI configs, Dockerfiles, Packer templates, Makefiles, onboarding docs.
- For each one, note what secrets are in scope when it runs.
- Search your public repositories for these patterns as an attacker would.

### Tools/Techniques

- A quick search across repositories:

    ```bash
    rg -n --hidden -e '(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z)?sh' \
      -g '*.yml' -g '*.yaml' -g 'Dockerfile*' -g '*.sh' -g 'Makefile' -g '*.pkr.hcl'
    ```

- GitHub code search for `curl` and `| bash` in `.github/workflows` and `.circleci/config.yml`.

### Metrics/Signal

- Number of pipe-to-shell installs in CI and image builds.
- Number of those that run with secrets in the environment.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For each remote script, ask three questions. Is the content pinned to a known version? Is its integrity checked against something the download server does not control? What can it read when it runs?

### Insight

Downloading a checksum from the same server as the script proves nothing, because an attacker who can change one can change the other. The expected hash must live in your repository, or the artefact must carry a signature tied to the vendor's identity.

### Practical

- Prefer vendors that publish versioned release artefacts with signatures or build provenance over a mutable `install.sh`.
- Check whether the vendor offers a package (apt, Homebrew, a pinned GitHub Action) as an alternative to the script.
- Check whether secrets are set at job level when only one step needs them.

### Tools/Techniques

- [OpenSSF Scorecard](https://scorecard.dev/) for the vendor's repository: look at "Signed-Releases" and "Pinned-Dependencies".
- `gh release view` to see whether a vendor publishes checksums, signatures or attestations with each release.

### Metrics/Signal

- Percentage of remote installs with a pinned version and a pinned hash or signature check.
- Steps with secrets they do not use.
:::

::: {! stage fortify}
## Fortify

### Explanation

Replace pipe-to-shell with download, verify, then run. Pin the version and the expected hash in your repository.

### Insight

Verification turns a silent compromise into a failed build. The Codecov tampering was caught by exactly this kind of hash comparison.

### Practical

- Pin version and SHA-256 in your repository and check before executing:

    ```bash
    set -euo pipefail
    VERSION=1.4.2
    SHA256=3f5c...e9a1   # copied from the vendor's signed release notes, committed to the repo
    curl -fsSLo tool.tar.gz \
      "https://github.com/example/tool/releases/download/v${VERSION}/tool_linux_amd64.tar.gz"
    echo "${SHA256}  tool.tar.gz" | sha256sum -c -
    tar -xzf tool.tar.gz tool
    ./tool upload
    ```

- Where the vendor signs releases with Sigstore, verify the signer identity as well as the bytes:

    ```bash
    cosign verify-blob tool.tar.gz \
      --bundle tool.tar.gz.sigstore.json \
      --certificate-identity "https://github.com/example/tool/.github/workflows/release.yml@refs/tags/v1.4.2" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    ```

- Where the vendor uses GitHub artifact attestations:

    ```bash
    gh attestation verify tool.tar.gz --repo example/tool
    ```

- Prefer a vendor's official GitHub Action or CircleCI Orb pinned to a full commit SHA or a pinned orb version, and check that it verifies its own downloads.
- Add a CI lint that blocks new pipe-to-shell lines. A valid Semgrep rule:

    ```yaml
    rules:
      - id: curl-pipe-shell
        languages: [generic]
        severity: WARNING
        message: Download, verify a pinned checksum or signature, then execute.
        pattern-regex: (curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b
    ```

### Tools/Techniques

- `sha256sum -c`, [cosign](https://docs.sigstore.dev/cosign/verifying/verify/), [`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify).
- Semgrep with the rule above, run on pull requests.

### Metrics/Signal

- Pipe-to-shell occurrences trending to zero.
- Builds failed by checksum or signature mismatch (each one needs investigating).
:::

::: {! stage limit}
## Limit

### Explanation

If a downloaded tool turns hostile, it should find one narrowly scoped token and no route to the attacker.

### Insight

The Codecov script stole everything in the environment because everything was in the environment. Step-level secrets would have reduced the haul to a single upload token.

### Practical

- Scope secrets to the step that uses them, not the job:

    ```yaml
    - name: Upload coverage
      run: ./tool upload
      env:
        VENDOR_TOKEN: ${{ secrets.VENDOR_TOKEN }}
    ```

- Run third-party uploaders in a separate job that receives only the coverage file as an artefact, with no cloud credentials and `permissions: {}`.
- Use OIDC federation for cloud access so there are no static keys to steal.
- Restrict runner egress to the hosts each job needs.

### Tools/Techniques

- GitHub Actions step-level `env`, job-level `permissions`, environments with required reviewers.
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) in `block` mode with an allowed-endpoints list.

### Metrics/Signal

- Jobs that run third-party tools alongside cloud or deploy credentials.
- Long-lived cloud keys still stored as CI secrets.
:::

::: {! stage expose}
## Expose

### Explanation

Detect a changed installer, and detect an installer that phones somewhere new.

### Insight

Mutable scripts change without warning. Recording the hash of what you executed gives you something to compare when an advisory lands.

### Practical

- Log the SHA-256 of every downloaded script or binary in the job output before running it.
- Alert on egress from CI to hosts outside the job's allow list.
- Subscribe to security advisories for every vendor whose tools run in your pipeline.
- When a vendor discloses a compromise, search your logged hashes and job history for the exposure window, then rotate every secret those jobs could see.

### Tools/Techniques

- Harden-Runner in `audit` mode to baseline outbound endpoints per job.
- CI log search for recorded hashes and download URLs.

### Metrics/Signal

- Unexpected outbound destinations from CI per week.
- Time from a vendor advisory to completed credential rotation.
:::

::: {! stage exercise}
## Exercise

### Explanation

Prove that your pipeline refuses a tampered installer, using a harmless one you control.

### Insight

The test is cheap: serve a script locally, change it, and see whether the build stops.

### Practical

1. In a sandbox repository, serve `install.sh` from a local web server in the CI job (`python3 -m http.server`).
2. Commit its SHA-256 and switch the job to the download-verify-run pattern.
3. Append a line that calls a [Canarytokens](https://canarytokens.org) URL. Run the job and confirm the checksum step fails before the script runs.
4. Remove the checksum check, run again, and confirm egress monitoring flags the canary call.
5. Open a pull request that adds a new `curl ... | bash` line and confirm the Semgrep rule blocks it.

### Tools/Techniques

- A local HTTP server and a sandbox CI project.
- Canarytokens for a harmless callback.

### Metrics/Signal

- Whether each control fired as expected.
- Time for the team to notice the egress alert.
:::

## Further Reading

- [Codecov security update (April 2021)](https://about.codecov.io/security-update/)
- [CISA: Codecov releases security update](https://www.cisa.gov/news-events/alerts/2021/04/22/codecov-releases-security-update)
- [Sigstore: verifying signatures with cosign](https://docs.sigstore.dev/cosign/verifying/verify/)
- [GitHub CLI: gh attestation verify](https://cli.github.com/manual/gh_attestation_verify)
