---
title: Rust Crates Supply Chain
category: Package Ecosystems
scenario: Typosquatted crate with a build script payload
focus:
  - typosquatted crates on crates.io
  - build.rs and proc-macro code execution
  - runtime secret and key theft
---

## Scenario

A team builds a payments service in Rust. A developer needs decimal arithmetic and types `cargo add rustdecimal` from memory. The real crate is `rust_decimal`. crates.io treats `-` and `_` as the same name, so an attacker cannot register `rust-decimal`, but a dropped underscore is a different name entirely.

The look-alike crate copies the real source, docs and features. It works. It also ships a `build.rs` that runs on every `cargo build`, `cargo check` and `cargo test`, including the automatic build-script runs rust-analyzer does when the developer opens the project in their editor.

1. On the laptop, `build.rs` reads `~/.cargo/credentials.toml`, `~/.aws/credentials` and any `.env` file it can find.
2. In CI, it checks for `GITLAB_CI` or `GITHUB_ACTIONS` and dumps environment variables, including a crates.io publish token.
3. It posts the haul to an endpoint dressed up as a legitimate API, then lets the build finish normally.

Nothing fails. The tests pass. The first sign of trouble is a new release of one of the team's own crates that nobody on the team published.

**Real-world precedent:** In May 2022 the Rust Security Response WG removed [`rustdecimal`](https://blog.rust-lang.org/2022/05/10/malicious-crate-rustdecimal/), a typosquat of `rust_decimal` that downloaded and ran a payload when `GITLAB_CI` was set. In September 2025 crates.io removed [`faster_log` and `async_println`](https://blog.rust-lang.org/2025/09/24/crates.io-malicious-crates-fasterlog-and-asyncprintln/), copies of a real logging crate that scanned files for Solana and Ethereum private keys at runtime and exfiltrated them over HTTP.

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers pick names that developers will mistype or half-remember: dropped separators (`rustdecimal`), plausible suffixes (`-rs`, `-utils`), or a crate that sounds like a companion to a popular one. They copy the real crate's README and code so the crates.io page looks right. Public `Cargo.toml` files on GitHub tell them which crates your organisation uses and which internal crate names exist.

### Insight

Rust runs dependency code earlier than many developers expect. Build scripts (`build.rs`) and procedural macros are ordinary Rust programs that execute on the build host with your user's permissions. `cargo fetch` only downloads; `cargo build`, `cargo check`, `cargo test` and your IDE's language server all execute. The September 2025 crates show the other path: payloads that wait until your code runs and then read your files.

### Practical

- Add dependencies with `cargo add` from a link you copied off the real project's README or docs.rs page, rather than from memory.
- Search your public repositories for `Cargo.toml` files that mention internal crate names. If an internal name is free on crates.io, consider reserving it.
- Note which of your direct dependencies have `build.rs` or are proc-macro crates. That list is your build-time attack surface.

### Tools/Techniques

- [crates.io](https://crates.io) crate pages: check owners, publish dates, repository link and download history before adding a crate.
- `cargo tree -e build` and `cargo tree -e normal,build --prefix depth` to see which crates feed build scripts.
- [RustSec advisory database](https://rustsec.org/advisories/) for crates already flagged as malicious or unmaintained.

### Metrics/Signal

- Count of direct dependencies whose crates.io owner or repository you have not checked.
- Count of crates in `Cargo.lock` that ship a `build.rs` or are proc macros.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Look at how crates enter your tree and what they can reach when they run. Is `Cargo.lock` committed and enforced in CI? Can a developer add a dependency without review? Does the CI job that runs `cargo test` also hold a crates.io token, cloud credentials or a deploy key?

### Insight

`Cargo.lock` pins exact versions and checksums. It stops silent drift, but it faithfully locks in a malicious crate if someone added it on purpose. The real control is review at the moment a new crate name appears in the lockfile diff.

### Practical

- Commit `Cargo.lock` for applications and libraries alike, and build with `--locked` in CI so a stale lockfile fails the build.
- Treat any lockfile diff that adds a new crate name as a review item, separate from version bumps.
- List the secrets available to the job that compiles and tests code. Ask whether each one is needed at that step.

### Tools/Techniques

- [`cargo-vet`](https://mozilla.github.io/cargo-vet/): records which crate versions someone has audited and lets you import audits from organisations such as Mozilla and Google.
- [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/): checks advisories, banned crates, licences and allowed sources in one pass.
- [`cargo-audit`](https://rustsec.org/): checks `Cargo.lock` against RustSec, including malware advisories.

### Metrics/Signal

- Percentage of crates in `Cargo.lock` covered by a `cargo-vet` audit or exemption.
- Number of CI jobs that run `cargo build` or `cargo test` with publish or cloud credentials in scope.
:::

::: {! stage fortify}
## Fortify

### Explanation

Make it hard for an unreviewed crate to land, and make your own publishing pipeline worth less to steal from.

### Insight

The token theft in this scenario only pays off if the token is long-lived. crates.io trusted publishing (launched July 2025) swaps stored API tokens for short-lived ones minted by OIDC from your CI workflow, so there is nothing durable to steal from the build environment.

### Practical

- Gate new crates in CI with `cargo vet` and `cargo deny check`. A `deny.toml` that restricts sources stops someone pointing a dependency at a random git repository:

    ```toml
    [sources]
    unknown-registry = "deny"
    unknown-git = "deny"
    allow-registry = ["https://github.com/rust-lang/crates.io-index"]

    [advisories]
    yanked = "deny"
    ```

- Move crate publishing to [trusted publishing](https://crates.io/docs/trusted-publishing) and revoke the old API tokens:

    ```yaml
    jobs:
      publish:
        runs-on: ubuntu-latest
        environment: release
        permissions:
          id-token: write
          contents: read
        steps:
          - uses: actions/checkout@v5
          - uses: rust-lang/crates-io-auth-action@v1
            id: auth
          - run: cargo publish
            env:
              CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}
    ```

- Pin third-party actions in that workflow to a commit SHA rather than a tag.
- Build release binaries with [`cargo auditable build`](https://github.com/rust-secure-code/cargo-auditable) so the dependency list is embedded in the binary and can be checked later with `cargo audit bin`.

### Tools/Techniques

- `cargo vet`, `cargo deny`, `cargo audit`.
- [`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable) for dependency metadata in shipped binaries.
- [Renovate](https://docs.renovatebot.com/) with `minimumReleaseAge` so brand-new crate versions wait a few days before a PR is opened.

### Metrics/Signal

- Number of remaining long-lived crates.io API tokens in your organisation.
- CI fails when a lockfile adds an unaudited crate.
:::

::: {! stage limit}
## Limit

### Explanation

Assume a malicious `build.rs` will run one day. Decide in advance what it can see and where it can send it.

### Insight

Compile and test steps do not need publish tokens or deploy credentials. Split them out, and the build-time payload in this scenario finds an empty environment.

### Practical

- Run `cargo build` and `cargo test` in a job with no secrets. Publish and deploy in a separate job that consumes the built artefact and does not compile untrusted code.
- Fetch dependencies in one step with network access (`cargo fetch --locked`), then build with `cargo build --offline --locked` in a step or container with egress blocked.
- Keep cloud and registry credentials out of developer home directories where possible. Use short-lived SSO sessions instead of static keys in `~/.aws/credentials`.
- For local work on unfamiliar code, open it in a dev container or VM so rust-analyzer's build-script runs happen away from your real credentials.

### Tools/Techniques

- GitHub Actions `environment` protection rules and job-level `permissions` to keep secrets out of build jobs.
- Container network policies or `--network none` for the offline build step.

### Metrics/Signal

- Build jobs with zero secrets in scope versus total build jobs.
- Outbound connections attempted during the offline build step (should be none).
:::

::: {! stage expose}
## Expose

### Explanation

Detect the crate arriving, and detect it acting.

### Insight

Both precedents were found by people reading code or by registry-side scanning. Your best early signal is the lockfile diff and the advisory feed. Your best late signal is a build that talks to the internet when it should not.

### Practical

- Run `cargo audit` on a schedule against `main`, not only on pull requests, so a newly published RustSec malware advisory reaches you even when the code has not changed.
- Alert on outbound network connections from build jobs to destinations outside your registry and mirror.
- Watch crates.io for releases of your own crates and alert on any version your release workflow did not produce.

### Tools/Techniques

- `cargo audit` or [OSV-Scanner](https://google.github.io/osv-scanner/) in a scheduled workflow.
- Runner egress monitoring such as [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) on GitHub Actions.
- `cargo audit bin` against deployed binaries built with `cargo-auditable`.

### Metrics/Signal

- Time between a RustSec malware advisory and your alert.
- Unexpected outbound connections per week from build jobs.
:::

::: {! stage exercise}
## Exercise

### Explanation

Prove that your controls catch a look-alike crate and a noisy build script, without touching crates.io.

### Insight

You do not need a real malicious crate to test this. A harmless crate in a private git repository exercises the same machinery. Path dependencies are skipped by `cargo-deny` source checks, so use git.

### Practical

1. Create a crate called `rustdecimal` in a private repository on your internal git server. Give it a `build.rs` that makes a single HTTPS request to a [Canarytokens](https://canarytokens.org) URL.
2. On a throwaway branch, add `rustdecimal = { git = "https://git.internal.example/sandbox/rustdecimal" }`.
3. Open a pull request. Check that `cargo deny check sources` fails on the unknown git source, and that a reviewer spots the new crate name in the lockfile diff.
4. Force the build through in a sandbox job. Check that the canary fires only where you expect, and that egress monitoring records the call.
5. Delete the branch and the repository when done.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org) for a harmless "secret" and callback.
- A sandbox CI project with the same job layout as production.

### Metrics/Signal

- Whether the pull request was blocked, and by which check.
- Time from the canary firing to someone on the team noticing.
:::

## Further Reading

- [Security advisory: malicious crate rustdecimal (Rust blog, May 2022)](https://blog.rust-lang.org/2022/05/10/malicious-crate-rustdecimal/)
- [crates.io: Malicious crates faster_log and async_println (Rust blog, September 2025)](https://blog.rust-lang.org/2025/09/24/crates.io-malicious-crates-fasterlog-and-asyncprintln/)
- [crates.io trusted publishing documentation](https://crates.io/docs/trusted-publishing)
- [cargo-vet book](https://mozilla.github.io/cargo-vet/)
- [The Cargo Book: build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
