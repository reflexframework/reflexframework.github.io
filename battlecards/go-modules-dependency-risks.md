---
title: Go Modules Dependency Risks
category: Package Ecosystems
scenario: Typosquatted and repo-jacked Go modules
focus:
  - typosquatted module paths
  - module proxy caching
  - repo-jacking and expired vanity domains
  - private module path leakage
---

## Scenario

Go has no central account-based registry. A module path is a location: `github.com/boltdb/bolt` means "fetch this from that GitHub repository", and a vanity path such as `go.example.com/lib` is resolved by fetching a page and reading its `go-import` meta tag. The public module proxy (`proxy.golang.org`) caches the first copy of each version it sees, and the checksum database (`sum.golang.org`) records its hash for everyone.

That design gives Go strong guarantees about *consistency*. It says nothing about whether the code you asked for is the code you meant.

1. A developer adds an embedded key-value store and pastes `github.com/boltdb-go/bolt` from a search result. The real module is `github.com/boltdb/bolt`.
2. The look-alike works. It also starts a goroutine from `init()` that connects to a remote server and runs commands it receives.
3. Nothing happens during `go build`. The backdoor wakes up the first time the service or its tests run, on a laptop, in CI and in production.
4. Someone on the team checks the GitHub repository for `boltdb-go/bolt` and finds clean code. The attacker has repointed the git tag. The proxy still serves the original, backdoored copy it cached years ago.

A second path needs no typo. A transitive dependency lives at `github.com/olduser/retry`. The maintainer renames their GitHub account. An attacker registers `olduser`, recreates the repository, and tags `v1.5.0`. The next `go get -u ./...` pulls it in. The same thing happens when a vanity domain's registration lapses and someone else buys it and serves a new `go-import` tag.

**Real-world precedent:** In February 2025 Socket disclosed that [`github.com/boltdb-go/bolt`](https://socket.dev/blog/malicious-package-exploits-go-module-proxy-caching-for-persistence), a typosquat of BoltDB, had been served with a remote-access backdoor by the Go module proxy since November 2021, while its GitHub tags pointed at clean code. In December 2023 [VulnCheck reported](https://www.vulncheck.com/blog/go-repojacking) roughly 15,000 Go module repositories exposed to repo-jacking through GitHub username changes and deleted accounts.

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers look for module paths that are easy to misremember (`boltdb-go/bolt`, `bolt-db/bolt`), maintainers who have renamed or deleted GitHub accounts, and vanity domains close to expiry. They also read public `go.mod` files to see which modules your organisation depends on, and they watch for private module paths that leak into the public proxy and checksum database.

### Insight

Because the proxy caches modules indefinitely, an attacker only needs to win once. A malicious version fetched through the proxy a single time stays available long after the source repository has been cleaned up. Reviewing the GitHub repository is not the same as reviewing the module you downloaded.

### Practical

- List every module path in your `go.mod` files whose host is GitHub, and check that each owner still exists under that name.
- List every vanity path (`go.example.com/...`) and check who owns the domain and when it expires.
- If you have renamed a GitHub organisation or user, recreate the old name as a placeholder so nobody else can claim it.
- Set `GOPRIVATE` for your internal paths. Without it, the `go` command asks the public proxy and checksum database about them, which tells the world your internal module names.

### Tools/Techniques

- [pkg.go.dev](https://pkg.go.dev): check a module's importers, license and source link before adding it.
- `go list -m all` to enumerate every module in your build.
- `go mod why -m <module>` to see why a module is in your graph.
- `whois` or your registrar's API for vanity domain expiry dates.

### Metrics/Signal

- Number of dependencies hosted under GitHub accounts that have been renamed or deleted.
- Number of vanity domains in your graph that expire within 90 days.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check how new modules enter your graph and what they can do once there. Go builds do not run dependency code: there are no install scripts, and `init()` runs only when a binary or test binary runs. That moves the risk to `go test` in CI and to production.

### Insight

`go.sum` and the checksum database prove you received the same bytes as everyone else. They do not prove those bytes are benign, and `go.sum` does not record where a module came from. In the boltdb-go case, the checksum database faithfully certified the backdoored version.

### Practical

- Review every pull request that adds a new line to the `require` block of `go.mod`. Check the path character by character against the project's official docs.
- Run `go mod tidy -diff` (Go 1.23+) in CI so unexpected graph changes fail the build.
- Check what a new dependency is capable of: network access, `os/exec`, file writes. A logging or storage library that opens outbound sockets is a red flag.
- Check whether any CI job sets `GOSUMDB=off`, `GOINSECURE`, `GOFLAGS=-mod=mod`, or a `GONOSUMDB` pattern broad enough to cover public modules. Each one weakens your defences.

### Tools/Techniques

- [Capslock](https://github.com/google/capslock): reports the capabilities (network, exec, files) a Go package can reach.
- [govulncheck](https://go.dev/doc/security/vuln/): checks your code against the Go vulnerability database, which also records malicious modules once reported.
- [OpenSSF Scorecard](https://scorecard.dev/) for the health of the source repository.

### Metrics/Signal

- New modules added per month and the percentage that had a named reviewer.
- Number of CI jobs that disable checksum verification.
:::

::: {! stage fortify}
## Fortify

### Explanation

Lock the module graph, keep internal paths private, and make toolchain selection explicit.

### Insight

The `go` command already does a lot for you. Since Go 1.16, build and test commands default to `-mod=readonly`, so they fail rather than silently editing `go.mod`. The job is to stop people turning these defaults off and to add the review step Go cannot do for you.

### Practical

- Configure private modules once, in the environment or `go env -w`:

    ```bash
    go env -w GOPRIVATE='github.com/acme-internal/*,go.acme.example/*'
    # GOPRIVATE implies GONOPROXY and GONOSUMDB for these paths
    ```

- Pin the toolchain in CI so a `toolchain` line in `go.mod` cannot trigger a download you did not plan for:

    ```bash
    export GOTOOLCHAIN=local
    export GOFLAGS=-mod=readonly
    go mod verify
    go build ./...
    ```

- Upgrade dependencies deliberately (`go get example.com/mod@v1.4.2`) rather than with a blanket `go get -u ./...`. Use Renovate or Dependabot so each bump is its own reviewable pull request.
- If you run an internal proxy such as Athens or Artifactory, configure it to serve only modules you have approved, and keep `GOSUMDB` enabled for public paths.
- For vanity paths you own, keep the domain on auto-renew with registrar lock enabled.

### Tools/Techniques

- `go mod verify`, `go mod tidy -diff`, `GOTOOLCHAIN=local`.
- [Athens](https://docs.gomods.io/) or a commercial repository manager as a curated `GOPROXY`.
- Renovate with `minimumReleaseAge` so brand-new versions wait before a PR is opened.

### Metrics/Signal

- Percentage of repositories with `GOPRIVATE` set in CI.
- Dependency updates merged through individual reviewed PRs versus bulk `go get -u`.
:::

::: {! stage limit}
## Limit

### Explanation

The boltdb-go payload ran wherever the program ran. Limit what a compromised dependency can reach in tests and in production.

### Insight

Most Go services have no reason to open arbitrary outbound connections. A default-deny egress policy turns a working backdoor into a failed connection attempt and a log line.

### Practical

- Run `go test` in CI with no deployment or cloud credentials in scope.
- In Kubernetes, apply a default-deny egress `NetworkPolicy` and allow only the services each workload needs.
- Ship Go services in minimal images (distroless or `scratch`) so a backdoor has no shell or tools to call.
- Give each service its own narrowly scoped cloud identity instead of a shared role.

### Tools/Techniques

- Kubernetes `NetworkPolicy`, or Cilium FQDN-aware egress policies.
- Distroless or `scratch` base images for static Go binaries.

### Metrics/Signal

- Workloads with default-deny egress versus total workloads.
- Blocked egress attempts per service.
:::

::: {! stage expose}
## Expose

### Explanation

Detect a bad module after the fact, both in your graph and in running behaviour.

### Insight

The Go vulnerability database is updated when malicious modules are reported. A scheduled `govulncheck` run against `main` catches modules that were clean on the day you merged them and flagged later.

### Practical

- Run `govulncheck ./...` on a schedule, as well as on pull requests.
- Generate an SBOM for each build and keep it, so you can answer "do we use `boltdb-go/bolt` anywhere?" in minutes.
- Alert on outbound connections from services to destinations outside their allow list.
- Alert when a module path in your graph changes host or owner between releases.

### Tools/Techniques

- `govulncheck` in a scheduled workflow.
- [Syft](https://github.com/anchore/syft) or `cyclonedx-gomod` for SBOMs, and [OSV-Scanner](https://google.github.io/osv-scanner/) to check them.
- Egress logs from your service mesh, CNI or cloud firewall.

### Metrics/Signal

- Time from a Go vulnerability database entry to your alert.
- Unexpected outbound connections per service per week.
:::

::: {! stage exercise}
## Exercise

### Explanation

Rehearse catching a look-alike module without publishing anything publicly.

### Insight

A `replace` directive lets you swap in a local copy of any module, so you can test review and egress controls safely.

### Practical

1. In a sandbox repository, add a dependency on a real module, then add `replace github.com/boltdb/bolt => ../bolt-lookalike` pointing at a local copy.
2. In the local copy, add an `init()` that makes one HTTPS request to a [Canarytokens](https://canarytokens.org) URL.
3. Open a pull request. Check that review catches the `replace` line.
4. Run the tests in a sandbox CI job with default-deny egress. Confirm the request is blocked and logged.
5. Separately, run Capslock on the look-alike and confirm it reports network capability.

### Tools/Techniques

- `replace` directives in a throwaway branch.
- [Canarytokens](https://canarytokens.org) for a harmless callback.

### Metrics/Signal

- Whether the pull request was blocked, and by which check.
- Whether the egress block produced an alert someone saw.
:::

## Further Reading

- [Go Supply Chain Attack: Malicious Package Exploits Go Module Proxy Caching for Persistence (Socket, February 2025)](https://socket.dev/blog/malicious-package-exploits-go-module-proxy-caching-for-persistence)
- [Go Repojacking (VulnCheck, December 2023)](https://www.vulncheck.com/blog/go-repojacking)
- [Go Modules Reference: private modules](https://go.dev/ref/mod#private-modules)
- [Go Toolchains](https://go.dev/doc/toolchain)
- [Go vulnerability management](https://go.dev/doc/security/vuln/)
