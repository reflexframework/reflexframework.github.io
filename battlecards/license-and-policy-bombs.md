---
title: Licence Changes and Protestware
category: Supply Chain Integrity
scenario: A routine upgrade changes your legal and operational risk
focus:
  - relicensing to source-available licences
  - licence policy gates in CI
  - protestware and maintainer sabotage
  - runtime and tooling licence terms
---

## Scenario

LedgerLoop sells a hosted reconciliation service. Its stack includes an Apache-2.0 actor framework, an Apache-2.0 infrastructure tool, and a few hundred npm packages. Renovate auto-merges minor and patch upgrades when tests pass.

Three things happen over a year.

1. The actor framework's next minor release moves to the Business Source License (BSL 1.1). The licence allows production use only under limits that LedgerLoop's hosted service does not meet. Renovate opens the PR, tests pass, and it merges. Nobody reads `LICENSE`.
2. A transitive npm dependency publishes a patch release that prints an endless stream of garbage on import. Its maintainer did it on purpose, as a protest. The build passes because the tests mock that module, and the release takes down a worker fleet.
3. Finance receives a quote for Oracle Java SE subscriptions priced per employee. Someone installed Oracle JDK on the build servers years ago.

During acquisition due diligence the buyer's lawyers find the BSL dependency. The deal stalls while LedgerLoop pins back to the last Apache-2.0 version and replaces the framework.

**Real-world precedent:** Lightbend moved [Akka to BSL 1.1 in September 2022](https://www.lightbend.com/blog/why-we-are-changing-the-license-for-akka), and the community forked the last Apache release as Apache Pekko. HashiCorp moved Terraform to BSL in August 2023, prompting the OpenTofu fork, and [Redis changed licence in March 2024](https://redis.io/blog/redis-adopts-dual-source-available-licensing/), prompting Valkey. In January 2022 the maintainer of `colors` and `faker` [sabotaged both packages](https://snyk.io/blog/open-source-npm-packages-colors-faker/), and in March 2022 `node-ipc` shipped protestware that overwrote files on machines with Russian or Belarusian IP addresses ([CVE-2022-23812](https://nvd.nist.gov/vuln/detail/CVE-2022-23812)). On the tooling side, Oracle moved Java SE subscriptions to per-employee pricing in January 2023.

::: {! stage recon}
## Reconnaissance

### Explanation

Nobody is attacking you here in the usual sense. The "adversary" is a change you did not notice: a vendor's commercial pressure, a burnt-out maintainer, or a pricing model. Reconnaissance is your own: know which components have a single company or a single person behind them, because those are the ones that can change the rules.

Single-vendor open source projects are the usual candidates for relicensing. MongoDB moved to the SSPL in 2018, Elastic moved Elasticsearch and Kibana to SSPL and the Elastic License in 2021, then added AGPL as an option in 2024. Single-maintainer packages with huge download counts are the usual candidates for sabotage.

### Insight

A project's licence describes the version you have. It says nothing binding about the next one. Previous releases keep the licence they shipped with, which is why forks like OpenTofu, Valkey and Pekko were possible.

### Practical

- List your direct dependencies and, for each, who controls the copyright: a foundation, a single company, or one person.
- Flag single-vendor projects that also sell a hosted version of the same thing. That is the commercial pattern behind most relicensing.
- Flag packages with one maintainer and very wide use.
- List the runtimes and build tools you run, including JDK distributions, and their licence terms.

### Tools/Techniques

- [deps.dev](https://deps.dev/) for licence, repository and maintainer data per package.
- [OpenSSF Scorecard](https://scorecard.dev/) for maintenance signals.
- `java -XshowSettings:properties -version 2>&1 | grep java.vendor` on build agents to find Oracle JDK installs.

### Metrics/Signal

- Direct dependencies controlled by a single company that sells a competing hosted service.
- Build agents or containers running a JDK distribution you have not chosen on purpose.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Find out what licences you ship today, transitive dependencies included, and whether anything checks licences when they change. Most teams check once, at adoption, and never again.

Be clear about the stakes. With SSPL, AGPL or BSL, non-compliance generally exposes you to termination of your licence and a copyright infringement claim, with damages or an injunction. A licensor cannot simply force you to publish your source code. The practical cost is usually a rushed migration, a commercial licence, or a stalled deal. I'm a developer and this card is written from that seat, so treat it as background rather than legal advice. Talk to your legal team about your own obligations.

### Insight

Upgrade automation is where licence drift gets in. A bot that merges green builds will merge a licence change without blinking, because nothing in the build fails.

### Practical

- Generate an SBOM with licence data for each service and compare it with your policy.
- Check whether your dependency PRs run any licence gate.
- Check which licence your pinned version of each key dependency uses, and which licence the latest version uses. A difference is an early warning.

```bash
# CycloneDX SBOM for a Maven project, then list licences
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
jq -r '.components[] | [.name, .version, (.licenses[0].license.id // .licenses[0].license.name // "UNKNOWN")] | @tsv' \
    target/bom.json | sort -k3
```

### Tools/Techniques

- CycloneDX plugins for Maven, Gradle and npm, or [Syft](https://github.com/anchore/syft).
- [ScanCode Toolkit](https://github.com/aboutcode-org/scancode-toolkit) to detect licences from the files themselves as well as package metadata.
- [OSS Review Toolkit (ORT)](https://github.com/oss-review-toolkit/ort) for whole-project licence analysis against a policy.

### Metrics/Signal

- Components with unknown or missing licence data.
- Components whose latest release uses a different licence from the one you run.
:::

::: {! stage fortify}
## Fortify

### Explanation

Put a licence gate on every dependency change, slow down upgrades enough for the community to spot sabotage, and choose components and runtimes whose terms you control.

### Insight

An allowlist ages better than a denylist. New source-available licences keep appearing, and an allowlist fails safe on all of them.

### Practical

- Add GitHub's dependency review to pull requests with `allow-licenses`. The `deny-licenses` input still works but is deprecated.

```yaml
name: Dependency review
on: [pull_request]
permissions:
    contents: read
    pull-requests: write
jobs:
    review:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v6
            - uses: actions/dependency-review-action@v5
              with:
                  allow-licenses: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, EPL-2.0
                  comment-summary-in-pr: on-failure
```

Pin both actions to a full commit SHA in practice.

- Run ORT or ScanCode on a schedule for the full tree, since dependency review only sees what a PR changes.
- Add a release-age delay so sabotaged releases are usually caught and pulled before you take them:

```json
{
    "minimumReleaseAge": "3 days",
    "packageRules": [
        {
            "matchUpdateTypes": ["major"],
            "automerge": false
        }
    ]
}
```

- In pnpm, set `minimumReleaseAge` in `pnpm-workspace.yaml` for the same effect at install time.
- Standardise on an OpenJDK distribution with terms you have read, such as Eclipse Temurin, and pin it in Dockerfiles and toolchain configuration.
- When a key dependency relicenses, pin the last acceptable version and plan a move to the fork or an alternative.

### Tools/Techniques

- [dependency-review-action](https://github.com/actions/dependency-review-action).
- Renovate `minimumReleaseAge`, pnpm `minimumReleaseAge`.
- ORT policy rules, ScanCode.

### Metrics/Signal

- Dependency PRs that ran a licence gate, as a percentage of all dependency PRs.
- Exceptions granted to the licence allowlist, each with an owner and an expiry date.
:::

::: {! stage limit}
## Limit

### Explanation

When a bad licence or a sabotaged release gets through, limit how far it spreads and how hard it is to undo. Lockfiles and pinned versions let you go back quickly. Good boundaries let you replace one component without touching the rest.

### Insight

A component hidden behind your own interface can be swapped in a sprint. One whose types leak through your entire codebase is a year of work.

### Practical

- Commit lockfiles and install with `npm ci`, `pnpm install --frozen-lockfile` or equivalent, so a sabotaged release cannot appear without a PR.
- Wrap heavyweight dependencies behind your own interfaces, so a relicensed library is a contained replacement.
- Keep a record of the last known-good version and licence for each critical dependency.
- Keep a rollback path for production deploys that does not require a fresh dependency install.

### Tools/Techniques

- Lockfiles and frozen installs.
- Architecture tests, for example ArchUnit, that stop framework types leaking across module boundaries.

### Metrics/Signal

- Time to roll back a bad dependency upgrade in production.
- Modules that import a given third-party framework directly.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for licence changes and odd releases in the components you already run. Both show up first in upstream repositories and advisories, before they reach you.

### Insight

Relicensing is usually announced in a blog post weeks before the release. Someone on the team reading the release notes of your top twenty dependencies would have seen most of these coming.

### Practical

- Fail the scheduled ORT or SBOM licence job when any component's licence changes between runs, and post the diff to the team channel.
- Subscribe to release notes and GitHub releases for your top dependencies.
- Watch for protestware signals: a release from a single maintainer that adds network calls, geolocation, file writes or infinite loops.
- Track Oracle JDK binaries on hosts and images with your inventory or SBOM tools.

### Tools/Techniques

- SBOM diffing between builds.
- Socket and similar tools that flag behaviour changes such as new network or filesystem access in a release.
- GitHub "Watch → Custom → Releases" on key upstream repositories.

### Metrics/Signal

- Licence changes detected per quarter, and time from detection to decision.
- Releases flagged for behaviour changes in your dependency tree.
:::

::: {! stage exercise}
## Exercise

### Explanation

Check the licence gate and the release-age delay work by triggering them on purpose in a sandbox.

### Insight

The exercise also tests your decision path. Someone has to decide what happens when the gate fires on a library you cannot easily drop.

### Practical

1. In a scratch repository, open a PR that adds a dependency licensed `BUSL-1.1` or `SSPL-1.0`. Confirm dependency review fails the PR.
2. Run a local Verdaccio registry, publish a benign package with a new version that prints a warning on import, and check that your release-age setting holds it back.
3. Pick one key dependency and write down, in an hour, how you would replace it if it relicensed tomorrow.
4. Agree who approves licence exceptions, and how quickly.

### Tools/Techniques

- A private scratch repository with your standard workflows.
- [Verdaccio](https://verdaccio.org/) as a local npm registry.

### Metrics/Signal

- Whether the gate fired, and how long the exception decision took.
- Key dependencies with a written replacement plan.
:::

## Further Reading

- [Lightbend: Why we are changing the licence for Akka (2022)](https://www.lightbend.com/blog/why-we-are-changing-the-license-for-akka)
- [Linux Foundation: Valkey launch (2024)](https://www.linuxfoundation.org/press/linux-foundation-launches-open-source-valkey-community)
- [OpenTofu](https://opentofu.org/)
- [Snyk: colors and faker sabotage (2022)](https://snyk.io/blog/open-source-npm-packages-colors-faker/)
- [GitHub dependency-review-action](https://github.com/actions/dependency-review-action)
- [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort)
