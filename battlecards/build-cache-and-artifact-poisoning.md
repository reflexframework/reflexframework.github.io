---
title: Build Cache and Artifact Poisoning
category: CI/CD & Build
scenario: Poisoned build cache entry becomes a published release
focus:
  - remote build cache writes from untrusted machines
  - CI cache poisoning across workflows
  - provenance for published artifacts
---

## Scenario

Your company builds an internal Java library, `com.example:auth-client`, used by about forty services. Its CI pipeline builds with Gradle, uses a shared Develocity remote build cache, and publishes the JAR to Artifactory. The services resolve `auth-client` from Artifactory like any other dependency.

To speed up local builds, every developer's machine is allowed to write to the remote cache.

1. An attacker compromises one developer's laptop with an infostealer.
2. They modify the Gradle installation on that laptop so `compileJava` adds a small payload to one class. The task's inputs (sources, classpath, compiler version) are unchanged, so its cache key is unchanged.
3. The developer builds `auth-client` as usual. Gradle stores the poisoned class files in the remote cache under the legitimate key.
4. The next CI build of `auth-client` gets a cache hit, skips compilation and packages the poisoned classes. CI publishes the JAR to Artifactory.
5. Forty services pick up the new version on their next dependency update. Every build log looks normal.

The build cache never checks how an output was produced. A matching key is the only test.

**Real-world precedent:** On 11 May 2026, an attacker published 84 malicious versions of 42 `@tanstack/*` npm packages ([TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)). A fork pull request triggered a `pull_request_target` workflow that ran the fork's code. That code wrote a poisoned pnpm store into the Actions cache under the key the release workflow would compute from the lockfile. Hours later the release workflow restored it, and the payload read the OIDC token from the runner's memory and published straight to npm. The releases carried valid provenance, because they really did come from the release workflow. Earlier, in the SolarWinds attack, the [SUNSPOT implant](https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/) sat on the build server and swapped a source file during compilation, so signed Orion releases shipped the SUNBURST backdoor (discovered December 2020). In December 2024, the first malicious [Ultralytics releases](https://blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection) were very likely built from a GitHub Actions cache poisoned by an earlier injected workflow run.

::: {! stage recon}
## Reconnaissance

### Explanation
The attacker needs to know which machines can write to the caches your release builds trust. Build configuration usually tells them.

### Insight
Caches are trusted implicitly. Anything that can write to a cache your release build reads is effectively part of your release pipeline.

### Practical
- Find every cache your release builds read: Gradle remote build cache, Bazel remote cache, GitHub Actions `actions/cache` and `setup-*` caches, Docker layer caches.
- For each one, list who and what can write to it.
- Check `settings.gradle.kts` for `isPush = true` without a CI condition.

### Tools/Techniques
- `grep -rn "isPush\|push = true" settings.gradle*` to find unconditional cache pushes.
- Develocity build cache node access control settings to list writers.
- [zizmor](https://github.com/zizmorcore/zizmor) to find GitHub Actions workflows that restore caches in release jobs.

### Metrics/Signal
- Number of identities with write access to caches used by release builds.
- Release workflows that restore caches.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Decide whether a poisoned cache entry could reach a published artifact without anyone noticing.

### Insight
On GitHub Actions, caches written on the default branch are readable from other workflows in the repository. A low-privilege workflow that untrusted input can influence can therefore seed the cache for your release workflow. Cache keys are usually derived from the lockfile, which is public, so the attacker can compute the exact key in advance. That is how the TanStack release job restored an attacker's pnpm store. Setting `permissions: contents: read` does not help, because `actions/cache` saves entries with the runner's own token, not `GITHUB_TOKEN`.

### Practical
- Check whether developer machines push to the remote Gradle cache. If they do, any compromised laptop can poison CI.
- Check whether your release job uses `actions/setup-python` (or `setup-node`, `setup-java`) with `cache:` enabled, or `actions/cache`.
- Check whether any workflow triggered by `pull_request_target`, `issue_comment` or similar runs on the default branch and writes caches.
- Check whether you produce provenance for published artifacts, and whether consumers verify it.

### Tools/Techniques
- [Gradle build cache docs](https://docs.gradle.org/current/userguide/build_cache.html) on push configuration.
- [zizmor](https://docs.zizmor.sh/audits/#cache-poisoning) `cache-poisoning` audit.
- [SLSA build requirements](https://slsa.dev/spec/v1.0/requirements): Build L3 requires that one build cannot inject entries into a cache used by another.

### Metrics/Signal
- Developer identities with cache write access (target: zero).
- Published artifacts without provenance.
:::

::: {! stage fortify}
## Fortify

### Explanation
Only trusted CI should write caches that release builds read. Release builds should not trust caches at all.

### Insight
Read-only caches for developers give them most of the speed benefit with none of the poisoning risk.

### Practical
- Make the remote Gradle cache writable by CI only:

    ```kotlin
    // settings.gradle.kts
    val isCiServer = System.getenv().containsKey("CI")

    buildCache {
        remote<HttpBuildCache> {
            url = uri("https://cache.example.com/cache/")
            isPush = isCiServer
            credentials {
                username = System.getenv("CACHE_USER")
                password = System.getenv("CACHE_PASSWORD")
            }
        }
    }
    ```

    Enforce it on the server too: developer accounts get read-only access, and only CI credentials can write.
- Build releases without the remote cache, or from a separate cache that only release builds write:

    ```bash
    ./gradlew clean publish --no-build-cache
    ```

- On GitHub Actions, disable caching in release workflows and keep publishing in its own workflow with minimal triggers.
- Never check out or build fork code in a `pull_request_target` workflow. Use `pull_request` for anything that runs PR code, so it gets a read-only token and an isolated cache scope.
- Generate provenance in the release job. On GitHub, use artifact attestations:

    ```yaml
    - uses: actions/attest-build-provenance@v4
      with:
        subject-path: build/libs/auth-client-*.jar
    ```

### Tools/Techniques
- [Develocity build cache node](https://docs.gradle.com/develocity/build-cache-node/) access control.
- [GitHub artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).
- [SLSA](https://slsa.dev/) build provenance.

### Metrics/Signal
- Release builds run with caching disabled or isolated.
- Share of published artifacts with attestations.
:::

::: {! stage limit}
## Limit

### Explanation
If a poisoned artifact is published, limit how far and fast it spreads.

### Insight
Forty services picked up the backdoor because nothing checked where the JAR came from. Provenance verification at consumption time stops the spread at the first service. Be clear about what it proves, though. Provenance says which workflow built an artifact. It cannot say the workflow was clean: the poisoned TanStack releases passed provenance checks because the hijacked release workflow signed them.

### Practical
- Verify provenance before deploying or promoting an artifact:

    ```bash
    gh attestation verify auth-client-2.4.1.jar --repo example/auth-client
    ```

- Promote artifacts through Artifactory repositories (staging, then release) only after verification succeeds.
- Use a release-age delay for internal dependency updates in Renovate, so a bad version has time to be caught before it fans out.
- Keep a way to purge the remote cache quickly. On Develocity, that is a single admin action. On GitHub, delete caches with `gh cache delete --all`. TanStack purged the caches of every repository in its organisation, since any of them could have held a poisoned entry.

### Tools/Techniques
- `gh attestation verify` from the GitHub CLI.
- [Renovate `minimumReleaseAge`](https://docs.renovatebot.com/configuration-options/#minimumreleaseage).

### Metrics/Signal
- Services that verify provenance of internal libraries.
- Time to purge all caches and rebuild a clean release.
:::

::: {! stage expose}
## Expose

### Explanation
Detect a release whose contents don't match its source.

### Insight
A cache entry carries no proof of how it was made, so a cache miss or hit tells you nothing about tampering. Rebuilding from source without the cache and comparing outputs does.

### Practical
- Make archives reproducible so rebuilds can be compared byte for byte. Gradle 9 does this by default. On Gradle 8 and earlier, add:

    ```kotlin
    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
    ```

- Run a scheduled job that rebuilds each release with `--no-build-cache` on a clean runner and compares checksums with the published artifact. Any difference needs investigating.
- Alert on cache writes from identities other than CI, if your cache server logs them.

### Tools/Techniques
- [Reproducible Builds](https://reproducible-builds.org/) guidance.
- [Gradle reproducible archives](https://docs.gradle.org/current/userguide/working_with_files.html#sec:reproducible_archives).

### Metrics/Signal
- Releases whose clean rebuild matches the published checksum.
- Cache writes by non-CI identities.
:::

::: {! stage exercise}
## Exercise

### Explanation
Show that a poisoned cache entry cannot reach a release.

### Insight
This one is easy to test safely in a sandbox, and the result is usually a surprise.

### Practical
1. Set up a throwaway project with a local build cache node (the Develocity build cache node runs as a container) and a local Artifactory or Nexus.
2. From a "developer" account, push a cache entry with a harmless marker class added.
3. Run the CI build. Did the push succeed? Did the release contain the marker?
4. Run the reproducibility check and confirm it flags the difference.
5. Time how long it takes to purge the cache and republish a clean artifact.

### Tools/Techniques
- The Develocity build cache node container image in a sandbox.
- A local Nexus or Artifactory instance as the release repository.

### Metrics/Signal
- Whether the marker reached the published artifact (target: no).
- Time from detection to clean republish.
:::

## Further Reading

- [Gradle: Build cache](https://docs.gradle.org/current/userguide/build_cache.html)
- [TanStack: npm supply chain compromise postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [CrowdStrike: SUNSPOT technical analysis](https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/)
- [William Woodruff: Ultralytics and cache poisoning](https://blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection)
- [SLSA v1.0 build levels](https://slsa.dev/spec/v1.0/levels)
- [Related card: Provenance and SBOM tampering](#battlecards-provenance-and-sbom-tampering-md)
