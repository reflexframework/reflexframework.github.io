---
title: Abandoned Package Hijack
category: Package Ecosystems
ref: RFX-PKG-01
precedent: "2022"
scenario: Attacker takes over a dormant package via an expired domain or a freed name
focus:
  - expired maintainer email domains
  - expired domains and renamed accounts behind Maven groupIds
  - revival hijack of deleted package names
  - dormant packages that suddenly release
---

## Scenario

A package is only as durable as the domain or account behind it. When the owner stops paying, an attacker can buy the identity and inherit the package. Here are three versions of the same story.

**PyPI or npm.** `py-formatter-util` is a small library that a popular data science toolkit depends on. It hasn't had a release in four years. The maintainer's email domain has lapsed. An attacker registers it, sets up a mailbox and requests a password reset. They copy the last release, add a few lines that send `AWS_` environment variables to their server, and publish `1.2.2`. The toolkit's loose version range pulls it into the next build.

**Freed names.** If the author had deleted the project instead, the attacker could simply register the freed name and publish a higher version. Anyone still installing it by name gets the new code.

**Maven.** An Android app depends on `org.tinycsv:tinycsv:3.2.0`. The maintainer let `tinycsv.org` expire in 2019. The app's Gradle build declares `google()`, `mavenCentral()` and JitPack, with no filters.

1. The attacker buys `tinycsv.org`. Maven Central won't grant a new claim on an existing namespace, so they go elsewhere.
2. JitPack accepts a custom groupId from anyone who controls the `git.` DNS record for the domain. They point `git.tinycsv.org` at their own GitHub repository and tag `3.2.1`, with a payload in a static initialiser.
3. Renovate auto-merges patch releases. Gradle searches every declared repository, finds `3.2.1` on JitPack, and the payload ships.

The same applies to `io.github.<user>` groupIds when the GitHub user is renamed or deleted.

::: {! precedent}
**Real-world precedent:** In May 2022 the PyPI package `ctx` was hijacked after its maintainer's email domain expired, and new releases stole environment variables ([PyPI](https://blog.pypi.org/posts/2025-08-18-preventing-domain-resurrections/)). A 2022 study found 2,818 npm maintainers using email addresses on expired domains, controlling 8,494 packages ([The Record](https://therecord.media/thousands-of-npm-accounts-use-email-addresses-with-expired-domains)). In January 2024 Oversecured's [MavenGate](https://oversecured.com/blog/introducing-mavengate-a-supply-chain-attack-method-for-java-and-android-applications) research found 6,170 of 33,938 domains and GitHub accounts behind Java groupIds could be bought or re-registered. In 2024 JFrog showed around 22,000 deleted PyPI names could be re-registered, a technique it called [Revival Hijack](https://jfrog.com/blog/revival-hijack-pypi-hijack-technique-exploited-22k-packages-at-risk/).
:::

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers look for packages that are still installed a lot but no longer looked after: no recent releases, a single maintainer, an email or groupId on a personal domain, or a project deleted while others still depend on it. MavenGate needed no stolen credentials. It reversed each groupId to a domain and checked whether the domain was for sale.

### Insight
Dormant packages are attractive because nobody watches them. A release after years of silence is unusual, yet most update bots treat it like any other patch.

### Practical
Find the dormant packages in your own tree. Lockfiles carry names and versions but no maintainer data, so query the registry:

```bash
# Last upload time of the latest release for each pinned PyPI package
while read -r name; do
    printf '%s ' "$name"
    curl -s "https://pypi.org/pypi/$name/json" | jq -r '.urls[0].upload_time_iso_8601 // "missing"'
done < <(sed -E 's/[=<>!~ ;].*//' requirements.txt | grep -v '^#' | grep -v '^$')
```

A result of `missing` can mean the project was deleted. That name may be free for anyone to register.

For Java, list the distinct groupIds in your graph and check each reversed domain with `whois`. For `io.github.*` and `com.github.*` groupIds, check the GitHub account still exists under that name.

```bash
# Distinct groupIds from a CycloneDX SBOM
jq -r '.components[].group // empty' target/bom.json | sort -u
```

### Tools/Techniques
- [PyPI JSON API](https://docs.pypi.org/api/json/), `npm view <pkg> time maintainers`, and [deps.dev](https://deps.dev/) for release history.
- `whois` and `dig` for domain status.
- [OpenSSF Scorecard](https://scorecard.dev/) "Maintained" check.

### Metrics/Signal
- Dependencies with no release in two years or more.
- Dependencies whose project no longer exists on the registry (target: zero).
- GroupIds in your graph whose domain has expired or changed hands.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
A dormant package is only dangerous if your builds would install a new version without anyone looking. Check three things: how loosely you pin, which repositories your builds search, and whether you verify artefacts against something the attacker can't reproduce.

### Insight
PGP signatures look like the answer for Maven, and rarely are. Central requires a signature, but any key will do. Nothing binds a namespace to a key, consumers seldom check, and Google's Maven repository doesn't sign at all.

### Practical
- Check whether requirements and lockfiles use exact pins with hashes, or open ranges.
- List the repositories each Gradle or Maven build declares, and whether each is filtered by group.
- Check whether you auto-merge upgrades for old, quiet libraries.
- For each dormant dependency, decide: replace it, vendor it, fork it under your control, or pin it with hashes. Remove anything unused.

### Tools/Techniques
- [pip-tools](https://pip-tools.readthedocs.io/) or [uv](https://docs.astral.sh/uv/) for pinned, hashed requirements.
- `./gradlew buildEnvironment` and `mvn help:effective-pom -Dverbose` for repository lists.
- [OSV-Scanner](https://google.github.io/osv-scanner/) for malicious-package records.

### Metrics/Signal
- Projects installing from hashed lockfiles.
- Builds that search more than one public repository without content filters.
- Dormant dependencies with a recorded decision.
:::

::: {! stage fortify}
## Fortify

### Explanation
Make sure a release from a hijacked identity cannot reach your builds by accident. Pin and verify, filter what each repository may serve, and pin the signing keys you trust.

### Insight
Hash-pinned installs refuse anything you have not reviewed. Gradle's verification metadata adds the binding PGP lacks: you record which key signed `org.tinycsv`, and a new key fails the build.

### Practical
- Python: generate hashed requirements and install in hash-checking mode.

```bash
uv pip compile requirements.in --generate-hashes -o requirements.txt
pip install --require-hashes -r requirements.txt
```

- npm: install from the lockfile with `npm ci`, and add a release-age gate (pnpm `minimumReleaseAge`, Renovate `minimumReleaseAge`). With uv, `--exclude-newer` ignores very new releases.
- Gradle: restrict secondary repositories to the groups that need them, and turn on dependency verification.

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        exclusiveContent {
            forRepository { maven { url = uri("https://jitpack.io") } }
            filter { includeGroup("com.github.some-org") }
        }
    }
}
```

```bash
./gradlew --write-verification-metadata sha256,pgp help
```

- In `gradle/verification-metadata.xml`, pin trusted keys to groups:

```xml
<trusted-keys>
    <trusted-key id="0123456789ABCDEF0123456789ABCDEF01234567" group="org.tinycsv"/>
</trusted-keys>
```

- Maven: use Maven Resolver [trusted checksums](https://maven.apache.org/resolver/expected-checksums.html), recorded once and committed, or [pgpverify-maven-plugin](https://www.simplify4u.org/pgpverify-maven-plugin/) with a key map.
- If you maintain packages: add a second verified email on a major provider, use trusted publishing, and archive projects instead of deleting them. PyPI has required 2FA since January 2024 and, since mid-2025, un-verifies emails whose domains expire.

### Tools/Techniques
- [pip hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/) and [uv](https://docs.astral.sh/uv/).
- Gradle [dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html) and [content filtering](https://docs.gradle.org/current/userguide/filtering_repository_content.html).
- [PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/) and npm trusted publishing.

### Metrics/Signal
- Builds installing from hashed lockfiles or committed verification metadata.
- Unfiltered public repositories across all Gradle builds. Target: one, Maven Central.
:::

::: {! stage limit}
## Limit

### Explanation
A hijacked release runs in your build, on developer laptops, and sometimes in your shipped product. Limit what it can read in each place.

### Insight
The ctx payload read environment variables. Builds and notebooks with no long-lived cloud keys give it nothing worth stealing. In an Android app, library code runs with every permission the app holds.

### Practical
- Use short-lived cloud credentials (OIDC in CI, SSO sessions on laptops) instead of static `AWS_` keys in the environment.
- Keep publishing and signing credentials out of the jobs that resolve and test dependencies.
- Install through a repository manager you control, so you can block a version everywhere at once.
- Keep Android app permissions to what features need.
- Hold back auto-merge for long-dormant dependencies.

```json
{
    "packageRules": [
        {
            "matchDatasources": ["maven", "pypi", "npm"],
            "minimumReleaseAge": "7 days"
        }
    ]
}
```

### Tools/Techniques
- [devpi](https://devpi.net/), Sonatype Nexus or JFrog Artifactory as a proxy.
- [Renovate `minimumReleaseAge`](https://docs.renovatebot.com/configuration-options/#minimumreleaseage) and `automerge` rules.

### Metrics/Signal
- Static cloud keys found in CI or developer environments.
- Time to block a package version across all builds.
:::

::: {! stage expose}
## Expose

### Explanation
Detect the change of hands as well as the malicious code. A new signing key, a new source repository, a new uploader, a deleted project that reappears, or a sudden release from a long-quiet project are all signals.

### Insight
These events are rare enough to review by hand. A library silent for five years that ships a patch release deserves a human look, whatever the scanner says.

### Practical
- In update PRs, show the gap since the previous release. Treat gaps over a year as needing review.
- Check whether new releases carry provenance (PEP 740 attestations, npm provenance) from the expected repository.
- Treat Gradle verification failures for a changed key as a security event, and alert when a dependency resolves from a different repository than before.
- Diff the new release against the last one before merging.

```bash
# Wheels only: downloading an sdist can run its build code
pip download py-formatter-util==1.2.1 --no-deps --only-binary :all: -d old
pip download py-formatter-util==1.2.2 --no-deps --only-binary :all: -d new
unzip -q old/*.whl -d old/src && unzip -q new/*.whl -d new/src
diff -r old/src new/src
```

### Tools/Techniques
- PyPI and npm package pages, which show attestations and the publishing workflow.
- Gradle verification failure reports.
- [OSV](https://osv.dev/), deps.dev, and malware feeds such as [Socket](https://socket.dev/) that flag maintainer and publisher changes.

### Metrics/Signal
- Dormant-package releases reviewed before merge.
- Signing-key changes on existing dependencies.
- Releases without attestations from projects that previously had them.
:::

::: {! stage exercise}
## Exercise

### Explanation
Practise spotting and handling a dormant package that suddenly releases, using private registries and a key you generate for the exercise.

### Insight
Most teams have no rule for "this package was quiet for four years and just shipped". The demo that changes minds is the build that turns red because the signing key changed while the code looked identical.

### Practical
1. Run a local [devpi](https://devpi.net/) index and a local [Reposilite](https://reposilite.com/) or Nexus instance.
2. Upload a benign `1.2.2` of an internal look-alike Python package that only writes a marker file. Let your update tooling propose it, and see whether hash pinning, release-age gates or review catches it.
3. Publish a benign copy of a real Java dependency's coordinates to the Maven instance with a higher version, signed with a throwaway `gpg --quick-generate-key` key. Add the repository to a sample Gradle project without filters and watch it resolve.
4. Add `exclusiveContent` and verification metadata. Confirm the build fails, and read the error together.
5. List every real dependency with an expired domain or a long silence, and agree an owner for each.

### Tools/Techniques
- [devpi](https://devpi.net/), [Reposilite](https://reposilite.com/) or Nexus Repository Community Edition.
- Your update bot pointed at the local registries.

### Metrics/Signal
- Which control stopped each test release.
- Dormant or expired-domain dependencies with an agreed owner and plan.
:::

## Further Reading

- [PyPI: Preventing domain resurrection attacks](https://blog.pypi.org/posts/2025-08-18-preventing-domain-resurrections/)
- [JFrog: Revival Hijack](https://jfrog.com/blog/revival-hijack-pypi-hijack-technique-exploited-22k-packages-at-risk/)
- [Oversecured: Introducing MavenGate (2024)](https://oversecured.com/blog/introducing-mavengate-a-supply-chain-attack-method-for-java-and-android-applications)
- [The Hacker News: MavenGate and Sonatype's response](https://thehackernews.com/2024/01/hackers-hijack-popular-java-and-android.html)
- [Gradle: dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html)
- Related cards: [Maintainer Account Takeover](#battlecards-maintainer-account-takeover-md), [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md)
