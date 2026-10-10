---
title: Dependency Confusion Attacks
category: Package Ecosystems
scenario: Public package shadows an internal package name
focus:
  - internal names leaked in public code
  - multi-index resolution in pip, npm and Gradle
  - repository manager group ordering
  - unowned internal namespaces
---

## Scenario

Acme publishes internal libraries to a private registry: Python packages such as `acme-billing-client`, and Java artefacts under the groupId `com.acme`. Two convenient settings make both ecosystems exposed.

The Python CI image has this `pip.conf`:

```ini
[global]
index-url = https://pypi.org/simple
extra-index-url = https://pypi.acme.internal/simple
```

Many teams read `extra-index-url` as a fallback. pip treats every index as equal, collects candidates from all of them and installs the highest version that fits.

1. An attacker finds `acme-billing-client` in a public `requirements.txt`.
2. They upload version `99.0.0` to PyPI as an sdist whose `setup.py` sends the hostname and environment variables to their server.
3. The next CI run sees `1.4.2` internally and `99.0.0` on PyPI. pip installs `99.0.0`, and the build-time code runs.

The Java builds go through one Nexus group repository with the Maven Central proxy listed before the internal hosted repository. Acme's domain is `acme.io`, and nobody owns `acme.com`.

1. The attacker finds `com.acme:ledger-core:2.4.1` in a stack trace pasted into a public issue.
2. They register `acme.com`, add the DNS TXT record Maven Central asks for, and get `com.acme` verified.
3. They publish `com.acme:ledger-core:2.4.1`, the exact version Acme pins. Nexus asks the Central proxy first, finds a match, and serves the attacker's JAR.

Maven did nothing wrong in step 3. It did exactly what the group repository told it to do.

**Real-world precedent:** In February 2021, Alex Birsan used this technique to run code inside Apple, Microsoft, PayPal and more than 30 other companies through npm, PyPI and RubyGems ([Birsan](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)). In December 2022, a `torchtriton` package on PyPI shadowed the PyTorch nightly dependency of the same name and stole data from machines that installed the nightly builds ([PyTorch](https://pytorch.org/blog/compromised-nightly-dependency/)).

::: {! stage recon}
## Reconnaissance

### Explanation
The attacker needs the name of a package that exists in your private registry but is free, or claimable, on a public one. They find names in public manifests, lockfiles, Dockerfiles, CI configs, JavaScript bundles and source maps, stack traces, Spring Boot actuator pages and blog posts.

For Java there is a second step. If the reversed domain behind your groupId is not yours, someone else can verify it on Maven Central. JitPack accepts a custom groupId from anyone who controls the matching `git.` DNS record.

### Insight
Birsan found many of his names in JavaScript files that companies served to browsers. Your build output leaks names as easily as your source code. Plenty of Java teams also chose `com.companyname` before checking which domain the company owned.

### Practical
- Search your organisation's public code the way an attacker would: `org:acme path:requirements.txt acme-`, `org:acme path:package.json "@acme/"`, `"com.acme" path:pom.xml`.
- Grep your public web bundles and source maps for internal package names.
- List internal names that are free on the public registry.

```bash
confused -l pip requirements.txt
confused -l npm package.json
confused -l mvn pom.xml
npx snync --directory .
```

- List every groupId in your hosted repositories and check who owns each reversed domain with `whois`. Search [central.sonatype.com](https://central.sonatype.com/) to see whether it is already claimed.

### Tools/Techniques
- [confused](https://github.com/visma-prodsec/confused): reports names in `requirements.txt`, `package.json`, `composer.json` or `pom.xml` that don't exist publicly.
- [snync](https://github.com/snyk-labs/snync): for npm, also flags a public package created after the name first appeared in your Git history.
- GitHub code search with `org:`, `path:` and `language:` qualifiers.

### Metrics/Signal
- Internal package names that are unclaimed on the public registry.
- Internal groupIds whose reversed domain you do not own. The target is zero.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Check how each client and repository manager decides where a name comes from. You are exposed wherever something can choose a public package for a name you consider internal.

The ecosystems fail differently. pip merges indexes and takes the highest version. npm sends unscoped names, and unrouted scopes, to the default registry. Maven tries repositories in order and takes the first match. Gradle does the same for fixed versions, but dynamic versions such as `2.+` take the highest version from any repository.

### Insight
The weak point is usually a well-meant convenience: an `extra-index-url` added to fix one build, a group repository with the public proxy first, or a laptop without the team's `.npmrc`. One badly ordered group repository undoes every careful POM in the company.

### Practical
- Python: find every `extra-index-url` in `pip.conf`, requirements files, Dockerfiles and CI variables (`PIP_EXTRA_INDEX_URL`).

```bash
pip config list
grep -rn "extra-index-url" --include="*.txt" --include="*.conf" --include="Dockerfile*" .
```

- uv: its default `first-index` strategy only takes versions from the first index that has the package. If the name is missing internally, uv moves on to the next index. Search for `unsafe-best-match`, which reproduces pip's behaviour.
- npm: check every internal package is scoped and `.npmrc` maps the scope to your registry.
- Maven and Gradle: print `mvn help:effective-settings`, note any `<mirrorOf>*</mirrorOf>`, and grep for ranges, `LATEST`, `RELEASE`, `+` and `latest.` versions.
- Repository managers: write down the member order of each Nexus group or Artifactory virtual repository, and whether a remote may serve internal names.
- After a Maven build, check where internal artefacts came from. Maven records the source repository beside each file.

```bash
find ~/.m2/repository/com/acme -name _remote.repositories -exec cat {} +
```

### Tools/Techniques
- `pip config list`, `npm config ls -l`, `mvn help:effective-settings`, `./gradlew dependencies`.
- Your repository manager's resolution settings and request logs.

### Metrics/Signal
- Build configurations with more than one index or repository for the same names.
- Group or virtual repositories where a public proxy can serve an internal name.
- Dynamic versions in production builds.
:::

::: {! stage fortify}
## Fortify

### Explanation
Make the source of every internal name unambiguous. Each client talks to one endpoint, and that endpoint never asks a public registry about names you own. Then check artefacts against hashes you recorded.

### Insight
Namespace filtering ends this attack. Repository order helps, but filtering stops the public proxy from ever being asked about `com.acme`. Owned scopes and verified namespaces stop the name being claimed in the first place.

### Practical
- **pip:** use a single `index-url` pointing at your repository manager, which proxies PyPI. Remove every `extra-index-url`.
- **uv:** pin internal packages to an explicit index, so they can never come from PyPI.

```toml
[tool.uv.sources]
acme-billing-client = { index = "acme" }

[[tool.uv.index]]
name = "acme"
url = "https://pypi.acme.internal/simple"
explicit = true
```

- **npm:** scope every internal package, route the scope in a committed `.npmrc` (`@acme:registry=https://npm.acme.internal/`), and create the `acme` organisation on npmjs.com.
- **Maven namespace:** register the domain behind every internal groupId, or move to a groupId you own, and verify it on Central. You don't need to publish anything to hold it.
- **Repository manager:** in Nexus, attach a routing rule to the Central proxy that blocks `com/acme/.*`. In Artifactory, add `com/acme/**` to the remote's Excludes Pattern and enable Priority Resolution on the local repository. Do the same for internal npm and Python names.
- **Gradle:** use `exclusiveContent` so internal groups only come from the internal repository, and block project-level repositories.

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository {
                maven { url = uri("https://nexus.acme.io/repository/internal/") }
            }
            filter {
                includeGroupByRegex("com\\.acme(\\..*)?")
            }
        }
        mavenCentral()
    }
}
```

- **Verification:** keep hashed lockfiles (`uv pip compile --generate-hashes`, `package-lock.json`). For Gradle, run `./gradlew --write-verification-metadata sha256,pgp help` and review changes to `gradle/verification-metadata.xml` like code. For Maven, record [trusted checksums](https://maven.apache.org/resolver/expected-checksums.html) into `.mvn/checksums/` and enforce them from `.mvn/maven.config`. A swapped artefact then fails the hash check.
- Pin exact versions and let Renovate or Dependabot propose upgrades.

### Tools/Techniques
- Artifactory Priority Resolution and include/exclude patterns; Nexus [routing rules](https://help.sonatype.com/en/routing-rules.html).
- [uv index configuration](https://docs.astral.sh/uv/concepts/indexes/).
- Gradle [content filtering](https://docs.gradle.org/current/userguide/filtering_repository_content.html) and [dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html).
- For claiming your names across registries, see [Registry Namespace Collisions](#battlecards-registry-namespace-collisions-md).

### Metrics/Signal
- Zero `extra-index-url` or `unsafe-best-match` settings in CI.
- 100% of internal npm packages under an owned scope.
- Gradle builds with `exclusiveContent` for internal groups and committed verification metadata.
:::

::: {! stage limit}
## Limit

### Explanation
A confused package runs code during the build: a `setup.py` for Python, a lifecycle script for npm, a test or plugin for Maven and Gradle. Limit what that code can reach.

### Insight
Birsan's payloads only phoned home with a hostname and username. A real attacker would take every secret in the build environment.

### Practical
- Resolve and test in a job with no deploy credentials. Fetch cloud credentials with OIDC only in the job that deploys.
- Restrict egress during dependency resolution to your repository manager, so the payload can't phone home.
- Stop install-time code where you can: `pip install --only-binary :all:`, `npm ci --ignore-scripts`, or pnpm, which no longer runs dependency lifecycle scripts unless you allow them.
- Give CI a read-only token for the repository manager. Only the publish job can write.
- Give developer laptops the same single-endpoint configuration through managed dotfiles or a dev container.

### Tools/Techniques
- GitHub Actions or GitLab CI OIDC for short-lived cloud credentials.
- CI egress allowlists through a proxy or [Harden-Runner](https://github.com/step-security/harden-runner).

### Metrics/Signal
- CI jobs that both resolve dependencies and hold deployment credentials.
- Blocked egress attempts from build steps.
:::

::: {! stage expose}
## Expose

### Explanation
Dependency confusion leaves clear traces: an internal name served by a public remote, a jump to a version like `99.0.0`, and a new public package or namespace with your name on it.

### Insight
A legitimate internal package has exactly one source. Any other source is an incident, so this alert can be strict. Your repository manager sees every request, so start there.

### Practical
- Alert when a remote (proxy) repository serves or caches anything under an internal name or groupId path.
- Alert when a lockfile change moves an internal package far above your release history.
- Fail CI on Gradle verification or Maven trusted-checksum mismatches, and send those failures to security as well as the developer.
- Run `snync` or `confused` on a schedule, and query Central for your groupIds.

```bash
curl -s "https://search.maven.org/solrsearch/select?q=g:com.acme&rows=20&wt=json" \
    | jq '.response.numFound'
```

### Tools/Techniques
- Artifactory or Nexus request logs shipped to your log platform.
- [snync](https://github.com/snyk-labs/snync) and [confused](https://github.com/visma-prodsec/confused) in scheduled CI jobs.
- [Dependency-Track](https://dependencytrack.org/) for SBOM-based monitoring.

### Metrics/Signal
- Internal names resolved from a public remote. Expected value: zero.
- Internal names or groupIds newly claimed on a public registry by someone else.
:::

::: {! stage exercise}
## Exercise

### Explanation
Rehearse the attack with two local registries: one plays your private registry, the other plays the public one. Never publish test packages to npmjs.com, PyPI, Maven Central or JitPack.

### Insight
The drill tests configuration, which is where this attack lives. The first run usually finds a forgotten build agent with its own `settings.xml`, a project-level `repositories {}` block or a laptop without `.npmrc`.

### Practical
1. Run two [Verdaccio](https://verdaccio.org/) instances, two [devpi](https://github.com/devpi/devpi) indexes, or two Nexus Community Edition containers. Call them "internal" and "public".
2. Publish `acme-drill` `1.0.0` to "internal" and `99.0.0` to "public". The "public" copy only resolves a DNS canary token, or writes a marker file in a Java test.
3. Point a sandbox project at both, copying your real CI and laptop configuration.
4. Build. You should get `1.0.0`, with no canary hit and no request for `acme-drill` reaching "public".
5. Remove one control at a time (routing rule, `exclusiveContent`, verification metadata) and record which layer still stops it.

### Tools/Techniques
- [Verdaccio](https://verdaccio.org/) for npm, [devpi](https://github.com/devpi/devpi) for Python, Nexus Repository Community Edition for Maven.
- [Canarytokens](https://canarytokens.org/) DNS tokens as the benign payload.

### Metrics/Signal
- The correct version installs on every configuration you tested.
- Number of layers that independently stopped the test package.
:::

## Further Reading

- [Alex Birsan: Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [PyTorch: Compromised PyTorch-nightly dependency chain](https://pytorch.org/blog/compromised-nightly-dependency/)
- [uv: Package indexes](https://docs.astral.sh/uv/concepts/indexes/)
- [Maven: repository order](https://maven.apache.org/guides/mini/guide-multiple-repositories.html)
- [Maven Central: namespace verification](https://central.sonatype.org/register/namespace/)
- Related cards: [Registry Namespace Collisions](#battlecards-registry-namespace-collisions-md), [Abandoned Package Hijack](#battlecards-abandoned-package-hijack-md)
