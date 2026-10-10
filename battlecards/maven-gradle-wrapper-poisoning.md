---
title: Maven and Gradle Wrapper Poisoning
category: CI/CD & Build
scenario: Malicious build wrapper slipped in through a pull request
focus:
  - tampered gradle-wrapper.jar
  - modified mvnw and gradlew scripts
  - wrapper checksum validation
  - malicious annotation processors
---

## Scenario

An open-source Java library gets a friendly pull request titled "Upgrade Gradle wrapper to latest". The contributor has a few earlier merged PRs that fixed typos. The diff shows a one-line change to `gradle-wrapper.properties`, a few lines in `gradlew`, and `gradle-wrapper.jar` as "Binary file not shown".

The new JAR behaves like a normal wrapper. It also reads credential files from the home directory and, when the task name starts with `publish`, downloads and runs a second-stage payload.

1. A maintainer checks out the branch to try it. IntelliJ IDEA imports the Gradle project, which runs the wrapper. The payload runs on the maintainer's laptop.
2. The PR is merged. The next release job runs `./gradlew publish` with the signing key and the repository credentials in its environment.
3. The payload takes both. The attacker can now publish signed releases of the library.

A variation on the same idea: a PR adds a test-scoped dependency that ships an annotation processor. `javac` runs processors inside the compiler, so the code runs during compilation, before any test.

**Real-world precedent:** In January 2023 Gradle [analysed two malicious wrapper JARs](https://blog.gradle.org/wrapper-attack-report) contributed to MinecraftOnline repositories. Both stole Discord credentials, and one fetched a further payload on `publish` tasks. Later that year the [fractureiser malware (June 2023)](https://github.com/trigram-mrp/fractureiser) spread through compromised Minecraft mod accounts and infected other JAR files it found on victims' machines.

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker looks for projects that accept outside contributions, publish from CI, and have no wrapper validation. All three are visible from the outside. The workflow files are public, and so is the absence of a validation step.

Wrapper upgrade PRs are a well-worn path. Maintainers like them, they are dull to review, and GitHub cannot render a binary diff.

### Insight

The wrapper is the first code that runs in any build. Hiding a payload there means it runs before your build logic, your tests or your scanners get a look.

### Practical

- Look at your project from the attacker's side: which workflows run on `pull_request_target`, which run on self-hosted runners, and which publish.
- Check whether `gradle-wrapper.jar`, `gradlew`, `mvnw` and `.mvn/` have a code owner.
- Count contributors who have only ever touched build files.

### Tools/Techniques

- GitHub code search for workflows in your organisation that run `./gradlew` or `./mvnw` without a wrapper validation step.
- [zizmor](https://github.com/zizmorcore/zizmor) to flag dangerous workflow triggers such as `pull_request_target`.

### Metrics/Signal

- Repositories with a committed wrapper and no validation.
- Wrapper-only PRs from first-time or low-history contributors.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check four things in each repository: whether the wrapper JAR matches an official release, whether the wrapper verifies the distribution it downloads, whether CI runs untrusted PR code with secrets, and whether annotation processing is explicit.

The Gradle wrapper JAR can be checked against Gradle's published checksums. The `gradlew` script itself is plain shell, so you review it like code. The Maven Wrapper's default `only-script` type has no JAR at all: `mvnw` downloads Maven directly, which makes the script and `distributionUrl` the things to watch.

### Insight

A checksum on the distribution only helps if the attacker cannot change the checksum in the same PR. Review and ownership rules carry as much weight as the hash.

### Practical

- Validate every wrapper JAR in the repository against Gradle's list. The `gradle/actions/wrapper-validation` action does this, including homoglyph look-alike file names.
- Check `gradle/wrapper/gradle-wrapper.properties` for `distributionSha256Sum`, and that `distributionUrl` points at `services.gradle.org`.
- Check `.mvn/wrapper/maven-wrapper.properties` for `distributionSha256Sum`, plus `wrapperSha256Sum` if you use a wrapper type with a JAR.
- Check for annotation processors your build runs. On JDK 23 and later, `javac` no longer discovers processors on the class path unless you pass `-proc:full` or configure a processor path. Gradle has ignored processors on the compile class path since Gradle 5.0. Anything in the `annotationProcessor` configuration still runs.

```bash
# Compare the committed wrapper JAR with Gradle's published checksums
sha256sum gradle/wrapper/gradle-wrapper.jar
# then look it up at https://gradle.org/release-checksums/
```

### Tools/Techniques

- [Gradle release checksums](https://gradle.org/release-checksums/).
- [`gradle/actions/wrapper-validation`](https://github.com/gradle/actions/blob/main/docs/wrapper-validation.md).
- `./gradlew dependencies --configuration annotationProcessor` to list what runs inside the compiler.

### Metrics/Signal

- Percentage of repositories with wrapper validation in CI.
- Percentage of wrapper properties files with a distribution checksum.
:::

::: {! stage fortify}
## Fortify

### Explanation

Validate the wrapper before anything executes it, pin the distribution hash, and never accept a wrapper JAR you did not generate. Regenerating the wrapper yourself takes a minute and removes the question.

### Insight

The safest answer to "Upgrade Gradle wrapper" from an outside contributor is a thank-you and a commit you generated from the official distribution.

### Practical

- Run wrapper validation before any Gradle step. If you use `gradle/actions/setup-gradle` v4 or later, it validates the wrapper automatically. The older `gradle/wrapper-validation-action` is deprecated.

```yaml
name: Validate Gradle Wrapper
on: [push, pull_request]
permissions:
    contents: read
jobs:
    validation:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v6
            - uses: gradle/actions/wrapper-validation@v6
```

Pin both actions to a full commit SHA in practice.

- Generate wrapper upgrades yourself, with the distribution hash from [gradle.org/release-checksums](https://gradle.org/release-checksums/):

```bash
./gradlew wrapper --gradle-version 9.1.0 \
    --gradle-distribution-sha256-sum <sha256-of-gradle-9.1.0-bin.zip>
```

That writes the hash into `gradle-wrapper.properties`:

```properties
distributionUrl=https\://services.gradle.org/distributions/gradle-9.1.0-bin.zip
distributionSha256Sum=<sha256-of-gradle-9.1.0-bin.zip>
```

- For Maven, set the distribution hash from the `.sha512`/`.sha256` published alongside the Maven binary, or from your own download:

```properties
# .mvn/wrapper/maven-wrapper.properties
distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip
distributionSha256Sum=<sha256-of-that-zip>
```

- Add CODEOWNERS entries for `gradlew`, `gradlew.bat`, `gradle/wrapper/`, `mvnw`, `mvnw.cmd` and `.mvn/`, and require code owner review in a branch ruleset.
- Make annotation processing explicit. Declare processors in Gradle's `annotationProcessor` configuration or Maven's `annotationProcessorPaths`, and review additions to either.

### Tools/Techniques

- `gradle/actions/setup-gradle` and `gradle/actions/wrapper-validation`.
- [Maven Wrapper](https://maven.apache.org/tools/wrapper/) `distributionSha256Sum` and `wrapperSha256Sum`.
- GitHub rulesets with required code owner review.

### Metrics/Signal

- Wrapper changes merged without a code owner review. Target: zero.
- Wrapper JARs in the organisation that do not match an official checksum. Target: zero.
:::

::: {! stage limit}
## Limit

### Explanation

A poisoned wrapper runs with whatever the build process can reach. On a laptop that is the developer's home directory. In CI it is every secret in the job's environment.

### Insight

The attack in the Gradle report waited for `publish`. Keep the publishing credentials away from jobs that run code you have not reviewed.

### Practical

- Never run fork PR code under `pull_request_target` or on a self-hosted runner with secrets. Use `pull_request`, which gets no secrets for forks.
- Split release into a build job without secrets and a publish job that only uploads the built artifact. Put the publish job behind a protected environment.
- Use trusted publishing or short-lived OIDC credentials where your registry supports them, so there is no long-lived token to steal.
- Review unfamiliar PRs in a container or a cloud dev environment, not in the IDE on your main laptop. IDE project import runs the build.

### Tools/Techniques

- GitHub environments with required reviewers for publish jobs.
- Dev containers or a disposable VM for reviewing outside contributions.

### Metrics/Signal

- Workflows that run PR code and have access to secrets.
- Long-lived publishing tokens still in CI secrets.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for wrapper changes and for builds behaving unlike builds. A Gradle wrapper should talk to `services.gradle.org` and your repositories. It should not read browser profiles or contact unknown hosts.

### Insight

Wrapper changes are rare. A simple alert on any change to those paths is cheap, and it rarely fires for the wrong reason.

### Practical

- Alert on any PR that touches wrapper files, and label it for extra review.
- Monitor outbound connections from CI jobs. A tool such as StepSecurity Harden-Runner can record and block unexpected egress on GitHub-hosted runners.
- Keep wrapper validation failures as hard failures, and send them to a security channel.

```yaml
# .github/labeler.yml for actions/labeler
build-wrapper:
    - changed-files:
          - any-glob-to-any-file:
                - "gradlew*"
                - "gradle/wrapper/**"
                - "mvnw*"
                - ".mvn/**"
```

### Tools/Techniques

- `actions/labeler` for automatic labels on wrapper changes.
- [Harden-Runner](https://github.com/step-security/harden-runner) for CI egress monitoring.

### Metrics/Signal

- Wrapper-change PRs per month, and who opened them.
- Unexpected outbound hosts contacted during builds.
:::

::: {! stage exercise}
## Exercise

### Explanation

Check that validation fails when it should, using a harmless altered JAR in a scratch repository.

### Insight

Teams often find a repository where the validation step exists but runs after the first Gradle call, which is too late.

### Practical

1. Create a private scratch repository with a fresh Gradle wrapper and your standard workflows.
2. Open a PR that changes one byte in `gradle-wrapper.jar`, for example by adding an empty file to the JAR with `jar uf`. The JAR still works and contains nothing harmful.
3. Confirm validation fails before any Gradle step runs.
4. Open a second PR that changes `distributionUrl` without updating `distributionSha256Sum`, and confirm the wrapper refuses the download.
5. Confirm code owners were requested for both PRs.

### Tools/Techniques

- A private scratch repository. Do not open test PRs against other people's projects.
- `jar uf` to make a benign change to the wrapper JAR.

### Metrics/Signal

- Time from the test PR opening to the first failed check.
- Repositories where the exercise found a gap.
:::

## Further Reading

- [Gradle: Wrapper Attack Report (2023)](https://blog.gradle.org/wrapper-attack-report)
- [Gradle: wrapper validation action](https://github.com/gradle/actions/blob/main/docs/wrapper-validation.md)
- [Gradle Wrapper: verifying the download](https://docs.gradle.org/current/userguide/gradle_wrapper.html#sec:verification)
- [Maven Wrapper documentation](https://maven.apache.org/tools/wrapper/)
- [fractureiser investigation](https://github.com/trigram-mrp/fractureiser)
- [JDK 23 annotation processing change](https://inside.java/2024/06/18/quality-heads-up/)
- Related cards: [GitHub Actions Workflow Poisoning](#battlecards-github-actions-workflow-poisoning-md), [Developer Review Fatigue](#battlecards-developer-review-fatigue-and-social-engineering-md)
