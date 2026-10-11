---
title: Build Tooling Blind Spots
category: CI/CD & Build
ref: RFX-CI-02
precedent: "2025"
scenario: Build plugins missing from the SBOM
focus:
  - plugin dependency graphs outside the application SBOM
  - build-time code with access to credentials
  - evidence levels for build-tool findings
---

## Scenario

A team ships a Java service built with Maven. Their release pipeline runs `mvn deploy` with the code-signing key and the registry credentials in the environment. The application SBOM goes out with every release, and the scanner report on it is short.

That SBOM describes the JAR, and only the JAR. The software that built it is missing. The compiler plugin, the test runner, the code generators, the SBOM generator itself and every CI action in the pipeline all execute code in that same environment. Each plugin brings its own dependency graph, and `mvn dependency:tree` does not show any of it.

An attacker who wants the signing key does not need to touch the application's dependencies:

1. They pick a build plugin, or one of its transitive dependencies, maintained by one or two people.
2. They compromise a release of it, or find a flaw it exposes when it processes files from the repository.
3. The next release build resolves and runs that code with the pipeline's secrets in reach.
4. The application SBOM for that release still looks clean, because the attack never entered the application.

A small Maven experiment shows the size of the gap. The author ran Trivy 0.74.0 against two SBOMs of the same tiny project in October 2026. The conventional CycloneDX application SBOM produced 18 vulnerability matches. An SBOM that also included the resolved Maven plugins and their dependencies, produced with the [SBOM+ Maven Plugin](https://noregressions.github.io/sbom-plus-maven-plugin/), produced 77 matches, including two rated critical. The code and the scanner were unchanged. Only the question changed.

Those 77 are version matches. None was shown to be exploitable, and nothing was exploited. The most interesting match was in the security tooling: the CycloneDX Maven Plugin that generated the application SBOM depended on `cyclonedx-core-java` 9.0.5, which is affected by [CVE-2025-64518](https://github.com/advisories/GHSA-6fhj-vr9j-g45r), an XML external entity flaw in BOM validation fixed in 11.0.1. The plugin loaded that library's XML parser and validated XML during normal use. It was validating XML it had generated itself, so the test did not show attacker-controlled input reaching that code.

::: {! precedent}
**Real-world precedent:** In March 2025 the `tj-actions/changed-files` action was altered to dump runner memory, and the secrets in it, into build logs ([CVE-2025-30066](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)). On 11 May 2026, attacker code ran inside a TanStack build tooling workflow, poisoned the dependency cache and reached the release job. It reused the tj-actions memory-dump technique to take the job's OIDC token and publish 84 malicious npm versions ([TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)). Earlier, a poisoned build produced malicious Ultralytics releases on PyPI in December 2024 ([PyPI analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)), [fractureiser](https://github.com/fractureiser-investigation/fractureiser) injected itself into JAR files on infected machines in June 2023, and Codecov's modified Bash Uploader sent CI environment variables to attackers from January to April 2021 ([Codecov](https://about.codecov.io/security-update/)). None of this code was part of the shipped application.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Build configuration is usually public. A `pom.xml`, `build.gradle` or workflow file tells an attacker exactly which plugins and actions run, and often which versions. From there they can look for plugins with old, vulnerable dependencies, or for small projects whose release process they could subvert.

They also look for build steps that process files a contributor controls: OpenAPI specs fed to code generators, XML or templates read by plugins, SBOMs or reports parsed by tooling. Those are the places where a flaw in a build tool meets untrusted input.

### Insight

Most teams have never listed their build tooling as dependencies. The attacker's list of what runs in your build is often more complete than yours.

### Practical

- List every Maven or Gradle plugin, with its version, across your repositories.
- Note which pipeline jobs hold signing keys, registry tokens or deploy credentials, and which plugins run in those jobs.
- Identify build steps that read files from pull requests or third parties.

### Tools/Techniques

- `mvn help:effective-pom` shows every plugin and version, including those inherited from parent POMs.
- `./gradlew buildEnvironment` shows the build script classpath for Gradle projects.
- GitHub code search across your organisation for `<plugin>` blocks and `uses:` lines.

### Metrics/Signal

- Number of distinct build plugins and CI actions in use, and how many have no pinned version.
- Number of release jobs where build plugins run alongside signing or publishing credentials.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Build an inventory of the build, then decide how much each finding matters. A vulnerability match against a build-tool component can mean very different things. The Maven experiment separated three levels of evidence:

| Level | What you have shown | Example from the experiment |
|---|---|---|
| Resolved | The component is in a plugin's dependency graph | Maven Site Plugin's `dom4j` 1.1; the plugin did not run in `mvn verify` |
| In an executing plugin's class realm | The plugin ran, and the JAR was available to it | Compiler Plugin's `commons-io` 2.11.0; no Commons IO classes loaded in the tested compilation |
| Relevant code loaded | The affected kind of functionality actually ran | `cyclonedx-core-java` 9.0.5 XML parser and validation classes loaded |

None of these levels shows exploitability. That needs attacker-controlled input reaching the vulnerable code with useful privileges, which is a separate question.

### Insight

Scope changes the count. Going from 18 to 77 matches did not make the application more vulnerable. It showed what the first scan had never been asked about.

### Practical

```bash
# What the application depends on
mvn dependency:tree

# Plugins and their dependencies (transitive resolution is the default)
mvn dependency:resolve-plugins -DoutputFile=target/plugins.txt

# Which classes were actually loaded during a build
JAVA_TOOL_OPTIONS="-Xlog:class+load=info:file=class-loading.log" mvn verify
grep -c 'org.apache.commons.io' class-loading.log
```

- Run `mvn -X` to see which JARs are placed in each plugin's class realm.
- Remember what the inventory leaves out. Plugin metadata does not cover the installed Maven or JDK, operating system packages, or CI actions.

### Tools/Techniques

- [SBOM+ Maven Plugin](https://noregressions.github.io/sbom-plus-maven-plugin/): writes a CycloneDX SBOM of project dependencies, build plugins with their transitive dependencies, and imported BOMs.
- [maven-dependency-plugin `resolve-plugins`](https://maven.apache.org/plugins/maven-dependency-plugin/resolve-plugins-mojo.html) for a quick text listing.
- JDK unified logging (`-Xlog:class+load`) to show what the JVM actually loaded.
- [Trivy](https://trivy.dev/) and [OSV-Scanner](https://google.github.io/osv-scanner/) to scan both SBOMs.

### Metrics/Signal

- Findings in build tooling, broken down by evidence level.
- Findings at the "relevant code loaded" level in jobs that hold credentials.
:::

::: {! stage fortify}
## Fortify

### Explanation

Treat build tooling as dependencies with the same care as application code. Pin it, update it, inventory it and scan it. Produce a build-scoped SBOM alongside the application SBOM so both questions get asked on every release.

### Insight

The SBOM generator, the scanner and the linter are code too. A security tool sits in your build with your build's privileges, so it needs the same scrutiny.

### Practical

- Pin every plugin version explicitly. The Maven Enforcer `requirePluginVersions` rule fails builds that rely on defaults.
- Let Renovate or Dependabot raise updates for plugins, as they do for libraries.
- For Gradle, turn on [dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html). It checks checksums for plugins and build script dependencies as well as libraries.
- Pin CI actions to full commit SHAs (see [GitHub Actions Workflow Poisoning](#battlecards-github-actions-workflow-poisoning-md)).
- Generate a build-scoped SBOM per release and keep it with the release artefacts.

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <version>3.6.3</version>
    <executions>
        <execution>
            <id>enforce-plugin-versions</id>
            <goals>
                <goal>enforce</goal>
            </goals>
            <configuration>
                <rules>
                    <requirePluginVersions/>
                </rules>
            </configuration>
        </execution>
    </executions>
</plugin>
```

### Tools/Techniques

- [SBOM+ Maven Plugin](https://noregressions.github.io/sbom-plus-maven-plugin/) for Maven build tooling.
- [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) both support SBOMs scoped to the build. CISA's [Types of SBOM](https://www.cisa.gov/resources-tools/resources/types-software-bill-materials-sbom) names the build SBOM as a distinct type.
- [Syft](https://github.com/anchore/syft) or [cdxgen](https://github.com/CycloneDX/cdxgen) run against your build image, to capture the JDK, Maven distribution and OS packages that plugin metadata misses.

### Metrics/Signal

- Percentage of plugins with explicit versions.
- Releases that ship with both an application SBOM and a build-scoped SBOM.
:::

::: {! stage limit}
## Limit

### Explanation

Assume a build plugin will one day run hostile code. Make sure it finds as little as possible. The key move is to keep secrets out of the jobs where most plugins run.

### Insight

The tj-actions payload took whatever was in the runner's memory. The TanStack payload took the OIDC token because the job it reached could publish. A test job that holds no signing key and no publish identity has nothing to give.

### Practical

- Split the pipeline. Compile and test in a job with no secrets. Sign and publish in a separate job that consumes the built artefact and runs as few plugins as possible.
- Use short-lived, identity-based credentials for publishing where your registry supports them, and scope them to the publish job.
- Resolve dependencies in one step, then build offline so plugins cannot fetch new code mid-build:

```bash
mvn -B dependency:go-offline
mvn -B -o verify
```

- Process third-party files, such as SBOMs you receive from suppliers, in a sandboxed job. The CycloneDX advisory suggests rejecting XML before validation where you can accept JSON.

### Tools/Techniques

- Separate CI jobs or GitHub environments for signing and publishing.
- Registry trusted publishing (OIDC) in place of stored tokens.
- Runner egress controls, such as [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) in block mode.

### Metrics/Signal

- Number of jobs that hold signing or publishing credentials while running the full plugin set.
- Long-lived registry tokens stored as CI secrets, trending to zero.
:::

::: {! stage expose}
## Expose

### Explanation

Detect changes in what your build runs. A new plugin dependency, a new class loaded during compilation or a new outbound connection from a build job are all worth a look.

### Insight

Build-scoped SBOMs become useful for detection once you diff them. A plugin update that pulls in a new HTTP client is easy to spot in a diff and invisible otherwise.

### Practical

- Diff the build-scoped SBOM between releases and review new components.
- Load build-scoped SBOMs into your SBOM platform as separate projects, so new advisories against build tooling raise alerts.
- Monitor network egress from build jobs and alert on new destinations.
- Keep class-loading logs from an occasional instrumented build and compare them over time.

### Tools/Techniques

- [OWASP Dependency-Track](https://dependencytrack.org/) with one project for the application and one for its build.
- `diff` or `jq` over two CycloneDX files' `components[].purl` lists.
- Harden-Runner in audit mode to baseline build egress.

### Metrics/Signal

- New components in the build-scoped SBOM per release.
- Alerts on new egress destinations from build jobs.
:::

::: {! stage exercise}
## Exercise

### Explanation

Reproduce the experiment on one of your own projects. Generate both SBOMs, scan each with two tools, and classify every build-tool finding by evidence level. Work on a copy of the project, with no real credentials present.

### Insight

Count the findings that reach the "relevant code loaded" level in a job that holds secrets. That number tells you far more than the size of the second scan.

### Practical

1. Generate the application SBOM and the build-scoped SBOM:

    ```bash
    mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
    mvn dev.noregressions:sbom-plus-maven-plugin:1.0.0:scan
    ```

2. Copy each file to a name ending in `.cdx.json`, which OSV-Scanner uses to recognise CycloneDX.
3. Scan both with two tools:

    ```bash
    cp target/bom.json app.cdx.json
    cp target/sbom-plus-cyclonedx.json build.cdx.json
    trivy sbom --scanners vuln -f json -o app-trivy.json app.cdx.json
    trivy sbom --scanners vuln -f json -o build-trivy.json build.cdx.json
    osv-scanner scan source -L app.cdx.json --format json --output-file app-osv.json
    osv-scanner scan source -L build.cdx.json --format json --output-file build-osv.json
    ```

4. List the findings that only appear in the build scan. Note where the two tools disagree.
5. For each build-tool finding, record the evidence level: resolved, in an executing plugin's class realm, or relevant code loaded. Use `mvn -X` and the class-loading log from Evaluate.
6. For anything at the third level, check whether untrusted input can reach that code and which credentials the job holds.

### Tools/Techniques

- SBOM+ Maven Plugin, CycloneDX Maven Plugin, Trivy and OSV-Scanner.
- A spreadsheet or VEX document to record the evidence level and your decision for each finding.

### Metrics/Signal

- Count of findings at each evidence level.
- Number of third-level findings in credentialed jobs, and the time taken to remove or isolate each.
:::

## Further Reading

- [SBOM+ Maven Plugin](https://noregressions.github.io/sbom-plus-maven-plugin/)
- [GitHub Advisory: CycloneDX Core Java BOM validation XXE (CVE-2025-64518)](https://github.com/advisories/GHSA-6fhj-vr9j-g45r)
- [CISA: Types of Software Bill of Materials](https://www.cisa.gov/resources-tools/resources/types-software-bill-materials-sbom)
- [TanStack: npm supply chain compromise postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [Codecov: Bash Uploader security update](https://about.codecov.io/security-update/)
- Related cards: [Build Cache and Artifact Poisoning](#battlecards-build-cache-and-artifact-poisoning-md), [Maven and Gradle Wrapper Poisoning](#battlecards-maven-gradle-wrapper-poisoning-md), [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md)
