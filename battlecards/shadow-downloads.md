---
title: Shadow Downloads
category: Network & Distribution
scenario: Build and runtime artefacts fetched from outside any governed repository
focus:
  - direct URL installs, curl in Dockerfiles and scripts
  - models and binaries pulled at runtime
  - build files that add their own repositories
  - egress logs compared with the SBOM
---

## Scenario

A company routes every package through an internal repository manager. Its SBOMs look complete. Its scanner reports are clean. Security signs off the release.

Then someone reads the build logs properly. The ML service's Dockerfile installs a CUDA-specific wheel from a URL on a university mirror. A setup script downloads a helper binary from a GitHub release and runs it. At startup, the service calls `from_pretrained()` and pulls the latest weights for a model from Hugging Face. A Gradle module adds a third-party Maven repository "temporarily", three years ago. A developer's `Makefile` runs `go install` against a module that has never been reviewed.

None of these went through the repository manager. None appear in the SBOM. None were scanned. If any of those sources changes what it serves, nobody would know which build picked it up.

These are shadow downloads: artefacts that reach your build or runtime by a path your governance cannot see.

**Real-world precedent:** Between January and April 2021, attackers modified [Codecov's Bash Uploader](https://about.codecov.io/security-update/), which many CI pipelines fetched and ran on every build. It sent CI environment variables to an attacker's server, and was spotted only when a customer compared its checksum with the published one. In June 2024 the new owner of the polyfill.io domain began [serving malicious JavaScript](https://sansec.io/research/polyfill-supply-chain-attack) to more than 100,000 sites that loaded it straight from the CDN. Sonatype's [2026 State of the Software Supply Chain](https://www.sonatype.com/state-of-the-software-supply-chain/2026/open-source-malware) report names shadow downloads as a growing gap, especially in ML pipelines: invisible to SBOMs, unscanned and unattributable.

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers look for software that fetches from a source they can influence. That might be a domain that is about to expire, a GitHub account with weak security, an unofficial mirror, a model repository with a mutable `main` branch, or a third-party Maven repository with no signing. Public Dockerfiles, CI configs and README install instructions tell them who is fetching what.

### Insight

Sonatype points out that MLOps has not yet absorbed many of the supply chain lessons from mainstream development. Teams under pressure to experiment pull wheels, CUDA libraries and models from wherever is easiest. Those are the paths with the least scrutiny.

### Practical

Find every place your build or runtime fetches something by URL:

- `curl`, `wget`, `ADD https://` and `Invoke-WebRequest` in Dockerfiles, scripts and CI files.
- `pip install https://...`, `pip install git+https://...`, `--extra-index-url` and `--find-links`.
- `repositories { maven { url ... } }` in Gradle files and `<repositories>` in POMs.
- `go install module@latest` and `GOPROXY=direct`.
- `from_pretrained()`, `hf_hub_download()` and `torch.hub.load()` without a pinned `revision`.
- `raw.githubusercontent.com`, `gist.github.com`, `pastebin.com` and release-download URLs anywhere in the repository.

```bash
git grep -nE 'curl |wget |ADD https?://|pip install (https?|git\+)|--extra-index-url|--find-links|raw\.githubusercontent|pastebin\.com|GOPROXY=direct|go install .*@latest|from_pretrained\(|hf_hub_download\(|torch\.hub\.load\('
```

### Tools/Techniques

- `git grep` or GitHub code search across the organisation.
- [Semgrep](https://semgrep.dev/) custom rules for the patterns above.
- Build tooling is a related blind spot: the [SBOM+ Maven Plugin](https://noregressions.github.io/sbom-plus-maven-plugin/) inventories Maven build plugins and their dependencies, which ordinary application SBOMs leave out.

### Metrics/Signal

- Number of direct-URL fetches found per repository.
- Number of distinct external domains your builds and services fetch from.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For each shadow download, ask four questions. Is the content pinned (a checksum, digest or commit)? Is it verified before use? Does it appear in the SBOM? Who controls the source?

An unpinned fetch from a source someone else controls means that someone else decides what you run.

### Insight

The SBOM tells you what your tools saw. Network egress tells you what your build actually fetched. The difference between the two is your shadow inventory.

### Practical

- Capture outbound connections from a representative CI build and from service start-up.
- Compare the domains contacted with the registries and repository manager your SBOM assumes. Anything else is a shadow source.
- For each shadow source, record what is fetched, whether it is pinned, and an owner.

```bash
# egress-domains.txt: one domain per line, from Harden-Runner, a proxy log or DNS logs
# approved-domains.txt: your repository manager and approved registries
sort -u egress-domains.txt > seen.txt
sort -u approved-domains.txt > approved.txt
comm -23 seen.txt approved.txt
```

### Tools/Techniques

- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) in `audit` mode to list every domain a GitHub Actions job contacts.
- Proxy or DNS logs for self-hosted runners and Kubernetes workloads.
- [Syft](https://github.com/anchore/syft) or your existing SBOM tool, to compare against.

### Metrics/Signal

- Egress domains not represented in the SBOM.
- Shadow downloads with no checksum, digest or commit pin.
:::

::: {! stage fortify}
## Fortify

### Explanation

Route everything through governed channels, and pin whatever cannot be routed. A repository manager or caching proxy can front PyPI, npm, Maven, Go modules, container registries and, in many products, Hugging Face. Once it does, the build should have no reason to reach the internet directly.

### Insight

Pinning turns a silent change into a loud failure. Codecov's tampering was caught by a checksum comparison. A pinned digest makes that check automatic.

### Practical

- **Send all package traffic through the repository manager.** Set it as the only index or registry in `pip.conf`, `.npmrc`, `settings.xml`, `GOPROXY` and Gradle settings.
- **Stop build files adding their own repositories.**

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url = uri("https://repo.example.internal/maven-public/") }
    }
}
```

```xml
<!-- Maven: fail the build if any POM declares its own repository -->
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-enforcer-plugin</artifactId>
  <executions>
    <execution>
      <id>no-repositories</id>
      <goals><goal>enforce</goal></goals>
      <configuration>
        <rules>
          <requireNoRepositories/>
        </rules>
      </configuration>
    </execution>
  </executions>
</plugin>
```

- **Pin and verify anything fetched by URL.** Pin base images by digest, and give remote files a checksum.

```dockerfile
FROM python:3.12-slim@sha256:<digest>

ADD --checksum=sha256:<sha256-of-file> https://downloads.example.org/tool-1.4.2.tar.gz /tmp/
```

- **Pin models to a commit and prefer safetensors.** Mirror approved models into your own storage or a proxy, and run production offline from that cache.

```python
from transformers import AutoModel

model = AutoModel.from_pretrained(
    "org/model-name",
    revision="<40-character commit sha>",
    use_safetensors=True,
)
```

- **Deny direct internet from CI where practical.** Allow only the repository manager and the services the job genuinely needs.

### Tools/Techniques

- Gradle [`RepositoriesMode.FAIL_ON_PROJECT_REPOS`](https://docs.gradle.org/current/userguide/declaring_repositories.html) and the Maven Enforcer [`requireNoRepositories`](https://maven.apache.org/enforcer/enforcer-rules/requireNoRepositories.html) rule.
- pip `--require-hashes`; Go `GOPROXY` pointed at your proxy with the checksum database left on.
- Dockerfile `ADD --checksum` and digest-pinned `FROM`.
- Hugging Face `revision` pinning, with `HF_HUB_OFFLINE=1` or `HF_ENDPOINT` pointing at an internal mirror.
- Harden-Runner `egress-policy: block` with `allowed-endpoints`, or network policies on self-hosted runners.

### Metrics/Signal

- Builds that pass with direct internet access removed.
- Percentage of images, remote files and models pinned by digest, checksum or commit.
:::

::: {! stage limit}
## Limit

### Explanation

If a shadow source is compromised, limit what its payload can reach. The Codecov script ran in CI with every environment variable available to it. Polyfill ran in every visitor's browser.

### Insight

The steps that fetch external content are rarely the steps that need secrets. Separating them is cheap.

### Practical

- Run download and install steps in a job or build stage with no secrets, and pass results on as artefacts.
- Use multi-stage Docker builds so download tools and fetched installers never reach the final image.
- Use short-lived OIDC credentials in CI so a stolen environment dump expires quickly.
- Load models and third-party scripts in processes with no access to production credentials.

### Tools/Techniques

- Separate CI jobs with explicit `permissions:` and secrets scoped per job or environment.
- Multi-stage Dockerfiles.
- Cloud OIDC federation from CI.

### Metrics/Signal

- CI jobs that fetch external content and also hold secrets.
- Lifetime of credentials exposed to build steps.
:::

::: {! stage expose}
## Expose

### Explanation

Detect new shadow downloads as they are introduced, and detect changes in what known sources serve. The first is a code review problem. The second is a network monitoring problem.

### Insight

A new egress domain from a build is cheap to spot and rarely benign. Treat it like a new dependency that skipped review.

### Practical

- Run the `git grep` patterns from Reconnaissance as a CI check on every PR.
- Alert on new egress destinations from CI and from services at start-up.
- Compare egress domains with the SBOM on a schedule, and open a ticket for each gap.
- Log the resolved digest or checksum of everything fetched, so you can answer "which builds got the bad version?" later.

### Tools/Techniques

- Semgrep or a simple grep-based CI check.
- Harden-Runner, proxy logs or DNS logs with alerting on new domains.
- Build provenance (SLSA, GitHub artifact attestations) recording what each build consumed.

### Metrics/Signal

- New shadow downloads introduced per month, and time to remove or govern them.
- Builds with unexplained egress.
:::

::: {! stage exercise}
## Exercise

### Explanation

Prove that your builds still work with the internet switched off, apart from the repository manager. Then prove you would notice a shadow source changing.

### Insight

The first offline build fails in surprising places: a test fixture downloaded at runtime, a tool that phones home for updates, a model fetched on first import. Each failure is a shadow download you did not know about.

### Practical

1. In a sandbox, run a full CI build with egress limited to your repository manager. Record every failure.
2. For each failure, route the fetch through the repository manager, pin it, or remove it.
3. Host a harmless file on a local web server, pin its checksum in a test Dockerfile, then change the file. Confirm the build fails.
4. Point a test service at a local copy of a model pinned by `revision`, then add a commit to that local repository. Confirm the service keeps loading the pinned version.

### Tools/Techniques

- A sandbox CI runner with egress rules, or Harden-Runner in `block` mode.
- A local HTTP server and a local Git repository standing in for remote sources.
- Your SBOM tool and the egress comparison script.

### Metrics/Signal

- Number of offline-build failures, trending to zero.
- Whether the modified file was caught by the checksum (it should be).
:::

## Further Reading

- [Sonatype: 2026 State of the Software Supply Chain, open source malware chapter](https://www.sonatype.com/state-of-the-software-supply-chain/2026/open-source-malware)
- [Codecov: Bash Uploader security update](https://about.codecov.io/security-update/)
- [Sansec: Polyfill supply chain attack](https://sansec.io/research/polyfill-supply-chain-attack)
- [PyTorch: Compromised PyTorch-nightly dependency chain](https://pytorch.org/blog/compromised-nightly-dependency/)
- [Hugging Face Hub environment variables](https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables)
- See also [curl | bash Installer Attacks](#battlecards-curl-bash-installer-attacks-md), [CDN Script Compromise and Mirror Substitution](#battlecards-cdn-and-mirror-substitution-md) and [Poisoned AI/ML Models](#battlecards-poisoned-ai-ml-models-md).
