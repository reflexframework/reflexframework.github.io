---
title: Provenance and SBOM Tampering
category: Supply Chain Integrity
ref: RFX-SCI-03
precedent: "2020–2024"
scenario: Validly signed artifact and SBOM from a compromised build
focus:
  - signing keys reachable from CI
  - forged SBOMs with valid signatures
  - SLSA Build L3 platform provenance
  - release artifacts that differ from source
---

## Scenario

Acme ships `acme-agent`, a Java monitoring agent that customers install on their servers. Each release is a shaded fat JAR. Release CI generates a CycloneDX SBOM from the Maven build and signs both the JAR and the SBOM with a cosign key stored as a repository secret. Customers' platform teams verify the signature and scan the SBOM before rollout.

1. An attacker exploits a script injection in a `pull_request_target` workflow in Acme's repository. The step runs with the repository's secrets.
2. They exfiltrate the cosign private key and the token used to upload release assets.
3. On their own machine they build a backdoored `acme-agent-4.8.2.jar`. The backdoor is a few classes shaded into an existing package. They copy the clean SBOM from the real build.
4. They sign both files with Acme's key and upload them as the release.
5. Customers run `cosign verify-blob` and it passes. The SBOM scan is clean, because the SBOM describes the clean build. Shaded code never shows up in a customer's lockfile either, because it is inside Acme's JAR.

The signature proved only that someone holding Acme's key signed the files. That was always the case. Nobody had a way to ask the more useful question: was this file built by Acme's release workflow, from this tag?

::: {! precedent}
**Real-world precedent:** SolarWinds' build server ran [SUNSPOT (2020)](https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/), which swapped a source file during compilation so a validly signed Orion release shipped the SUNBURST backdoor. In [xz-utils (March 2024)](https://openwall.com/lists/oss-security/2024/03/29/4), part of the backdoor existed only in the release tarballs, not in git. In [Ultralytics (December 2024)](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/), a compromised GitHub Actions build published malicious releases to PyPI, and later ones used a leftover API token.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker looks for the path from "can run code in your CI" to "can publish something your customers trust". Public workflow files show which events run with secrets, how releases are signed, and where the key lives. A cosign key in `secrets.COSIGN_PRIVATE_KEY` is a clear target.

They also check what your customers verify. If the instructions say "verify the signature with our public key", then the key is all they need.

### Insight

Any long-lived signing key in CI is reachable by anything that runs in that job. Once it leaks, it signs whatever the attacker likes, from wherever they like, until you rotate it.

### Practical

- Read your release workflows as an attacker would. Note every secret, every step that runs before signing, and every trigger that runs untrusted code.
- Read your own customer-facing verification docs. Note exactly what a passing check proves.
- List every place your build can be influenced without a reviewed commit: caches, downloaded tools, base images, self-hosted runners.

### Tools/Techniques

- [zizmor](https://github.com/zizmorcore/zizmor) to find injection and dangerous triggers in GitHub Actions workflows.
- OpenSSF Scorecard's `Dangerous-Workflow` and `Token-Permissions` checks.

### Metrics/Signal

- Long-lived signing keys stored as CI secrets.
- Workflows that run on `pull_request_target` or `workflow_run` and check out PR code.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Place your releases on the SLSA build track. Build L1 means provenance exists. Build L2 means a hosted build platform signs it. Build L3 means the platform keeps the signing material away from the build steps, so a compromised step cannot forge provenance.

A self-signed SBOM sits outside that scale. It is a claim from whoever held the key. Check whether consumers can tie an artifact's digest to a specific repository, workflow and commit.

### Insight

Provenance tells you where and how something was built. It does not tell you the build was clean. The Ultralytics releases built by the compromised workflow carried genuine PyPI attestations. Those attestations were still valuable: they showed investigators the malicious code was injected during the build, not committed to the repository.

Check the SBOM's scope as well as its signature. Most SBOMs describe the application's dependencies and leave out the build tooling that produced it: Maven plugins, Gradle plugins, compilers and their own transitive dependencies. That tooling ran code in your release job, and it is where a SUNSPOT-style attack lives. In one Maven experiment, an SBOM that included resolved build plugins produced 77 scanner matches against 18 for the application-only SBOM. A match is a lead for investigation, and the gap is still worth closing. See [Build Tooling Blind Spots](#battlecards-build-tooling-blind-spots-md).

An SBOM is also only as true as the governance behind it. [Sonatype's 2026 State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction) warns that "shadow downloads" (wheels, CUDA libraries, models or scripts fetched from outside governed repositories) rarely appear in SBOMs or inventories. When builds pull artifacts that way, your signed compliance artefacts drift away from what actually shipped, with no tampering needed. See [Shadow Downloads](#battlecards-shadow-downloads-md).

### Practical

- For each release artifact, ask whether a consumer can verify the building workflow and source commit as well as a key.
- Check whether release jobs restore caches that untrusted workflows can write.
- Check whether release artifacts can be rebuilt from the tagged source. The xz lesson is that a release tarball can differ from git.
- Check whether release assets on GitHub are immutable once published.

### Tools/Techniques

- [SLSA v1.1 build levels](https://slsa.dev/spec/v1.1/levels).
- `diffoscope` to compare a rebuilt artifact with the published one.

### Metrics/Signal

- Release artifacts with platform-generated provenance, as a percentage of all releases.
- Release jobs that restore caches shared with PR workflows.
:::

::: {! stage fortify}
## Fortify

### Explanation

Remove the long-lived key, and let the platform produce the provenance. On GitHub, artifact attestations sign with a short-lived Sigstore certificate tied to the workflow run. Producing them from a reusable workflow that the calling repository cannot modify meets SLSA Build L3. Attest the SBOM the same way, so the SBOM is bound to the artifact digest and to the workflow that produced both.

### Insight

With keyless, workflow-bound signing, a stolen secret no longer lets anyone sign from a laptop. The attacker in this scenario would have to get their JAR built by Acme's release workflow from a tag, which is far harder to do quietly.

### Practical

- Move signing and attestation into a reusable workflow in a separate, tightly controlled repository. Call it from release workflows, pinned to a commit.

```yaml
# acme/secure-builds/.github/workflows/java-release.yml (reusable)
on:
    workflow_call:
permissions:
    contents: read
    id-token: write
    attestations: write
    artifact-metadata: write
jobs:
    build:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v6
            - run: ./mvnw -B verify org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
            - uses: actions/attest@v4
              with:
                  subject-path: target/acme-agent-*.jar
            - uses: actions/attest@v4
              with:
                  subject-path: target/acme-agent-*.jar
                  sbom-path: target/bom.json
```

Pin actions to full commit SHAs in practice. The caller needs the same permissions, and invokes it with `uses: acme/secure-builds/.github/workflows/java-release.yml@<commit-sha>`.

- Publish verification instructions that check the workflow and source ref:

```bash
gh attestation verify acme-agent-4.8.2.jar \
    --repo acme/acme-agent \
    --signer-repo acme/secure-builds \
    --source-ref refs/tags/v4.8.2 \
    --deny-self-hosted-runners

gh attestation verify acme-agent-4.8.2.jar \
    --repo acme/acme-agent \
    --signer-repo acme/secure-builds \
    --predicate-type https://cyclonedx.org/bom
```

- For npm packages, publish with trusted publishing so provenance is generated automatically. Consumers can check with `npm audit signatures`.
- For PyPI, trusted publishing with `pypa/gh-action-pypi-publish` produces PEP 740 attestations by default.
- Do not restore caches in release jobs, or key release caches so PR workflows cannot write them.
- Enable immutable releases on GitHub so published assets and tags cannot be swapped later.
- Build releases from the git tag only. Do not hand-craft release tarballs or JARs outside CI.

### Tools/Techniques

- [GitHub artifact attestations and SLSA Build L3](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3).
- [npm provenance](https://docs.npmjs.com/generating-provenance-statements) and [PEP 740](https://peps.python.org/pep-0740/).
- [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) for provenance from the SLSA GitHub generators.

### Metrics/Signal

- Long-lived signing keys left in CI. Target: zero.
- Releases whose documented verification checks signer workflow and source ref.
:::

::: {! stage limit}
## Limit

### Explanation

Assume one release gets through. You want it to be one release, on one channel, for a short time. That means fast revocation, customers who verify at install time, and builds that cannot reach other projects' secrets.

### Insight

Verification at deploy time is what turns a bad release into a blocked deploy. If customers only verify when they first adopt you, a later bad release sails through.

### Practical

- Give the release job only the permissions it needs. Keep upload tokens in a protected environment that requires approval.
- Ask customers to verify attestations in their deployment pipeline, or with an admission policy for container images.
- Keep a documented way to mark a release as withdrawn: delete the asset, publish an advisory, and update the "latest" pointer.
- Separate release infrastructure per product, so one compromised repository cannot sign for others.

### Tools/Techniques

- GitHub environments with required reviewers.
- Sigstore policy-controller or Kyverno image verification for container releases.

### Metrics/Signal

- Customers or internal teams verifying at deploy time.
- Time from "bad release confirmed" to "asset withdrawn and advisory published".
:::

::: {! stage expose}
## Expose

### Explanation

Look for releases that do not match how your releases are made. Every genuine release has an attestation from the expected workflow, created by a tagged run. Anything else is suspicious by definition.

### Insight

You can verify your own releases the way customers should. A scheduled job that runs `gh attestation verify` against each published asset catches a forged upload quickly.

### Practical

- After each release, download the published assets and verify their attestations from a separate workflow or account.
- Alert on release assets uploaded outside the release workflow, using the audit log.
- Periodically rebuild a release from its tag and compare it with the published artifact. Investigate any difference that is not explained by known non-determinism.
- Watch Sigstore's transparency log (Rekor) for signatures made with your identities outside your release workflows.

### Tools/Techniques

- GitHub audit log streaming for `release` events.
- [Reproducible Builds](https://reproducible-builds.org/) tooling and `diffoscope`.
- Maven's `artifact:compare` goal for checking reproducible Maven builds.

### Metrics/Signal

- Published assets without a matching attestation. Target: zero.
- Rebuild comparisons that differ from the published artifact.
:::

::: {! stage exercise}
## Exercise

### Explanation

Show that your verification catches a forged release, using a test repository and throwaway artifacts.

### Insight

The useful result is seeing which check fails. If only the key-based check exists, the forged release passes, and that is the lesson.

### Practical

1. In a private test repository, release a small JAR with attestations from your reusable workflow.
2. On a laptop, build a modified JAR and sign it with a throwaway cosign key that you pretend was leaked. Upload it to a second test release.
3. Run your published customer verification steps against both. Confirm the forged one fails `gh attestation verify` while `cosign verify-blob` with the "leaked" key passes.
4. Run the scheduled self-verification job and confirm it alerts on the forged asset.

### Tools/Techniques

- A private test repository and throwaway keys.
- Your real customer-facing verification instructions, followed word for word.

### Metrics/Signal

- Which checks caught the forged release.
- Time from forged upload to alert.
:::

## Further Reading

- [CrowdStrike: SUNSPOT, an implant in the build process (2021)](https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/)
- [Andres Freund: backdoor in upstream xz/liblzma (2024)](https://openwall.com/lists/oss-security/2024/03/29/4)
- [PyPI: Ultralytics attack analysis (2024)](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [SLSA v1.1 build levels](https://slsa.dev/spec/v1.1/levels)
- [GitHub: artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- Related cards: [Build Cache and Artifact Poisoning](#battlecards-build-cache-and-artifact-poisoning-md), [GitHub Actions Workflow Poisoning](#battlecards-github-actions-workflow-poisoning-md)
