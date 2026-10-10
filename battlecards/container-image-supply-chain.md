---
title: Container Base Image and Registry Risks
category: Infrastructure & Cloud
scenario: Stale base image carries a backdoor and published layers leak live credentials
focus:
  - base image provenance and digest pinning
  - secrets left in image layers
  - untrusted Docker Hub publishers and lookalike repositories
---

## Scenario

A team runs a dozen small services. Each Dockerfile starts `FROM` something somebody chose two years ago. One uses an old Debian tag nobody has touched since spring 2024. Another uses a community image with a friendly name and a lot of pulls. Nobody knows who publishes it.

The pipeline builds with `COPY . .` and pushes to a public Docker Hub repository so a partner can pull the images. The repository root holds a `.env` file with a database password, a cloud access key and an AI provider token. The `.dockerignore` file does not exist.

Two things go wrong, quietly:

1. The old Debian tag was built during the window when backdoored `xz-utils` 5.6.0 and 5.6.1 were in Debian testing. The image still ships the compromised `liblzma`. Every service built on it inherits that library, and so does every image built on top of those.
2. The `.env` file lands in a layer. Somebody spots it and deletes it in a later commit, so the next build drops it. The old image tag is still on Docker Hub, and the layer that holds the file is still there. Nobody rotated the keys.

An attacker who scans Docker Hub for credentials does not need to break anything. They pull the image, unpack the layers and read the file.

**Real-world precedent:** In August 2025, Binarly found at least 35 images on Docker Hub that still shipped the xz backdoor (CVE-2024-3094), including Debian images and images built on them; Debian chose to leave the old tags up as historical artefacts ([BleepingComputer](https://www.bleepingcomputer.com/news/security/docker-hub-still-hosts-dozens-of-linux-images-with-the-xz-backdoor/), [Binarly](https://www.binarly.io/blog/persistent-risk-xz-utils-backdoor-still-lurking-docker)). In December 2025, Flare reported 10,456 images uploaded to Docker Hub in a single month that exposed one or more secrets, often through a copied `.env` file, and found that 75% of leaked keys removed from images were never revoked ([Flare](https://flare.io/learn/resources/docker-hub-secrets-exposed)). In April 2024, JFrog found about 2.81 million "imageless" Docker Hub repositories used to push malware and phishing links; Docker removed them ([JFrog](https://jfrog.com/blog/attacks-on-docker-with-millions-of-malicious-repositories-spread-malware-and-phishing-scams/)).

::: {! stage recon}
## Reconnaissance

### Explanation

Public registries are searchable, and so are public Dockerfiles. An attacker can list every image your organisation publishes, pull each tag and read every layer. Tools that scan layers for secrets are free and fast, so this is cheap to do at scale.

Your Dockerfiles also tell attackers which base images you trust. If they see `FROM someuser/node-tools:latest`, they know a single account controls what runs in your build. If they see an old tag, they know you are not rebuilding.

### Insight

Deleting a file in a later layer, or in a later tag, removes nothing from the registry. The attacker reads the history you forgot you published.

### Practical

- List every public repository your organisation and its staff publish to on Docker Hub, GHCR and other registries. Include personal and contractor accounts used for work.
- Pull your own public images and look at them the way an attacker would: `docker history --no-trunc` and a layer-by-layer secret scan.
- Grep your Dockerfiles for `FROM` lines and record each base image, its tag and its publisher.

### Tools/Techniques

- `docker history --no-trunc <image>` shows the commands, `ARG` and `ENV` values recorded in each layer.
- [TruffleHog](https://github.com/trufflesecurity/trufflehog): `trufflehog docker --image <image>` unpacks and scans every layer.
- [Trivy](https://trivy.dev/): `trivy image --scanners secret <image>`.
- GitHub code search across your organisation for `FROM ` in `Dockerfile` and `Containerfile`.

### Metrics/Signal

- Number of public image repositories, and how many of them belong to personal accounts.
- Secrets found in any layer of any published tag, live or deleted from the latest build.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For each base image, answer three questions. Who publishes it? Is it pinned to something that cannot move? When was it last rebuilt? Then check your own published images for credentials in any layer, across every tag that is still public.

Docker Hub marks Docker Official Images, Verified Publisher and Sponsored OSS repositories. Everything else is a community upload, and anyone can create an account. Popular pull counts prove nothing, since attackers inflate them.

### Insight

A tag is a pointer that the publisher can move. An old tag that never moves is a different problem: it keeps the bugs and backdoors it was built with. You want a fixed reference that you update on purpose.

### Practical

- Classify each base image as official, verified publisher, minimal or hardened image, or unknown community image.
- Flag `FROM` lines that use `latest`, a floating tag, or a tag older than your patch policy allows.
- Scan base images for known vulnerabilities and for CVE-2024-3094 specifically if any were built in 2024.
- Check whether the image ships a signature or provenance you can verify.

### Tools/Techniques

- `docker buildx imagetools inspect <image>` or `crane digest <image>` to resolve a tag to its digest.
- `cosign tree <image>` to see signatures and attestations attached to an image.
- Trivy, [Grype](https://github.com/anchore/grype) or Docker Scout for vulnerability scanning.
- [Hadolint](https://github.com/hadolint/hadolint) for Dockerfile hygiene, and `docker build --check` for BuildKit's build checks, including `SecretsUsedInArgOrEnv`.

### Metrics/Signal

- Percentage of `FROM` lines pinned by digest.
- Base images from unknown community publishers.
- Age of the oldest base image in production.
:::

::: {! stage fortify}
## Fortify

### Explanation

Pull base images from publishers you can name, pin them by digest and let a bot update the digest. Keep secrets out of the build context and out of layers altogether. Sign what you publish so consumers can check it came from your pipeline.

### Insight

Docker retired Docker Content Trust for Official Images in 2025, so `DOCKER_CONTENT_TRUST=1` no longer protects you there. Signature checks now mean Sigstore or Notation.

### Practical

- Use Docker Official Images, verified publishers, or minimal images such as distroless, Chainguard Images or Docker Hardened Images. Fewer packages means fewer places for a backdoor to hide.
- Pin by digest and keep the tag as a comment for humans. Renovate (`docker:pinDigests`) and Dependabot both raise pull requests when the digest changes.
- Add a `.dockerignore` that excludes `.env`, `.git`, keys and local config. Copy only what the image needs.
- Pass build-time credentials with BuildKit secret mounts. They are never written to a layer.
- Use multi-stage builds so compilers, package manager config and tokens stay in the build stage.

```dockerfile
# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim@sha256:<digest> AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
COPY src ./src
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian12@sha256:<digest>
COPY --from=build /app/dist /app
CMD ["/app/server.js"]
```

```bash
docker build --secret id=npmrc,src=$HOME/.npmrc -t ghcr.io/example/app:1.4.2 .
```

- Sign images in CI with keyless cosign and attach build provenance (GitHub artifact attestations or SLSA provenance).

### Tools/Techniques

- [Sigstore cosign](https://docs.sigstore.dev/cosign/signing/signing_with_containers/) for keyless signing.
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) for container provenance.
- Renovate or Dependabot for digest updates.
- `.dockerignore`, BuildKit `--mount=type=secret`, multi-stage builds.

### Metrics/Signal

- Percentage of images built from approved base images, pinned by digest.
- Images published with a signature and provenance.
- Build checks failing on secrets in `ARG` or `ENV`, trending to zero.
:::

::: {! stage limit}
## Limit

### Explanation

Assume a base image will turn out to be bad, or a key will slip into a layer. Limit what the backdoor can reach and how long a leaked key stays useful. Block unknown images from running in your clusters at all.

### Insight

Flare found that most developers who pulled a leaked key from an image never revoked it. The key stayed live. Revoke and rotate first, then tidy up.

### Practical

- Enforce signature and source checks at admission. Only images signed by your pipeline, or by named publishers, should run.
- Mirror approved base images into a private registry and point builds at the mirror.
- Use short-lived, workload-identity credentials at runtime so nothing worth stealing is baked into an image.
- Keep images private unless they truly need to be public. Publish to a separate, audited namespace when they do.
- Run containers as non-root, read-only, with no unneeded network egress.

```bash
cosign verify \
    --certificate-identity-regexp '^https://github.com/example/app/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/example/app@sha256:<digest>
```

### Tools/Techniques

- Kubernetes admission control: [Kyverno](https://kyverno.io/) `ImageValidatingPolicy` or [Sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/).
- Pull-through caches and mirrors in Harbor, Artifactory, Nexus or a cloud registry.
- Cloud workload identity (IRSA, GKE Workload Identity, Azure Workload Identity) in place of keys in images.
- See [Kubernetes Misconfigurations](#battlecards-kubernetes-misconfigurations-md) for runtime hardening.

### Metrics/Signal

- Admission denials for unsigned or unknown images.
- Static credentials found inside images, trending to zero.
- Time from detecting a leaked secret in an image to revoking it.
:::

::: {! stage expose}
## Expose

### Explanation

Watch two things: what goes into your images, and what runs that you did not expect. Scan every image at build and on a schedule, because a clean image today can match a new advisory tomorrow. Watch registry and cluster events for images that bypassed the normal path.

### Insight

The xz backdoor sat in public images for more than a year after disclosure. Continuous rescanning would have flagged it on the first run after the CVE landed.

### Practical

- Fail the build on any secret found in the final image, and scan all intermediate layers as well.
- Rescan the images you run in production every day against current vulnerability data.
- Alert on pods that run images from outside your approved registries, or by tag without a digest.
- Turn on secret scanning for your registries and repositories, and subscribe to provider leak notifications.

### Tools/Techniques

- TruffleHog or Trivy secret scanning in CI, after `docker build` and before `docker push`.
- Trivy Operator or your registry's built-in scanning for continuous rescans.
- Kubernetes audit logs and admission controller reports.
- GitHub secret scanning and push protection on the repositories that hold Dockerfiles.

### Metrics/Signal

- Secrets detected per build, and whether each was revoked.
- Running images with critical findings older than your fix window.
- Pods running unsigned images or images from unknown registries.
:::

::: {! stage exercise}
## Exercise

### Explanation

Prove your pipeline catches a leaked secret in a layer, and that your cluster refuses an unsigned image. Use canary tokens and a local registry, so nothing real leaks and nothing reaches Docker Hub.

### Insight

A scan that only reads the final filesystem misses a file added in one layer and deleted in the next. Find out which kind you have.

### Practical

1. Run a local registry: `docker run -d -p 5000:5000 --name registry registry:2`.
2. Generate an AWS-style canary token (for example from Thinkst Canarytokens) and write it into a `.env` file in a test project.
3. Build an image that copies the `.env` file in one layer and deletes it in the next. Push it to `localhost:5000`.
4. Run your CI secret scan against the image. Check it reports the layer, and that the canary did not fire from anywhere unexpected.
5. Deploy the unsigned image to a test cluster with your admission policy on. Confirm it is rejected.
6. Pick one production base image and time how long it takes to move every service to a new digest.

### Tools/Techniques

- `registry:2`, Thinkst Canarytokens, TruffleHog, Trivy.
- [kind](https://kind.sigs.k8s.io/) with Kyverno or policy-controller installed.

### Metrics/Signal

- Whether the scan found the deleted-layer secret.
- Whether admission blocked the unsigned image.
- Hours to roll a new base image digest across all services.
:::

## Further Reading

- [Binarly: Persistent Risk: XZ Utils Backdoor Still Lurking in Docker Images](https://www.binarly.io/blog/persistent-risk-xz-utils-backdoor-still-lurking-docker)
- [Flare: Thousands of Exposed Secrets Found on Docker Hub](https://flare.io/learn/resources/docker-hub-secrets-exposed)
- [JFrog: Attacks on Docker Hub with millions of malicious repositories](https://jfrog.com/blog/attacks-on-docker-with-millions-of-malicious-repositories-spread-malware-and-phishing-scams/)
- [Docker: Build secrets](https://docs.docker.com/build/building/secrets/)
- [Docker: Retiring Docker Content Trust](https://www.docker.com/blog/retiring-docker-content-trust/)
- Related cards: [Docker Socket and Privileged Builds](#battlecards-docker-socket-and-privileged-builds-md), [Kubernetes Misconfigurations](#battlecards-kubernetes-misconfigurations-md), [Exposed Secrets in Code and Config](#battlecards-exposed-secrets-in-code-and-config-md)
