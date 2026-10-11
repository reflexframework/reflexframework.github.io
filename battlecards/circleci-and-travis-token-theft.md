---
title: Hosted CI Secret Theft (CircleCI, Travis CI)
category: CI/CD & Build
ref: RFX-CI-10
precedent: "2023"
scenario: Secrets stored in a hosted CI service leak or are stolen
focus:
  - provider-side breach of stored secrets
  - secrets exposed to fork pull requests and logs
  - long-lived keys versus OIDC
---

## Scenario

Your open-source project builds on a hosted CI service. Over the years the project settings have collected secrets: an AWS access key for publishing docs, a Docker Hub password, and a GitHub personal access token for release automation. None has been rotated since it was added.

1. The CI provider announces a security incident. An attacker had access to its systems and to customer environment variables. Every customer is told to rotate every secret.
2. Nobody on your team owns that list of secrets. It takes two days to work out where each one is used.
3. Meanwhile, the attacker uses your Docker Hub password to push a new tag of your base image with a cryptominer added.
4. A separate risk sits in your own config. A debug step runs `env | base64` to diagnose a failing build. The provider's log masking looks for exact secret values, so the encoded output appears in public build logs.

::: {! precedent}
**Real-world precedent:** In January 2023, [CircleCI disclosed a breach](https://circleci.com/blog/jan-4-2023-incident-report/) in which malware on an engineer's laptop stole an SSO session. Attackers accessed customer environment variables, tokens and keys, and CircleCI told all customers to rotate every secret. In September 2021, a Travis CI bug ([CVE-2021-41077](https://nvd.nist.gov/vuln/detail/CVE-2021-41077)) exposed public repositories' secrets to builds triggered by pull requests from forks.
:::

::: {! stage recon}
## Reconnaissance

### Explanation
Two kinds of attacker care about your hosted CI secrets. One breaches the provider and gets everyone's secrets at once. The other reads your public config and build logs looking for mistakes.

### Insight
You can't stop a provider breach. You can make sure the secrets it holds are few, short-lived and quick to rotate.

### Practical
- List every secret stored in each CI project and context, with an owner and the systems it unlocks.
- For public projects, open a few recent build logs while logged out. Look for anything that resembles a key, including base64 blobs.
- Check whether any of your projects still mention `travis-ci.org`. That service shut down in 2021; stale badges and configs point to builds nobody is watching.

### Tools/Techniques
- CircleCI's API or UI to list [project environment variables and contexts](https://circleci.com/docs/guides/security/env-vars/).
- [gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) to scan repository history and downloaded logs.
- GitHub [secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning) for secrets committed to repositories.

### Metrics/Signal
- Number of stored CI secrets without a named owner.
- Age of the oldest stored secret.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Assess what a leak of your CI secrets would unlock and how secrets could reach untrusted code.

### Insight
Fork pull requests are the classic gap. Hosted CI services keep secrets away from fork builds by default, but a single checkbox reverses that.

### Practical
- In CircleCI, check **Project Settings > Advanced > Pass secrets to builds from forked pull requests**. For public projects it should be off.
- Check whether any job prints the environment, runs with `set -x` around secret use, or encodes secrets. Masking only catches exact matches.
- Check how jobs log in to registries. `docker login -p "$PASSWORD"` puts the password on the command line, where it can show in process lists and logs.
- For each secret, ask: could this be an OIDC-issued short-lived credential instead?

### Tools/Techniques
- `grep -rnE 'set -x|printenv|env \|' .circleci/ .travis.yml` to find risky debug steps.
- [CircleCI OIDC tokens](https://circleci.com/docs/guides/permissions-authentication/openid-connect-tokens/) documentation.

### Metrics/Signal
- Projects passing secrets to fork builds.
- Share of stored secrets that could be replaced by OIDC.
:::

::: {! stage fortify}
## Fortify

### Explanation
Store fewer secrets in the CI provider, and handle the remaining ones carefully.

### Insight
The best secret to lose in a provider breach is one that expired an hour ago. OIDC gets you there.

### Practical
- Use OIDC for cloud access. CircleCI issues `$CIRCLE_OIDC_TOKEN_V2` to jobs. Exchange it for short-lived AWS credentials and drop the static key:

    ```yaml
    jobs:
      publish-docs:
        docker:
          - image: cimg/aws:2026.09
        steps:
          - run:
              name: Assume role via OIDC
              command: |
                aws sts assume-role-with-web-identity \
                  --role-arn "$DOCS_ROLE_ARN" \
                  --role-session-name "circleci-$CIRCLE_BUILD_NUM" \
                  --web-identity-token "$CIRCLE_OIDC_TOKEN_V2" \
                  --duration-seconds 900
    ```

    Restrict the IAM trust policy to your organisation and project IDs in the token's `sub` claim.
- Log in to registries without exposing the password:

    ```bash
    echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USER" --password-stdin
    ```

- Use Docker Hub access tokens with the narrowest scope, never the account password.
- Keep files you must commit encrypted with [SOPS](https://github.com/getsops/sops) and decrypt them in the job with a KMS key reached via OIDC.
- Keep secrets for publishing in restricted contexts (CircleCI) that only release jobs can use.

### Tools/Techniques
- [CircleCI OIDC](https://circleci.com/docs/guides/permissions-authentication/openid-connect-tokens/) with AWS, Google Cloud or Vault.
- [CircleCI contexts with security groups](https://circleci.com/docs/guides/security/contexts/).
- [SOPS](https://github.com/getsops/sops).

### Metrics/Signal
- Number of long-lived cloud keys in CI settings (target: zero).
- Jobs using `--password-stdin` or credential helpers for registry login.
:::

::: {! stage limit}
## Limit

### Explanation
Assume your CI secrets leak tomorrow. Limit what each one opens and make rotation routine.

### Insight
The CircleCI breach hurt most where teams had never rotated anything. Scripted monthly rotation is dull, and dull is what you want during an incident.

### Practical
- Give each secret one job: a Docker Hub token that can push one repository, an AWS role that can write one bucket.
- Rotate stored secrets on a schedule and script it. If you can't script it, that secret is a priority for OIDC.
- Protect release artifacts so a stolen registry token is less useful: sign images with cosign and verify signatures at deploy time.
- Use fine-grained GitHub tokens or a GitHub App limited to the repositories release automation touches.

### Tools/Techniques
- [Sigstore cosign](https://docs.sigstore.dev/cosign/signing/overview/) for image signing and verification.
- [Docker Hub access token scopes](https://docs.docker.com/security/for-developers/access-tokens/).

### Metrics/Signal
- Time to rotate every CI secret (measure it, then cut it).
- Share of deployments verifying image signatures.
:::

::: {! stage expose}
## Expose

### Explanation
Detect a stolen CI secret being used outside CI.

### Insight
A CI credential has a very predictable life. It runs from known IP ranges at build time. Use from anywhere else is a strong signal.

### Practical
- Alert when AWS CloudTrail shows a CI role or key used from IP addresses outside your provider's published ranges, or outside build hours for scheduled jobs.
- Watch Docker Hub and your registry for tags pushed by tokens outside a pipeline run.
- Subscribe to your CI provider's status and security notices, and treat an incident notice as a page.

### Tools/Techniques
- AWS CloudTrail and GuardDuty, or your cloud's equivalent.
- [Canarytokens](https://canarytokens.org/) AWS keys stored alongside real secrets as tripwires.

### Metrics/Signal
- Cloud API calls from CI credentials outside expected IP ranges.
- Registry pushes without a matching pipeline run.
:::

::: {! stage exercise}
## Exercise

### Explanation
Rehearse the "rotate everything" email before it arrives.

### Insight
After the CircleCI incident, the slow part for many teams was finding every secret they had stored there.

### Practical
1. Pick one project. Pretend the provider has just told you all its secrets are compromised.
2. Rotate every secret using only your runbook. Time it and note every secret that surprised you.
3. Add a Canarytoken AWS key as a project variable. Use it from your laptop and confirm the alert fires.
4. Open a test pull request from a fork that prints `env | sort | cut -d= -f1`. Confirm no secret names appear.

### Tools/Techniques
- [Canarytokens](https://canarytokens.org/).
- A throwaway fork under your own account for the pull request test.

### Metrics/Signal
- Time to rotate all secrets for one project.
- Secrets visible to fork builds (target: zero).
:::

## Further Reading

- [CircleCI incident report, 4 January 2023](https://circleci.com/blog/jan-4-2023-incident-report/)
- [CVE-2021-41077: Travis CI secrets exposed to fork builds](https://nvd.nist.gov/vuln/detail/CVE-2021-41077)
- [CircleCI: Using OpenID Connect tokens in jobs](https://circleci.com/docs/guides/permissions-authentication/openid-connect-tokens/)
- [Related card: GitHub OIDC misconfiguration](#battlecards-github-oidc-misconfiguration-md)
