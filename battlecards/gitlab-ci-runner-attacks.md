---
title: GitLab CI Runner Attacks
category: CI/CD & Build
ref: RFX-CI-09
precedent: "2026"
scenario: Malicious dependency runs on a shared GitLab runner
focus:
  - CI variable and job token theft
  - persistent runner and cache tampering
  - job token scope
---

## Scenario

Your team builds a Python service on GitLab. Jobs run on a self-managed runner pool that several projects share. The runners use the shell executor on long-lived VMs because "it's faster".

1. An attacker takes over the maintainer account of a small test helper that sits deep in your `requirements-dev.txt`. They publish version `1.2.4` with a payload in `setup.py`.
2. Your requirements file pins `>=1.2`, so the next pipeline installs it. The payload runs as the runner's user during `pip install`.
3. It reads every CI/CD variable in the job environment: a static `AWS_ACCESS_KEY_ID`, a deploy token, and `CI_JOB_TOKEN`. It sends them to an attacker-controlled host.
4. Because the shell executor shares one filesystem, the payload also edits files under other projects' build and cache directories on the same VM. It drops a modified `site-packages` module into a neighbouring project's cached virtualenv.
5. The neighbouring project's next job restores that cache and ships the backdoored module in its container image.

GitLab's defaults would have blocked some of this. Caches are per project, and protected and unprotected branches get separate caches. The cross-project step only works because the runner keeps state on a shared host.

::: {! precedent}
**Real-world precedent:** On 30 April 2026, `lightning` 2.6.2 and 2.6.3 appeared on PyPI with a credential harvester that ran as soon as the package was imported ([Lightning advisory, CVE-2026-44484](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3)). Part of the Mini Shai-Hulud campaign, it searched environment variables and files for cloud keys, tokens and CI/CD secrets ([Deepwatch](https://www.deepwatch.com/labs/ca-a-26-005-update-3-mini-shai-hulud-supply-chain-compromise/)). Any CI job that ran tests against it could hand over whatever its runner held. The older precedent is the [Codecov Bash Uploader](https://about.codecov.io/security-update/), which thousands of pipelines (GitLab included) piped into a shell. From January to April 2021 a modified copy sent every CI environment variable to the attackers.
:::

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers rarely target a GitLab instance head-on. They compromise something your pipeline already runs: a dependency, a container image, or a script fetched with `curl`. Public `.gitlab-ci.yml` files tell them which runners you use, which variables you expect and whether you build with Docker-in-Docker.

### Insight
The payload does its own reconnaissance at runtime. It checks `CI`, `GITLAB_CI` and `CI_SERVER_URL`, then dumps the environment. A CI runner is a far richer target than a laptop, and it runs your dependencies' install scripts on every pipeline.

### Practical
- List what your pipelines execute that you didn't write: base images, `pip`/`npm` install scripts, `include:` templates from other projects, remote scripts.
- Read your own public `.gitlab-ci.yml` as an attacker would. Note runner tags, variable names, and any `docker:dind` services.
- Find which runners serve which projects: **Admin > CI/CD > Runners** on self-managed, or **Settings > CI/CD > Runners** per project.

### Tools/Techniques
- [deps.dev](https://deps.dev/) to see the full transitive tree for a Python or npm package.
- `pip-audit` and [OSV-Scanner](https://github.com/google/osv-scanner) for known-bad versions in your lock files.
- [GitLab runner docs](https://docs.gitlab.com/ci/runners/) to confirm executor types and scope (instance, group or project runners).

### Metrics/Signal
- Number of third-party `include:` sources and remote scripts in pipelines.
- Count of transitive dependencies with install-time code in CI jobs.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Ask what a single malicious install script could reach on your runners today. The answer depends on the executor, how long the runner lives, what variables are exposed, and how the job token is scoped.

### Insight
Shared state is the real problem. A shell executor on a long-lived VM, or a Docker executor that mounts the host socket, lets one job tamper with what the next job sees. Cache key choice matters less: `$CI_COMMIT_REF_SLUG` already gives each branch its own cache, and GitLab never shares caches between projects.

### Practical
- Check each runner's `config.toml` for `executor = "shell"`, `privileged = true` and `/var/run/docker.sock` in `volumes`.
- Check **Settings > CI/CD > General pipelines**. Is **Use separate caches for protected branches** still on? It is by default.
- List variables per project and group. Flag any that are unmasked, unprotected, or long-lived cloud keys.
- Check the job token allowlist under **Settings > CI/CD > Job token permissions**. GitLab 18.0 turned on an instance setting that enforces the allowlist for every project. Self-managed administrators can switch it off, so check that it is still on.

### Tools/Techniques
- [GitLab caching docs](https://docs.gitlab.com/ci/caching/) for the protected/unprotected cache split.
- [CI/CD job token docs](https://docs.gitlab.com/ci/jobs/ci_job_token/) for allowlist behaviour.
- `gitlab-runner list` on runner hosts to see registered runners and executors.

### Metrics/Signal
- Runners using the shell executor or a mounted Docker socket.
- Projects with static cloud keys in CI/CD variables.
- Projects whose job token allowlist is disabled.
:::

::: {! stage fortify}
## Fortify

### Explanation
Stop the payload arriving, and make sure it lands somewhere clean if it does.

### Insight
Pinning and hash checking stop a hijacked version slipping in silently. Ephemeral, per-job environments stop one job poisoning another. You want both. Blocking install-time code is not enough on its own: the `lightning` payload ran on import, so a wheel-only install would still have run it in the test step.

### Practical
- Pin dependencies with hashes and install strictly:

    ```bash
    pip install --require-hashes --no-deps -r requirements-dev.lock
    ```

- Use Renovate's `minimumReleaseAge` so new versions wait a few days before your pipelines pick them up.
- Run jobs on the Docker or Kubernetes executor with a fresh container per job. Use autoscaled instance runners that are destroyed after each job for anything that touches secrets.
- Keep sensitive projects on their own runners. Register a project or group runner and route jobs with tags:

    ```yaml
    deploy:
      tags: [payments-isolated]
      script:
        - ./deploy.sh
    ```

- Key caches to lock files so a cache only matches identical dependencies:

    ```yaml
    cache:
      key:
        files:
          - requirements-dev.lock
      paths:
        - .venv/
    ```

### Tools/Techniques
- [GitLab Runner autoscaling](https://docs.gitlab.com/runner/runner_autoscale/) for ephemeral VMs.
- [Renovate](https://docs.renovatebot.com/configuration-options/#minimumreleaseage) `minimumReleaseAge`.
- `pip-compile --generate-hashes` (pip-tools) or `uv pip compile --generate-hashes` to produce hashed lock files.

### Metrics/Signal
- Share of CI jobs installing from hashed lock files.
- Share of runners that are single-use.
:::

::: {! stage limit}
## Limit

### Explanation
Assume the payload runs. Shrink what it can steal and where it can go.

### Insight
Everything in the job environment is gone the moment untrusted code runs. So keep long-lived secrets out of the environment entirely.

### Practical
- Replace static cloud keys with OIDC. Request `id_tokens` in the job and exchange them for short-lived cloud credentials scoped to that project and branch:

    ```yaml
    deploy:
      id_tokens:
        AWS_ID_TOKEN:
          aud: https://gitlab.example.com
      script:
        - >
          aws sts assume-role-with-web-identity
          --role-arn "$ROLE_ARN"
          --role-session-name "gitlab-$CI_JOB_ID"
          --web-identity-token "$AWS_ID_TOKEN"
    ```

- Mark deploy variables as **Protected** so they only reach jobs on protected branches and tags. Test jobs that install dev dependencies then never see them.
- Keep the job token allowlist enabled and list only the projects that genuinely need to call this one.
- Leave the job token option that allows Git push requests (generally available since GitLab 18.4) switched off unless a job truly needs it. Otherwise a stolen job token can push code.
- Restrict runner egress to your package mirror, GitLab and container registry. A payload that cannot reach the internet cannot exfiltrate.

### Tools/Techniques
- [GitLab OIDC with AWS](https://docs.gitlab.com/ci/cloud_services/aws/) and [Google Cloud](https://docs.gitlab.com/ci/cloud_services/google_cloud/).
- Kubernetes [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) for Kubernetes-executor runner pods.
- A local mirror (Nexus, Artifactory or devpi) as the only allowed package source.

### Metrics/Signal
- Count of static cloud credentials left in CI/CD variables (target: zero).
- Unprotected variables available to merge request pipelines.
:::

::: {! stage expose}
## Expose

### Explanation
You want to see install scripts doing things install scripts shouldn't: network calls to unknown hosts, reading the environment, writing outside the build directory.

### Insight
Job logs show what the script asked for. They won't show what a `setup.py` did in the background. You need runner-level telemetry.

### Practical
- Log DNS and outbound connections from runner hosts. Alert on destinations outside your allowlist.
- Run Falco or Tetragon on runner nodes. Alert on processes started by `pip` or `npm` that open sockets or read `/proc/*/environ`.
- Watch CloudTrail (or equivalent) for the runner's credentials being used from IP addresses that aren't your runners.
- Review the [job token authentication log](https://docs.gitlab.com/ci/jobs/ci_job_token/) under **Settings > CI/CD > Job token permissions** for projects you don't expect to be calling yours.

### Tools/Techniques
- [Falco](https://falco.org/) or [Tetragon](https://tetragon.io/) for runtime detection on runner hosts.
- An egress proxy (Squid or similar) with request logging in front of the runner network.

### Metrics/Signal
- Outbound connections from CI jobs to hosts not on the allowlist.
- Cloud API calls using CI credentials from non-runner IP addresses.
:::

::: {! stage exercise}
## Exercise

### Explanation
Prove that a malicious install script on your runners is contained and noticed.

### Insight
The useful question is "what could it reach?", answered on your real runners. Run it safely and you get an honest answer.

### Practical
1. Build a benign package in a private package index (devpi or a Nexus PyPI repository). Its `setup.py` lists environment variable *names* only, writes a marker file to the runner's home directory, and resolves a canary DNS name.
2. Add it to a throwaway project that uses the same runner pool as production projects.
3. Run the pipeline. Check which variable names it saw, whether the marker survived to the next job, and whether another project's job could read it.
4. Confirm your egress controls blocked or logged the DNS call and that someone was alerted.
5. Plant a [Canarytoken](https://canarytokens.org/) AWS key as a CI variable and confirm its use triggers an alert.

### Tools/Techniques
- [Canarytokens](https://canarytokens.org/) for fake cloud keys.
- A private devpi or Nexus PyPI repository for the test package. Never publish it to PyPI.

### Metrics/Signal
- Whether the marker file persisted across jobs (it shouldn't).
- Time from canary DNS lookup to alert.
:::

## Further Reading

- [GitLab: CI/CD job token](https://docs.gitlab.com/ci/jobs/ci_job_token/)
- [GitLab: Caching in CI/CD](https://docs.gitlab.com/ci/caching/)
- [GitLab: OpenID Connect in cloud services](https://docs.gitlab.com/ci/cloud_services/)
- [Lightning AI: Compromise of PyTorch Lightning PyPI package versions](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3)
- [Codecov security update (2021)](https://about.codecov.io/security-update/)
