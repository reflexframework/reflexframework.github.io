---
title: Docker Socket and Privileged Builds
category: CI/CD & Build
scenario: Build job escapes to the runner host through the Docker socket
focus:
  - mounted /var/run/docker.sock
  - privileged build containers
  - rootless image builds
---

## Scenario

Your self-hosted GitLab runner uses the Docker executor. To let jobs build images, someone added the host's Docker socket to the runner's `config.toml`:

```toml
[runners.docker]
  privileged = false
  volumes = ["/var/run/docker.sock:/var/run/docker.sock", "/cache"]
```

Every job container can now talk to the host's Docker daemon.

1. A transitive Python dependency is hijacked. Its install script runs during `pip install` in an ordinary test job.
2. The script checks for `/var/run/docker.sock`. Finding it, it calls the Docker API and starts a new container that mounts the host's root filesystem:

    ```bash
    docker run --rm --privileged -v /:/host alpine \
      chroot /host sh -c 'cat /etc/gitlab-runner/config.toml'
    ```

3. That container runs as root on the host. The script reads the runner's registration token and the cloud credentials on the VM, and adds a cron job for persistence.
4. Every later job on that runner, including release builds, now runs on a host the attacker controls.

Access to the Docker socket is root on the host. The `privileged = false` setting doesn't help, because the attacker asks the daemon for a new privileged container.

**Real-world precedent:** In January 2024, Snyk disclosed [Leaky Vessels](https://snyk.io/blog/leaky-vessels-docker-runc-container-breakout-vulnerabilities/), including [CVE-2024-21626](https://github.com/advisories/GHSA-xr7r-f8xq-vfvv) in runc. A crafted image or Dockerfile could escape to the host during `docker run` or `docker build`, which is exactly what CI runners do with untrusted code all day.

::: {! stage recon}
## Reconnaissance

### Explanation
The payload does its own reconnaissance. It checks for a Docker socket, a `DOCKER_HOST` variable, or signs that it is running privileged. Attackers can also read public CI configuration for `docker.sock` mounts and `--privileged` options.

### Insight
CI configs that mount the socket are easy to find. So are blog posts recommending it, which is how it got into your config in the first place.

### Practical
- Search your CI configuration for socket mounts and privileged settings:

    ```bash
    grep -rnE "docker\.sock|privileged|--privileged" \
      .gitlab-ci.yml .github/workflows/ Jenkinsfile /etc/gitlab-runner/config.toml 2>/dev/null
    ```

- On GitHub Actions, look for `container:` or `services:` blocks with `options: --privileged` or a socket volume. There is no `privileged: true` key; it is passed through `options`.

### Tools/Techniques
- `grep` across repositories, or GitHub code search within your organisation.
- [zizmor](https://github.com/zizmorcore/zizmor) for wider GitHub Actions workflow review.

### Metrics/Signal
- Runners and workflows that mount the Docker socket.
- Jobs that run with `--privileged`.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Find out which jobs can reach a Docker daemon or run privileged, and what lives on those hosts.

### Insight
Docker-in-Docker (`docker:dind`) needs a privileged container. A socket mount needs nothing at all. Both hand the job a path to root on the runner.

### Practical
- From a test job on each runner, check what the job can see:

    ```bash
    ls -l /var/run/docker.sock 2>/dev/null
    echo "DOCKER_HOST=${DOCKER_HOST:-unset}"
    grep CapEff /proc/self/status
    ```

    A `CapEff` of `000001ffffffffff` or similar (all bits set) means the container is privileged.
- Check the runtime version on each runner. runc before 1.1.12 is vulnerable to CVE-2024-21626:

    ```bash
    runc --version
    ```

- Note what lives on each runner host: runner tokens, cloud credentials, caches shared with other jobs.

### Tools/Techniques
- [Trivy](https://github.com/aquasecurity/trivy) (`trivy rootfs /` on a runner host) to find vulnerable runc and containerd packages.
- `capsh --decode=<CapEff value>` (from libcap) to list the capabilities a job actually has.

### Metrics/Signal
- Runners on vulnerable runc versions.
- Jobs with Docker daemon access or full capabilities.
:::

::: {! stage fortify}
## Fortify

### Explanation
Build images without giving jobs a Docker daemon or root.

### Insight
Kaniko used to be the standard answer, but it was archived in June 2025 and always ran as root inside its container. Rootless BuildKit and Buildah are the current options.

### Practical
- Remove the socket mount and `privileged = true` from runner configuration.
- Build images with rootless BuildKit. GitLab's documented job:

    ```yaml
    build-image:
      image:
        name: moby/buildkit:rootless
        entrypoint: [""]
      variables:
        BUILDKITD_FLAGS: --oci-worker-no-process-sandbox
      before_script:
        - mkdir -p ~/.docker
        - echo "{\"auths\":{\"$CI_REGISTRY\":{\"username\":\"$CI_REGISTRY_USER\",\"password\":\"$CI_REGISTRY_PASSWORD\"}}}" > ~/.docker/config.json
      script:
        - |
          buildctl-daemonless.sh build \
            --frontend dockerfile.v0 \
            --local context=. \
            --local dockerfile=. \
            --output type=image,name=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA,push=true
    ```

- Or use Buildah in a rootless container, which GitLab also documents for OpenShift.
- Patch runc to 1.1.12 or later on every runner host, and keep Docker Engine and containerd current.
- Where Docker must run, use [Docker rootless mode](https://docs.docker.com/engine/security/rootless/) on the runner host so the daemon itself is not root.

### Tools/Techniques
- [GitLab: Build images with BuildKit](https://docs.gitlab.com/ci/docker/using_buildkit/).
- [BuildKit rootless mode](https://github.com/moby/buildkit/blob/master/docs/rootless.md).
- [Buildah](https://buildah.io/).

### Metrics/Signal
- Runners with the Docker socket mounted (target: zero).
- Image builds using rootless BuildKit or Buildah.
:::

::: {! stage limit}
## Limit

### Explanation
If a job does reach the host, make the host cheap to lose.

### Insight
A runner that lives for one job and holds no long-lived secrets is a poor prize. Compromise it and you get a VM that is about to be deleted.

### Practical
- Run privileged-capable workloads (if you must) on dedicated runners with their own tags, used only by trusted branches.
- Use autoscaled runners that create a fresh VM per job and destroy it afterwards.
- Keep cloud credentials off runner hosts. Use OIDC tokens per job instead.
- Separate release runners from test runners, so a test job can never poison the host that builds releases.

### Tools/Techniques
- [GitLab Runner autoscaling](https://docs.gitlab.com/runner/runner_autoscale/) or GitHub [Actions Runner Controller](https://github.com/actions/actions-runner-controller).
- Runner tags (GitLab) or runner groups (GitHub) to route trusted jobs.

### Metrics/Signal
- Share of runners that are single-use.
- Release jobs sharing hosts with test jobs (target: zero).
:::

::: {! stage expose}
## Expose

### Explanation
Detect a job talking to the Docker daemon or starting privileged containers.

### Insight
Legitimate test jobs almost never start containers that mount `/` from the host. When one does, that is your alert.

### Practical
- Watch the socket with auditd:

    ```bash
    auditctl -w /var/run/docker.sock -p rwxa -k docker-socket
    ```

- Inspect every container created on a runner host for `--privileged` or bind mounts of `/`:

    ```bash
    docker events --filter type=container --filter event=create --format '{{.Actor.ID}}' |
      while read -r id; do
        docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} binds={{.HostConfig.Binds}}' "$id"
      done
    ```

- Run Falco on runner hosts with a rule for socket connections from containers. This rule uses only built-in fields, no macros:

    ```yaml
    - rule: Docker socket connection from container
      desc: A process inside a container connected to the Docker socket
      condition: >
        evt.type = connect and evt.dir = < and
        container.id != host and
        fd.typechar = u and fd.name contains docker.sock
      output: >
        Docker socket used from container
        (command=%proc.cmdline container=%container.name image=%container.image.repository)
      priority: WARNING
    ```

### Tools/Techniques
- [Falco rules](https://falco.org/docs/concepts/rules/).
- Linux auditd.

### Metrics/Signal
- Docker socket connections from job containers.
- Containers created on runners with host root mounts.
:::

::: {! stage exercise}
## Exercise

### Explanation
Prove that a job on your runners can't reach the host.

### Insight
This is quick to test and the answer is binary.

### Practical
1. On a non-production runner configured like the real ones, run a job that only reports whether `/var/run/docker.sock` exists and its `CapEff` value.
2. If the socket is reachable, run `docker ps` from the job. If that works, the job has root on the host. Stop there.
3. Switch the project to rootless BuildKit, remove the socket mount, and rerun. Confirm image builds still work.
4. Confirm your Falco rule or auditd alert fired during step 2.

### Tools/Techniques
- A disposable runner VM.
- The checks from the Evaluate stage, run as a pipeline job.

### Metrics/Signal
- Runners where step 2 succeeded (target: zero).
- Time from socket access to alert.
:::

## Further Reading

- [Snyk: Leaky Vessels container breakout vulnerabilities](https://snyk.io/blog/leaky-vessels-docker-runc-container-breakout-vulnerabilities/)
- [GitLab: Use BuildKit to build Docker images](https://docs.gitlab.com/ci/docker/using_buildkit/)
- [Docker: Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/)
- [Docker: Rootless mode](https://docs.docker.com/engine/security/rootless/)
