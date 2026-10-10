---
title: Dev Container Lifecycle Hooks
category: Developer Environment
scenario: Malicious devcontainer.json commands and features in a cloned repository
focus:
  - postCreateCommand token theft
  - initializeCommand running on the host
  - untrusted dev container features
  - Codespaces secrets scoping
---

## Scenario

An attacker publishes a polished starter repository, "fastapi-ai-starter". It has a good README, a few hundred stars bought in bulk, and a `.devcontainer/` folder so "it just works" in VS Code and GitHub Codespaces.

The `devcontainer.json` looks routine at a glance:

```json
{
    "name": "FastAPI AI Starter",
    "image": "mcr.microsoft.com/devcontainers/python:3.12",
    "features": {
        "ghcr.io/fastapi-ai-tools/devcontainer-features/ai-cli:1": {}
    },
    "initializeCommand": "sh .devcontainer/scripts/check-docker.sh",
    "postCreateCommand": "pip install -r requirements.txt && sh .devcontainer/scripts/setup.sh"
}
```

Three things in it run attacker code:

1. `initializeCommand` runs on the **host**, before the container exists. `check-docker.sh` reads `~/.aws/credentials`, `~/.npmrc` and `~/.config/gh/hosts.yml` from the developer's laptop and posts them out.
2. The "ai-cli" feature is the attacker's own OCI artifact. Its `install.sh` runs as root during the image build.
3. `postCreateCommand` runs inside the container. In Codespaces it can read `GITHUB_TOKEN` and every Codespaces secret the developer has made available to this repository.

The developer clicks "Reopen in Container", trusts the folder when asked, and gets a working environment. The attacker gets their credentials.

**Real-world precedent:** In February 2026 Orca Security showed that a [malicious repository or pull request could run code in GitHub Codespaces](https://orca.security/resources/blog/hacking-github-codespaces-rce-supply-chain-attack/) through `devcontainer.json` `postCreateCommand`, `.vscode/tasks.json` and `.vscode/settings.json`, and steal the user's GitHub token and Codespaces secrets. Microsoft considers this behaviour by design. North Korea's Contagious Interview campaign uses the same "open the repository and it runs" pattern with VS Code tasks ([Jamf Threat Labs, January 2026](https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/)).

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker needs developers to open their repository in a dev container. They build lures that people want: starter templates, AI tooling, "fix this bug" interview tasks, or a helpful pull request to a popular project.

They also learn what dev containers can run and where. The [dev container specification](https://containers.dev/implementors/json_reference/) defines several lifecycle hooks: `initializeCommand` (on the host), then `onCreateCommand`, `updateContentCommand`, `postCreateCommand`, `postStartCommand` and `postAttachCommand` (in the container).

### Insight

Dev containers are meant to remove set-up friction. Every hook that saves you a manual step is also a place where someone else's script runs with your access.

### Practical

Look at what your own team opens:

- Search your organisation for dev container configs and list every hook and feature they use.
- Note any repositories where external contributors can change `.devcontainer/`.
- Check whether developers use Codespaces, and which secrets they have made available to which repositories.

```bash
gh search code --owner your-org --filename devcontainer.json "initializeCommand"
gh search code --owner your-org --filename devcontainer.json "features"
```

### Tools/Techniques

- `gh search code` or GitHub code search with `path:.devcontainer/`.
- The Codespaces settings page (`github.com/settings/codespaces`) to review user secrets and their repository access.

### Metrics/Signal

- Number of repositories with `initializeCommand` set.
- Number of dev container features pulled from publishers outside your organisation and `devcontainers/`.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Before opening any unfamiliar repository in a container, read its `.devcontainer/` folder like you would read a shell script you were about to run with `sudo`.

### Insight

`initializeCommand` is the most dangerous hook because it runs on your machine, outside the container, with your full user access. The container-side hooks are less dangerous on a laptop but still see any credentials you mount or forward. In Codespaces they see the session's GitHub token and secrets.

Features are code too. A feature is a tarball with an `install.sh` that runs as root during the build, from whichever registry the reference points to.

### Practical

1. Open the repository in Restricted Mode first (do not trust it) and read `.devcontainer/devcontainer.json` and any scripts it calls.
2. Decode anything encoded. A base64 blob piped to `sh` is never a set-up step you need.
3. Check every feature reference. Prefer features from `ghcr.io/devcontainers/features/` or your own organisation.
4. Check for mounts of host paths (`~/.ssh`, `~/.aws`) in `mounts` or `runArgs`.

```bash
jq '{initializeCommand, onCreateCommand, postCreateCommand, postStartCommand,
     postAttachCommand, features: (.features | keys?), mounts, runArgs}' \
    .devcontainer/devcontainer.json
```

`jq` fails on files with comments. Strip comments first, or read the file by eye.

### Tools/Techniques

- VS Code Restricted Mode for reading untrusted repositories.
- `jq` and a text editor.
- `oras manifest fetch` or `docker buildx imagetools inspect` to see what a feature reference resolves to.

### Metrics/Signal

- Percentage of dev container configs reviewed before first use.
- Host-path mounts in dev container configs.
:::

::: {! stage fortify}
## Fortify

### Explanation

Treat dev container configuration as code that needs review, pin what it pulls in, and do not trust folders you have not read.

### Insight

Workspace Trust is the last prompt between "clone" and "run". Reopening a folder in a container means trusting it. Make it a deliberate decision.

### Practical

- Never trust a folder just to make the prompt go away. Read `.devcontainer/` and `.vscode/` first.
- Add CODEOWNERS for `.devcontainer/` and `.vscode/` so changes need review from a platform or security owner.
- Pin images by digest and commit the dev container lockfile, which records each feature's resolved digest. Use `--frozen-lockfile` with the dev container CLI in CI.
- Keep a short allowlist of feature publishers. Copy third-party features into your own registry if you need them.
- Avoid `initializeCommand` in your own repositories unless you really need host-side work.

```json
{
    "name": "service-template",
    "image": "mcr.microsoft.com/devcontainers/java:21@sha256:<digest>",
    "features": {
        "ghcr.io/devcontainers/features/node:1": { "version": "22" }
    },
    "postCreateCommand": "./mvnw -q -DskipTests dependency:go-offline"
}
```

### Tools/Techniques

- [Dev container CLI](https://github.com/devcontainers/cli) with `devcontainer build --frozen-lockfile`.
- Dependabot's `devcontainers` ecosystem to keep pinned features current.
- CODEOWNERS and repository rulesets.

### Metrics/Signal

- Percentage of dev container configs with pinned image digests and a committed lockfile.
- Changes to `.devcontainer/` merged without owner review.
:::

::: {! stage limit}
## Limit

### Explanation

Decide what a malicious hook could reach, and shrink it.

### Insight

On a laptop the prize is whatever sits in your home directory. In Codespaces it is the session token and the Codespaces secrets you have made available to that repository.

### Practical

- Scope Codespaces user secrets to the specific repositories that need them, never "all repositories".
- Do not mount `~/.ssh`, `~/.aws` or `~/.config/gh` into dev containers. Use SSH agent forwarding with a hardware-backed key, or short-lived credentials obtained inside the container.
- Prefer fine-grained personal access tokens with access to named repositories, read-only permissions, and a short expiry. Classic tokens use broad scopes such as `repo` and `read:packages` and cannot be limited to one repository.
- Open untrusted repositories in a Codespace or VM with no personal secrets, not on your main laptop.

### Tools/Techniques

- [Codespaces secrets settings](https://docs.github.com/en/codespaces/managing-your-codespaces/managing-your-account-specific-secrets-for-github-codespaces).
- [Fine-grained personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) and organisation policies that restrict classic tokens.
- `aws sso login` inside the container instead of mounted credential files.

### Metrics/Signal

- Codespaces secrets available to all repositories (target: zero).
- Classic personal access tokens still active in the organisation.
:::

::: {! stage expose}
## Expose

### Explanation

Spot a malicious hook when it runs, and spot stolen tokens when they are used.

### Insight

A setup script that calls `curl` to an unknown host, or reads files under `~/.ssh` and `~/.aws`, stands out against normal set-up work like `pip install` and `npm ci`.

### Practical

- Review the dev container creation log (in VS Code: "Dev Containers: Show Container Log") after first opening an unfamiliar repository.
- Alert on processes spawned by the Dev Containers extension or the dev container CLI that make network calls to hosts outside your registries.
- Watch GitHub's organisation audit log for token use from unexpected IP ranges, and for new deploy keys, webhooks or OAuth apps.

### Tools/Techniques

- Endpoint tooling or osquery on developer machines for host-side `initializeCommand` behaviour.
- GitHub audit log streaming to your log platform.
- GitHub secret scanning for tokens that appear in public places after theft.

### Metrics/Signal

- Dev container builds that make outbound calls to unknown hosts.
- Time from a token being used from an unknown IP to its revocation.
:::

::: {! stage exercise}
## Exercise

### Explanation

Let developers see, safely, how much a dev container hook can do.

### Insight

Many developers do not know `initializeCommand` runs on the host. A two-minute demo fixes that.

### Practical

1. Create a private test repository with this config:

    ```json
    {
        "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
        "initializeCommand": "echo host-side-canary > /tmp/devcontainer-host-canary.txt",
        "postCreateCommand": "env | cut -d= -f1 | sort > /tmp/container-env-names.txt"
    }
    ```

2. Ask a volunteer to open it. Afterwards, show them the canary file on their own machine and the list of variable names inside the container.
3. Add a feature reference from an unknown publisher and check that your review process catches it.
4. Open the same repository in Codespaces and review which secrets were visible.

### Tools/Techniques

- A private repository and a disposable Codespace.
- Canary files and variable names only. Never print secret values.

### Metrics/Signal

- Percentage of volunteers who read `.devcontainer/` before trusting the folder.
- Whether the review process caught the untrusted feature.
:::

## Further Reading

- [Dev container JSON reference (lifecycle hooks)](https://containers.dev/implementors/json_reference/)
- [Orca Security: hacking GitHub Codespaces via VS Code defaults](https://orca.security/resources/blog/hacking-github-codespaces-rce-supply-chain-attack/)
- [GitHub: managing Codespaces secrets](https://docs.github.com/en/codespaces/managing-your-codespaces/managing-your-account-specific-secrets-for-github-codespaces)
- [VS Code: Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust)
- [Malicious IDE Extensions](#battlecards-malicious-ide-extensions-md)
