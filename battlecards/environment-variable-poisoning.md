---
title: Environment Variable and Runtime Hook Hijacking
category: CI/CD & Build
ref: RFX-CI-07
precedent: "2026"
scenario: PATH, preload and runtime-hook variables hijacked on build agents and developer machines
focus:
  - PATH hijacking on shared build agents
  - LD_PRELOAD, BASH_ENV and $GITHUB_ENV injection
  - NODE_OPTIONS, JAVA_TOOL_OPTIONS and Python .pth hooks
  - DYLD_* and GIT_CONFIG_* on developer machines
---

## Scenario

A platform team runs a handful of long-lived Jenkins agents shared by every project. The agents put `/opt/build-tools/bin` on `PATH` so teams can drop in helper scripts. That directory is writable by the `jenkins` user.

One team's build pulls a compromised package. Its install script runs as `jenkins`, like everything else on the agent.

1. It writes a wrapper called `npm` into `/opt/build-tools/bin`, ahead of `/usr/bin` on `PATH`. The wrapper posts the environment to the attacker, then runs the real `/usr/bin/npm` with the same arguments.
2. It drops a `.pth` file into the agent's shared Python `site-packages`. Python runs it every time any interpreter starts.
3. The next day another team's release job runs `npm publish` on the same agent. The wrapper captures `NPM_TOKEN`, `AWS_ACCESS_KEY_ID` and everything else that job was given.

The same package lands on a developer's laptop. There it appends three lines to `~/.zshrc`:

```bash
export NODE_OPTIONS="--require $HOME/.cache/node/telemetry.js"
export JAVA_TOOL_OPTIONS="-javaagent:$HOME/.m2/agent/metrics.jar"
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0="$HOME/.cache/git/fsm.sh"
```

Now every Node process loads `telemetry.js` first. Every JVM started from that shell loads a Java agent. Every `git status` runs `fsm.sh`. None of this needs root or touches a system binary. Builds pass and nothing looks wrong.

On GitHub Actions the door is different. Any step can write `NAME=value` lines to the file at `$GITHUB_ENV`, and every later step in the job inherits them. A step that writes `LD_PRELOAD` or `BASH_ENV` there, or writes untrusted input there, poisons the rest of the job.

::: {! precedent}
**Real-world precedent:** On 24 March 2026 attackers published [LiteLLM 1.82.7 and 1.82.8 to PyPI](https://docs.litellm.ai/blog/security-update-march-2026). Version 1.82.8 added `litellm_init.pth`, so the credential stealer ran at every Python start-up, whether or not LiteLLM was imported. From January to April 2021 a modified [Codecov Bash Uploader](https://about.codecov.io/security-update/) sent the environment variables of customers' CI jobs to an attacker's server. GitHub [disabled the `set-env` workflow command in 2020](https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/) and [blocked `NODE_OPTIONS` from `$GITHUB_ENV` in 2023](https://github.blog/changelog/2023-10-05-github-actions-node_options-is-now-restricted-from-github_env/) for exactly these reasons.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

An attacker who lands code on a build agent or laptop wants code that runs often, runs as you, and survives. They look at what runs next, as which user, and with what environment.

They run `env`, walk every `PATH` entry for writable directories, and check `/etc/ld.so.preload`. They read shell start-up files, workflow files and `Jenkinsfile`s. They note which runtimes you use (`node`, `java`, `python`, `git`) and whether your build scripts call tools by bare name.

### Insight

Shared, long-lived agents let one job's leftovers affect the next. Developer machines run more interpreters than almost any other computer, and each runtime has its own documented way to pre-load code. Few developers know them all.

### Practical

Do the attacker's survey yourself, as the build user or as you:

```bash
echo "$PATH" | tr ':' '\n' | while read -r d; do
    [ -d "$d" ] && [ -w "$d" ] && echo "WRITABLE: $d"
done
env | grep -E '^(LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|ENV|NODE_OPTIONS|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|PYTHONPATH|DYLD_|GIT_SSH_COMMAND|GIT_CONFIG_)'
cat /etc/ld.so.preload 2>/dev/null
grep -nE 'NODE_OPTIONS|JAVA_TOOL_OPTIONS|PYTHONPATH|DYLD_|GIT_CONFIG_|GIT_SSH' \
    ~/.zshrc ~/.zprofile ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null
```

Also check workflow files for steps that write to `$GITHUB_ENV` or `$GITHUB_PATH` using issue titles, branch names, pull request bodies or artifact contents.

### Tools/Techniques

- `env`, `find`, `ls -ld` and the loop above.
- `git config --show-origin --show-scope --list` to see every Git setting and where it came from.
- [zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint) to flag risky `$GITHUB_ENV` writes and template injection.

### Metrics/Signal

- `PATH` entries writable by the build user on each agent.
- Workflows that write user-controlled data to `$GITHUB_ENV`.
- Runtime-hook variables set in developers' shells that nobody can explain.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Work out which variables and files can change what your tools run, and who can set them.

### Insight

The dangerous hooks fall into a few groups:

- **Command lookup:** `PATH`. Bare command names resolve to the first match.
- **Dynamic linker:** `LD_PRELOAD` and `LD_LIBRARY_PATH` load extra code into dynamically linked programs. Statically linked Go binaries ignore them, but `git`, `curl`, `python` and `node` are usually dynamic.
- **Shell start-up:** non-interactive `bash` sources the file named in `BASH_ENV`. It does not read `.bashrc`.
- **Node.js:** `NODE_OPTIONS` accepts `--require` and `--import`, which load a module before your code.
- **JVM:** `JAVA_TOOL_OPTIONS` and `JDK_JAVA_OPTIONS` accept `-javaagent:`. The JVM prints `Picked up JAVA_TOOL_OPTIONS: ...` to stderr.
- **Python:** `PYTHONPATH` can shadow standard modules. `sitecustomize.py` runs at start-up. Any line starting with `import` in a `.pth` file in `site-packages` is executed, which is how the LiteLLM payload ran.
- **macOS:** `DYLD_INSERT_LIBRARIES` loads a library into a process. System Integrity Protection strips it only for Apple-protected binaries, and the hardened runtime ignores it unless entitled. Many Homebrew-built tools have neither.
- **Git:** `GIT_SSH_COMMAND` replaces the SSH client. `GIT_CONFIG_COUNT` with `GIT_CONFIG_KEY_n` and `GIT_CONFIG_VALUE_n` injects any config key, including `core.fsmonitor`, `core.sshCommand` and `core.hooksPath`.

### Practical

1. List every place the build environment is set: agent launch config, Jenkins node properties, systemd units, container image `ENV`, workflow `env:` blocks. Note who can change each.
2. Confirm whether agents are reused between jobs from different repositories or teams.
3. Look for `.pth` files with `import` lines in every `site-packages` you use:

```bash
python3 - <<'EOF'
import site, pathlib
for d in site.getsitepackages() + [site.getusersitepackages()]:
    for p in pathlib.Path(d).glob("*.pth"):
        for line in p.read_text(errors="ignore").splitlines():
            if line.startswith(("import ", "import\t")):
                print(f"{p}: {line[:120]}")
EOF
```

### Tools/Techniques

- `systemctl show <agent-unit> -p Environment` and {% verbatim %}`docker inspect --format '{{.Config.Env}}' <image>`{% endverbatim %}.
- `codesign -dv --verbose=4 "$(command -v node)" 2>&1 | grep -i runtime` to check for the hardened runtime on macOS.
- osquery's `process_envs` table to see the variables of running processes.

### Metrics/Signal

- Agents that run jobs from more than one trust boundary.
- `.pth` files with `import` lines that do not belong to a package you recognise.
:::

::: {! stage fortify}
## Fortify

### Explanation

Start every build step from a known, minimal environment. Remove the writable directories and install scripts that let an attacker plant hooks in the first place.

### Insight

Clearing variables inside your script is too late. By the time `build.sh` runs `unset LD_PRELOAD`, the shell has already sourced `BASH_ENV` and loaded any preload library. Clean the environment before the shell starts.

### Practical

Launch builds with an empty environment and only the variables you name:

```groovy
pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps {
                withCredentials([string(credentialsId: 'npm-token', variable: 'NPM_TOKEN')]) {
                    sh '''
                        exec env -i \
                            PATH=/usr/bin:/bin \
                            HOME="$WORKSPACE" \
                            NPM_TOKEN="$NPM_TOKEN" \
                            /bin/bash --noprofile --norc ./build.sh
                    '''
                }
            }
        }
    }
}
```

`env -i` drops `LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS` and `JAVA_TOOL_OPTIONS`. `--noprofile --norc` stops bash reading start-up files. It does not help with a `.pth` file already in `site-packages`, so keep that directory clean too.

On build agents:

- Make every `PATH` directory owned by root and not writable by the build user.
- Use absolute paths in release scripts, or check `command -v npm` against an expected path.
- Run each job on a fresh agent or container, so nothing one job writes survives to the next.
- In GitHub Actions, never write untrusted input to `$GITHUB_ENV` or `$GITHUB_PATH`. Pass it through an intermediate `env:` variable and quote it.

On developer machines:

- Keep install scripts off. npm 12 and pnpm 10 and later block dependency install scripts by default; approve the few you need with npm `allowScripts` or pnpm `allowBuilds`. On older npm, set `ignore-scripts=true` in `~/.npmrc`.
- Keep shell start-up files in a dotfiles repository and diff them against what is on disk.
- Use a virtual environment per project, so a poisoned `site-packages` reaches less.
- Treat any `GIT_CONFIG_*` variable in your shell as suspicious.

### Tools/Techniques

- `env -i` and `bash --noprofile --norc`.
- Ephemeral agents: Kubernetes pod agents for Jenkins, GitHub-hosted runners, or self-hosted runners with `--ephemeral`.
- npm `allowScripts`, pnpm `allowBuilds`, Bun `trustedDependencies`.
- `uv` or `venv` for isolated Python environments; chezmoi or a plain dotfiles repository.

### Metrics/Signal

- Release jobs that start from `env -i` or a fresh container.
- Writable `PATH` directories on agents (target: zero).
- Developers with install scripts blocked by default.
:::

::: {! stage limit}
## Limit

### Explanation

If a hook does run, make sure it finds as little as possible, valid for as short a time as possible.

### Insight

Codecov's attackers and the LiteLLM payload both harvested whatever the environment and home directory held. A job or laptop holding only short-lived, narrowly scoped tokens gives them very little.

### Practical

- Give each CI job only the secrets it uses. Do not load the whole credential set into every stage.
- Prefer OIDC federation to cloud providers over static `AWS_ACCESS_KEY_ID` values.
- Use npm and PyPI trusted publishing, so no long-lived publish token exists to steal.
- Keep release jobs on dedicated agents that never run untrusted pull request builds.
- Restrict agent egress to the registries and services the build needs.
- On laptops, do not export secrets in shell start-up files. Inject them per command with a secrets manager CLI.
- Use a hardware security key for SSH and Git signing, so a hook cannot copy the key.

### Tools/Techniques

- GitHub Actions OIDC with AWS, Azure or GCP.
- `op run`, `doppler run` or `aws-vault exec` to give secrets only to the process that needs them.
- FIDO2 keys for SSH (`ed25519-sk`).

### Metrics/Signal

- Static cloud keys present in CI environments.
- Long-lived tokens stored in developer home directories.
:::

::: {! stage expose}
## Expose

### Explanation

Detect new files in tool and `site-packages` directories, and unexpected hook variables, before or during a build.

### Insight

A wrapper must be written somewhere on `PATH`. A hook must appear in the environment, a start-up file or `site-packages`. All are easy to see if you look.

### Practical

Run a preflight step that fails the build on surprises. It cannot stop code that `BASH_ENV` already ran, so treat it as detection and keep `env -i` as prevention.

```bash
#!/bin/bash
set -euo pipefail
for v in LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV NODE_OPTIONS JAVA_TOOL_OPTIONS; do
    if [ -n "${!v:-}" ]; then
        echo "Unexpected $v=${!v}" >&2
        exit 1
    fi
done
if [ -s /etc/ld.so.preload ]; then
    echo "/etc/ld.so.preload is not empty" >&2
    exit 1
fi
for tool in npm git python3; do
    echo "$tool -> $(command -v "$tool")"
done
```

On agents with Falco, alert on writes into the tool directories:

```yaml
- list: build_tool_dirs
  items: [/opt/build-tools/bin, /usr/local/bin]

- rule: Write to build tool directory
  desc: A process wrote into a directory on the build agent's PATH
  condition: >
    open_write and fd.name pmatch (build_tool_dirs)
    and not proc.name in (dpkg, apt, apt-get, rpm, dnf, yum)
  output: "Write to PATH dir (file=%fd.name cmd=%proc.cmdline user=%user.name)"
  priority: WARNING
```

Also grep CI logs for `Picked up JAVA_TOOL_OPTIONS`; it should only show values you set. On laptops, alert when shell start-up files change outside a dotfiles sync, and flag `node` processes with `--require` pointing into hidden directories.

### Tools/Techniques

- [Falco](https://falco.org/docs/concepts/rules/conditions/) or auditd on `PATH` directories, `site-packages` and `/etc/ld.so.preload`.
- osquery `process_envs` and `file_events`, or your EDR's process telemetry.
- Egress logs showing agents posting to unknown hosts.

### Metrics/Signal

- Writes to tool directories or `site-packages` outside package-manager runs.
- Builds failed by the preflight check, and their root cause.
:::

::: {! stage exercise}
## Exercise

### Explanation

Plant harmless hooks on a disposable agent and in a throwaway account, then see what notices.

### Insight

A wrapper that passes its arguments through keeps builds green. Teams believe their agents are clean because nothing failed.

### Practical

1. On an isolated test agent, create `/opt/build-tools/bin/npm` that writes variable *names* (never values) to a local file, then runs the real `npm`:

    ```bash
    #!/bin/sh
    env | cut -d= -f1 > /tmp/npm-wrapper-canary.txt
    exec /usr/bin/npm "$@"
    ```

2. Run a normal pipeline. If the canary file appears, your `PATH` hardening has a gap. Repeat with the `env -i` launch and confirm the wrapper is not reached.
3. In a throwaway user account, create `~/.cache/canary.js` containing `console.error("CANARY: preload ran")`. Set `NODE_OPTIONS="--require $HOME/.cache/canary.js"` and run `node -e 1`.
4. In a fresh virtual environment, add `canary.pth` containing `import sys; print("CANARY: pth ran", file=sys.stderr)` and start `python`.
5. Check whether Falco, file integrity monitoring or your preflight raised an alert for each. Then remove everything.

### Tools/Techniques

- A disposable agent VM, container or user account.
- Canary messages and variable names only. No network calls, no real secrets.

### Metrics/Signal

- Which hooks were reached before and after hardening.
- Time from planting each hook to the first alert.
:::

## Further Reading

- [LiteLLM: security update, March 2026](https://docs.litellm.ai/blog/security-update-march-2026)
- [Codecov: Bash Uploader security update (2021)](https://about.codecov.io/security-update/)
- [GitHub: NODE_OPTIONS restricted from GITHUB_ENV (2023)](https://github.blog/changelog/2023-10-05-github-actions-node_options-is-now-restricted-from-github_env/)
- [GitHub Security Lab: keeping your Actions safe from untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/)
- [Python: the site module and .pth files](https://docs.python.org/3/library/site.html)
- [Git: configuration via environment variables](https://git-scm.com/docs/git-config#ENVIRONMENT)
