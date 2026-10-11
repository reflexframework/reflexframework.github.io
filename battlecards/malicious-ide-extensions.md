---
title: Malicious IDE Extensions
category: Developer Environment
ref: RFX-DEV-04
precedent: "2025"
scenario: Trojanised editor extensions and auto-run workspace config
focus:
  - malicious VS Code and Open VSX extensions
  - extension credential theft
  - auto-run tasks in .vscode/
  - extension allowlists
---

## Scenario

A developer at a small fintech uses Cursor. They search the built-in marketplace for a Solidity extension and pick the one with the most installs. It is called "Solidity Language", it has a polished README, and it has been downloaded tens of thousands of times.

The download count is fake. The extension does nothing useful. On activation it runs a PowerShell script that installs a remote access tool, and a stealer then collects browser sessions, SSH keys, `~/.aws/credentials`, `.npmrc` tokens and crypto wallet seed phrases.

A week later a recruiter sends the same developer a "take-home exercise" repository. It contains a `.vscode/tasks.json` with a task set to `runOn: folderOpen`. The developer opens the folder, clicks "Trust" to get syntax highlighting working, and the task quietly fetches and runs a second payload.

No permission prompt appeared at any point. VS Code extensions run with the same rights as the editor itself, and a trusted workspace can run its own tasks.

::: {! precedent}
**Real-world precedent:** In July 2025 [Kaspersky reported](https://www.kaspersky.com/blog/malicious-extensions-for-cursor-ai/53802/) a fake "Solidity Language" extension on Open VSX, installed through Cursor, that led to roughly $500,000 in stolen crypto. In October 2025 Koi Security found [GlassWorm](https://www.bleepingcomputer.com/news/security/self-spreading-glassworm-malware-hits-openvsx-vs-code-registries/), a self-spreading worm hidden in Open VSX extensions with invisible Unicode, which stole GitHub, npm and Open VSX credentials. [Sonatype's 2026 State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction) tracks GlassWorm in three waves across Open VSX and the VS Code Marketplace: 17 October (12 extensions that impersonated developer tools, stole credentials, drained crypto wallets and used the Solana blockchain for command and control), 9 November (3 new extensions under fresh publisher accounts to dodge cleanup) and 1 December (24 extensions with artificially inflated download counts). In July 2025 a [wiper prompt shipped in Amazon Q Developer for VS Code v1.84.0](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/) after a malicious contribution. North Korea's Contagious Interview campaign hides commands in `.vscode/tasks.json` in fake interview repositories, which run once the victim trusts the folder ([Jamf Threat Labs, January 2026](https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/)).
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers study which editors and extensions a target community uses. Job adverts, public dotfiles and `.vscode/extensions.json` files in open repositories all reveal the toolchain. Niche languages with few good extensions are attractive, because a convincing fake can climb the search results quickly.

They also pick the marketplace. Cursor, Windsurf, VSCodium and other VS Code forks cannot use Microsoft's Visual Studio Marketplace, so they pull from [Open VSX](https://open-vsx.org/). Open VSX has historically had lighter publisher checks, and inflated download counts have pushed fakes above the real extension in search.

### Insight

An extension is code you run with your full user privileges, every time the editor starts. VS Code has no permission model for extensions: the [extension host has the same permissions as VS Code itself](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security). It can read any file you can, spawn processes and open network connections.

Workspace Trust does not change that. Trust controls what a *workspace* may do (tasks, debug configs, some settings). An installed extension still runs in an untrusted window, even if some extensions limit their own features there.

### Practical

- List what your team actually runs: `code --list-extensions --show-versions` (or `cursor --list-extensions`).
- Note which editors are forks that install from Open VSX.
- Search your organisation's repositories for auto-run tasks: `"runOn": "folderOpen"` in `.vscode/tasks.json`.
- Check whether developers' machines hold long-lived credentials in plain files (`~/.aws/credentials`, `~/.npmrc`, `~/.docker/config.json`).

### Tools/Techniques

- `code --list-extensions --show-versions` for an inventory per machine.
- GitHub code search: `path:.vscode/tasks.json "folderOpen"` across your organisation.
- Your MDM or endpoint agent to collect `~/.vscode/extensions/` contents fleet-wide.

### Metrics/Signal

- Number of distinct extensions installed across the team, and how many come from Open VSX.
- Number of repositories containing `runOn: folderOpen` tasks.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Assess each extension as you would a dependency with full system access. Who publishes it? Is the publisher verified? Does the repository link go to real source that matches the package? How old is it, and does the download count make sense against its ratings and issues?

### Insight

Download counts and ratings are easy to fake. In the Cursor case the fake had more installs than the genuine extension. GlassWorm's third wave in December 2025 inflated its download counts on purpose, to climb the search results. Look for the boring signals instead: a long publishing history, a real issue tracker and a publisher you already know.

Disabling editor telemetry does not help here. Telemetry settings control what the editor sends to its vendor. A malicious extension ignores them and makes its own network calls.

### Practical

1. Unpack a suspicious extension and read it: a `.vsix` file is a zip archive.
2. Look at `package.json` for `activationEvents` of `*` or `onStartupFinished`. These run the extension on every launch, whatever you are editing.
3. Search the bundled JavaScript for `child_process`, `exec`, `spawn`, `eval`, unexpected `fetch` or `https.request` calls, and long runs of invisible characters.
4. Compare the package against the linked source repository. A mismatch is a red flag.

```bash
mkdir /tmp/ext-review && cd /tmp/ext-review
unzip -q ~/Downloads/suspicious.vsix
jq '.activationEvents, .main, .publisher' extension/package.json
grep -rnE "child_process|execSync|spawn\(|eval\(" extension/ | head
# GlassWorm hid code in Unicode variation selectors (U+FE00 to U+FE0F)
rg -l '[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]' extension/
```

### Tools/Techniques

- `unzip`, `jq`, `grep` and `rg` (ripgrep) are enough for a first look.
- [vsce](https://github.com/microsoft/vscode-vsce) `ls` to list what a package contains.
- [Open VSX](https://open-vsx.org/) and Visual Studio Marketplace publisher pages to check verification and history.

### Metrics/Signal

- Percentage of installed extensions from verified publishers.
- Extensions with `*` or `onStartupFinished` activation that nobody has reviewed.
:::

::: {! stage fortify}
## Fortify

### Explanation

Control which extensions can be installed, and stop repositories from running code just because they were opened.

### Insight

VS Code 1.96 added the [`extensions.allowed`](https://code.visualstudio.com/docs/enterprise/extensions) setting, which organisations can enforce through the `AllowedExtensions` device policy. Unlisted extensions are blocked, and already installed extensions that are not on the list are disabled. Since VS Code 1.97, installing from a new third-party publisher also asks you to confirm you trust that publisher.

There is an apparent conflict about the `.vscode/` folder. Some advice says gitignore it, other advice says commit `extensions.json`. Commit a reviewed `extensions.json` that recommends a short, approved list. Treat `tasks.json`, `launch.json` and `settings.json` as executable code and review them in pull requests like any script.

### Practical

Enforce an allowlist. In user settings or, better, through managed policy:

```json
{
    "extensions.allowed": {
        "microsoft": true,
        "github": true,
        "redhat": "stable",
        "esbenp.prettier-vscode": true,
        "vscjava.vscode-java-pack": true
    }
}
```

Commit a recommendations list so new starters install the right things:

```json
{
    "recommendations": [
        "vscjava.vscode-java-pack",
        "esbenp.prettier-vscode"
    ],
    "unwantedRecommendations": []
}
```

Keep automatic tasks off. `task.allowAutomaticTasks` defaults to `off` and prompts once per workspace; refuse that prompt for code you have not read. Never trust a workspace from an unknown source just to make the editor stop nagging.

Add a CODEOWNERS rule so changes under `.vscode/` and `.devcontainer/` need a security-aware reviewer:

```text
/.vscode/       @your-org/platform-security
/.devcontainer/ @your-org/platform-security
```

### Tools/Techniques

- VS Code `AllowedExtensions` policy via Group Policy, macOS configuration profiles or Linux `policy.json`.
- A private extension marketplace if you need tighter control than an allowlist.
- CODEOWNERS and rulesets to require review of editor configuration.

### Metrics/Signal

- Percentage of managed machines with the `AllowedExtensions` policy applied.
- Pull requests touching `.vscode/tasks.json` that merged without a review from the owning team.
:::

::: {! stage limit}
## Limit

### Explanation

Assume an extension will eventually turn bad, through a fake, a compromised publisher account or a poisoned update. Reduce what it can reach from your laptop.

### Insight

A stealer takes whatever is on disk and in the environment. Short-lived credentials stolen at 10am are useless by lunchtime. Long-lived ones in `~/.aws/credentials` or `~/.npmrc` are the prize.

### Practical

- Use SSO-backed, short-lived cloud credentials (`aws sso login`, `gcloud auth login`) instead of static keys in dotfiles.
- Use npm and PyPI trusted publishing from CI, so no long-lived publish token sits on a laptop.
- Keep SSH keys in a hardware key or a password manager's SSH agent so they cannot be copied as files.
- Open unknown repositories (interview tasks, "can you look at this bug?") in a disposable environment: a Codespace, a throwaway VM or a dev container on a machine with no credentials.
- Keep crypto wallets and production access off your everyday development profile.

### Tools/Techniques

- AWS IAM Identity Center, `gcloud` and `az` device-code login for short-lived sessions.
- 1Password, Bitwarden or Secretive (macOS) for SSH keys outside the filesystem.
- Separate OS user accounts or VMs for untrusted code.

### Metrics/Signal

- Number of long-lived cloud or registry tokens found on developer machines.
- Time to revoke every credential on a machine after an extension compromise is confirmed.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for the behaviour a malicious extension or auto-run task produces: the editor spawning shells and downloaders, and network calls to places your tools never normally talk to.

### Insight

A healthy editor rarely starts `curl`, `powershell` or `node -e` within seconds of opening a folder. That process tree is the clearest signal of both the extension and the `tasks.json` attack, and researchers tracking Contagious Interview recommend alerting on it.

### Practical

- Alert when `Code`, `Cursor` or `Windsurf` (or their helper processes) spawn `curl`, `wget`, `powershell`, `bash -c`, `osascript` or `node -e` shortly after launch.
- Flag new extension directories appearing under `~/.vscode/extensions/` or `~/.cursor/extensions/` on managed machines.
- Watch for reads of `~/.aws/credentials`, `~/.ssh/` and browser profile directories by the extension host process.
- Subscribe to the security bulletins of the extensions you allow, and to Open VSX and Marketplace takedown news.

### Tools/Techniques

- Your EDR's process-tree rules (Microsoft Defender for Endpoint, CrowdStrike, SentinelOne) or osquery on macOS and Linux.
- Little Snitch or LuLu on macOS to see which extension is phoning home.
- GitHub secret scanning alerts, which often fire first when stolen tokens are reused.

### Metrics/Signal

- Alerts for editor processes spawning network tools, and time to triage them.
- Time from a public takedown notice to removal of that extension from your fleet.
:::

::: {! stage exercise}
## Exercise

### Explanation

Practise spotting and stopping both attack paths with harmless stand-ins.

### Insight

Most developers have never opened a `.vsix` or read a `tasks.json`. One short session changes that, and makes the "Trust this folder?" prompt mean something.

### Practical

1. Build a benign extension locally with `yo code` that, on activation, writes a canary file and makes a request to a canary token URL. Install it with `code --install-extension ./canary.vsix`. Do not publish it to any marketplace.
2. Check that your allowlist policy blocks it, and that your endpoint tooling raised an alert for the network call.
3. Create a private test repository with a `tasks.json` that runs `echo "auto task ran" > /tmp/canary-task.txt` on `folderOpen`. Ask a volunteer to open it and see whether they notice before trusting it.
4. Walk through credential rotation for a laptop "compromised" by the canary extension, and time it.

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "canary",
            "type": "shell",
            "command": "echo 'auto task ran' > /tmp/canary-task.txt",
            "runOptions": { "runOn": "folderOpen" }
        }
    ]
}
```

### Tools/Techniques

- `yo code` and `vsce package` to build the canary extension.
- [Canarytokens](https://canarytokens.org/) for the network beacon.

### Metrics/Signal

- Percentage of volunteers who inspected `.vscode/` before trusting the test repository.
- Whether the allowlist blocked the canary, and how long the alert took to arrive.
:::

## Further Reading

- [VS Code: extension runtime security](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security)
- [VS Code: manage extensions in the enterprise (`extensions.allowed`)](https://code.visualstudio.com/docs/enterprise/extensions)
- [BleepingComputer: Self-spreading GlassWorm malware hits OpenVSX, VS Code registries](https://www.bleepingcomputer.com/news/security/self-spreading-glassworm-malware-hits-openvsx-vs-code-registries/)
- [Kaspersky: fake Open VSX extension led to crypto theft](https://www.kaspersky.com/blog/malicious-extensions-for-cursor-ai/53802/)
- [AWS security bulletin AWS-2025-015 (Amazon Q Developer extension)](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)
- [Jamf Threat Labs: threat actors expand abuse of VS Code](https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/)
