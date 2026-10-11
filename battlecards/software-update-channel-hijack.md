---
title: Hijacked Auto-Update Channels
category: Network & Distribution
ref: RFX-NET-03
precedent: "2025"
scenario: Attacker controls the server your updater trusts
focus:
  - updaters that trust whatever the server sends
  - signature verification with a pinned key
  - rollback, freeze and selective targeting
  - hosting and release infrastructure as attack surface
---

## Scenario

A small team ships a popular desktop tool. It checks for updates on start-up. The updater fetches a manifest from `https://update.example-tool.org/latest.xml`, reads a download URL from it, fetches the installer and runs it. The manifest arrives over HTTPS, so everyone feels safe.

The site runs on shared hosting. An attacker gets into the hosting provider and from there into the update endpoint:

1. They leave the real site alone. Most users see nothing unusual.
2. For requests from a short list of IP ranges belonging to target organisations, the server returns a modified manifest.
3. That manifest points at an installer on a server the attacker controls. It still uses HTTPS, with a perfectly valid certificate for the attacker's own domain.
4. The updater checks the version number, downloads the file and runs it. Nothing checks who built it.
5. The hosting provider spots the intrusion and cleans up. The attacker kept credentials to internal services and carries on redirecting for months.

TLS did its job throughout. It proved the client was talking to the update server, and the update server was the problem.

::: {! precedent}
**Real-world precedent:** From June to December 2025, attackers compromised the shared hosting behind Notepad++ and redirected update traffic from selected users to malicious installers, exploiting weak verification in the WinGUp updater. The maintainer disclosed it on 2 February 2026 and moved to signed manifests and enforced installer signature checks ([Notepad++](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)). Older cases show the build-side version of the same risk: ASUS Live Update shipped trojanised, validly signed updates aimed at a few hundred machines in 2018 ([Kaspersky, Operation ShadowHammer](https://securelist.com/operation-shadowhammer/89992/)), and the 3CX desktop app shipped a signed, trojanised build through its normal updates in March 2023 ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise)).
:::

::: {! stage recon}
## Reconnaissance

### Explanation

An attacker starts by reading your updater. Desktop apps and CLIs are easy to unpack, and update traffic is easy to capture. In an afternoon they learn the manifest URL, its format, whether anything is signed and what the client checks before it runs the payload.

Then they look at who controls that URL. Shared hosting, a CDN account, a DNS registrar, an object storage bucket, a GitHub release token in CI. Any of these is a way to change what the updater receives without touching your code.

They also look at your users. An updater that runs on a developer workstation or a build server is a privileged foothold inside every customer that installs it. That is why these attacks are often selective.

### Insight

Your updater is a remote code execution feature you built on purpose. The attacker's job is to become the party it trusts.

### Practical

- Write down every updater you ship: desktop app, CLI self-update command, agent, plugin, browser helper.
- For each one, trace the full path: manifest URL, download URL, hosting provider, DNS, CDN, storage, and the accounts and tokens that can change each one.
- Record what the client actually verifies today, by reading the code. Do not rely on the design doc.

### Tools/Techniques

- An intercepting proxy such as [mitmproxy](https://mitmproxy.org/) in a lab, to see your own update traffic the way an attacker would.
- Your registrar, DNS and hosting account settings, to list who holds admin access.

### Metrics/Signal

- Number of shipped updaters with a documented trust chain.
- Number of people and tokens that can change the manifest, the binaries or the DNS for the update host.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Assess each updater against one question. If an attacker fully controls the update server, what can they make the client do?

A weak updater trusts TLS and the manifest. A better one verifies an Authenticode or Developer ID signature, but accepts any valid certificate. A strong one verifies a signature against a key pinned in the shipped app, refuses older versions, and notices when metadata stops changing.

### Insight

"We use HTTPS" answers a different question. HTTPS protects the connection. It says nothing about whether the server is honest.

### Practical

Score each updater on these checks:

- Is the payload signed, and does the client verify that signature before writing or running anything?
- Is the verifying key or certificate identity pinned in the app, or will any valid signature do?
- Is the manifest signed too, so an attacker cannot point it at another file or another version?
- Does the client refuse a version older than the one installed (rollback protection)?
- Does signed metadata expire, so a server cannot keep serving stale updates forever (freeze protection)?
- Can a server pass extra arguments, scripts or URLs that the client executes?

### Tools/Techniques

- [The Update Framework (TUF) specification](https://theupdateframework.github.io/specification/latest/) as a checklist. It names rollback, freeze, mix-and-match and arbitrary-package attacks.
- A lab with a fake update server and a hosts file entry, to test what the client accepts.

### Metrics/Signal

- Updaters that would run an unsigned or wrongly signed payload, trending to zero.
- Updaters with rollback and freeze protection.
:::

::: {! stage fortify}
## Fortify

### Explanation

Sign every update and verify it in the client against a key the client already holds. That one change turns a hosting compromise from code execution into a failed download. Then sign the metadata, so the attacker cannot replay old signed versions or swap one signed file for another.

### Insight

Most update frameworks already do this. The failures come from home-grown updaters and from frameworks configured with verification switched off.

### Practical

- Use an updater that enforces signatures. Examples:
    - [Tauri updater](https://v2.tauri.app/plugin/updater/): signature checking is mandatory, and the public key lives in `tauri.conf.json` under `plugins.updater.pubkey`.
    - [Sparkle](https://sparkle-project.org/documentation/) on macOS: put an EdDSA public key in `SUPublicEDKey` and sign archives with `generate_appcast`. Sparkle 2.9 adds signed feeds with `SURequireSignedFeed`.
    - Windows installers: verify the Authenticode signature and check the signer's identity, not only that some trusted certificate signed it.
- For a self-updating CLI or agent, use [TUF](https://theupdateframework.io/) through [go-tuf](https://github.com/theupdateframework/go-tuf) or [python-tuf](https://github.com/theupdateframework/python-tuf). TUF gives you signed, expiring metadata, rollback protection and key rotation.
- Keep signing keys off the web server and out of everyday CI jobs. Sign in a separate release job or with an HSM or cloud KMS. See [Code-Signing Certificate Theft and Misissuance](#battlecards-code-signing-certificate-abuse-md).
- Treat the hosting account like production. Hardware-key MFA on registrar, DNS, CDN and hosting accounts, and short-lived deploy credentials.

A minimal Tauri configuration looks like this. The app will not install an update that fails the check:

```json
{
  "bundle": {
    "createUpdaterArtifacts": true
  },
  "plugins": {
    "updater": {
      "pubkey": "CONTENTS OF YOUR PUBLIC KEY FILE",
      "endpoints": [
        "https://github.com/example/tool/releases/latest/download/latest.json"
      ]
    }
  }
}
```

### Tools/Techniques

- Tauri signer (`tauri signer generate`), Sparkle `generate_keys`, signify or minisign for small CLIs.
- [Sigstore](https://www.sigstore.dev/) to publish signatures to a public transparency log, so every signing event leaves a record you can monitor.
- GitHub artifact attestations and immutable releases for binaries hosted on GitHub.

### Metrics/Signal

- Percentage of updaters verifying signatures against a pinned key.
- Updaters with signed manifests and expiring metadata.
:::

::: {! stage limit}
## Limit

### Explanation

Assume one day something bad gets through. Perhaps the signing key leaks, or the build itself is compromised, as at 3CX. Limit how many users get it and how much it can do.

### Insight

A signed malicious build is still a malicious build. Signing moves the attacker's target from your web host to your build and your keys, so those need their own controls.

### Practical

- Roll out updates in stages: a small percentage first, then wider. Give yourself a way to halt the rollout from the server.
- Ship a kill switch that the client honours only when it is signed with the same pinned key.
- Run the updater with the least privilege it needs. Avoid an always-on service running as SYSTEM or root if a per-user update will do.
- Plan key rotation before you need it. TUF supports it natively. With Sparkle, rotating the EdDSA key needs care, so read its key-change guidance before an incident.
- Let enterprise customers turn auto-update off and pull updates through their own software distribution.

### Tools/Techniques

- Staged rollout features in your update server or app store channel.
- Separate signing keys or TUF roles per product, so one leaked key does not cover everything.

### Metrics/Signal

- Maximum share of users who could receive a release in its first 24 hours.
- Time to halt a rollout, measured in a drill.
:::

::: {! stage expose}
## Expose

### Explanation

Selective targeting is designed to avoid your notice. Most users get the real update, so nobody complains. Detection has to come from the data you hold: server logs, client telemetry, transparency logs and your own monitoring of the update endpoint.

### Insight

Selective delivery meant most Notepad++ users never saw a bad update. Build your updater so that a failed verification reaches you, not only the user.

### Practical

- Report verification failures from the client to a telemetry endpoint you control, with the URL and hash it was offered.
- Monitor the update endpoint from several networks and regions. Compare the manifest you get with the one you published.
- Watch transparency logs for signatures made with your identity that you did not make.
- Alert on changes to DNS records, TLS certificates for the update host (via Certificate Transparency), and hosting or CDN configuration.
- Keep and review update server access logs. Look for manifests served to a narrow set of clients that differ from the rest.

### Tools/Techniques

- Certificate Transparency monitoring, such as [crt.sh](https://crt.sh/) searches or a CT monitoring service.
- Sigstore Rekor searches for your signing identity.
- Synthetic checks that fetch and verify your own manifest on a schedule.

### Metrics/Signal

- Client verification failures per release, with an alert on any spike.
- Differences between the published manifest and the one served to monitoring probes.
:::

::: {! stage exercise}
## Exercise

### Explanation

Attack your own updater in a lab. Stand up a fake update server, point a test install at it, and see what it accepts. Use a harmless payload that only writes a marker file.

### Insight

Teams are often surprised by step 3 below. A client that checks "is this signed?" will happily install an older signed version with a known flaw.

### Practical

1. In an isolated VM, add a hosts file entry so your update hostname resolves to a local server.
2. Serve a manifest that points to an unsigned build of a harmless test app. Confirm the client refuses it and reports the failure.
3. Serve an old, correctly signed release. Confirm the client refuses the downgrade.
4. Serve a stale manifest past its expiry, if you use expiring metadata. Confirm the client notices.
5. Run a release drill: halt a staged rollout and rotate a test signing key. Time both.

### Tools/Techniques

- A local HTTP server and mitmproxy in an isolated VM.
- A test build signed with a throwaway key, never your production key.

### Metrics/Signal

- Pass or fail for each test case, per updater, tracked over time.
- Time to halt a rollout and time to rotate a key.
:::

## Further Reading

- [Notepad++: Hijacked incident info update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [The Update Framework](https://theupdateframework.io/)
- [Kaspersky: Operation ShadowHammer](https://securelist.com/operation-shadowhammer/89992/)
- [Mandiant: 3CX software supply chain compromise](https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise)
- Related cards: [CDN Script Compromise and Mirror Substitution](#battlecards-cdn-and-mirror-substitution-md), [DNS Hijacking and Man-in-the-Middle on Dependency Downloads](#battlecards-dns-and-mitm-attacks-md), [Code-Signing Certificate Theft and Misissuance](#battlecards-code-signing-certificate-abuse-md), [curl | bash Installer Attacks](#battlecards-curl-bash-installer-attacks-md)
