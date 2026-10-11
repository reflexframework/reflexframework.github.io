---
title: Code-Signing Certificate Theft and Misissuance
category: Supply Chain Integrity
ref: RFX-SCI-01
precedent: "2026"
scenario: Malware signed with your name on it
focus:
  - signing keys on build servers and laptops
  - certificates issued to an attacker in your name
  - revocation and timestamping
  - keyless signing with Sigstore
---

## Scenario

A company ships a Windows desktop agent and a Java command-line tool. Both are signed. The code-signing certificate lives on a hardware token plugged into a build server, and the token PIN sits in a CI variable so release builds can sign without a human.

An attacker gets into the build server through an old Jenkins plugin. They never copy the private key: the token will not let them. They do not need to. With the PIN in the environment, they can ask the token to sign anything they like. They sign an information stealer and a fake updater.

To every Windows machine that sees them, those binaries come from your company. SmartScreen warnings are quieter. Some endpoint tools trust them more. Your customers' allowlists, built on your publisher name, let them straight through.

There is a second route that never touches your systems at all:

1. An attacker compromises your certificate authority's support staff, or tricks them.
2. They complete a pending certificate order in your organisation's name.
3. They receive a perfectly valid certificate that you never asked for and cannot see.
4. They sign malware with it. You find out when a researcher emails you.

Either way, remember what a signature proves. It says who signed the code and that nobody changed it afterwards. It says nothing about whether the code is safe.

::: {! precedent}
**Real-world precedent:** In April 2026 an attacker sent a malicious screensaver file, disguised as a screenshot, through DigiCert's support chat. From an infected support analyst's machine they retrieved initialisation codes for approved EV code-signing orders and issued certificates to themselves. DigiCert revoked 60 certificates; 27 were tied to the attacker, and some had signed Zhong Stealer malware ([Mozilla bug 2033170](https://bugzilla.mozilla.org/show_bug.cgi?id=2033170), [Help Net Security](https://www.helpnetsecurity.com/2026/05/04/digicert-breach-code-signing-certificates-malware/)). In March 2022 two expired Nvidia code-signing certificates leaked by Lapsus$ were signing malware within a day ([ThreatDown](https://www.threatdown.com/blog/stolen-nvidia-certificates-used-to-sign-malware-heres-what-to-do/)). In May 2023 MSI's firmware image signing keys and Intel Boot Guard keys appeared in data leaked after a ransomware attack ([Help Net Security](https://www.helpnetsecurity.com/2023/05/08/msi-private-keys-leaked/)).
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers want your signature because it borrows your reputation. A signed binary from a known vendor gets fewer warnings and more trust. They look for the easiest place to make your key sign something: a build server with the token attached, a developer laptop with a `.pfx` file and its password in a notes app, a CI secret holding a base64 certificate.

They also look at your certificate authority. Your organisation's legal name, address and approved orders are what a CA uses to issue a certificate. If they can get into the CA's process, your own key security does not matter.

### Insight

Most teams cannot answer three simple questions. Where are all our signing keys? Who can make them sign? Which certificates exist in our name? An attacker who answers them first wins.

### Practical

- List every code-signing certificate your organisation holds: Authenticode, Apple Developer ID, Java JAR signing, GPG release keys, Android upload keys.
- For each one, record where the key lives, which machines and jobs can use it, and who holds the PIN or password.
- Search repositories and CI variables for signing material: `.pfx`, `.p12`, `.jks`, `.pem` files and secrets with names like `SIGNING_CERT` or `KEYSTORE_PASSWORD`.
- Ask your CA who in your organisation is allowed to order code-signing certificates.

### Tools/Techniques

- [Gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog) across repositories and history for private keys and keystores.
- Your CA's account portal or API to list issued and pending code-signing certificates.
- `signtool verify /pa /v` (Windows SDK) or `Get-AuthenticodeSignature` in PowerShell to see which certificate signed a shipped binary.

### Metrics/Signal

- Number of signing keys with a known location and owner.
- Number of signing keys stored as files rather than in hardware.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Since 1 June 2023 the CA/Browser Forum's [Code Signing Baseline Requirements](https://cabforum.org/working-groups/code-signing/requirements/) have required publicly trusted code-signing keys to be generated and kept in hardware: a token or HSM at FIPS 140-2 Level 2 or Common Criteria EAL 4+. That stops the key being copied. It does not stop it being used. A token plugged into a compromised build server will sign whatever the attacker sends it.

Evaluate who and what can trigger a signature, and whether anything checks what is being signed.

### Insight

Hardware keys turned "steal the key" into "borrow the signer". The defence has to move with it: control access to the signing operation and log every use.

### Practical

- For each key, trace the path from "someone wants a signature" to "signature produced". Count the steps where nobody checks what is being signed.
- Check whether signing happens in the same job that runs tests, plugins and third-party actions.
- Check older keys. Keys created before June 2023 may still exist as exportable files, and older GPG or JAR signing keys were never covered by the CA rules.
- Confirm your signed releases are timestamped. Without a timestamp, signatures stop validating when the certificate expires, which tempts teams into long-lived certificates.

```bash
# Java: who signed this JAR, and is there a timestamp?
jarsigner -verify -verbose -certs app.jar | grep -E 'Signed by|Timestamped by'
```

### Tools/Techniques

- `jarsigner -verify`, `signtool verify /pa /v` and `codesign -dv --verbose=4` (macOS) to inspect signatures and timestamps.
- Your HSM or cloud KMS audit logs to see who has used each key.

### Metrics/Signal

- Signing keys usable by more than one pipeline or person.
- Releases signed without a trusted timestamp.
:::

::: {! stage fortify}
## Fortify

### Explanation

Keep keys in an HSM or cloud KMS, and put a narrow signing service in front of them. Build jobs submit an artefact and receive a signature. They never hold the key, the token or the PIN. The signing service decides what it will sign: only artefacts from your release pipeline, from a protected branch, with provenance that matches.

For open-source releases, consider keyless signing with Sigstore. There is no long-lived key to steal. Each signature is bound to a short-lived certificate for your CI workload identity and recorded in a public transparency log.

### Insight

The best signing key is one nobody can reach directly. The next best is one where every use leaves a record that someone reads.

### Practical

- Move code-signing keys into an HSM or a cloud KMS that meets the CA rules. Tools such as Jsign can sign Authenticode and JARs with keys held in AWS KMS, Azure Key Vault, Google Cloud KMS or a PKCS#11 HSM.
- Run signing in a separate job, or a separate service, that receives the built artefact and nothing else.
- Require an approval, or at least a protected release environment, before the signing job runs.
- Timestamp every signature with an RFC 3161 timestamp authority, so you can revoke a key from a given date without invalidating everything signed before it.
- For open source, sign in CI with Sigstore and publish the bundle with the release:

```bash
# In CI, using the workflow's OIDC identity (no stored key)
cosign sign-blob --bundle tool.sigstore.json tool.tar.gz

# Consumers verify both the signature and who signed it
cosign verify-blob tool.tar.gz \
    --bundle tool.sigstore.json \
    --certificate-identity "https://github.com/example/tool/.github/workflows/release.yml@refs/heads/main" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

### Tools/Techniques

- Cloud KMS and HSM signing: AWS KMS, Azure Key Vault Managed HSM, Google Cloud KMS.
- Managed Windows signing services such as Microsoft [Artifact Signing](https://azure.microsoft.com/en-us/products/artifact-signing) (formerly Trusted Signing), which keeps keys in Microsoft-managed HSMs.
- [Jsign](https://ebourg.github.io/jsign/) for Authenticode signing from Java tooling with remote keys.
- [Sigstore](https://docs.sigstore.dev/) (cosign, Rekor, Fulcio) for keyless signing, and GitHub artifact attestations, which use Sigstore under the hood.

### Metrics/Signal

- Percentage of signing keys in hardware or KMS behind a signing service.
- Number of jobs that can sign without an approval step.
:::

::: {! stage limit}
## Limit

### Explanation

Assume one day a certificate in your name will sign something it should not. Plan how far that can spread and how fast you can stop it.

Revocation is your main lever, and it is a blunt one. Revoking a certificate from its issue date, as DigiCert did, invalidates every signature it ever made, including your genuine releases. Revoking from a later date keeps older timestamped signatures valid but trusts anything the attacker backdated. Timestamps and narrow certificates give you choices here.

### Insight

One certificate for every product means one revocation breaks every product. Smaller blast radius starts with more than one key.

### Practical

- Use separate certificates, or at least separate keys, for different product lines and for drivers versus applications.
- Keep certificate lifetimes short and rotate on a schedule you have practised.
- Write the revocation runbook now: who calls the CA, what revocation date you will ask for, which releases you will re-sign, and how customers get them.
- Tell customers to pin trust to more than your publisher name. For example, Windows App Control policies can trust a specific signer and file attributes, not every binary with your name on it.
- Give the signing service rate limits and an allowlist of artefact types, so a stolen pipeline cannot sign hundreds of arbitrary files quietly.

### Tools/Techniques

- [App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/) (formerly WDAC) policies for customers who want to block a specific compromised certificate.
- Sigstore's short-lived certificates, which expire in minutes and so need no revocation.

### Metrics/Signal

- Number of products that share a single signing certificate.
- Time to revoke a certificate and ship re-signed releases in your last drill.
:::

::: {! stage expose}
## Expose

### Explanation

You want to know about every signature made with your keys and every certificate issued in your name. For TLS certificates, Certificate Transparency logs give you that for free. Publicly trusted code-signing certificates have no equivalent public log, so you have to build the picture yourself.

### Insight

DigiCert's customers learned about certificates in their name from malware reports. The goal is to learn first from your own signing logs and your CA.

### Practical

- Log every signing operation with the artefact hash, the job, the commit and the requester. Compare it to your release list. A signature with no matching release is an incident.
- Alert on KMS or HSM key use from anywhere other than the signing service.
- Ask your CA for notifications on new orders and issuance for your organisation, and review the issued-certificate list monthly.
- Search malware repositories for files signed with your organisation's name. VirusTotal Intelligence supports searches on signature fields.
- For Sigstore-signed releases, watch the Rekor transparency log for entries using your identity.

### Tools/Techniques

- Cloud audit logs: AWS CloudTrail `Sign` events for KMS keys, Azure Key Vault diagnostic logs, Google Cloud audit logs.
- [rekor-monitor](https://github.com/sigstore/rekor-monitor) to watch the Rekor log for your signing identities.
- VirusTotal Intelligence searches on signer names.

### Metrics/Signal

- Signatures produced with no matching release record.
- Certificates in your name that your team did not order.
:::

::: {! stage exercise}
## Exercise

### Explanation

Practise losing a key in a sandbox. Use a test CA and a throwaway certificate so nothing real is at stake, then walk through detection, revocation and re-signing.

### Insight

Teams that have rehearsed revocation argue about the revocation date in a meeting room. Teams that have not argue about it during the incident.

### Practical

1. Create a private test CA and a code-signing certificate with OpenSSL or [step-ca](https://smallstep.com/docs/step-ca/) in an isolated environment.
2. Set up the signing service and a test pipeline that signs a harmless binary with it.
3. From a different "rogue" job, try to request a signature. Confirm it is refused, and that the attempt appears in the logs.
4. Sign a second benign file through the real service with no matching release record. Check whether your monitoring flags the orphan signature.
5. Revoke the test certificate from a chosen date and verify which earlier timestamped signatures still validate.
6. Time how long it takes to issue a new certificate, re-sign and republish the test releases.
7. For Sigstore, run `cosign verify-blob` with the wrong `--certificate-identity` and confirm verification fails.

### Tools/Techniques

- OpenSSL or step-ca for a private test CA.
- A test KMS key in a sandbox cloud account.
- cosign for keyless signing and identity checks.

### Metrics/Signal

- Time from orphan signature to alert.
- Time from "key compromised" to re-signed releases available.
:::

## Further Reading

- [CA/Browser Forum: Code Signing Baseline Requirements](https://cabforum.org/working-groups/code-signing/requirements/)
- [Mozilla bug 2033170: DigiCert misissued code signing certificates](https://bugzilla.mozilla.org/show_bug.cgi?id=2033170)
- [Sigstore documentation](https://docs.sigstore.dev/)
- [Help Net Security: MSI firmware and Intel Boot Guard private keys leaked](https://www.helpnetsecurity.com/2023/05/08/msi-private-keys-leaked/)
- Related cards: [Provenance and SBOM Tampering](#battlecards-provenance-and-sbom-tampering-md), [Hijacked Auto-Update Channels](#battlecards-software-update-channel-hijack-md), [Jenkins CI/CD Compromise](#battlecards-jenkins-ci-cd-compromise-md)
