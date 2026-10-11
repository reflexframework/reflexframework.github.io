---
title: Malicious Third-Party Mobile SDKs
category: Package Ecosystems
ref: RFX-PKG-10
precedent: "2025"
scenario: An analytics SDK that steals from every install
focus:
  - SDK vetting before adoption
  - privacy manifests, SDK signatures and Play SDK Index
  - permission and network diffs between builds
---

## Scenario

A mobile team is under pressure to add customer support chat and better analytics to their banking app. A free SDK promises both, with an optional OCR feature to read receipts. They add it through Gradle on Android and Swift Package Manager on iOS. It is three lines of configuration on each platform.

The SDK works as advertised. It also does more:

1. On first launch it fetches a remote configuration from a server that looks like a Google or Firebase domain.
2. When the user opens the support chat, it asks for photo library access "to attach screenshots". Most users say yes.
3. It runs on-device OCR over the gallery, looking for wallet recovery phrases, one-time codes and screenshots of passwords.
4. Matching images go to the attacker's server over an encrypted channel that blends in with the app's own analytics traffic.

The team never wrote any of this code, but it ships inside their signed app to every user. The store listing carries their name. The privacy policy they wrote does not mention gallery scanning, and the regulator will not care whose code it was.

Third-party SDKs run with the full permissions and identity of the host app. They see what the app sees. Most teams review them less than they review a pull request from a new colleague.

::: {! precedent}
**Real-world precedent:** In February 2025 Kaspersky reported [SparkCat](https://securelist.com/sparkcat-stealer-in-app-store-and-google-play-2/115385/), a malicious SDK posing as an analytics module in apps on both Google Play and the App Store. It used OCR to find crypto wallet recovery phrases in users' photos; the infected Play apps had over 242,000 downloads. Kaspersky could not tell whether developers added it knowingly or through a supply chain compromise. In April 2023 McAfee found the [Goldoson](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/) library in more than 60 legitimate Google Play apps with over 100 million downloads; it collected installed-app lists, Wi-Fi and Bluetooth device data and location, and committed ad fraud, without the app developers' knowledge. In January 2024 the [FTC barred X-Mode Social](https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-prohibits-data-broker-x-mode-social-outlogic-selling-sensitive-location-data) from selling sensitive location data it had collected through an SDK embedded in third-party apps.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers who want mobile data at scale do not need to write a popular app. They need a popular SDK, or a way into one. There are three routes:

- **Build a lure SDK.** Offer something teams want for free: analytics, ads mediation, OCR, push, crash reporting. Monetise the data.
- **Buy or take over an existing SDK.** Small SDK vendors get acquired. Old CocoaPods and Maven artefacts get abandoned.
- **Compromise distribution.** In 2024, researchers showed that orphaned pods on CocoaPods trunk could be claimed by anyone ([CVE-2024-38368](https://nvd.nist.gov/vuln/detail/CVE-2024-38368), fixed server-side in 2023).

Shipped apps reveal which SDKs they embed. Anyone can unpack an APK or IPA and list the libraries inside.

### Insight

Your app's SDK list is public. Theirs is a shopping list: which SDKs reach which audiences, and which small vendors sit inside big apps.

### Practical

- List every SDK in each of your apps, including the ones your SDKs pull in transitively.
- Note which SDKs are closed-source binaries (XCFrameworks, AARs) and which are source you can read.
- Record who owns each SDK and when you last checked that the vendor is still the same company.

### Tools/Techniques

- Android: `./gradlew :app:dependencies --configuration releaseRuntimeClasspath`.
- iOS: `Package.resolved` for Swift Package Manager, `Podfile.lock` for CocoaPods.
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) or [Exodus Privacy](https://reports.exodus-privacy.eu.org/) to see which trackers and SDKs a built APK contains, as an attacker would.

### Metrics/Signal

- Number of third-party SDKs per app, and how many are closed-source.
- SDKs with no named owner on your team.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Vet an SDK before it goes in, and again when its vendor or behaviour changes. The question is simple: what does this code do with the access my app gives it?

Both platforms now give you some help. Apple requires [privacy manifests](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files) declaring collected data and use of required-reason APIs. Since May 2024 it has required manifests and, for binary dependencies, valid signatures from SDKs on its [list of commonly used third-party SDKs](https://developer.apple.com/support/third-party-SDK-requirements/). Google's [Play SDK Index](https://play.google.com/sdks) shows the permissions popular SDKs request, links to their Data safety guidance and flags versions with policy problems.

### Insight

A privacy manifest is the vendor's own declaration. SparkCat-style code will not declare "scans your photos for seed phrases". Treat manifests and index entries as a starting point for questions, then check behaviour yourself.

### Practical

- For each candidate SDK, ask: who publishes it, how is it funded, what permissions does it add, what data does it send and where?
- Read its privacy manifest (`PrivacyInfo.xcprivacy`) and check it against what the SDK claims to do.
- Check the Play SDK Index entry for permissions and any policy warnings on the version you plan to use.
- Diff the merged Android manifest with and without the SDK to see every permission it adds.
- Prefer SDKs whose source you can read and build. Be wary of a binary SDK that downloads its configuration or code at runtime.

### Tools/Techniques

- Xcode's privacy report: archive the app, then in the Organizer choose Generate Privacy Report to see the combined manifests.
- Android Studio's Merged Manifest view, or `apkanalyzer manifest permissions app-release.apk`.
- Play SDK Index and Play Console's SDK warnings.

### Metrics/Signal

- Percentage of SDKs that passed a documented review before first use.
- SDKs that request permissions unrelated to their stated purpose.
:::

::: {! stage fortify}
## Fortify

### Explanation

Lock down how SDKs get into the build. Pin exact versions, verify what you download, and make every SDK change a reviewed change.

### Insight

An SDK update is new code running with your app's identity. It deserves the same review as a feature branch, and usually gets none because it arrives as a one-line version bump.

### Practical

- Android: turn on [Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html) so every artefact is checked against recorded checksums or signatures. Restrict each repository to the groups it should serve with `content { includeGroup(...) }` filters.

```bash
./gradlew --write-verification-metadata sha256 help
git add gradle/verification-metadata.xml
```

- iOS: commit `Package.resolved` and `Podfile.lock`. Review diffs to them in pull requests; a changed revision or checksum is a code change.
- Use Xcode's [XCFramework signature checks](https://developer.apple.com/documentation/xcode/verifying-the-origin-of-your-xcframeworks). Xcode records the signing identity of a binary framework and fails the build if a later version is unsigned or signed by someone else.
- Plan your way off CocoaPods. The CocoaPods team plans to make trunk [read-only from December 2026](https://blog.cocoapods.org/CocoaPods-Specs-Repo/), so pods there will receive no further updates.
- Ask SDK vendors for a privacy manifest, a signed binary and a named security contact. Write it into the contract.

### Tools/Techniques

- Gradle dependency verification and repository content filtering.
- Swift Package Manager with committed `Package.resolved`; CODEOWNERS on lockfiles.
- Renovate or Dependabot to raise SDK updates as reviewable pull requests.

### Metrics/Signal

- Builds with dependency verification enabled.
- SDK version changes merged without a reviewer from the mobile team.
:::

::: {! stage limit}
## Limit

### Explanation

An SDK can only take what your app can reach. Keep permissions and data narrow, and give SDKs less than the whole app.

### Insight

SparkCat needed gallery access. An app that uses the system photo picker never holds that permission, so the SDK has nothing to scan.

### Practical

- Use the Android Photo Picker and iOS `PHPickerViewController`. Both return only the images the user selects, with no library-wide permission.
- Remove permissions you do not need. Use `tools:node="remove"` in your Android manifest to strip permissions an SDK adds without good reason.
- Initialise SDKs late and only when needed. Do not hand them user identifiers, tokens or screen content they do not require.
- Keep secrets out of the app binary entirely. An SDK can read anything the app can.
- Isolate risky SDKs behind your own interface, so removing one is a small change you can ship quickly.

### Tools/Techniques

- Android Photo Picker, iOS `PHPickerViewController`.
- Android manifest merger rules (`tools:node="remove"`).
- Remote feature flags that can switch off an SDK's initialisation without a new release.

### Metrics/Signal

- Sensitive permissions (photos, location, contacts, SMS) declared per app, trending down.
- Time to remove an SDK from production after a decision to drop it.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for the moment an SDK starts doing something new. Compare each release build with the last: permissions, privacy declarations, embedded libraries and network destinations.

### Insight

A malicious SDK has to talk to someone. New domains in the network log of a test run are the most reliable signal you will get.

### Practical

- In CI, extract the permission list from each release build and fail the job if it changes without an approved pull request.

```bash
apkanalyzer manifest permissions app/build/outputs/apk/release/app-release.apk \
    | sort > permissions.txt
diff -u permissions-baseline.txt permissions.txt
```

- Run your UI test suite on an emulator or simulator through an intercepting proxy, and diff the set of domains contacted between releases.
- Diff the Xcode privacy report between releases.
- Read Play Console pre-launch reports and SDK warnings, and subscribe to security advisories from your SDK vendors.

### Tools/Techniques

- `apkanalyzer` for permissions and DEX contents.
- [mitmproxy](https://mitmproxy.org/) in front of an emulator or simulator during UI tests.
- MobSF for automated static and dynamic analysis of each build.

### Metrics/Signal

- New network destinations per release, with an owner and a reason for each.
- Unexplained permission or privacy manifest changes caught before release.
:::

::: {! stage exercise}
## Exercise

### Explanation

Test whether your process catches a misbehaving SDK. Build a harmless "canary SDK" in-house, add it to a branch of your app, and see which checks notice.

### Insight

If a deliberately noisy SDK gets through review, a quiet one will too.

### Practical

1. Write a small Android library and Swift package called something plausible, such as `insights-lite`. It should request photo access, read a test image's file name, and send it to a canary token URL or a local HTTP server you control. Use no real user data.
2. Publish it to a local Maven repository (`mavenLocal()` or a private Nexus) and a local Swift package path. Never publish it to Maven Central, CocoaPods trunk or any public registry.
3. Add it to a throwaway branch through a normal pull request with a vague description.
4. Record which checks fire: code review, permission diff, dependency verification, privacy report diff, proxy-based egress check.
5. Fix the gaps, delete the branch and the library.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org/) or a local HTTP listener for the callback.
- A local Maven repository and a local Swift package.
- An emulator and simulator with mitmproxy.

### Metrics/Signal

- Number of controls that flagged the canary SDK, and at which stage.
- Time from merge to detection.
:::

## Further Reading

- [Kaspersky Securelist: SparkCat stealer in App Store and Google Play](https://securelist.com/sparkcat-stealer-in-app-store-and-google-play-2/115385/)
- [Apple: Third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/)
- [Apple: Verifying the origin of your XCFrameworks](https://developer.apple.com/documentation/xcode/verifying-the-origin-of-your-xcframeworks)
- [Google Play SDK Index](https://play.google.com/sdks)
- [Gradle: Verifying dependencies](https://docs.gradle.org/current/userguide/dependency_verification.html)
- Related cards: [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md), [Abandoned Package Hijack](#battlecards-abandoned-package-hijack-md)
