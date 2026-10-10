# You Don't Know What You've Shipped

For a long time developers have had a strange relationship with security. I don't mean security as in authorisation, access control etc. I mean software supply chain security. Even the term is rarely heard in development circles. If it is discussed, it's as part of a compliance regime, of audits, licences and of course CVEs.

Since about 2014, software supply chain attacks have grown at an uncomfortable rate. In the last handful of years that growth has accelerated dramatically. Even so, it's not something developers are usually aware of, and they are certainly not conscious of their growing responsibilities in keeping the creation, maintenance and deployment of software safe.

As a developer reading this, your connection with software supply chain security probably starts (and usually ends) with CVEs. Larger organisations may place restrictions on tools and components you use based on licensing concerns, but other than that your exposure is reactive. Some scanning software detects a vulnerability in a dependency used (directly or indirectly) by an application and your job is to bump the version of the troublesome component to a newer version. In fact, in large organisations that 'bump' may even be done by folk who have no insight into the workings of the application. Their job is just to keep it safe and running.

Of course, sometimes 'bumping' the component is problematic. The replacement component has attached consequences that mean more work has to take place other than a simple update and retest. The new component, or maybe one of its dependencies, has API changes, behaviour changes, even new runtime consequences and requirements that force a development team to spend resources fixing the issues. All just to keep an existing application running. All effort that isn't contributing to new features and value.

Ecosystems vary in the likelihood of a component update, even one that's just a security fix, not causing additional work. It's partly about the attitude and culture of the ecosystem rather than simply intrinsic technical differences. You may be lucky to be using components that have an ethos of trying hard not to break consumers, but how would you know that? What about all the other dependencies? The tool providers? The OS packages you rely on? At this moment we rely on a mix of information, support contract wording and just "that's how we do it", collective community attitudes.

Let's consider something relatively simple.

Think about the last time you added a dependency to an application. What made you choose it? Was it the API? Documentation? Popularity? Perhaps it was recommended by somebody, or perhaps an AI assistant suggested it.

**Did you check its licence?**

I'm guessing many of you did, or at least your organisation has tooling that checks licences on your behalf. We've become accustomed to checking whether we're legally allowed to use and distribute other people's software. It's part of normal software development practice.

**Now, did you check whether the project had a `SECURITY.md` file?**

For those unfamiliar with it, [`SECURITY.md`](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/add-security-policy) is a convention used by projects, particularly those hosted on GitHub, to document how security vulnerabilities should be reported and, sometimes, which versions of the software are supported.

It's a simple thing. A way for somebody who discovers a security problem to contact the people who might be able to fix it, without announcing the vulnerability to the entire world.

Did you look for one? Did you check whether it described a working reporting process? Did you establish whether the version you were planning to use was still receiving security fixes?

What about the people maintaining the project? Are they active? Do they respond to security reports? Have they released anything recently? Have you any idea who they are?

I'm not suggesting that every developer needs to conduct a detailed security audit before adding a library. But it's interesting that we've developed reasonably mature habits around licensing while giving considerably less attention to whether the software we're choosing can actually be maintained securely.

This status quo is not only under threat, it's being actively targeted and has started to break. Many of the certainties we relied on around software supply chains are going to be stressed and broken. Many of them will turn out not to be certainties at all.

Much of the way we manage software supply chain security relies on assumptions. Assumptions about how vulnerabilities are discovered, who reports them, who fixes them and how we find out whether the software we're using is affected. Some of these assumptions are reasonable, some have always been questionable, and others are becoming increasingly difficult to rely on.

AI is making this particularly interesting. We're getting better at discovering vulnerabilities, but finding them is only the beginning of a process that still depends heavily on people. The consequences extend well beyond the security researchers and maintainers involved. They eventually reach every organisation running the affected software.

To understand what's changing, we need to examine some of those assumptions.

## Assumption: Security vulnerabilities eventually get a CVE

The first one is complex, but it helps set the scene for the others. The assumption is that all security bugs eventually get a CVE.

To examine this one we need to look at what a CVE is and what it's not. We need to look under the covers at how CVEs are created and maintained and who does all this work.

Before that, it's vital to understand that not all security issues are even reported. The bad actors targeting the software supply chain are as capable as any developer, are very well motivated and obviously operate without the ethical boundaries of responsible security researchers. There are also people who discover vulnerabilities with the intention of selling them rather than reporting them to the people who could fix them.

The term RCE, or Remote Code Execution, is particularly important. An RCE vulnerability can potentially allow an attacker to execute code on a target system. These vulnerabilities can be especially valuable to attackers, particularly when they affect widely deployed software and can be exploited reliably.

The critical part is often that the vulnerability is not yet publicly known. Sometimes that means never reported, sometimes that means disclosure is delayed so it can be exploited. When attackers exploit an unknown vulnerability before defenders have had an opportunity to address it, we're dealing with what's commonly called a zero-day vulnerability.

And that can eventually leave a lot of people dealing with the fallout.

Assuming that the security issue gets reported, where does it go? What happens to turn a discovery into a CVE?

It often starts with the discoverer contacting the vulnerable component's creators. That's harder than it looks. The ethical reporter doesn't want to publish the vulnerability details for fear of exploitation, but sometimes that does happen if the reporter feels insufficient progress is being made to resolve the issue.

Assuming the reporter contacts the component owner or one of the coordination bodies (more about them later), what starts next is a 'cone of silence' covering the conversations between the reporter, the coordinator and the resolver.

There's a lot going on under this cone. Verification of the problem, triage of a solution, testing that the fix works and, of course, deciding the initial vulnerability impact. There may also be discussions with downstream maintainers, operating system vendors and other organisations affected by the same issue.

The actual raising of the CVE is a little more complicated than you might expect. For a start, the CVE isn't the vulnerability itself. It's a unique identifier that allows everyone to refer to the same problem. That might sound like a minor distinction, but it's important. A CVE doesn't mean that a fix exists, that the vulnerability has been exploited, or even that everyone agrees on how serious it is.

There is also a distinction between reserving a CVE identifier and publishing the CVE record. The identifier can be reserved while the vulnerability is still being investigated and the fix is being developed. This allows the people involved to use a common reference without revealing the details publicly.

Not just anyone can assign these identifiers. That responsibility belongs to organisations known as [CVE Numbering Authorities, or CNAs](https://www.cve.org/ProgramOrganization/CNAs). Some are major software vendors, some are open source organisations, and others are involved in vulnerability coordination. Each CNA has a defined scope within which it can assign CVE identifiers. If the component maintainer isn't a CNA, the reporter needs to find one that can handle the vulnerability.

This is where the process starts to become interesting, particularly for open source.

For an actively maintained project with a responsive security team, the process can be relatively straightforward. The report is acknowledged, the vulnerability is investigated, a fix is developed and a disclosure date is agreed. Ideally, the fix and the public CVE record appear at roughly the same time, giving users an opportunity to protect themselves.

Of course, that assumes there's someone available to receive the report, someone capable of developing the fix and someone willing to coordinate the release. It also assumes the vulnerability can be understood and resolved within a reasonable period.

None of those things is guaranteed.

Open source projects range from large, commercially supported ecosystems to software maintained by a single person in their spare time. That maintainer might have moved on to something else, might no longer use the software, or might simply lack the time to investigate a complex security report. The vulnerability doesn't become any less serious because nobody is available to deal with it.

And what happens when the affected version is no longer supported? A vulnerability might be discovered in the current release of a component, but the same underlying issue could have existed for years. The maintainers may fix the versions they support while leaving older releases untouched. That doesn't necessarily mean those older versions are safe. It means nobody is committing to fixing them.

There's another important distinction here. The decision to assign a CVE and the decision to fix a vulnerability are not the same thing. A vulnerability can be documented without a patch being available, and an unsupported version can remain vulnerable long after newer versions have been fixed.

This is one of the reasons that treating the CVE database as a complete list of vulnerabilities in the software you use is dangerous. The process relies on vulnerabilities being discovered, recognised, reported and recorded. At each stage, something can fail to happen.

Now think about that dependency you added earlier. Suppose somebody discovers a security problem in it. Who are they going to contact? Is there a security reporting policy? Is the maintainer still active? If the problem is reported, will somebody investigate it?

Perhaps checking for that `SECURITY.md` file wasn't such a trivial question after all.

Of course, the presence of a file doesn't guarantee that anybody will respond, any more than its absence proves that a project is insecure. But at least it gives us something to investigate.

Let's assume everything has gone according to plan. The vulnerability has been verified, a CVE identifier has been assigned, the fix is ready and the details are published.

Now what?

You might think that publication is the point at which the problem has been resolved. For the people maintaining the component, that may well be true. They've investigated the issue, produced a fix and made it available.

For everyone consuming that component, however, the work is only just beginning.

## Assumption: A published CVE tells us what software is vulnerable

So we've got a CVE. The vulnerability has been reported, investigated and published. Perhaps there's even a fix available. Surely that's enough for the software security tools to work out which applications are affected?

Not quite.

The CVE record provides a common identifier and information about the vulnerability. But someone still has to establish which software products and versions are affected, how serious the problem is and what can be done about it.

That information may come from the original reporter, the project maintainer, the CNA or organisations that enrich vulnerability data after publication.

One of those organisations is [NIST](https://www.nist.gov/), which operates the [National Vulnerability Database, or NVD](https://nvd.nist.gov/). The NVD takes published CVE information and adds further analysis where available, including affected-product information and severity assessments. Other databases, such as [OSV](https://osv.dev/), provide vulnerability information in formats intended to make it easier to identify affected open source package versions.

All very useful, but there's a catch.

The information isn't necessarily complete, consistent or available immediately. Different sources can have different assessments of the same vulnerability, and working out exactly which versions are affected can be surprisingly difficult.

The NVD itself provides a useful illustration of the problem. Starting in 2024, it developed a substantial backlog of CVEs awaiting enrichment. In [April 2026, NIST explained](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth) that its increased analysis throughput still wasn't enough to keep up with submissions. Its response included prioritising which CVEs received enrichment.

Think about what that means. We have a system that identifies and publishes vulnerabilities, and another that adds information many downstream security tools depend on. The second system cannot necessarily keep pace with the first.

And there's another complication with affected versions.

Software projects don't necessarily share the same interpretation of version numbers or support policies. A security fix may appear in several branches, be backported into an older release or be incorporated into a vendor-maintained fork. The version number alone may not tell you whether the vulnerability is present.

Suppose a vulnerability is discovered in version 5.2 of a component and fixed in version 5.3. What about version 4.8? Or 3.6?

Was the vulnerable code present in those versions? Did it behave the same way? Were there architectural changes that introduced the vulnerability later? Did an older branch receive an independent fix?

Someone has to investigate those questions.

If the maintainers are only supporting the latest release, they may have no intention of doing that work for older versions. The CVE record might therefore contain incomplete information about the software still running in production.

Now return to our original dependency choice. We selected a version because it was compatible with our application, perhaps because it was recommended in the documentation or because a framework depended on it.

If the vulnerability data doesn't accurately describe that version, what is our scanner supposed to report?

The scanner doesn't necessarily have enough information to know.

This is an important distinction. A vulnerability can exist in software without being recognised by the vulnerability databases. And a vulnerability database can contain a perfectly valid CVE without sufficiently describing every affected version.

The information is useful, but it isn't complete.

## Assumption: The severity score tells us what to fix first

Having identified a vulnerability, we're going to need some way to decide what to do about it.

This is where [CVSS](https://www.first.org/cvss/) comes in. The Common Vulnerability Scoring System provides a way to describe and score the technical severity characteristics of a vulnerability. It's familiar to anyone who has worked with security scanners. A vulnerability appears with a score, often accompanied by a label such as Low, Medium, High or Critical.

The temptation is to treat this as a straightforward priority list. Fix the critical vulnerabilities first, then the high ones, and work your way down.

But severity isn't the same as risk.

A remotely exploitable vulnerability in a component exposed to the internet is a different proposition from the same vulnerability in a component that cannot be reached by an attacker in your deployment. An apparently less severe vulnerability that's actively being exploited may be considerably more urgent than a critical vulnerability for which exploitation is unlikely.

There are other sources of information intended to help with these decisions. [CISA maintains the Known Exploited Vulnerabilities catalogue, or KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), containing vulnerabilities for which there is evidence of exploitation in the wild. [EPSS, the Exploit Prediction Scoring System](https://www.first.org/epss/), estimates the probability of exploitation activity for a published CVE over the next 30 days.

These are useful signals, but they answer different questions. CVSS describes technical severity. KEV records known exploitation. EPSS provides a statistical estimate of exploitation likelihood.

None of them knows everything about your application, how it is configured, which functions it uses or how important the affected system is to your organisation.

And not appearing on KEV doesn't mean a vulnerability isn't being exploited. It means the vulnerability hasn't met the criteria for inclusion in that catalogue.

This distinction matters because security teams are already having to make decisions about more vulnerabilities than they can realistically investigate in detail. Scores and classifications help reduce the workload, but they cannot replace the contextual knowledge needed to make the right decision.

We're going to return to this problem when we look at AI, because the question of how to prioritise vulnerability work is about to become much more important.

## Assumption: Somebody is maintaining the software

Let's return to those older releases and the question of who is responsible for fixing them.

End-of-life, or EOL, is often treated as a lifecycle management problem. You have some software, the project or vendor stops supporting it, and eventually you upgrade or replace it.

That's a reasonable description of what should happen. It's rather less representative of what actually happens in large organisations.

Applications can run for years or decades. They depend on components that depend on other components. Some of those components continue to evolve, while others stop receiving updates.

Some have formal end-of-support dates. Others simply become inactive. The last release might be several years old, with no announcement explaining whether anyone intends to maintain it.

The application doesn't necessarily stop working when that happens. In fact, that's part of the problem. As long as the software continues to behave as expected, there's little immediate incentive to change it.

But the absence of maintenance changes the security equation.

If a vulnerability is discovered in a supported version, there's at least some expectation that somebody will investigate and address it. If the affected version is unsupported, that expectation may no longer exist.

More subtly, the people receiving vulnerability reports may have no reason to investigate older releases. If the maintainers don't intend to fix those releases, they may not spend time establishing whether each old version is affected.

And if a project has no active maintainer at all, there may be nobody available to receive or evaluate a report in the first place.

It's important not to confuse this with the rules of the CVE Programme. End-of-life software can still have CVEs assigned to it. The absence of a patch is not a reason to prohibit CVE assignment.

But the practical processes that lead to discovery, verification and publication depend on people doing the work. Where those people are missing, the information can be missing too.

This creates an uncomfortable possibility. Software that has stopped receiving security attention can appear to have fewer vulnerabilities than software that's actively maintained and investigated.

A project with a steady stream of CVEs might be showing evidence that its security process is working. Another project with no published CVEs might be exceptionally well written. Or it might simply have nobody looking.

How would you know which?

Consider our original dependency again. Suppose its last release was three years ago. Its documentation is still available, the API works perfectly and thousands of other projects continue to use it.

Is that a problem?

Not necessarily. Some software is relatively stable and doesn't require frequent changes. A lack of releases isn't proof of poor quality.

But there's a difference between software that doesn't need changing and software that nobody is willing or able to change.

If a vulnerability is discovered tomorrow, who is going to investigate it? Who will produce a fix? And who will tell you whether the version you're running is affected?

Those are questions we should have considered before adding the dependency. They become considerably harder to answer after we've built an application around it.

For organisations with substantial estates of older applications, this becomes a serious problem. If your vulnerability management process relies entirely on matching your software inventory against CVE databases, you have no reliable way to distinguish an unsupported component with no known vulnerabilities from an unsupported component that nobody is assessing.

The lack of a CVE is not evidence that a component is safe. For unsupported software, it may be evidence of very little indeed.

And now we're going to make this entire process considerably more complicated.

## Assumption: The vulnerability reporting system can keep up

Until fairly recently, discovering a complex security vulnerability usually required considerable expertise and time. Security researchers needed to understand the software, locate the vulnerable behaviour, determine whether it was exploitable and produce enough evidence to persuade somebody else that the problem was real.

That limited how much vulnerability research could be done. It didn't prevent vulnerabilities being found, but it placed practical constraints on the rate at which new discoveries could be made.

AI is changing those constraints.

We've already seen AI become very capable at reading, explaining and generating source code. Applying those capabilities to vulnerability research is a relatively obvious next step.

Instead of asking an AI to implement a feature, we can ask it to examine an implementation for unexpected behaviour, explore unusual execution paths or identify places where untrusted input can lead to dangerous operations.

The interesting development is that this is no longer limited to generating a list of suspicious-looking code. Increasingly capable systems can investigate candidate vulnerabilities, develop tests, reason about exploitability and sometimes produce evidence that a defect is real.

Anthropic's [Project Glasswing and Claude Mythos](https://www.anthropic.com/research/glasswing-initial-update) provide a particularly interesting example. Project Glasswing was established to use highly capable AI systems to identify vulnerabilities in important software, giving defenders an opportunity to discover and fix problems before similarly capable systems became widely available to attackers.

Anthropic subsequently described significantly expanded finding volumes in its [Cyber Verification Programme](https://www.anthropic.com/news/cyber-verification-program). We need to be careful about interpreting these numbers: verified findings are not necessarily unique public CVEs, and not all findings will generate alerts against software a particular organisation uses. Nevertheless, the research illustrates the potential scale of automated vulnerability discovery.

An [opt-in vulnerability-finding service for open source](https://www.anthropic.com/research/launching-opt-in-vuln-finding-service-for-open-source) also raises an important question for maintainers. Projects that could never afford extensive specialist security research may gain new discovery capabilities, but somebody still has to deal with the results.

Think about what happens next.

Somebody has to verify each finding, determine which versions are affected, decide whether it represents a distinct vulnerability, coordinate disclosure and work out what to do about it.

And we have not suddenly acquired a comparable increase in the number of experienced open source maintainers, security coordinators or engineers available to maintain older software.

The bottleneck is moving.

It's also important to distinguish between genuinely useful discoveries and low-quality AI-generated vulnerability reports. Some reports are simply wrong. The AI has misunderstood the code, invented a possible attack path or failed to recognise an existing defence. Others are duplicates or describe behaviour that is intentional rather than vulnerable.

Even a report that's clearly wrong takes time to dismiss. Someone has to read it, understand the claim and establish why it isn't valid. The curl project's experiences with poor-quality vulnerability reports provide a useful example of the burden created by submissions that appear convincing but fall apart under examination.

Now imagine that happening across thousands of projects.

A maintainer might previously have received a handful of security reports each year. Suddenly they're receiving dozens or hundreds of potential findings. Some are genuine. Some are duplicates. Some are wrong. But somebody has to distinguish between them.

If the project is maintained by a small team, or perhaps just one person, time spent triaging reports is time that isn't available for developing and testing fixes.

This is where we need to recognise that the problem isn't simply an increasing number of CVEs. Before we even get to a published CVE, there's potentially much more work for people receiving, validating and coordinating reports. And after publication, another group needs to act.

## Assumption: Finding more vulnerabilities makes software safer

There's an obvious argument that discovering more vulnerabilities is always good because it gives us the opportunity to fix problems we didn't previously know existed.

And broadly, that's true. We cannot deliberately remediate a vulnerability we don't know about.

But discovering a problem doesn't mean it has been resolved. In some circumstances it simply means we now have another problem competing for limited attention.

Imagine a project receives ten credible vulnerability reports in a month. Its maintainers investigate them, fix the critical problems, publish advisories and schedule the less urgent work. Now imagine that project receives a hundred reports. Or a thousand.

Even if only some are genuine, separating useful findings from noise can become substantial work. And each published vulnerability can become work for downstream maintainers, distributions, vendors and consuming organisations.

The problem doesn't stop at the first fix. Projects may have several supported branches. Vendors may maintain patched forks. Organisations may have custom modifications or depend on behaviour that changed in newer versions.

This is why **patch generation and software maintenance are not the same thing**.

AI may become very good at generating changes that address vulnerabilities. But producing a patch is not the same as producing a safe, supported release. A maintainer needs to establish intended behaviour, preserve it, assess regressions, test compatibility and decide where to apply the change.

For older software, this can be particularly difficult. Sometimes the closest thing we have to a behavioural specification is whatever the software currently does. Applications may have come to rely on quirks and undocumented behaviour.

A patch that fixes the vulnerability but changes those behaviours may be technically correct and operationally disastrous.

This is one of the reasons I consider a project's test suite to be one of its most important long-term assets. Source code can be replaced or rewritten. The tests, when they accurately describe intended and established behaviour, provide evidence that a change hasn't broken something.

Of course, existing test suites aren't automatically sufficient. They may miss important behaviour, and AI-generated tests can make the same assumptions as AI-generated patches. AI can help, but it doesn't eliminate the need to decide what correct behaviour means.

And what about our dependency? Suppose its maintainers used to deal with ten security issues a year and are now presented with fifty or a hundred. Does that make the dependency safer? Eventually, perhaps, but only if the findings are investigated, fixed, tested and released. In the meantime, unresolved issues can grow faster than the maintainers can deal with them.

## Assumption: Our organisations can deal with the vulnerabilities they discover

Let's follow the vulnerability downstream.

A new CVE is published against a widely used library. Vulnerability databases receive the information. SCA tools identify affected components in the software they scan. Security teams start seeing alerts.

In a large organisation, that single vulnerability might affect dozens, hundreds or thousands of applications. Each application needs assessing. Is the component present? Is the affected version in use? Is vulnerable functionality reachable? Is the system exposed? Is a fix available? What are the consequences of upgrading?

Some questions can be automated. Others require knowledge of the application and its operating environment.

Now suppose the rate of published vulnerabilities increases substantially. It's tempting to assume this just means more alerts, but security teams must assess findings, development teams must investigate and fix applications, release teams must deploy changes, and testing teams must establish whether anything has broken.

What happens when the amount of work arriving grows faster than the capacity to deal with it? Backlogs grow. Exceptions accumulate. Decisions are deferred. More vulnerabilities remain unresolved for longer.

We should improve correlation, reachability analysis, prioritisation and automated testing, but automation doesn't remove every constraint. Sometimes remediation requires substantial engineering work.

A tenfold increase in vulnerability *findings* doesn't necessarily mean a tenfold increase in *published CVEs*, but even a smaller increase can generate considerable downstream work.

And that assumes we can identify which applications are affected. Can we?

## Assumption: We know what's in our applications

Most organisations have some form of vulnerability scanning. Software Composition Analysis, or SCA, tools identify software components, match them against vulnerability data and report known issues.

The idea is straightforward. If we know what an application contains, including component versions, we can check those against vulnerability databases. But it depends on knowing what the application contains.

We have build systems, package managers, dependency manifests and lockfiles. Maven, Gradle, npm and pip can all provide useful information, but what we declare, what the build resolves, what gets packaged and what actually runs aren't necessarily the same things.

Some dependencies are direct. Others are transitive. Some are for tests or builds. Others are downloaded dynamically, supplied by the runtime or bundled into another component.

Java developers know about shaded JARs, where dependencies can be repackaged and identifying metadata can be lost. Other ecosystems have equivalent problems with vendored source and static linking.

Container images add operating system packages, runtime libraries and tools that weren't mentioned in the application's dependency manifest. CI/CD actions, build plugins and install scripts may execute code with access to credentials even though they never appear in the finished application.

Which of these are included when you ask for a dependency list? It depends on how you ask and which tool you use.

Remember the dependency we added earlier? What did it bring with it? How much did we investigate? How much can our normal tools recognise?

## Assumption: An SBOM is a complete inventory

[Software Bills of Materials, or SBOMs](https://www.cisa.gov/sbom), are increasingly used to document the components in software products. Formats such as [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) make that information portable.

The idea is attractive. With a reliable inventory, we can understand what we ship, identify vulnerabilities, manage licensing and respond to new problems. But generating an SBOM doesn't automatically mean we've identified everything.

An SBOM based on a manifest can describe what the build system thinks it needs, while missing embedded components or later packaging steps. An artefact scan can find different things but lose origin and relationship information. Both can miss components.

Do we include build tools? Code generators? Operating system packages? Container layers? Dynamically loaded modules? Copied source code? It depends on the scope and purpose of the inventory.

The inventory represents what the tool managed to discover, not proof that everything has been found. That's an argument for improving SBOMs, not abandoning them.

### Assumption: Security vulnerabilities only matter in the software we ship

Think about the last time you generated an SBOM. What was it describing? For many developers, the answer is the dependencies in the delivered application: the JAR, container image or deployable artefact.

That makes sense, because we want to know what users will run.

**But what about the software that built it?**

Build systems execute code. Maven and Gradle plugins execute code. Code generators, test frameworks, package-manager installation scripts and CI/CD actions execute code. Some have access to source repositories, signing keys, registry credentials and deployment secrets. Yet none of those dependencies necessarily appears in the artefact being shipped.

**So, Mr Developer, did you think CVEs were only about the software that ends up running in production?**

A vulnerability in a build plugin doesn't have to be present in the finished application to matter. If exploitation is possible during the build, an attacker may influence the output, steal credentials or compromise the build environment. Malicious packages and hostile installation scripts can also create supply chain risk without an existing CVE.

For example, `mvn dependency:tree` is useful, but it doesn't list every component Maven will execute. Maven plugins have their own dependency graphs. Those plugins and their dependencies are resolved and executed by Maven, but aren't part of the application's ordinary dependency tree.

This is why I built the [SBOM+ Maven Plugin](https://noregressions.github.io/sbom-plus-maven-plugin/). It is designed to expose Maven build-tooling dependencies alongside project dependencies and imported BOM information. The purpose is to inspect the broader build supply chain, not claim that every dynamically executed script or external CI tool can be discovered from Maven metadata.

You may find components you've never heard of, in versions you've never selected, maintained by projects you've never investigated. The same problem we started with, except this software runs in the environment producing what you deliver.

An SBOM can describe build-time or runtime environments, but only if generated with the appropriate scope. An application-focused inventory and a build-tooling inventory answer different questions.

SCA introduces another limitation. Even if a component is correctly identified, matching depends on sufficiently accurate vulnerability data. An SBOM with missing components and a database with missing vulnerability information can produce a wonderfully clean security report. That doesn't necessarily make the application secure.

I tried this with a deliberately small Maven application. The application-focused CycloneDX SBOM listed five dependency components and, when scanned with Trivy 0.74.0, produced 18 vulnerability matches. I then generated a second inventory including the resolved Maven plugins and their dependencies, using SBOM+, and scanned it with exactly the same tool. This time Trivy reported 77 matches, including two rated critical. The source code hadn't changed, and neither had the scanner. We had changed what we asked it to examine.

Those 77 findings aren't 77 exploitable vulnerabilities in the application. Some came from a Maven Site Plugin that wasn't executed during the ordinary `verify` build. In another case, Commons IO 2.11.0 was included in the executing Compiler Plugin's class realm, but an instrumented compilation showed no Commons IO classes being loaded. A dependency can be available to a tool without its affected functionality being exercised.

The most revealing result was in the security tooling. The CycloneDX Maven Plugin that generated the original SBOM depends on CycloneDX Core Java 9.0.5. Trivy reported CVE-2025-64518 against that library, an XML external-entity vulnerability affecting its validation functionality. We ran the SBOM generator with JVM class-loading instrumentation: it loaded CycloneDX's XML parser and Java's schema-validation classes, and the plugin logged that it generated **and validated** an XML BOM. So the affected *kind* of functionality was part of the tool's normal operation.

That doesn't mean we exploited it. In our test, the tool validated XML it had generated itself, not an arbitrary document supplied by an attacker. Establishing whether untrusted XML could reach the vulnerable validation path is a separate question. But we've found a reported vulnerability in a dependency of the tool used to describe the security of our application's dependencies. It never needed to become part of our application's runtime to deserve scrutiny.

More alerts and more visibility are not necessarily the same thing.

## Assumption: When a vulnerability is reported, we can fix it

Let's suppose the scanner has done its job. It's found a vulnerable dependency, matched it to a CVE and suggested a fixed version.

Now we just upgrade it.

Except we started this article by explaining why upgrades aren't always simple. They can break APIs, change runtime behaviour and introduce new system requirements. The supported release might not be compatible with the application. Sometimes there isn't a fixed version for the branch being used.

Organisations may accept risk temporarily, introduce compensating controls, attempt a backport, obtain extended support or migrate. None is necessarily trivial.

The longer an application accumulates unsupported dependencies, the harder remediation can become. A simple-looking alert may expose years of deferred maintenance.

It's possible to maintain older software securely, but somebody needs to do that work. Commercial extended support, such as [HeroDevs Never-Ending Support](https://www.herodevs.com/), can provide security maintenance for EOL open source components while an organisation plans its migration. Maintaining a private fork is another option if the engineering and test capability exists.

When we first add a dependency, changing our minds may be easy. Six months later, with substantial code depending on its API and behaviour, replacement may involve major engineering work.

The time to investigate a dependency is when we still have the freedom to choose something else.

## Assumption: Choosing a dependency is primarily a development decision

Let's return to our original dependency. We selected it because it did something useful. Its API and documentation looked reasonable. It was widely used.

Now we know more about what that decision means. We know that not every vulnerability gets reported, affected-version data can be incomplete, unsupported software can lose security attention, AI can increase the burden on maintainers, and even identifying everything introduced by one dependency can be difficult.

Would we still make the same choice? Perhaps. But wouldn't it be useful to know more before making it?

For a start, why knowingly select a component with unresolved, relevant security vulnerabilities when alternatives exist? Why choose a library whose maintenance position is unclear? Why use software without looking at the people and practices behind it?

[Cloudsmith Navigator](https://cloudsmith.com/navigator) brings package health, maintenance and quality signals into that investigation. [OpenSSF Scorecard](https://scorecard.dev/) looks at observable project security practices such as code review, branch protection, security policy and binary artefacts committed into source control.

There is evidence that those signals can be useful. In its [2022 State of the Software Supply Chain research](https://www.sonatype.com/resources/state-of-the-software-supply-chain-2022/project-quality-metrics), Sonatype used OpenSSF Scorecard checks to distinguish projects with known vulnerabilities from those without. Its model using individual checks achieved **89% classification accuracy** in the reported study. Code review and the checking-in of binaries emerged as particularly influential signals, followed by practices such as dependency pinning and branch protection.

Think about that. Before auditing the code ourselves, we can learn something from how its maintainers work.

This does **not** establish that projects without review will necessarily acquire CVEs in the future, or that checking in binaries makes software insecure. It demonstrates an association with known vulnerability status in the studied sample, not a causal guarantee or a prospective prediction.

But it gives us a reason to ask better questions. You checked the licence. Did you check the `SECURITY.md`? Whether changes are reviewed before merging? Why executables are checked into source control?

A high Scorecard result doesn't mean software is free of vulnerabilities. A low result doesn't prove that the maintainers don't know what they're doing. These are indicators to investigate, not verdicts.

Lifecycle matters too. [endoflife.date](https://endoflife.date/) provides published software support timelines; [HeroDevs EOL DS](https://www.herodevs.com/) can help assess unsupported dependencies in software estates. That can highlight exposure that CVE-only scanning won't establish. End-of-life isn't the same as a known vulnerability, but it changes who's available to handle the next one.

We should be making informed dependency choices before introducing software, not relying entirely on downstream scanning to tell us when a choice has become problematic.

## Assumption: AI can make those dependency decisions for us

Increasingly, developers aren't necessarily choosing dependencies themselves. AI assistants generate build configurations, select frameworks and install packages from ecosystems the developer may know little about. Agents can execute installation and build commands with little intervention.

This can be enormously productive, but it changes where decisions are made. An experienced Java developer may understand Maven, but if an AI generates a Python or JavaScript application, the developer may be depending on package manager behaviours they don't understand. Version selection, resolution, installation scripts and provenance differ across ecosystems.

An application can compile and pass tests while introducing dependencies that nobody evaluated. The AI solved the immediate development problem; it didn't necessarily make a sound supply chain decision.

And the same class of AI that helps choose dependencies can increasingly discover vulnerabilities in them and propose fixes. We could use AI to select packages, AI to find their vulnerabilities, and AI to patch them, while people responsible for the resulting applications understand less about the underlying supply chain.

The answer isn't to stop using AI. We should use it to perform more of the investigation developers previously lacked time to do: check maintenance evidence, security practices, alternatives, vulnerability status and EOL support. But those checks need to be deliberate policy, not an assumption that the AI will do the right thing simply because it generates working code.

## So what should developers actually do?

We've covered a lot of ground: vulnerabilities that never get reported, incomplete CVE data, maintainers without capacity, AI accelerating discovery, imperfect inventories and applications that can't easily be upgraded.

All of which sounds rather depressing. But much of the response involves changing habits rather than buying expensive security infrastructure.

Remember that dependency where I asked whether you'd checked its licence or looked for a `SECURITY.md`? Let's go back and investigate it properly.

### Before adding a dependency

Check the licence, but also look at maintenance history, supported versions, reporting routes and how the project handles changes. Use Cloudsmith Navigator for package health and quality signals and Scorecard for development practices. Look at the underlying evidence, not only the aggregate scores. The Sonatype result about code review and checked-in binaries is a reason to ask questions, not a prediction about any individual project's future.

### Is the version still supported?

Use endoflife.date and HeroDevs EOL DS to check lifecycle status and maintenance evidence. A component without CVEs can still be unsupported. Ask who will investigate and fix a vulnerability discovered tomorrow.

### What dependencies have we introduced?

Look at the project's dependency graph using build-system tools and [Google deps.dev](https://deps.dev/). Try [OWASP cdxgen](https://github.com/CycloneDX/cdxgen) or [Syft](https://github.com/anchore/syft) to generate SBOMs from different views of the project or build output. Compare what you declared, resolved and packaged. The differences are useful evidence about scope and detection methods.

### What did we use to build it?

Inspect Maven plugins and their own dependencies with the SBOM+ Maven Plugin, alongside your normal project dependency tree. Think about CI/CD actions, installation scripts and code generators too. The important question isn't just what runs in production, but which third-party code can execute with access to your source, signing and deployment environment.

### What vulnerabilities are known?

[Snyk](https://snyk.io/), [Trivy](https://trivy.dev/) and [Docker Scout](https://docs.docker.com/scout/) can help assess vulnerabilities in application dependencies, repositories and container images. [OSV-Scanner](https://google.github.io/osv-scanner/) provides another way to check against open source vulnerability information.

Try scanning the same target with more than one tool. Do they identify the same components? The same affected versions? The same CVEs? If not, investigate why. Differences may reflect scanner scope, identification techniques or database coverage. More scanners don't automatically mean more security, but the differences can expose assumptions worth checking.

### Which findings should we handle first?

Combine known exploitation (KEV), estimated exploitation likelihood (EPSS), severity (CVSS) and the application's actual exposure and context. Determine whether vulnerable functionality is reachable and whether a safe remediation exists. No single score can make that decision for your organisation.

### What about an entire estate?

An individual project is one problem; hundreds or thousands of applications are another. [OWASP Dependency-Track](https://dependencytrack.org/) can use SBOMs to monitor application portfolios, while [OpenSSF GUAC](https://github.com/ossf/guac) links evidence such as component relationships, provenance and vulnerability information.

[Vulnerability Exploitability eXchange (VEX)](https://github.com/openvex/spec) can communicate whether a product is affected by a particular vulnerability and why. That helps avoid repeating assessments, especially when vendor patches or forks mean a version string alone doesn't give the full answer.

But a portfolio view built on incomplete inventories still contains blind spots. Pair vulnerability management with lifecycle and EOL assessment, including the components nobody is publishing new CVEs against.

### The tools are evidence, not answers

Notice something about these tools: they don't solve the same problem. Some tell us about maintainers, others about component identity, others about vulnerability records, others about lifecycles or exploitation. None can guarantee safety.

Together they let us ask better questions about what we choose, what we build with, what we ship and what we'll do when something goes wrong.

We've become accustomed to checking licences because we understand that incorporating somebody else's code carries obligations. Perhaps it's time to treat security and maintenance with the same seriousness.

## Changing the way we think about software supply chain security

At the beginning I described the familiar developer experience: a scanner identifies a vulnerable dependency, somebody asks for an upgrade and the developer must make it work without breaking the application.

That model assumes vulnerabilities are discovered and reported; records contain usable affected-version information; scanners can identify the software we're running; somebody maintains the affected component; a fix exists; and the organisation has the capacity to adopt it.

None of these assumptions was entirely reliable before AI. Increasingly powerful automated vulnerability research is making their limitations much more apparent.

We may soon find vulnerabilities much faster than maintainers and consumers can resolve them. That doesn't mean we should stop looking; it means we need to improve validation, coordination, inventories, prioritisation and the capacity to maintain software safely.

But developers can start before the ecosystem catches up. Investigate the dependencies you accept. Understand their support position, their transitive dependencies and the practices of the people maintaining them. Remember that build tools and CI/CD software are part of the supply chain too. Use SBOMs and scanners, but understand their scope and blind spots. And apply the same standards when an AI selects software on your behalf.

Open source remains an extraordinary success of collaborative software development. Nothing here changes that. But we need to understand the software we rely on, who is responsible for maintaining it, and what happens when that maintenance stops.

Security cannot begin when a CVE appears in a scanner report. By then, many of the decisions determining how hard the problem will be to resolve were made months or years earlier.

Those decisions were often made by developers. Increasingly, they're being made by AI acting on our behalf.

Either way, they're still our responsibility.

---

*Companion exercise:* [Maven dependency and build-tooling investigation](../README.md). The exercise is designed to record observations, not assume any particular CVE outcome or certify a dependency as safe.
