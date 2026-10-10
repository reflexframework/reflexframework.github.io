---
title: End-of-Life Dependencies
category: Package Ecosystems
scenario: Unsupported frameworks with no patch path
focus:
  - EOL release lines that no longer receive fixes
  - clean scans hiding unassessed versions
  - AI assistants suggesting outdated versions
---

## Scenario

A team runs a customer portal that has worked quietly for years. The front end is AngularJS 1.8. The back end uses Spring Framework 5.3. The build image still ships Node 18. The scanner report is short, and nobody has touched the dependency versions in a long time.

Every one of those release lines is end-of-life. AngularJS support ended on 31 December 2021, Spring Framework 5.3 open source support on 31 August 2024, and Node 18 on 30 April 2025 ([endoflife.date](https://endoflife.date/)).

An attacker scanning the internet reads `angular.version.full` from the portal's public JavaScript and sees 1.8.3. They check the public advisories. As of October 2026, OSV lists ten advisories against `angular` 1.8.3, all published after support ended, and none with a fixed version. One of them, [CVE-2024-21490](https://github.com/advisories/GHSA-4w4v-5hc9-xrr2), is a ReDoS in `ng-srcset` handling.

The back end has a similar story. [CVE-2024-38816](https://spring.io/security/cve-2024-38816), a path traversal in applications that serve static resources through functional routes, was fixed in open source Spring Framework 6.1.13. The 5.3.x fix (5.3.40) was available only through commercial support. On the open source 5.3 line, 5.3.39 is the last release.

Meanwhile a developer asks an AI assistant to add a logging library to an old module. The suggestion is a version that was popular years ago, and it goes in without anyone checking whether it is still supported.

**Real-world precedent:** Sonatype's [2026 State of the Software Supply Chain](https://www.sonatype.com/state-of-the-software-supply-chain/Introduction) report found that 5 to 15% of components in enterprise dependency graphs are EOL, and that more than 81,000 package versions with known CVEs are both EOL and unpatchable. It also found that 14% of Log4j artifacts affected by Log4Shell are now EOL, accounting for more than 619 million downloads in 2025. Log4j 1.x itself reached end of life in 2015, and OSV now lists six later CVEs against 1.2.17 with no fixed 1.x release.

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers like EOL software because the exposure is permanent. A flaw in a supported line closes when users upgrade. A flaw in an EOL line stays open for everyone who cannot or will not move.

Fingerprinting is cheap. Framework versions leak through JavaScript bundles, `X-Powered-By` and `Server` headers, default error pages and public repositories. Once an attacker knows the line, the public advisory databases tell them which flaws have no fix. When a fix lands only in a newer line, the patch diff can point straight at the bug in the old code.

### Insight

Sonatype's report notes that advisory coverage often degrades for unsupported versions and that abandoned code is reviewed less. So "no CVE" can simply mean nobody is looking. In that case the scanner has nothing to tell you.

The same report warns that AI models recommend EOL components because their training data reflects historical popularity instead of current support status.

### Practical

- Look at your own public surfaces the way an attacker would: response headers, error pages, bundled JavaScript.
- List the runtimes and frameworks behind each service, including build images and base images.
- Ask the AI tools your team uses which version of a library they would suggest, and compare with the current supported line.

### Tools/Techniques

- `curl -sI https://your-app.example` to see the headers you expose.
- Browser developer tools to inspect bundled framework versions.
- [endoflife.date](https://endoflife.date/) for published support dates across hundreds of products.

### Metrics/Signal

- Number of public-facing services that reveal an EOL framework version.
- Services running on EOL runtimes (Node, Python, Java) in production or CI.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Inventory support status alongside vulnerabilities. A CVE scan alone cannot separate an unsupported component with no known flaws from one that nobody is assessing. You need lifecycle data as a second input.

### Insight

EOL is not one date. Some projects publish clear support windows. Others simply stop releasing. Treat "no release in years and no stated support policy" as a finding to investigate, even without an official EOL date.

### Practical

- Check runtimes and frameworks against endoflife.date's API:

```bash
while read -r product cycle; do
  curl -s "https://endoflife.date/api/v1/products/$product/releases/$cycle" |
    jq -r --arg p "$product" '.result | "\($p) \(.name): EOL=\(.isEol) since \(.eolFrom)"'
done <<'LIST'
spring-framework 5.3
nodejs 18
python 3.8
angularjs 1.8
LIST
```

- For libraries without a published lifecycle, check the latest release date and the advisories against your version with deps.dev:

```bash
curl -s https://api.deps.dev/v3/systems/npm/packages/angular/versions/1.8.3 |
  jq '{publishedAt, advisoryKeys}'
```

- Read the project's `SECURITY.md` for a supported versions table.
- For each advisory against an EOL component, record whether a fix exists in your line at all.

### Tools/Techniques

- [endoflife.date API](https://endoflife.date/docs/api/v1/).
- [deps.dev](https://deps.dev/) and its [API](https://docs.deps.dev/api/v3/) for release history and advisories.
- [OSV](https://osv.dev/) to see whether an advisory lists a fixed version for your line.
- [OpenSSF Scorecard](https://scorecard.dev/) for maintenance signals on libraries without a lifecycle policy.

### Metrics/Signal

- Percentage of components in each application that are EOL. Track it as a standing metric, like vulnerability counts.
- Known advisories against EOL components with no fix in your line.
:::

::: {! stage fortify}
## Fortify

### Explanation

Stop EOL versions coming in, then work through the ones you have. Every EOL component needs an exit path and an owner. The main routes are:

- **Upgrade** to a supported line, accepting the migration work.
- **Replace** the component with a maintained alternative.
- **Commercial extended support**, where a vendor backports security fixes to the EOL line while you plan a migration.
- **Fork and maintain** it yourself, which is only realistic with a good test suite and people to look after it. Community forks such as [reload4j](https://reload4j.qos.ch/) for Log4j 1.x show what that involves.

### Insight

Your tests are the specification for every one of these routes. An upgrade, a replacement or a backported patch is only safe if you can show the application still behaves as it did. For old software, the closest thing to a specification is often what it currently does.

### Practical

- Add an EOL check to CI that fails new pull requests introducing an EOL runtime or framework line.
- Before migrating, write characterisation tests that pin the current behaviour of the code that uses the EOL component.
- Set support-status rules for AI assistants in your repository instructions, and review AI-generated manifests for version choices.
- Plan upgrades before the EOL date. endoflife.date publishes dates well in advance for most runtimes.

### Tools/Techniques

- endoflife.date API calls in CI, or SBOM tooling that reports lifecycle status.
- Renovate or Dependabot for routine upgrades, so lines do not drift into EOL unnoticed.
- Characterisation (approval) tests around the EOL component's call sites.

### Metrics/Signal

- New EOL components introduced per month, trending to zero.
- Every EOL component has a named owner, a chosen exit path and a target date.
:::

::: {! stage limit}
## Limit

### Explanation

While an EOL component remains, reduce what an attacker can do with its flaws. Narrow its exposure to untrusted input and keep it away from sensitive data and credentials.

### Insight

Many EOL flaws need a specific feature to be reachable. CVE-2024-38816 needs static resources served through functional routes. CVE-2024-21490 needs attacker-influenced input in `ng-srcset`. Knowing the condition tells you what to switch off.

### Practical

- For each unfixed advisory, read the conditions and remove or guard the affected feature.
- Put EOL services behind authentication and an allow-list where the use case allows it.
- Add request-level filtering for known exploit patterns as a temporary measure, with an expiry date.
- Run EOL services with minimal privileges and separate them from services holding sensitive data.

### Tools/Techniques

- The advisory's own workaround section, where one exists.
- Reverse proxy or WAF rules targeted at the specific advisory.
- Network segmentation for services that cannot yet move.

### Metrics/Signal

- Unfixed advisories with a documented compensating control.
- EOL services reachable without authentication.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for two events: a support date approaching, and a new advisory against an EOL line you run. The first gives you time to plan. The second means a flaw with no upstream fix is now public.

### Insight

New advisories keep arriving for EOL lines. OSV's ten advisories against AngularJS 1.8.3 were all published after support ended, the latest in 2026.

### Practical

- Alert six months before any runtime or framework you use reaches EOL.
- Subscribe to new advisories for the EOL components in your inventory, and flag any with no fixed version.
- Check the [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) daily for entries affecting your EOL components.
- Log and alert on requests matching the exploit patterns for unfixed advisories.

### Tools/Techniques

- Scheduled CI jobs that query the endoflife.date API.
- [OWASP Dependency-Track](https://dependencytrack.org/) or similar, fed with your SBOMs, for new advisory alerts.
- The KEV JSON feed matched against CVE IDs from your scanner output.

### Metrics/Signal

- Time from a new advisory against an EOL component to a decision on it.
- Components that passed their EOL date without an exit plan.
:::

::: {! stage exercise}
## Exercise

### Explanation

Run an EOL drill on one real application. Assume a critical flaw with no upstream fix is announced today in its most important EOL component, then measure how ready you are.

### Insight

The drill usually shows where the real effort lies: proving the application still works after the change.

### Practical

1. Run the Evaluate checks and pick the most important EOL component.
2. Write down the exit path you would take and who would do the work.
3. On a branch, attempt the first step: upgrade to the supported line, or swap in the replacement.
4. Run the test suite and note what breaks, and what changed without any test noticing.
5. Record the time taken and the gaps in test coverage around that component.

### Tools/Techniques

- A branch and a CI run, with no production changes.
- Code coverage reports focused on the component's call sites.

### Metrics/Signal

- Time to a passing build on a supported line.
- Behaviour changes found by review that the tests missed.
:::

## Further Reading

- [endoflife.date](https://endoflife.date/) and its [API documentation](https://endoflife.date/docs/api/v1/)
- [Sonatype: 2026 State of the Software Supply Chain](https://www.sonatype.com/state-of-the-software-supply-chain/Introduction)
- [Spring: CVE-2024-38816](https://spring.io/security/cve-2024-38816)
- [GitHub Advisory: AngularJS ReDoS (CVE-2024-21490)](https://github.com/advisories/GHSA-4w4v-5hc9-xrr2)
- Related cards: [Abandoned Package Hijack](#battlecards-abandoned-package-hijack-md), [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md)
