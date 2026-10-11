---
title: CDN Script Compromise and Mirror Substitution
category: Network & Distribution
ref: RFX-NET-01
precedent: "2024"
scenario: Third-party script domain changes hands, and a package mirror shadows real sources
focus:
  - third-party scripts loaded from CDNs and external domains
  - Subresource Integrity and Content Security Policy
  - shadowed package sources and mirror trust
---

## Scenario

An online retailer's checkout page loads a browser-compatibility script from a free public service, exactly as that project's README suggested in 2016:

```html
<script src="https://cdn.compat-service.example/v3/compat.min.js"></script>
```

The original maintainer stops paying attention. The domain and the GitHub organisation are sold. Months later, the new owner starts serving extra JavaScript. It only fires on mobile browsers, at certain hours, and never for visitors who look like site administrators. On the checkout page it reads card fields and posts them to a look-alike analytics domain.

Nobody on the team changed any code, so nothing showed up in review. The script URL is HTTPS and the certificate is valid, because the attacker now owns the domain. A man-in-the-middle was never needed.

The same team's backend has a quieter version of the problem. Its build installs Python packages with:

```bash
pip install --extra-index-url https://pypi.internal.example/simple -r requirements.txt
```

pip treats both indexes as equals and picks the highest version it finds. Anyone who publishes a higher-numbered package to the public index under the name of an internal one wins. That is [dependency confusion](#battlecards-dependency-confusion-attacks-md), and it is mirror substitution by another name.

::: {! precedent}
**Real-world precedent:** In June 2024 Sansec reported that [polyfill.io](https://sansec.io/research/polyfill-supply-chain-attack), bought by a new owner earlier that year, was injecting malicious redirects into more than 100,000 websites that loaded its script. In 2018 Magecart attackers modified a JavaScript file served by British Airways' own website and skimmed card details from around 429,000 customers and staff; the UK ICO [fined BA £20 million](https://www.theregister.com/2020/10/16/british_airways_ico_fine_20m/) in 2020.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers look for third-party scripts loaded by many high-value sites, especially from domains run by a single maintainer or a project that has gone quiet. Buying a domain, or re-registering an expired one, gives them a valid certificate and every site that still links to it. On the backend side, they look for internal package names in public repositories and build logs, and for builds using `--extra-index-url`.

### Insight

Compromising the CDN itself is hard. Owning the domain the CDN URL points to, or the account that publishes to it, is often easy. Your trust in a script URL is really trust in whoever controls that domain today.

### Practical

- Inventory every external script, stylesheet and font your pages load, and who owns each domain.
- Check each domain's registration and ownership history for recent changes.
- Search your build configs for `--extra-index-url`, multiple npm registries, and registry mirrors you no longer manage.

### Tools/Techniques

- Browser DevTools network panel, or a headless crawl, to list third-party origins per page.
- `whois` and certificate transparency search ([crt.sh](https://crt.sh)) to spot ownership and certificate changes.
- `rg -n 'extra-index-url|registry=|<script[^>]+src="https?://'` across your repositories.

### Metrics/Signal

- Number of third-party script origins on payment and login pages.
- Number of builds using more than one package index without explicit source mapping.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For each external script, ask whether you could self-host it, whether it is static enough to pin with Subresource Integrity (SRI), and what your Content Security Policy (CSP) allows. For each package source, ask which index wins when names collide.

### Insight

SRI only works for files whose content never changes. Services like polyfill.io deliberately served different code to different browsers, which ruled out SRI and should have ruled out using them on sensitive pages. The British Airways case adds a second lesson: self-hosting removes the third party but not the need to watch what you serve.

### Practical

- Mark each external script as "self-host", "pin with SRI" or "remove".
- Check whether your CSP restricts `script-src` to named origins, and whether it reports violations anywhere.
- Check your Python tooling. uv's default index strategy stops at the first index that has a package, which blocks this class of confusion. pip's `--extra-index-url` does not.
- For container images, check whether deployments reference tags or digests, and whether anything verifies signatures. Docker Content Trust (Notary v1) is being retired, so plan on Sigstore cosign or Notation.

### Tools/Techniques

- Google's [CSP Evaluator](https://csp-evaluator.withgoogle.com/) for policy weaknesses.
- PCI DSS v4.0 requirements 6.4.3 and 11.6.1, which require an inventory and tamper detection for payment page scripts, as a ready-made checklist.

### Metrics/Signal

- Percentage of external scripts on sensitive pages that are self-hosted or SRI-pinned.
- Builds where a public index can override an internal package name.
:::

::: {! stage fortify}
## Fortify

### Explanation

Bundle or self-host what you can, pin what you cannot, restrict script origins, and give every package name exactly one source.

### Insight

The strongest fix for a third-party script is not loading it at runtime. Install it as a dependency, lock it with a hash, and ship it from your own origin.

### Practical

- Self-host third-party JavaScript through your package manager and bundler, so it is covered by your lockfile.
- Where you must load from a CDN, pin an exact version and add SRI:

    ```html
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
            integrity="sha384-<hash>"
            crossorigin="anonymous"></script>
    ```

    ```bash
    curl -fsSL https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js \
      | openssl dgst -sha384 -binary | openssl base64 -A
    ```

- Send a strict CSP and collect violation reports:

    ```text
    Reporting-Endpoints: csp="https://www.example.com/csp-reports"
    Content-Security-Policy: script-src 'self' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'self'; report-to csp
    ```

- Replace `--extra-index-url` with a single index. Either point at one internal proxy that serves both internal and public packages with internal names taking priority, or use uv with explicit index pinning:

    ```toml
    # pyproject.toml
    [[tool.uv.index]]
    name = "internal"
    url = "https://pypi.internal.example/simple"
    explicit = true

    [tool.uv.sources]
    acme-billing = { index = "internal" }
    ```

- Pin container images by digest and verify signatures with cosign or Notation before deploy.

### Tools/Techniques

- npm, pnpm or uv lockfiles with integrity hashes.
- SRI, CSP with `report-to`.
- [cosign](https://docs.sigstore.dev/) or [Notation](https://notaryproject.dev/) for images.

### Metrics/Signal

- Runtime-loaded third-party scripts trending down.
- Internal package names that can resolve from more than one index (target zero).
:::

::: {! stage limit}
## Limit

### Explanation

Keep a hostile script away from the data it wants, and a substituted package away from credentials.

### Insight

A skimmer can only read what is on the page it runs in. Payment fields isolated in a provider's iframe, on a page with almost no third-party code, give it very little.

### Practical

- Host card entry in your payment provider's hosted fields or iframe, not in your own DOM.
- Keep checkout and login pages free of marketing, analytics and A/B testing scripts where you can.
- Use CSP `connect-src` to limit where page scripts can send data.
- Install backend dependencies in a CI step with no publish or cloud credentials.

### Tools/Techniques

- Payment provider hosted fields.
- CSP `connect-src` and `form-action` directives.

### Metrics/Signal

- Third-party scripts present on payment pages.
- CI install steps with secrets in scope.
:::

::: {! stage expose}
## Expose

### Explanation

Detect script content that changes, and packages that arrive from the wrong source.

### Insight

The polyfill.io payload hid from admins and only fired for some users at some times. Monitoring has to fetch scripts the way real users do, from different devices and at different times.

### Practical

- Fetch every external script on a schedule with several mobile and desktop user agents. Alert when the hash changes.
- Watch CSP violation reports for new origins. A skimmer calling a new domain shows up here first.
- Alert on domain ownership or name server changes for every script origin you depend on.
- In CI, fail the build if an internal package name was downloaded from the public index. pip's `--report` output and uv's lockfile both record each package's source URL.

### Tools/Techniques

- A small scheduled job using `curl -A "<user agent>"` and `sha256sum` against a recorded baseline.
- CSP reporting to your logging stack.
- `pip install --dry-run --report report.json` to inspect resolved package URLs.

### Metrics/Signal

- Script hash changes per month, each one explained.
- CSP violations from previously unseen origins.
:::

::: {! stage exercise}
## Exercise

### Explanation

Rehearse a swapped script and a shadowed package in a local lab.

### Insight

Both drills take minutes and give the team a concrete picture of what SRI, CSP and single-index installs actually block.

### Practical

1. Serve a test page and a "CDN" script from two local nginx containers. Add SRI and CSP to the page.
2. Change one character in the CDN script. Confirm the browser refuses it and your CSP report endpoint receives a violation.
3. Remove SRI, change the script to `fetch()` a [Canarytokens](https://canarytokens.org) URL, and confirm `connect-src` blocks it and reports it.
4. Run two local package indexes (devpi or pypiserver). Put `acme-billing 1.0.0` on the "internal" one and a harmless `acme-billing 99.0.0` on the "public" one. Show that `pip --extra-index-url` picks 99.0.0, and that your hardened configuration does not.

### Tools/Techniques

- nginx containers, devpi or pypiserver, Canarytokens.

### Metrics/Signal

- Whether each control blocked and reported the change.
- Time to detect the swapped script with your scheduled hash check.
:::

## Further Reading

- [Sansec: Polyfill supply chain attack hits 100K+ sites (June 2024)](https://sansec.io/research/polyfill-supply-chain-attack)
- [The Register: ICO fines British Airways £20m over 2018 breach](https://www.theregister.com/2020/10/16/british_airways_ico_fine_20m/)
- [MDN: Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)
- [Docker: Retiring Docker Content Trust](https://www.docker.com/blog/retiring-docker-content-trust/)
- [uv: package indexes](https://docs.astral.sh/uv/concepts/indexes/)
