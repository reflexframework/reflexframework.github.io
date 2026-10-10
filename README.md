# REFLEX Framework

A developer-first security framework for the AI age, published at [reflexframework.com](https://reflexframework.com).

The site is built with [TestGun](https://github.com/spoole167/TestGun) from plain markdown: a web site
with a page per file (`battlecards/dns.md` → `_site/battlecards/dns.html`) and a navigation bar, plus a
PDF of the same pages (`_site/reflex-framework.pdf`).

## Layout

```
manifest.yml            # what TestGun builds: sources, page order, outputs
pom.xml                 # runs testgun-maven-plugin in `mvn package`
index.md                # home
stages/                 # the six REFLEX stages
battlecards.md          # battlecard index
battlecards/            # one file per attack scenario
cve-analysis.md         # CVE analysis index
cve-analysis/           # one file per CVE
author.md               # about
front/contents.md       # the navigation bar: plain links, then a dropdown per heading
layouts/                # page layouts: battlecard
styles/reflex.css       # the look, for web and PDF
```

## Building

You need Java 21+, Maven, and TestGun in your local Maven repository.

```bash
make testgun            # once: install TestGun from ~/claude_projects/TestGun (or TESTGUN_DIR=...)
make website            # build _site/index.html and _site/reflex-framework.pdf
make preview            # build, then serve on http://localhost:8000/
make clean
```

## Writing content

- Links between pages are written as anchors made from the target's path —
  `battlecards/dns.md` is `#battlecards-dns-and-mitm-attacks-md` — and the site build points them at the right file.
- Battlecard stages are TestGun divs: `::: {! stage recon}` ... `:::` (recon, evaluate, fortify,
  limit, expose, exercise). CVE pages use `::: {! callout callout-note}`.
- Battlecards take their title, category, scenario and focus from front matter; the other
  pages start with a `# Heading`. See CLAUDE.md for the full card format and category list.
- Inline code containing `${{ }}` must be wrapped in `{% verbatim %}` ... `{% endverbatim %}`.
- New files in `stages/`, `battlecards/` or `cve-analysis/` are picked up automatically; add
  them to the matching index page too, and new CVEs to `front/contents.md`.

## Deployment

Pushing to `master` runs `.github/workflows/publish.yml`, which checks out TestGun (using the
`TESTGUN_TOKEN` secret), installs it, builds the site and deploys `_site` to GitHub Pages.
