# REFLEX Framework

A developer-first security framework for the AI age, published at [reflexframework.com](https://reflexframework.com).

The site is built with [Paperband](https://github.com/noregressions/paperband) from plain markdown: a web site
with a page per file (`battlecards/dns.md` → `_site/battlecards/dns.html`) and a navigation bar, plus a
PDF of the same pages (`_site/reflex-framework.pdf`).

## Layout

```
manifest.yml            # what Paperband builds: sources, page order, outputs
pom.xml                 # runs paperband-maven-plugin 0.2.0 in `mvn package`
index.md                # home
stages/                 # the six REFLEX stages
battlecards.md          # battlecard index
battlecards/            # one file per attack scenario
cve-analysis.md         # CVE analysis index
cve-analysis/           # one file per CVE
author.md               # about
front/contents.md       # the navigation bar: plain links, then a dropdown per heading
layouts/                # page layouts: battlecard
styles/base.css         # shared structure and the PDF's print styles
styles/themes/          # web themes: field-manual, blueprint, console, classic
assets/fonts/           # self-hosted web fonts (OFL)
```

## Building

You need Java 21+, Maven, and Paperband 0.2.0 in your local Maven repository (it isn't on Maven Central yet).

```bash
make paperband          # once: install Paperband from ~/claude_projects/TestGun (or PAPERBAND_DIR=...)
make website            # build _site/index.html and _site/reflex-framework.pdf
make preview            # build, then serve on http://localhost:8000/
make clean
```

## Themes

The web site has four looks. The PDF always uses the print styles in `styles/base.css`.

```bash
make themes                     # list them
make theme THEME=blueprint      # switch (rewrites the stylesheets line in manifest.yml)
make website                    # rebuild
```

- `field-manual`: paper and ink, battlecards as case files, stages as numbered manual sections (the default)
- `blueprint`: a supply chain schematic, with the stages as nodes on a pipeline
- `console`: a dark threat-intel record with status chips and stage tabs
- `classic`: the original dark look with emoji stage icons

Each theme is one self-contained CSS file nested under `body.web`. To make another, copy one and edit it.

## Writing content

- Links between pages are written as anchors made from the target's path —
  `battlecards/dns.md` is `#battlecards-dns-and-mitm-attacks-md` — and the site build points them at the right file.
- Battlecard stages are Paperband divs: `::: {! stage recon}` ... `:::` (recon, evaluate, fortify,
  limit, expose, exercise). CVE pages use `::: {! callout callout-note}`.
- Battlecards take their title, category, scenario and focus from front matter; the other
  pages start with a `# Heading`. See CLAUDE.md for the full card format and category list.
- Inline code containing `${{ }}` must be wrapped in `{% verbatim %}` ... `{% endverbatim %}`.
- New files in `stages/`, `battlecards/` or `cve-analysis/` are picked up automatically; add
  them to the matching index page too, and new CVEs to `front/contents.md`.

## Deployment

Pushing to `master` runs `.github/workflows/publish.yml`, which checks out Paperband from its
public repo (pinned to the 0.2.0 commit), installs it, builds the site and deploys `_site` to GitHub Pages.
