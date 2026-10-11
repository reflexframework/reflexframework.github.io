# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Reflex Framework** - a developer-first security framework for the AI age. The project is built with **Paperband** 0.2.0 (`dev.noregressions.paperband`, a Maven-based markdown publishing tool, formerly TestGun; source at `~/claude_projects/TestGun`, GitHub `noregressions/paperband`) and provides:

- **6-stage security framework** (REFLEX: Reconnaissance, Evaluate, Fortify, Limit, Expose, Exercise)
- **67 battlecards** covering real-world attack scenarios like supply chain attacks, AI-powered threats, and CI/CD compromises
- **Two outputs from the same pages**: a web site with a page per file and a top navigation bar (`_site/`, GitHub Pages; `battlecards/dns.md` → `_site/battlecards/dns.html`) and a PDF (`_site/reflex-framework.pdf`)

## Build Commands

```bash
make website     # build _site/index.html and _site/reflex-framework.pdf (mvn package)
make preview     # build, then serve _site on http://localhost:8000/
make clean       # remove _site and target
make themes      # list the web themes
make theme THEME=blueprint   # switch the web theme (edits the stylesheets line in manifest.yml)
make paperband   # install Paperband into ~/.m2 from PAPERBAND_DIR (default ~/claude_projects/TestGun); needed until 0.2.0 is on Maven Central
make deps        # check Java and Maven
```

The build runs with `failOnWarnings`, so Paperband warnings (missing front matter, content that doesn't fit a PDF page, etc.) fail it.

## Architecture Overview

### Build System
- **Build tool**: Make wrapper around Maven running `paperband-maven-plugin` (see `pom.xml`); needs Java 21+
- **Manifest**: `manifest.yml` lists the sources, the page order (`sequence`) and the outputs (web with `nav: top` and `contents: front/contents.md`; the pdf has its own sequence without the contents)
- **Navigation**: `front/contents.md` is the navigation bar, not a page: links before the first heading are entries of their own, each `##` heading is a dropdown of the links under it. Every page also gets Paperband's header and previous/next pager, in sequence order
- **Layouts**: `layouts/battlecard.yml` (a meta strip of `ref`, `category` and `precedent`, the title, scenario and focus, a six-stage rail on the web only, then the body); other pages use Paperband's built-in default layout
- **Styling**: `styles/base.css` (shared structure and the PDF's print styles, `body.paged`) plus one web theme from `styles/themes/`: `field-manual` (default), `blueprint`, `console` or `classic` (the original dark look). Each theme is a self-contained file nested under `body.web`, restyling Paperband's `.site-header`, `nav.site-topnav`, `.site-pager`, so it never touches the PDF. Switch with `make theme THEME=<name>`; add a theme by dropping a new file into `styles/themes/`. The build joins the stylesheets into `_site/site.css`
- **Fonts**: self-hosted in `assets/fonts/` (OFL, from Google Fonts) and copied to `_site/fonts/` by `make website`; themes declare them with `@font-face`. Don't use `@import` in a theme: Paperband puts its own CSS first in `site.css`, so an `@import` would be ignored
- **PDF**: printed in Chromium via `dev.noregressions.paperband:chromium`

### Content Organization
- **Framework stages**: `/stages/` - 6 core REFLEX methodology files (01-06)
- **Battlecards**: `/battlecards/` - 67 attack scenario files
- **CVE Analysis**: `/cve-analysis/` - CVE analyses through REFLEX framework
- **Main pages**: `index.md` (homepage), `battlecards.md` (battlecard index), `cve-analysis.md` (CVE analysis index), `author.md` (about page)
- **Templates**: `cve-analysis-template.md` - Reusable prompt/template for analyzing CVEs through REFLEX (not part of the build)
- **Static Assets**: `/assets/images/` with `DESIGN_SYSTEM.md` and `QUICK_START_ICONS.md` for visual guidelines

### Content Categories
Battlecards are organized by:
- Supply Chain & Dependencies
- Language ecosystems (Python, Java, JavaScript, Go, Rust)
- AI/ML Security
- CI/CD & Infrastructure
- Social Engineering & IDE Security

### Deployment
- **Target**: GitHub Pages
- **Trigger**: Push to main/master branch
- **Workflow**: `.github/workflows/publish.yml` — checks out Paperband from its public repo, pinned to the 0.2.0 commit (no token needed), installs it, runs `make website`, deploys `_site`

## Development Workflow

1. **Content editing**: Modify `.md` files in the appropriate directories
2. **Local preview**: Run `make preview`
3. **Build verification**: Run `make website` to ensure a clean (warning-free) build
4. **Deployment**: Push to main/master triggers automatic GitHub Pages deployment

## Content Standards

- **Markdown syntax is Paperband's, not Quarto's/Pandoc's**:
  - Divs use `{! ...}` markers: `::: {! stage fortify}` ... `:::` (not Pandoc's `{.class}`)
  - Pebble templating is active: `{{ }}`, `{% %}`, `{# #}` and `[[ ]]`, `[% %]`, `[# #]` outside fenced code blocks are template tags, **including inside inline code**. Wrap inline GitHub Actions expressions: `{% verbatim %}`${{ github.event.* }}`{% endverbatim %}`
  - Front matter must start on the file's first line (a leading blank line hides it)
- **Links**: cross-references are written as anchors made from the target's path (the site build rewrites them to the target's `.html`) — lowercase, each run of non-alphanumerics becomes `-`: `battlecards/dns.md` → `#battlecards-dns-and-mitm-attacks-md`, `stages/01-reconnaissance.md` → `#stages-01-reconnaissance-md`
- **Framework stages**: Follow REFLEX methodology structure. No emoji in headings or the nav: each theme adds its own stage markers (numbers, dots, icons) with CSS
- **Battlecards**: front matter `title`, `category`, `ref`, `precedent`, `scenario`, `focus` (2-4 items, never empty) — the battlecard layout renders these, so no H1 or metadata block in the body. `ref` is a permanent ID, `RFX-<area>-<nn>` (areas: PKG, CI, SRC, DEV, AI, SEC, INF, NET, SOC, SCI); give a new card the next free number in its area and never renumber. `precedent` is the year (or range, `"2018–2026"`) of the lead real-world incident. Then `## Scenario`, and the `**Real-world precedent:**` line citing the real incident with a source, wrapped in a `::: {! precedent}` ... `:::` block, six stage blocks `::: {! stage recon|evaluate|fortify|limit|expose|exercise}` each with `## Reconnaissance|Evaluate|Fortify|Limit|Expose|Exercise` and `### Explanation / Insight / Practical / Tools/Techniques / Metrics/Signal`, then optional `## Further Reading`. The CSS adds stage colours and icons; no emoji in prose
  - `category` is one of: Package Ecosystems, CI/CD & Build, Source Control & Review, Developer Environment, AI/ML Security, Secrets & Credentials, Infrastructure & Cloud, Network & Distribution, Social Engineering, Supply Chain Integrity
  - `battlecards.md` is grouped by category; add new cards to it
  - Exercises must be safe: canary tokens, local registries (Verdaccio), sandboxes — never publish to public registries or use real malware/secrets
- **Voice**: Steve Poole's — British English, short sentences, active voice, no em dashes joining clauses, no "not X, but Y" constructions
- **CVE Analysis**: Use `cve-analysis-template.md`
  - File naming: `cve-analysis/cve-yyyy-nnnn.md`; also add it to `cve-analysis.md` and the CVE Analysis group in `front/contents.md`
  - Title format: `CVE-YYYY-NNNN: [Vulnerability Name] - REFLEX Analysis`
  - Developer-focused language, actionable insights for each REFLEX stage
- **Image Assets**: Organize in `/assets/images/` with descriptive file names; SVG for diagrams, PNG for complex images
- **Wide content**: code blocks wrap in the PDF; very wide tables can still fail the PDF fit check

## Configuration Files

- **Manifest**: `manifest.yml` - sources, page order, outputs
- **Maven**: `pom.xml` - Paperband plugin and version
- **Build automation**: `Makefile`
- **Deployment**: `.github/workflows/publish.yml`
