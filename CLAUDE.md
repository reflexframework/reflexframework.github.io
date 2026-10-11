# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Reflex Framework** - a developer-first security framework for the AI age. The project is built with **Paperband** (a Maven-based markdown publishing tool, `dev.noregressions.paperband` on Maven Central; GitHub `noregressions/paperband`) and provides:

- **6-stage security framework** (REFLEX: Reconnaissance, Evaluate, Fortify, Limit, Expose, Exercise)
- **67 battlecards** covering real-world attack scenarios like supply chain attacks, AI-powered threats, and CI/CD compromises
- **Two outputs from the same pages**: a web site with a page per file and a top navigation bar (`_site/`, GitHub Pages; `battlecards/dns.md` → `_site/battlecards/dns.html`) and a PDF (`_site/reflex-framework.pdf`)

## Build Commands

```bash
make website     # build _site/index.html and _site/reflex-framework.pdf (mvn package)
make preview     # build, then serve _site on http://localhost:8000/
make clean       # remove _site and target
make deps        # check Java and Maven
```

The build runs with `failOnWarnings`, so Paperband warnings (missing front matter, content that doesn't fit a PDF page, etc.) fail it.

## Architecture Overview

### Build System
- **Build tool**: Make wrapper around Maven running `paperband-maven-plugin` (see `pom.xml`); needs Java 21+
- **Manifest**: `manifest.yml` lists the sources, the page order (`sequence`) and the outputs (web with `nav: top` and `contents: front/contents.md`; the pdf has its own sequence without the contents)
- **Navigation**: `front/contents.md` is the navigation bar, not a page: links before the first heading are entries of their own, each `##` heading is a dropdown of the links under it. Every page also gets Paperband's header and previous/next pager, in sequence order
- **Layouts**: `layouts/battlecard.yml` (title and category from front matter, then the body); other pages use Paperband's built-in default layout
- **Styling**: `styles/reflex.css` — dark theme on the web (`body.web`, restyling Paperband's `.site-header`, `nav.site-topnav`, `.site-pager`), light print theme in the PDF (`body.paged`); the web build writes the styles to `_site/site.css`
- **PDF**: printed in Chromium via Paperband's `chromium` module (Playwright)

### Content Organization
- **Framework stages**: `/stages/` - 6 core REFLEX methodology files (01-06)
- **Battlecards**: `/battlecards/` - 67 attack scenario files
- **CVE Analysis**: `/cve-analysis/` - CVE analyses through REFLEX framework
- **Main pages**: `index.md` (homepage), `battlecards.md` (battlecard index), `cve-analysis.md` (CVE analysis index), `author.md` (about page)
- **Templates**: `cve-analysis-template.md` - Reusable prompt/template for analyzing CVEs through REFLEX (not part of the build)
- **Static Assets**: `/assets/images/`

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
- **Workflow**: `.github/workflows/publish.yml` — sets up Java 21, installs Playwright's Chromium system libraries, runs `make website` (the paperband plugin comes from Maven Central), uploads `_site` and deploys it with `actions/deploy-pages`

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
- **Framework stages**: Follow REFLEX methodology structure (🔍📊🛡️⚡👁️💪)
- **Battlecards**: front matter `title`, `category`, `scenario`, `focus` (2-4 items, never empty) — the battlecard layout renders these, so no H1 or metadata block in the body. Then `## Scenario`, a `**Real-world precedent:**` line citing the real incident with a source, six stage blocks `::: {! stage recon|evaluate|fortify|limit|expose|exercise}` each with `## Reconnaissance|Evaluate|Fortify|Limit|Expose|Exercise` and `### Explanation / Insight / Practical / Tools/Techniques / Metrics/Signal`, then optional `## Further Reading`. The CSS adds stage colours and icons; no emoji in prose
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
