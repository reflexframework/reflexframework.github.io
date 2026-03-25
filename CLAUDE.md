# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Reflex Framework** - a developer-first security framework for the AI age. The project is a Quarto-based website and book that provides:

- **6-stage security framework** (REFLEX: Reconnaissance, Evaluate, Fortify, Limit, Expose, Exercise)
- **64+ battlecards** covering real-world attack scenarios like supply chain attacks, AI-powered threats, and CI/CD compromises
- **Dual output formats**: Website (GitHub Pages) and downloadable book

## Build Commands

### Essential Commands
```bash
# Build and preview website locally
make preview

# Build website for deployment
make website

# Build book version
make book

# Build both outputs
make all

# Clean output directories
make clean

# Check Quarto dependencies
make deps
```

### Direct Quarto Commands
```bash
# Preview website (alternative to make preview)
quarto preview --profile website

# Render website manually
quarto render --profile website

# Preview book version
quarto preview --profile book
```

## Architecture Overview

### Build System
- **Build tool**: Make wrapper around Quarto
- **Configuration switching**: Makefile swaps between `_quarto.yml` (book) and `_quarto-website.yml` (website) during builds
- **Output directories**: `_site/` for website, `_book/` for book

### Content Organization
- **Framework stages**: `/stages/` - 6 core REFLEX methodology files (01-06)
- **Battlecards**: `/battlecards/` - 64+ attack scenario files organized by category
- **CVE Analysis**: `/cve-analysis/` - CVE analyses through REFLEX framework
- **Main pages**: `index.qmd` (homepage), `battlecards.qmd` (battlecard index), `cve-analysis.qmd` (CVE analysis index), `author.qmd` (about page)
- **Templates**: `cve-analysis-template.md` - Reusable template for analyzing CVEs through REFLEX
- **Styling**: `styles.css` for cybersecurity-themed CSS
- **Static Assets**: `/assets/` - All static assets including images, CSS, and JavaScript
  - `assets/images/` - Organized visual assets with comprehensive design system
    - `logos/` - Branding assets
    - `diagrams/` - Technical illustrations
    - `icons/` - Organized icon library (stages, severity, tech, vulnerabilities)
    - `stages/` - REFLEX stage-specific visuals
    - `battlecards/` - Battlecard illustrations
    - `screenshots/` - UI examples and tool screenshots
  - `assets/css/` - Additional stylesheets
  - `assets/js/` - JavaScript files
  - **Design System**: `DESIGN_SYSTEM.md` and `QUICK_START_ICONS.md` for visual guidelines

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
- **Workflow**: `.github/workflows/quarto-publish.yml`
- **Dependencies**: Python 3.11, Quarto, matplotlib, numpy, jupyter

## Development Workflow

1. **Content editing**: Modify `.qmd` files in appropriate directories
2. **Local preview**: Run `make preview` to test changes
3. **Build verification**: Run `make website` to ensure clean build
4. **Deployment**: Push to main/master triggers automatic GitHub Pages deployment

## Content Standards

- **Framework stages**: Follow REFLEX methodology structure (🔍📊🛡️⚡👁️💪)
- **Battlecards**: Include real-world attack scenarios with practical defense strategies
- **CVE Analysis**: Use `cve-analysis-template.md` to structure CVE analyses through REFLEX framework
  - File naming: `cve-analysis/cve-yyyy-nnnn.qmd`
  - Title format: `CVE-YYYY-NNNN: [Vulnerability Name] - REFLEX Analysis`
  - Developer-focused language, actionable insights for each REFLEX stage
- **Image Assets**: Organize in `/assets/images/` directory with appropriate subdirectories
  - Use descriptive file names: `log4shell-attack-flow.png`
  - Stage-specific images: `assets/images/stages/01-reconnaissance-visual.png`
  - Battlecard visuals: `assets/images/battlecards/dependency-confusion-diagram.png`
  - Optimize for web delivery (SVG preferred for diagrams, PNG for complex images)
- **Code execution**: Disabled (`execute: enabled: false`) - content is documentation-focused
- **Cross-references**: Use relative links between stages, battlecards, and CVE analyses

## Configuration Files

- **Website config**: `_quarto-website.yml` - navbar, site metadata, theming
- **Book config**: `_quarto.yml` - book structure, chapters, PDF output
- **Build automation**: `Makefile` - handles config switching and build orchestration
- **Deployment**: `.github/workflows/quarto-publish.yml` - automated publishing to GitHub Pages