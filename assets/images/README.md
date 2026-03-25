# Image Assets Organization

This directory contains all visual assets for the REFLEX Framework website.

## Directory Structure

### `/assets/images/`
Main directory for all image assets:

- **`logos/`** - REFLEX branding, HeroDevs logos, partner logos
- **`diagrams/`** - Technical diagrams, architecture visuals, flow charts
- **`screenshots/`** - Tool screenshots, UI examples, demonstration images
- **`icons/`** - Stage icons (🔍📊🛡️⚡👁️💪), UI icons, badges
- **`stages/`** - Visual assets specific to each REFLEX stage (01-06)
- **`battlecards/`** - Images and diagrams specific to individual battlecard analyses

### `/assets/`
Complete static assets structure:

- **`assets/images/`** - All image assets (this directory)
- **`assets/css/`** - Additional stylesheets (beyond main styles.css)
- **`assets/js/`** - JavaScript files for enhanced functionality

## Usage in Quarto Files

### Basic Image Syntax
```markdown
![Alt text](assets/images/diagrams/reflex-overview.png)
```

### With Figure Captions
```markdown
![REFLEX Framework Overview](assets/images/diagrams/reflex-framework.png){#fig-reflex-overview}

This shows the six-stage REFLEX methodology for developer security.
```

### Responsive Images
```markdown
![Stage Icons](assets/images/icons/reflex-stages.png){.img-fluid}
```

### Stage-Specific Images
```markdown
![Reconnaissance Stage](assets/images/stages/01-reconnaissance-visual.png)
![Fortify Implementation](assets/images/stages/03-fortify-diagram.png)
```

## Image Guidelines

### File Naming Conventions
- Use kebab-case: `reflex-framework-overview.png`
- Include stage numbers: `01-reconnaissance-process.png`
- Be descriptive: `log4shell-attack-flow.png`

### Recommended Formats
- **Diagrams**: SVG (preferred) or PNG
- **Screenshots**: PNG
- **Photos**: JPG
- **Icons**: SVG or PNG with transparency

### Size Guidelines
- **Header images**: 1200x400px
- **Diagrams**: Max 800px wide
- **Screenshots**: Original resolution, but optimize for web
- **Icons**: 64x64px, 128x128px, 256x256px variants

## Optimization
All images should be optimized for web delivery:
- Compress images before committing
- Use appropriate formats (SVG for simple graphics, PNG for complex images with transparency)
- Consider using WebP format for modern browser support