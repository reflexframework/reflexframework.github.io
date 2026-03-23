# Quarto Website and Book Project

This project demonstrates how to create both a website and a book using Quarto with shared content. The website is automatically published to GitHub Pages.

## Project Structure

```
├── _quarto.yml          # Main Quarto configuration with profiles
├── Makefile            # Build automation
├── index.qmd           # Homepage (shared between website and book)
├── chapters/           # Shared content chapters
│   ├── chapter1.qmd
│   └── chapter2.qmd
├── styles.css          # Custom CSS styling
├── .github/workflows/  # GitHub Actions for publishing
│   └── quarto-publish.yml
└── README.md          # This file
```

## Prerequisites

- [Quarto](https://quarto.org/docs/get-started/) installed
- Python with matplotlib and numpy for code execution
- Make (usually pre-installed on macOS/Linux)

## Building the Project

### Using Make (Recommended)

```bash
# Build both website and book
make all

# Build website only
make website

# Build book only
make book

# Preview website locally
make preview

# Clean output directories
make clean

# Check dependencies
make deps

# Show help
make help
```

### Using Quarto Directly

```bash
# Build website
quarto render --profile website

# Build book
quarto render --profile book

# Preview website
quarto preview --profile website

# Preview book
quarto preview --profile book
```

## Output Locations

- **Website**: Generated in `_site/` directory
- **Book**: Generated in `_book/` directory

## GitHub Pages Setup

1. Enable GitHub Pages in your repository settings
2. Set source to "GitHub Actions"
3. Push to main/master branch to trigger automatic deployment

The website will be available at: `https://[username].github.io/[repository-name]/`

## Customization

### Adding New Chapters

1. Create a new `.qmd` file in the `chapters/` directory
2. Update the `chapters` list in both website navbar and book chapters in `_quarto.yml`

### Styling

- Edit `styles.css` for custom styling
- Change themes in `_quarto.yml` (cosmo, flatly, journal, etc.)

### Configuration

- **Website settings**: Edit the `website` profile in `_quarto.yml`
- **Book settings**: Edit the `book` profile in `_quarto.yml`

## Development Workflow

1. Edit content in `.qmd` files
2. Run `make preview` to see changes locally
3. Commit and push to trigger GitHub Pages deployment

## Troubleshooting

- **Quarto not found**: Install from https://quarto.org
- **Python errors**: Install required packages: `pip install matplotlib numpy jupyter`
- **Make not found**: Install build tools for your platform
- **GitHub Pages not updating**: Check Actions tab for deployment status