# Makefile for Quarto Website and Book

.PHONY: all website book clean preview serve help

# Default target
all: website book

# Build website
website:
	@echo "Building website..."
	mv _quarto.yml _quarto-book.yml
	mv _quarto-website.yml _quarto.yml
	quarto render
	mv _quarto.yml _quarto-website.yml
	mv _quarto-book.yml _quarto.yml

# Build book
book:
	@echo "Building book..."
	quarto render

# Clean output directories
clean:
	@echo "Cleaning output directories..."
	rm -rf _site _book

# Preview website locally
preview:
	@echo "Starting website preview..."
	quarto preview --profile website

# Serve website (alias for preview)
serve: preview

# Build and preview book
book-preview:
	@echo "Starting book preview..."
	quarto preview --profile book

# Install/check dependencies
deps:
	@echo "Checking Quarto installation..."
	quarto check

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build both website and book"
	@echo "  website      - Build website only"
	@echo "  book         - Build book only"
	@echo "  clean        - Remove output directories"
	@echo "  preview      - Preview website locally"
	@echo "  serve        - Alias for preview"
	@echo "  book-preview - Preview book locally"
	@echo "  deps         - Check Quarto dependencies"
	@echo "  help         - Show this help message"