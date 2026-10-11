# Builds the REFLEX site with Paperband (see manifest.yml and pom.xml).
# Outputs: _site/index.html (the web page) and _site/reflex-framework.pdf.

.PHONY: all website preview serve clean deps help

PORT ?= 8000

all: website

# Build the web page and the PDF
website:
	@echo "Building site with Paperband..."
	mvn -q package
	cp .nojekyll CNAME _site/

# Build, then serve _site locally
preview: website
	@echo "Serving http://localhost:$(PORT)/"
	cd _site && python3 -m http.server $(PORT)

serve: preview

# Clean output directories
clean:
	rm -rf _site target

# Check the toolchain
deps:
	@java -version
	@mvn -version | head -1

help:
	@echo "Available targets:"
	@echo "  website  - Build _site/index.html and _site/reflex-framework.pdf (default)"
	@echo "  preview  - Build, then serve _site on http://localhost:$(PORT)/"
	@echo "  clean    - Remove output directories"
	@echo "  deps     - Check Java and Maven"
