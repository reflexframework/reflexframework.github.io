# Builds the REFLEX site with Paperband (see manifest.yml and pom.xml).
# Outputs: _site/index.html (the web page) and _site/reflex-framework.pdf.

.PHONY: all website preview serve clean deps paperband theme themes help

PORT ?= 8000
# A checkout of github.com/noregressions/paperband
PAPERBAND_DIR ?= $(HOME)/claude_projects/TestGun
THEMES := $(basename $(notdir $(wildcard styles/themes/*.css)))

all: website

# Build the web page and the PDF
website:
	@echo "Building site with Paperband..."
	mvn -q package
	cp .nojekyll CNAME _site/
	mkdir -p _site/fonts && cp assets/fonts/*.woff2 _site/fonts/

# Build, then serve _site locally
preview: website
	@echo "Serving http://localhost:$(PORT)/"
	cd _site && python3 -m http.server $(PORT)

serve: preview

# Switch the web theme (the PDF always uses the print styles in styles/base.css)
theme:
	@test -n "$(THEME)" || { echo "Usage: make theme THEME=<name>  (one of: $(THEMES))"; \
	  echo "Current: $$(sed -n 's#^stylesheets:.*themes/\([a-z-]*\)\.css.*#\1#p' manifest.yml)"; exit 1; }
	@test -f styles/themes/$(THEME).css || { echo "No such theme: $(THEME) (one of: $(THEMES))"; exit 1; }
	sed -i.bak 's#themes/[a-z-]*\.css#themes/$(THEME).css#' manifest.yml && rm -f manifest.yml.bak
	@echo "Theme is now $(THEME). Run make website to rebuild."

# List the themes
themes:
	@echo "$(THEMES)"

# Clean output directories
clean:
	rm -rf _site target

# Install Paperband into the local Maven repository from a checkout (until the version in pom.xml is on Maven Central)
paperband:
	mvn -q -f $(PAPERBAND_DIR)/pom.xml install -pl core,chromium,maven-plugin -am -DskipTests

# Check the toolchain
deps:
	@java -version
	@mvn -version | head -1

help:
	@echo "Available targets:"
	@echo "  website  - Build _site/index.html and _site/reflex-framework.pdf (default)"
	@echo "  preview  - Build, then serve _site on http://localhost:$(PORT)/"
	@echo "  theme    - Switch the web theme: make theme THEME=<name> (make themes lists them)"
	@echo "  clean    - Remove output directories"
	@echo "  paperband - Install Paperband from PAPERBAND_DIR into ~/.m2"
	@echo "  deps     - Check Java and Maven"
