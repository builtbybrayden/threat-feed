# One-command workflows. On Windows, run these in Git Bash / WSL, or run the
# underlying `python ...` commands directly (see the README).
PYTHON ?= ./.venv/Scripts/python.exe
SITE_PORT ?= 8000

.PHONY: help install run offline demo serve test icons sample coverage-index clean

help:
	@echo "install         install pinned dependencies"
	@echo "run             full online pipeline run"
	@echo "offline         run from sample_data/ (no network)"
	@echo "demo            offline build + serve site/ at http://localhost:$(SITE_PORT)"
	@echo "serve           serve site/ locally (needed for the service worker / fetch)"
	@echo "test            run the test suite"
	@echo "coverage-index  clone nuclei-templates and (re)build the coverage index"
	@echo "icons           regenerate the PWA icons"
	@echo "sample          refresh sample_data/ from the current state.json"

install:
	$(PYTHON) -m pip install -r requirements.txt

run:
	$(PYTHON) -m pipeline.ingest

offline:
	$(PYTHON) -m pipeline.ingest --offline

# The key demo command: build offline, then serve over http so the PWA works.
demo: offline serve

serve:
	cd site && $(PYTHON) -m http.server $(SITE_PORT)

test:
	$(PYTHON) -m pytest -q

icons:
	$(PYTHON) tools/gen_icons.py

sample:
	$(PYTHON) tools/make_sample.py

coverage-index:
	git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git nuclei-templates
	$(PYTHON) -m pipeline.coverage --templates ./nuclei-templates --out cache/coverage_index.json

clean:
	rm -rf nuclei-templates cache __pycache__ pipeline/__pycache__ .pytest_cache
