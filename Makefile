# Makefile for Hybrid Binary-Protected Release & Licensing Engine

PYTHON ?= $(shell if [ -f .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)

.PHONY: help setup keygen build sign test clean run red-team

help:
	@echo "Available commands:"
	@echo "  make setup     - Create virtual environment and install requirements"
	@echo "  make keygen    - Generate Ed25519 asymmetric keypair in .secrets/"
	@echo "  make build     - Compile core_engine and create dist/client_release/"
	@echo "  make sign      - Generate a 30-day host-bound enterprise license"
	@echo "  make test      - Run automated pytest security and pricing test suite"
	@echo "  make red-team  - Run standalone red-team verification script"
	@echo "  make run       - Launch compiled release FastAPI server"
	@echo "  make clean     - Remove compiled binaries and build artifacts"

setup:
	@if [ ! -d ".venv" ]; then python3 -m venv .venv; fi
	@.venv/bin/pip install --upgrade pip
	@.venv/bin/pip install -r requirements.txt

keygen:
	@$(PYTHON) scripts/keygen.py

build:
	@bash scripts/build_release.sh

sign:
	@$(PYTHON) scripts/sign_license.py --client "Acme Global Enterprise Inc." --tier enterprise --days 30 --out dist/client_release/license.key

test:
	@$(PYTHON) -m pytest tests/test_security_and_pricing.py -v

red-team:
	@$(PYTHON) tests/red_team_verification.py

run:
	@cd dist/client_release && ../../$(PYTHON) -m uvicorn app_wrapper.main:app --host 0.0.0.0 --port 8000 --reload

clean:
	@rm -rf build/ dist/ build_tmp/ .pytest_cache/ htmlcov/ .coverage
	@find . -type f \( -name "*.so" -o -name "*.pyd" -o -name "*.c" -o -name "*.pyc" -o -name "*.pyo" \) ! -path "./.venv/*" -delete
	@find . -type d -name "__pycache__" ! -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name ".DS_Store" -delete 2>/dev/null || true
	@find . -type f -name "*.key" ! -path "./dist/*" ! -path "./.secrets/*" -delete 2>/dev/null || true

