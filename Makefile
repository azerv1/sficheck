# Developer shortcuts; everything runs through uv. Recipes are plain commands, so they work
# whether make hands them to sh (Linux, macOS, Git Bash) or cmd.exe.

.DEFAULT_GOAL := help
.PHONY: help sync lint format test clean audit install

help:
	@echo make sync - install the dev environment from uv.lock
	@echo make lint - ruff, format check, mypy, complexipy, vulture, deptry
	@echo make format - fix imports and reformat
	@echo make test - run the test suite
	@echo make audit - check the locked dependencies for known vulnerabilities
	@echo make install - install the sficheck command for this user
	@echo make clean - remove caches and build output

sync:
	uv sync

lint:
	uv run ruff check
	uv run ruff format --check
	uv run mypy
	uv run complexipy
	uv run vulture
	uv run deptry .

format:
	uv run ruff check --fix --select I
	uv run ruff format

test:
	uv run pytest

audit:
	uv export --frozen --no-emit-project --quiet -o build/audit-req.txt
	uv run pip-audit -r build/audit-req.txt --disable-pip

install:
	uv tool install --reinstall .

clean:
	uv run --no-project python -c "import pathlib, shutil; [shutil.rmtree(p) if p.is_dir() else p.unlink() for g in ('build', 'dist', '*.egg-info', '.tox', '.*_cache', '.hypothesis', '.coverage*', '**/__pycache__') for p in pathlib.Path().glob(g) if '.venv' not in p.parts]"
