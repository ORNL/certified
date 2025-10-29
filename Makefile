# credit to https://medium.com/totalenergies-digital-factory/migrate-your-poetry-project-to-uv-b2c829b70cd9

.PHONY: install
install: ## Install the virtual environment
	@echo "🚀 Creating virtual environment using uv"
	uv sync --all-extras

.PHONY: check
check: ## Run code quality tools.
	@echo "🚀 Checking lock file consistency with 'pyproject.toml'"
	uv lock --locked
	@echo "🚀 Static type checking: Running mypy"
	uv run mypy .

.PHONY: test
test: ## Test the code with pytest
	@echo "🚀 Testing code: Running pytest"
	uv run python -m pytest --cov --cov-config=pyproject.toml

publish: build ## Publish to pypi
	@echo "🚀 Publishing project"
	$(eval user := $(shell sed -ne 's/username *= *//p' $(HOME)/.pypirc))
	$(eval pass := $(shell sed -ne 's/password *= *//p' $(HOME)/.pypirc))
	uv run --isolated --no-project --with dist/*.whl tests/smoke_test.py
	uv run --isolated --no-project --with dist/*.tar.gz tests/smoke_test.py
	uv publish -u $(user) -p $(pass)

.PHONY: build
build: clean-build ## Build wheel file
	@echo "🚀 Creating wheel file"
	#uvx --from build pyproject-build --installer uv
	uv build

.PHONY: clean-build
clean-build: ## Clean build artifacts
	@echo "🚀 Removing build artifacts"
	uv run python -c "import shutil; import os; shutil.rmtree('dist') if os.path.exists('dist') else None"

.PHONY: help
help:
	@uv run python -c "import re; \
 [[print(f'\033[36m{m[0]:<20}\033[0m {m[1]}') for m in re.findall(r'^([a-zA-Z_-]+):.*?## (.*)$$', open(makefile).read(), re.M)] for makefile in ('$(MAKEFILE_LIST)').strip().split()]"

.DEFAULT_GOAL := help
