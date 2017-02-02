SHELL=/bin/bash -eo pipefail

wheel: lint constants clean
	./setup.py bdist_wheel

constants: aegea/constants.json

aegea/constants.json:
	python -c "import aegea; aegea.initialize(); from aegea.util.constants import write; write()"

test_deps:
	pip install coverage flake8 pytest pytest-cov

lint: test_deps
	./setup.py flake8
	flake8 --filename='*' $$(grep -r -l '/usr/bin/env python' aegea scripts)

test: test_deps lint
	mkdir -p "$${CIRCLE_TEST_REPORTS:-.}/pytest"
	pytest --capture=no --cov=aegea --cov-config .coveragerc test/test.py --junit-xml "$${CIRCLE_TEST_REPORTS:-.}/pytest/junit.xml"

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install: clean
	pip install wheel
	python ./setup.py bdist_wheel
	pip install --upgrade dist/*.whl

install_venv: clean
	virtualenv --prompt "(aegea-venv) " .venv
	source .venv/bin/activate; pip install --upgrade pip
	source .venv/bin/activate; pip install --upgrade setuptools
	source .venv/bin/activate; pip install --upgrade wheel
	source .venv/bin/activate; python ./setup.py bdist_wheel
	source .venv/bin/activate; pip install --upgrade dist/*.whl
	@echo "Run \". $$(pwd)/.venv/bin/activate\" to activate the aegea installation"

clean:
	-rm -rf build dist
	-rm -rf *.egg-info
	-rm -rf .venv

.PHONY: wheel lint test test_deps docs install clean

include common.mk
