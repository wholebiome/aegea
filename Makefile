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
	pytest --capture=no --cov=aegea test/test.py --junit-xml "$${CIRCLE_TEST_REPORTS:-.}/pytest/junit.xml"

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install: clean
	pip install wheel
	python ./setup.py bdist_wheel
	pip install --upgrade dist/*.whl

clean:
	-rm -rf build dist
	-rm -rf *.egg-info

.PHONY: wheel lint test test_deps docs install clean

include common.mk
