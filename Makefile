SHELL=/bin/bash

wheel: lint build_constants
	./setup.py bdist_wheel

build_constants: aegea/constants.json

aegea/constants.json:
	python -c "from aegea.util.constants import write; write()"

lint:
	./setup.py flake8
#	flake8 scripts/*
#	pylint -E --disable=no-member aegea

test: lint install
	./setup.py test

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install: lint build_constants
	-rm -rf dist
	./setup.py bdist_wheel
	pip install --upgrade dist/*.whl

clean:
	-rm -rf *.egg-info

.PHONY: lint test docs install clean
