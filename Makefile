SHELL=/bin/bash

flake8:
	./setup.py flake8

test: flake8 install
	./setup.py test

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install:
	./setup.py install

clean:
	-rm -rf *.egg-info

.PHONY: flake8 test docs install clean
