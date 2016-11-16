all:
	pip install chalice
	if ! [[ -d fogdog-api ]]; then chalice new-project fogdog-api; fi
	cd fogdog-api; chalice deploy --no-autogen-policy
