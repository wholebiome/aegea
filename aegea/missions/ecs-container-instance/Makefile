SHELL=bash

rootfs.skel: %: %.in environment
	-rm -rf $@
	cp -R $@.in $@
	source environment; \
            wd=$$(basename "$$(pwd)"); \
            wd=$${wd//-/_}; \
            config_var_prefix=$${wd^^}; \
            vars=" $$(compgen -A variable $$config_var_prefix)"; \
            for i in $$(find $@ -type f); do cat $$i | envsubst "$${vars//[[:space:]]/ $$}" | sponge $$i; done

clean:
	-rm -rf rootfs.skel

.PHONY: rootfs.skel
