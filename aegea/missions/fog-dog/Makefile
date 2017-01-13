SHELL=/bin/bash

rootfs.skel: %: %.in environment
	-rm -rf $@
	cp -R $@.in $@
	source environment; vars=" $$(compgen -A variable FOG)"; for i in $$(find $@ -type f); do cat $$i | envsubst "$${vars//[[:space:]]/ $$}" | sponge $$i; done

clean:
	-rm -rf rootfs.skel

.PHONY: rootfs.skel
