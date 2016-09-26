rootfs.skel: %: %.in
	cp -R $@.in $@
	source environment; for i in $$(find $@ -type f); do cat $$i | envsubst | sponge $$i; done

clean:
	-rm -rf rootfs.skel
