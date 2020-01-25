$(obj)/%: $(src)/%.scd
	$(SCDOC) < $< > $@

MAN_5=$(obj)/apk-cache.5 \
	$(obj)/apk-keys.5 \
	$(obj)/apk-repositories.5 \
	$(obj)/apk-world.5

MAN_8=$(obj)/apk.8 \
	$(obj)/apk-add.8 \
	$(obj)/apk-audit.8 \
	$(obj)/apk-cache.8 \
	$(obj)/apk-del.8 \
	$(obj)/apk-dot.8 \
	$(obj)/apk-fetch.8 \
	$(obj)/apk-fix.8 \
	$(obj)/apk-index.8 \
	$(obj)/apk-info.8 \
	$(obj)/apk-list.8 \
	$(obj)/apk-manifest.8 \
	$(obj)/apk-policy.8 \
	$(obj)/apk-stats.8 \
	$(obj)/apk-update.8 \
	$(obj)/apk-upgrade.8 \
	$(obj)/apk-verify.8 \
	$(obj)/apk-version.8

docs: $(MAN_5) $(MAN_8)
targets += docs

install.5: $(MAN_5)
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man5
	for page in $^; do $(INSTALL) $$page $(DESTDIR)$(MANDIR)/man5/; done

install.8: $(MAN_8)
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man8
	for page in $^; do $(INSTALL) $$page $(DESTDIR)$(MANDIR)/man8/; done

install: install.5 install.8
