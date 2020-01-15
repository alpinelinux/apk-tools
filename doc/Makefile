$(obj)/%.5: $(src)/%.5.scd
	$(SCDOC) < $< > $@

$(obj)/%.8: $(src)/%.8.scd
	$(SCDOC) < $< > $@

docs: $(obj)/apk.8 \
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
	$(obj)/apk-repositories.5 \
	$(obj)/apk-world.5
targets += docs

install: docs
	# TODO
