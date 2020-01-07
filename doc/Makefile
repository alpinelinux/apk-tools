$(obj)/%.5: $(src)/%.5.scd
	$(SCDOC) < $< > $@

$(obj)/%.8: $(src)/%.8.scd
	$(SCDOC) < $< > $@

docs: $(obj)/apk.8 \
	$(obj)/apk-add.8 \
	$(obj)/apk-del.8 \
	$(obj)/apk-repositories.5 \
	$(obj)/apk-world.5
targets += docs

install: docs
	# TODO
