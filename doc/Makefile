$(obj)/%.8: $(src)/%.8.scd
	$(SCDOC) < $< > $@

docs: $(obj)/apk.8
targets += docs

install: docs
	# TODO
