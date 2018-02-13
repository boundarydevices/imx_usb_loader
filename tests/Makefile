IMX_USB ?= ../imx_usb

%.test: % FORCE
	@echo Testing $*
	@$(IMX_USB) -v -S 0x15a2:0x0061 $* > $@
	@diff $*.output $@

tests:	test.imx.test test-dcd.imx.test test-plugin.imx.test

%.output: % FORCE
	$(IMX_USB) -v -S 0x15a2:0x0061 $* > $@

regen:	test.imx.output test-dcd.imx.output test-plugin.imx.output

FORCE: ;

.PHONY: tests regen
