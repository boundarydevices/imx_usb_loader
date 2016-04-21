all: imx_usb imx_uart

DESTDIR ?=
prefix ?= /usr
bindir ?= $(prefix)/bin
sysconfdir ?= $(prefix)/etc

BUILDHOST := $(shell uname -s)
BUILDHOST := $(patsubst CYGWIN_%,CYGWIN,$(BUILDHOST))

CFLAGS := -Wall -Wno-pointer-sign $(CFLAGS)

ifneq ($(BUILDHOST),CYGWIN)
USBCFLAGS = `pkg-config --cflags libusb-1.0 hidapi`
USBLDFLAGS = `pkg-config --libs libusb-1.0 hidapi`
else
USBCFLAGS = -I/usr/include/libusb-1.0 -I/usr/include/hidapi
USBLDFLAGS = -L/usr/lib -lusb-1.0 -lhidapi
endif
CONFCPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'

imx_usb.o : imx_usb.c
	$(CC) -c $*.c -o $@ -Wstrict-prototypes -Wno-trigraphs -pipe -ggdb $(USBCFLAGS) $(CFLAGS) $(CONFCPPFLAGS)

%.o : %.c
	$(CC) -c $*.c -o $@ -Wstrict-prototypes -Wno-trigraphs -pipe -ggdb $(CFLAGS) $(CONFCPPFLAGS)

imx_usb: imx_usb.o imx_sdp.o
	$(CC) -o $@ $@.o imx_sdp.o $(LDFLAGS) $(USBLDFLAGS)

imx_uart: imx_uart.o imx_sdp.o
	$(CC) -o $@ $@.o imx_sdp.o $(LDFLAGS)

install: imx_usb imx_uart
	mkdir -p '$(DESTDIR)$(sysconfdir)/imx-loader.d/'
	install -m644 *.conf '$(DESTDIR)$(sysconfdir)/imx-loader.d/'
	mkdir -p '$(DESTDIR)$(bindir)'
	install -m755 imx_usb '$(DESTDIR)$(bindir)/imx_usb'
	install -m755 imx_uart '$(DESTDIR)$(bindir)/imx_uart'

clean:
	rm -f imx_usb imx_uart imx_usb.o imx_uart.o imx_sdp.o

.PHONY: all clean install
