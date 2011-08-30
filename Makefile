all: imx_usb

CFLAGS = `pkg-config --cflags libusb-1.0`

%.o : %.cpp
	$(CC) -c $*.cpp -o $@ -Wno-trigraphs -pipe -ggdb -Wall $(CFLAGS)

%.o : %.c
	$(CC) -c $*.c -o $@ -Wstrict-prototypes -Wno-trigraphs -pipe -ggdb $(CFLAGS)

imx_usb.lds:
	ld --verbose|sed \
	-e '1,/===/d' \
	-e '/===/d' \
	-e '/\.data \.data\.\*/i\     __processor_info_start = \.\;     \*\(\.data\.processor_info\)\;     __processor_info_end = \.\;' \
	-e '/__data_start__*/a\     ___processor_info_start = \.\;     \*\(\.data\.processor_info\)\;     ___processor_info_end = \.\;' \
	> $@


imx_usb: imx_usb.o imx_usb.lds
	gcc -o $@ $@.o -T $@.lds -lusb-1.0

clean:
	rm -f imx_usb imx_usb.lds imx_usb.o

