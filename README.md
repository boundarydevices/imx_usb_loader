# imx_loader

i.MX/Vybrid recovery utility

## Description
This utility allows to download and execute code on Freescale i.MX5/i.MX6
and Vybrid SoCs through the Serial Download Protocol (SDP). Depending on
the board, there is usually some kind of recovery button to bring the SoC
into serial download boot mode, check documentation of your hardware.

The utility support USB and UART as serial link.

## Installation
1. Clone
1. Make sure libusb (1.0) is available
1. Make sure that libhid is available (http://www.signal11.us/oss/hidapi/)
1. Compile using make

Two binaries are available, imx_usb and imx_uart for the two supported
connections.

## Usage
Using USB, your device should be detected automatically using the USB
VID/PID from imx_usb.conf. Using UART, the user has to specify a
configuration file. This file is needed to use the correct protocol
variant for the target device (transfer configuration). The
configuration file can also contains work item(s).

Work items can also be defined using the command line. By specifying a
file in the command line, the utility automatically uses this file as
a work item and reads parameter from its header:

```
./imx_usb u-boot.imx
```

However, parameters can also specified manually, e.g.

```
./imx_usb u-boot.imx -l0x3f400400 -s370796 -v
```

The UART link uses hardware flow control using RTS/CTS, so make sure
those are available. The imx_uart utility will configure the target
tty with the right baud rate (115200) and flow control settings:

```
./imx_uart /dev/ttyUSB0 vybrid_usb_work.conf u-boot.imx
```

