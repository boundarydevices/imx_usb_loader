# imx_loader

i.MX/Vybrid recovery utility

## Description
This utility allows to download and execute code on Freescale i.MX5/i.MX6/i.MX7
and Vybrid SoCs through the Serial Download Protocol (SDP). Depending on
the board, there is usually some kind of recovery button to bring the SoC
into serial download boot mode, check documentation of your hardware.

The utility support USB and UART as serial link.

## Installation
1. Clone
1. Make sure libusb (1.0) is available
1. Compile using make

Two binaries are available, imx_usb and imx_uart for the two supported
connections.

### Windows

Two variants have been tested successfully to build imx_usb and imx_uart
on Windows:
1. MinGW (using the Microsoft C runtime)
1. Visual Studio 2015 and 2017

#### MinGW

MinGW allows to use the GNU toolchain (including GCC) to compile a native
Microsoft Windows application. A MinGW specific make file (Makefile.mingw)
is available which allows to build imx_usb/imx_uart with the native make
port (mingw32-make.exe). After installing MinGW, make sure you have a
compiled copy of libusb available and build imx_loader using:

```
mingw32-make -f Makefile.mingw LIBUSBPATH=C:\path\to\libusb
```

This dynamically links against libusb, hence make sure to ship the
library libusb-1.0.dll along with imx_usb.exe.

#### Visual Studio

The subdirectory msvc/ contains the project files for Visual Studio 2015 and
2017. Make sure you have the Visual C++ component installed. There is one
solution containing two projects, one for imx_usb and one for imx_uart. The
imx_usb project requires libusb to be present at ../../libusb (relative to the
msvc) directory. If you use an alternative location or compile libusb from
source too, you will have to alter the include/library path in the project
settings.

### macOS

libusb and pkg-config can be installed via Homebrew.

If imx_usb fails to claim interface, com.apple.driver.usb.IOUSBHostHIDDevice
needs to be unloaded so libusb can claim, run:

```
sudo kextunload -b com.apple.driver.usb.IOUSBHostHIDDevice
```

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

