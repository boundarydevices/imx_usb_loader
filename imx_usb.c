/*
 * imx_usb:
 *
 * Program to download and execute an image over the USB boot protocol
 * on i.MX series processors.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <unistd.h>
#include <ctype.h>
#include <sys/io.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#include <libusb-1.0/libusb.h>

#include "imx_sdp.h"

#ifdef DEBUG
#define dbg_printf(fmt, args...)	fprintf(stderr, fmt, ## args)
#else
#define dbg_printf(fmt, args...)    /* Don't do anything in release builds */
#endif

struct mach_id;
struct mach_id {
	struct mach_id * next;
	unsigned short vid;
	unsigned short pid;
	char file_name[256];
};

static void print_devs(libusb_device **devs)
{
	int j, k, l;
	int i = 0;
	for (;;) {
		struct libusb_device_descriptor desc;
		struct libusb_config_descriptor *config;
		libusb_device *dev = devs[i++];
		if (!dev)
			break;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return;
		}

		libusb_get_config_descriptor(dev, 0, &config);

		printf("%04x:%04x (bus %d, device %d) bNumInterfaces:%i\n",
			desc.idVendor, desc.idProduct,
			libusb_get_bus_number(dev), libusb_get_device_address(dev),
			config->bNumInterfaces);
		for (j = 0; j < config->bNumInterfaces; j++) {
			const struct libusb_interface *inter = &config->interface[j];
			printf("  alternates:%i\n", inter->num_altsetting);
			for (k = 0; k < inter->num_altsetting; k++) {
				const struct libusb_interface_descriptor *interdesc = &inter->altsetting[k];
				printf("    Interface Number: %i, Number of endpoints: %i\n",
						interdesc->bInterfaceNumber, interdesc->bNumEndpoints);
				for (l = 0; l < interdesc->bNumEndpoints; l++) {
					const struct libusb_endpoint_descriptor *epdesc = &interdesc->endpoint[l];
					printf("      Descriptor Type: %x, EP Address: %i, wMaxPacketSize: %i\n",
							epdesc->bDescriptorType, epdesc->bEndpointAddress, epdesc->wMaxPacketSize);
				}
			}
		}
		libusb_free_config_descriptor(config);
	}
}
/*
	{0x066f, 0x3780, "mx23", 0, 1024, MODE_HID, HDR_NONE},
	{0x15a2, 0x004f, "mx28", 0, 1024, MODE_HID, HDR_NONE},
	{0x15a2, 0x0052, "mx50", 0, 1024, MODE_HID, HDR_MX53},
	{0x15a2, 0x0054, "mx6", 0x10000000, 1024, MODE_HID, HDR_MX53},
	{0x15a2, 0x0041, "mx51", 0x90000000, 64, MODE_BULK, HDR_MX51},
	{0x15a2, 0x004e, "mx53", 0x70000000, 512, MODE_BULK, HDR_MX53},
	{0x066f, 0x37ff, "linux gadget", 512, MODE_BULK, HDR_NONE},
};
*/

/*
 * Parse USB specific machine configuration
 */
static struct mach_id *parse_imx_conf(char const *filename)
{
	unsigned short vid;
	unsigned short pid;
	char line[512];
	struct mach_id *head = NULL;
	struct mach_id *tail = NULL;
	struct mach_id *curr = NULL;
	const char *p;

	FILE* xfile = fopen(filename, "rb" );
	if (!xfile) {
		printf("Could not open file: %s\n", filename);
		return NULL;
	}

	while (fgets(line, sizeof(line), xfile) != NULL) {
		p = line;
		while (*p==' ') p++;
		if (p[0] == '#')
			continue;
		vid = get_val(&p, 16);
		if (p[0] != ':') {
			printf("Syntax error(missing ':'): %s [%s]\n", p, line);
			continue;
		}
		p++;
		pid = get_val(&p, 16);
		if (p[0] != ',') {
			printf("Syntax error(missing ','): %s [%s]\n", p, line);
			continue;
		}
		p++;
		while (*p==' ') p++;
		if (!(vid && pid)) {
			printf("vid/pid cannot be 0: %s [%s]\n", p, line);
			continue;
		}
		curr = (struct mach_id *)malloc(sizeof(struct mach_id));
		curr->next = NULL;
		curr->vid = vid;
		curr->pid = pid;
		move_string(curr->file_name, p, sizeof(curr->file_name) - 1);
		if (!head)
			head = curr;
		if (tail)
			tail->next = curr;
		tail = curr;
		printf("vid=0x%04x pid=0x%04x file_name=%s\n", curr->vid, curr->pid, curr->file_name);
	}
	fclose(xfile);
	return head;
}

static struct mach_id * imx_device(unsigned short vid, unsigned short pid, struct mach_id *p)
{
//	printf("%s: vid=%x pid=%x\n", __func__, vid, pid);
	while (p) {
		if ((p->vid == vid) && (p->pid == pid))
			return p;
		p = p->next;
	}
	return NULL;
}


static libusb_device *find_imx_dev(libusb_device **devs, struct mach_id **pp_id, struct mach_id *list)
{
	int i = 0;
	struct mach_id *p;
	for (;;) {
		struct libusb_device_descriptor desc;
		libusb_device *dev = devs[i++];
		if (!dev)
			break;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return;
		}
		p = imx_device(desc.idVendor, desc.idProduct, list);
		if (p) {
			*pp_id = p;
			return dev;
		}
	}
	fprintf(stderr, "no matching USB device found\n");
	*pp_id = NULL;
	return NULL;
}


// HID Class-Specific Requests values. See section 7.2 of the HID specifications
#define HID_GET_REPORT			0x01
#define HID_GET_IDLE			0x02
#define HID_GET_PROTOCOL		0x03
#define HID_SET_REPORT			0x09
#define HID_SET_IDLE			0x0A
#define HID_SET_PROTOCOL		0x0B
#define HID_REPORT_TYPE_INPUT		0x01
#define HID_REPORT_TYPE_OUTPUT		0x02
#define HID_REPORT_TYPE_FEATURE		0x03
#define CTRL_IN			LIBUSB_ENDPOINT_IN |LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE
#define CTRL_OUT		LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE

#define EP_IN	0x80


/*
 * For HID class drivers, 4 reports are used to implement
 * Serial Download protocol(SDP)
 * Report 1 (control out endpoint) 16 byte SDP comand
 *  (total of 17 bytes with 1st byte report id of 0x01
 * Report 2 (control out endpoint) data associated with report 1 commands
 *  (max size of 1025 with 1st byte of 0x02)
 * Report 3 (interrupt in endpoint) HAB security state
 *  (max size of 5 bytes with 1st byte of 0x03)
 *  (0x12343412 production)
 *  (0x56787856 engineering)
 * Report 4 (interrupt in endpoint) date associated with report 1 commands
 *  (max size of 65 bytes with 1st byte of 0x04)
 *
 */
int transfer_hid(struct sdp_dev *dev, int report, unsigned char *p, unsigned int cnt,
		unsigned int expected, int* last_trans)
{
	int err;
	struct libusb_device_handle *h = (struct libusb_device_handle *)dev->priv;
	if (cnt > dev->max_transfer)
		cnt = dev->max_transfer;
#ifdef DEBUG
	printf("report=%i\n", report);
	if (report < 3)
		dump_bytes(p, cnt, 0);
#endif
	unsigned char tmp[1028];
	tmp[0] = (unsigned char)report;
	if (report < 3) {
		memcpy(&tmp[1], p, cnt);
		err = libusb_control_transfer(h,
				CTRL_OUT,
				HID_SET_REPORT,
				(HID_REPORT_TYPE_OUTPUT << 8) | report,
				0,
				tmp, cnt + 1, 1000);
		*last_trans = (err > 0) ? err - 1 : 0;
		if (err > 0)
			err = 0;
	} else {
		*last_trans = 0;
		memset(&tmp[1], 0, cnt);
		err = libusb_interrupt_transfer(h, 1 + EP_IN, tmp, cnt + 1, last_trans, 1000);
		dbg_printf("libusb_interrupt_transfer, err=%d, trans=%d\n", err,
				*last_trans);
		if (err >= 0) {
			if (tmp[0] == (unsigned char)report)
				if (*last_trans > 1) {
					*last_trans -= 1;
					memcpy(p, &tmp[1], *last_trans);
				}
			else {
				printf("Unexpected report %i err=%i, cnt=%i, last_trans=%i, %02x %02x %02x %02x\n",
					tmp[0], err, cnt, *last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
				err = 0;
			}
		}
	}
#ifdef DEBUG
	if (report >= 3)
		dump_bytes(p, cnt, 0);
#endif
	return err;
}



/*
 * For Bulk class drivers, the device is configured as
 * EP0IN, EP0OUT control transfer
 * EP1OUT - bulk out
 * (max packet size of 512 bytes)
 * EP2IN - bulk in
 * (max packet size of 512 bytes)
 */

int transfer_bulk(struct sdp_dev *dev, int report, unsigned char *p, unsigned int cnt,
		unsigned int expected, int* last_trans)
{
	int err;
	struct libusb_device_handle *h = (struct libusb_device_handle *)dev->priv;
	if (cnt > dev->max_transfer)
		cnt = dev->max_transfer;
#ifdef DEBUG
	printf("report=%i\n", report);
	if (report < 3)
		dump_bytes(p, cnt, 0);
#endif
	*last_trans = 0;
	err = libusb_bulk_transfer(h, (report < 3) ? 1 : 2 + EP_IN, p, cnt, last_trans, 1000);

#ifdef DEBUG
	if (report >= 3)
		dump_bytes(p, cnt, 0);
#endif
	return err;
}

libusb_device_handle * open_vid_pid(struct mach_id *mach, struct sdp_dev *p_id)
{
	int r = libusb_init(NULL);
	int err;
	libusb_device_handle *h;
	h = libusb_open_device_with_vid_pid(NULL, mach->vid, mach->pid);
	if (!h) {
		printf("%s:Could not open device vid=0x%x pid=0x%x\n", __func__,
				mach->vid, mach->pid);
		goto err1;
	}
	if (libusb_kernel_driver_active(h, 0))
		libusb_detach_kernel_driver(h, 0);
	err = libusb_claim_interface(h, 0);
	if (err) {
		printf("claim failed, err=%i\n", err);
		goto err2;
	}
	err = do_status(p_id);
	if (!err)
		return h;
	printf("status failed, err=%i\n", err);
err2:
	libusb_release_interface(h, 0);
	libusb_close(h);
err1:
	libusb_exit(NULL);
	return NULL;
}

#define ARRAY_SIZE(w) sizeof(w)/sizeof(w[0])

void print_usage(void)
{
	printf("Usage: imx_usb [OPTIONS...] [JOBS...]\n"
		"  e.g. imx_usb -v u-boot.imx\n"
		"Load data on target connected to USB using serial download protocol. The target\n"
		"type is detected using USB ID, a appropriate configuration file.\n"
		"\n"
		"Where OPTIONS are\n"
		"   -h --help		Show this help\n"
		"   -v --verify		Verify downloaded data\n"
		"   -c --configdir=DIR	Reading configuration directory from non standard\n"
		"			directory.\n"
		"\n"
		"And where [JOBS...] are\n"
		"   FILE [-lLOADADDR] [-sSIZE] ...\n"
		"Multiple jobs can be configured. The first job is treated special, load\n"
		"address, jump address, and length are read from the IVT header. If no job\n"
		"is specified, the jobs definied in the target specific configuration file\n"
		"is being used.\n");
}

int parse_opts(int argc, char * const *argv, char const **configdir,
		int *verify, struct sdp_work **cmd_head)
{
	int c;

	static struct option long_options[] = {
		{"help",	no_argument, 		0, 'h' },
		{"verify",	no_argument, 		0, 'v' },
		{"configdir",	required_argument, 	0, 'c' },
		{0,		0,			0, 0 },
	};

	while ((c = getopt_long(argc, argv, "+hvc:", long_options, NULL)) != -1) {
		switch (c)
		{
		case 'h':
		case '?':
			print_usage();
			return -1;
		case 'v':
			*verify = 1;
			break;
		case 'c':
			*configdir = optarg;
			break;
		}
	}

	if (optind < argc) {
		// Parse optional job arguments...
		*cmd_head = parse_cmd_args(argc - optind, &argv[optind]);
	}

	return 0;
}

int main(int argc, char * const argv[])
{
	struct sdp_dev *p_id;
	struct mach_id *mach;
	libusb_device **devs;
	libusb_device *dev;
	int r;
	int err;
	ssize_t cnt;
	libusb_device_handle *h = NULL;
	int config = 0;
	int verify = 0;
	struct sdp_work *curr;
	struct sdp_work *cmd_head = NULL;
	char const *conf;
	char const *base_path = get_base_path(argv[0]);
	char const *conf_path = "/etc/imx-loader.d/";

	err = parse_opts(argc, argv, &conf_path, &verify, &cmd_head);
	if (err < 0)
		return -1;

	// Get list of machines...
	conf = conf_file_name("imx_usb.conf", base_path, conf_path);
	if (conf == NULL)
		return -1;

	struct mach_id *list = parse_imx_conf(conf);
	if (!list)
		return -1;

	r = libusb_init(NULL);
	if (r < 0)
		goto out;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0)
		goto out;

//	print_devs(devs);
	dev = find_imx_dev(devs, &mach, list);
	if (dev) {
		err = libusb_open(dev, &h);
		if (err)
			printf("%s:Could not open device vid=0x%x pid=0x%x err=%d\n", __func__, mach->vid, mach->pid, err);
	}
	libusb_free_device_list(devs, 1);

	if (!h)
		goto out;

	// Get machine specific configuration file..
	conf = conf_file_name(mach->file_name, base_path, conf_path);
	if (conf == NULL)
		goto out;

	p_id = parse_conf(conf);
	if (!p_id)
		goto out;

	if (p_id->mode == MODE_HID)
		p_id->transfer = &transfer_hid;
	if (p_id->mode == MODE_BULK)
		p_id->transfer = &transfer_bulk;

	// USB private pointer is libusb device handle...
	p_id->priv = h;

	libusb_get_configuration(h, &config);
	printf("%04x:%04x(%s) bConfigurationValue =%x\n",
			mach->vid, mach->pid, p_id->name, config);

	if (libusb_kernel_driver_active(h, 0))
		 libusb_detach_kernel_driver(h, 0);

	err = libusb_claim_interface(h, 0);
	if (err) {
		printf("Claim failed\n");
		goto out;
	}
	printf("Interface 0 claimed\n");
	err = do_status(p_id);
	if (err) {
		printf("status failed\n");
		goto out;
	}

	// By default, use work from config file...
	curr = p_id->work;

	if (cmd_head != NULL)
		curr = cmd_head;

	if (curr == NULL) {
		printf("no job found\n"); 
		goto out;
	}

	while (curr) {
		if (curr->mem)
			perform_mem_work(p_id, curr->mem);
//		printf("jump_mode %x\n", curr->jump_mode);
		if (curr->filename[0]) {
			err = DoIRomDownload(p_id, curr, verify);
		}
		if (err) {
			err = do_status(p_id);
			break;
		}
		if (!curr->next && (!curr->plug || curr != cmd_head))
			break;
		err = do_status(p_id);
		printf("jump_mode %x plug=%i err=%i\n", curr->jump_mode, curr->plug, err);
		if (err) {
			int retry;
			/* Rediscovers device */
			libusb_release_interface(h, 0);
			libusb_close(h);
			libusb_exit(NULL);
			for (retry = 0; retry < 10; retry++) {
				printf("sleeping\n");
				sleep(3);
				printf("done sleeping\n");
				h = open_vid_pid(mach, p_id);
				if (h)
					break;
			}
			if (!h)
				goto out;
		}
		if (curr == cmd_head && curr->plug) {
			curr->plug = 0;
			continue;
		}
		curr = curr->next;
	}

exit:
	libusb_release_interface(h, 0);
out:
	if (h)
		libusb_close(h);
	libusb_exit(NULL);
	return 0;
}
