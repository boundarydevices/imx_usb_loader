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

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#ifdef __FreeBSD__
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif

#include "portable.h"
#include "imx_sdp.h"
#include "imx_loader.h"
#include "imx_loader_config.h"

struct mach_id;
struct mach_id {
	struct mach_id *next;
	struct mach_id *nextbatch;
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

static struct mach_id *parse_imx_mach(const char **pp)
{
	unsigned short vid;
	unsigned short pid;
	struct mach_id *curr = NULL;
	const char *p = *pp;

	while (*p==' ') p++;
	if (p[0] == '#')
		return NULL;
	vid = get_val(&p, 16);
	if (p[0] != ':') {
		printf("Syntax error(missing ':'): %s [%s]\n", p, *pp);
		return NULL;
	}
	p++;
	pid = get_val(&p, 16);
	if (p[0] != ',') {
		printf("Syntax error(missing ','): %s [%s]\n", p, *pp);
		return NULL;
	}
	p++;
	while (*p==' ') p++;
	if (!(vid && pid)) {
		printf("vid/pid cannot be 0: %s [%s]\n", p, *pp);
		return NULL;
	}
	curr = (struct mach_id *)malloc(sizeof(struct mach_id));
	curr->next = NULL;
	curr->nextbatch = NULL;
	curr->vid = vid;
	curr->pid = pid;
	p = move_string(curr->file_name, p, sizeof(curr->file_name) - 1);

	*pp = p;
	return curr;
}

/*
 * Parse USB specific machine configuration
 */
static struct mach_id *parse_imx_conf(char const *filename)
{
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
		curr = parse_imx_mach(&p);
		if (!curr)
			continue;

		if (!head)
			head = curr;
		if (tail)
			tail->next = curr;
		tail = curr;
		printf("vid=0x%04x pid=0x%04x file_name=%s\n", curr->vid, curr->pid, curr->file_name);

		while (p[0] == ',') {
			p++;
			// Second machine in batch...
			curr->nextbatch = parse_imx_mach(&p);
			curr = curr->nextbatch;
			printf("-> vid=0x%04x pid=0x%04x file_name=%s\n", curr->vid, curr->pid, curr->file_name);
		}
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


static libusb_device *find_imx_dev(libusb_device **devs, struct mach_id **pp_id, struct mach_id *list, int bus, int address)
{
	int i = 0;
	struct mach_id *p;
	for (;;) {
		struct libusb_device_descriptor desc;
		libusb_device *dev = devs[i++];
		if (!dev)
			break;
		if ((bus >= 0 && libusb_get_bus_number(dev) != bus) ||
		    (address >= 0 && libusb_get_device_address(dev) != address))
			continue;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return NULL;
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
		if (report == 2)
			cnt = dev->max_transfer;
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
			if (tmp[0] == (unsigned char)report) {
				if (*last_trans > 1) {
					*last_trans -= 1;
					memcpy(p, &tmp[1], *last_trans);
				}
			} else {
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

int transfer_simulation(struct sdp_dev *dev, int report, unsigned char *p, unsigned int cnt,
		unsigned int expected, int* last_trans)
{
	int err = 0;
	if (cnt > dev->max_transfer)
		cnt = dev->max_transfer;

	printf("report=%i, cnt=%d\n", report, cnt);
	switch (report) {
	case 1:
	case 2:
		dump_bytes(p, cnt, 0);
		break;
	case 3:
	case 4:
		memset(p, 0, cnt);
		break;
	}

	err = do_simulation(dev, report, p, cnt, expected, last_trans);

	/* On error, do not transmit anything */
	if (err)
		*last_trans = 0;
	else
		*last_trans = cnt;

	return err;
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
		"   -d --debugmode	Enable debug logs\n"
		"   -c --configdir=DIR	Reading configuration directory from non standard\n"
		"			directory.\n"
		"   -b --bus=NUM		Filter bus number.\n"
		"   -D --device=NUM	Filter device address.\n"
		"   -S --sim=VID:PID	Simulate a device of VID:PID\n"
		"\n"
		"And where [JOBS...] are\n"
		"   FILE [-lLOADADDR] [-sSIZE] ...\n"
		"Multiple jobs can be configured. The first job is treated special, load\n"
		"address, jump address, and length are read from the IVT header. If no job\n"
		"is specified, the jobs definied in the target specific configuration file\n"
		"is being used.\n");
}

int do_work(struct sdp_dev *p_id, struct sdp_work **work, int verify)
{
	struct sdp_work *curr = *work;
	int err = 0;

	err = do_status(p_id);
	if (err) {
		fprintf(stderr, "status failed\n");
		return err;
	}

	while (curr) {
		/* Do current job */
		if (curr->mem)
			perform_mem_work(p_id, curr->mem);
		if (curr->filename[0])
			err = DoIRomDownload(p_id, curr, verify);
		if (err) {
			fprintf(stderr, "DoIRomDownload failed, err=%d\n", err);
			do_status(p_id);
			break;
		}

		/* Check if more work is to do... */
		if (!curr->next) {
			/*
			 * If only one job, but with a plug-in is specified
			 * reexecute the same job, but this time download the
			 * image. This allows to specify a single file with
			 * plugin and image, and imx_usb will download & run
			 * the plugin first and then the image.
			 * NOTE: If the file does not contain a plugin,
			 * DoIRomDownload->process_header will set curr->plug
			 * to 0, so we won't download the same image twice...
			 */
			if (curr->plug) {
				curr->plug = 0;
			} else {
				curr = NULL;
				break;
			}
		} else {
			curr = curr->next;
		}

		/*
		 * Check if device is still here, otherwise return
		 * with work (retry)
		 */
		err = do_status(p_id);
		if (err < 0) {
			err = 0;
			break;
		}
	}

	*work = curr;

	return err;
}

int do_simulation_dev(char const *base_path, char const *conf_path,
		struct mach_id *list, int verify, struct sdp_work *cmd_head,
		char const *vidpid)
{
	int err;
	struct mach_id *mach;
	struct sdp_dev *p_id;
	struct sdp_work *curr = NULL;
	char const *conf;
	unsigned short vid, pid;

	sscanf(vidpid, "%hx:%hx", &vid, &pid);
	printf("Simulating with vid=0x%04hx pid=0x%04hx\n", vid, pid);

	mach = imx_device(vid, pid, list);
	if (!mach) {
		fprintf(stderr, "Could not find device vid=0x%04x pid=0x%04x\n",
			vid, pid);
		return -1;
	}

	// Get machine specific configuration file..
	conf = conf_file_name(mach->file_name, base_path, conf_path);
	if (conf == NULL)
		return -1;

	p_id = parse_conf(conf);
	if (!p_id)
		return -1;

	p_id->transfer = &transfer_simulation;
	curr = p_id->work;

	// Prefer work from command line, disable batch mode...
	if (cmd_head) {
		curr = cmd_head;
		mach->nextbatch = NULL;
	}

	err = do_work(p_id, &curr, verify);
	dbg_printf("do_work finished with err=%d, curr=%p\n", err, curr);

	do_simulation_cleanup();

	return err;
}

int do_autodetect_dev(char const *base_path, char const *conf_path,
		struct mach_id *list, int verify, struct sdp_work *cmd_head,
		int bus, int address)
{
	struct sdp_dev *p_id;
	struct mach_id *mach;
	libusb_device **devs;
	libusb_device *dev;
	int err = 0;
	ssize_t cnt;
	struct sdp_work *curr = NULL;
	libusb_device_handle *h = NULL;
	char const *conf;
	int retry;
	int config = 0;

	err = libusb_init(NULL);
	if (err < 0)
		return err;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0) {
		err = LIBUSB_ERROR_NO_DEVICE;
		goto out_deinit_usb;
	}

	if (debugmode)
		print_devs(devs);
	dev = find_imx_dev(devs, &mach, list, bus, address);
	libusb_free_device_list(devs, 1);
	if (!dev) {
		err = LIBUSB_ERROR_NO_DEVICE;
		goto out_deinit_usb;
	}

	while (mach) {
		// Get machine specific configuration file..
		conf = conf_file_name(mach->file_name, base_path, conf_path);
		if (conf == NULL) {
			err = LIBUSB_ERROR_OTHER;
			break;
		}

		p_id = parse_conf(conf);
		if (!p_id) {
			err = LIBUSB_ERROR_OTHER;
			break;
		}

		if (p_id->mode == MODE_HID)
			p_id->transfer = &transfer_hid;
		if (p_id->mode == MODE_BULK)
			p_id->transfer = &transfer_bulk;

		curr = p_id->work;

		// Prefer work from command line, disable batch mode...
		if (cmd_head) {
			curr = cmd_head;
			mach->nextbatch = NULL;
		}

		if (curr == NULL) {
			fprintf(stderr, "no job found\n");
			err = LIBUSB_ERROR_OTHER;
			break;
		}

		// Wait for device...
		printf("Trying to open device vid=0x%04x pid=0x%04x", mach->vid, mach->pid);
		fflush(stdout);
		for (retry = 0; retry < 50; retry++) {
			h = libusb_open_device_with_vid_pid(NULL, mach->vid, mach->pid);
			if (h)
				break;

			msleep(500);
			if (retry % 2)
				printf(".");
			fflush(stdout);
		}
		printf("\n");
		if (!h) {
			err = LIBUSB_ERROR_NO_DEVICE;
			fprintf(stderr, "Could not open device vid=0x%04x pid=0x%04x\n",
				mach->vid, mach->pid);
			break;
		}

		// USB private pointer is libusb device handle...
		p_id->priv = h;

		libusb_get_configuration(h, &config);
		dbg_printf("bConfigurationValue = 0x%x\n", config);

		if (libusb_kernel_driver_active(h, 0))
			 libusb_detach_kernel_driver(h, 0);

		err = libusb_claim_interface(h, 0);
		if (err) {
			fprintf(stderr, "claim interface failed\n");
			break;
		}
		printf("Interface 0 claimed\n");

		err = do_work(p_id, &curr, verify);
		dbg_printf("do_work finished with err=%d, curr=%p\n", err, curr);

		libusb_release_interface(h, 0);
		libusb_close(h);

		if (err)
			break;

		// We might have to retry the same machine in case of plugin...
		if (!curr)
			mach = mach->nextbatch;
	}

out_deinit_usb:
	libusb_exit(NULL);

	return err;
}

static const struct option long_options[] = {
	{"help",	no_argument, 		0, 'h' },
	{"debugmode",	no_argument, 		0, 'd' },
	{"verify",	no_argument, 		0, 'v' },
	{"version",	no_argument, 		0, 'V' },
	{"configdir",	required_argument, 	0, 'c' },
	{"bus",		required_argument,	0, 'b' },
	{"device",	required_argument, 	0, 'D' },
	{"sim",		required_argument, 	0, 'S' },
	{0,		0,			0, 0 },
};

int main(int argc, char * const argv[])
{
	int err, c;
	int verify = 0;
	struct sdp_work *cmd_head = NULL;
	char const *conf;
	char const *base_path = get_base_path(argv[0]);
	char const *conf_path = get_global_conf_path();
	char const *sim_vidpid = NULL;
	int bus = -1;
	int address = -1;

	while ((c = getopt_long(argc, argv, "+hdvVc:b:D:S:", long_options, NULL)) != -1) {
		switch (c)
		{
		case 'h':
		case '?':
			print_usage();
			return EXIT_SUCCESS;
		case 'd':
			debugmode = 1; /* global extern */
			break;
		case 'v':
			verify = 1;
			break;
		case 'V':
			printf("imx_usb " IMX_LOADER_VERSION "\n");
			return EXIT_SUCCESS;
		case 'c':
			conf_path = optarg;
			break;
		case 'b':
			bus = atoi(optarg);
			break;
		case 'D':
			address = atoi(optarg);
			break;
		case 'S':
			sim_vidpid = optarg;
			break;
		}
	}

	if (optind < argc) {
		// Parse optional job arguments...
		cmd_head = parse_cmd_args(argc - optind, &argv[optind]);
	}

	// Get list of machines...
	conf = conf_file_name("imx_usb.conf", base_path, conf_path);
	if (conf == NULL)
		return EXIT_FAILURE;

	struct mach_id *list = parse_imx_conf(conf);
	if (!list)
		return EXIT_FAILURE;

	if (sim_vidpid)
		err = do_simulation_dev(base_path, conf_path, list, verify,
					cmd_head, sim_vidpid);
	else
		err = do_autodetect_dev(base_path, conf_path, list, verify,
					cmd_head, bus, address);
	if (err < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
