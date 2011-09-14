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


#include <libusb.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

struct usb_id {
	unsigned short vid;
	unsigned short pid;
	const unsigned char *name;
	unsigned ram_base;
	unsigned short max_transfer;
#define MODE_HID	0
#define MODE_BULK	1
	unsigned char mode;
#define HDR_NONE	0
#define HDR_MX51	1
#define HDR_MX53	2
	unsigned char header_type;
};

#define P_DDR_INIT	0
#define P_BURN_PROGRAM	1
#define P_FILE_TO_BURN	2

static const char* file_suffixes[] = {
	"ddr_init_xm.bin",		//program to run to initialize ddr
	"ecspi_ram_write_xm.bin",	//program to run to program serial eeprom
	"ubl_ecspi.bin"			//program to be burned into serial eeprom, loaded to ram_base + 0x03f00000
};
static struct usb_id ids[] = {
//	{0x066f, 0x3780, "mx23", 0, 1024, MODE_HID, HDR_NONE},
//	{0x15a2, 0x004f, "mx28", 0, 1024, MODE_HID, HDR_NONE},
//	{0x15a2, 0x0052, "mx50", 0, 1024, MODE_HID, HDR_MX53},
	{0x15a2, 0x0054, "mx6", 0x10000000, 1024, MODE_HID, HDR_MX53},
	/* i.MX31/25/35/51/53 belong to Bulk-IO mode */
	{0x15a2, 0x0041, "mx51", 0x90000000, 64, MODE_BULK, HDR_MX51},
	{0x15a2, 0x004e, "mx53", 0x70000000, 512, MODE_BULK, HDR_MX53},
	{0x066f, 0x37ff, "linux gadget", 512, MODE_BULK, HDR_NONE},
	{0, 0}			//end of list
};

int create_file_name(char* buffer, struct usb_id *p_id, int purpose)
{
	return sprintf(buffer, "%s_%s", p_id->name, file_suffixes[purpose]);
}
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

static struct usb_id * imx_device(unsigned short vid, unsigned short pid)
{
	struct usb_id *p = ids;
	while (p->vid || p->pid) {
		if ((p->vid == vid) && (p->pid == pid))
			return p;
		p++;
	}
	return NULL;
}

static libusb_device *find_imx_dev(libusb_device **devs, struct usb_id **pp_id)
{
	int i = 0;
	struct usb_id *p;
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
		p = imx_device(desc.idVendor, desc.idProduct);
		if (p) {
			*pp_id = p;
			return dev;
		}
	}
	*pp_id = NULL;
	return NULL;
}

long GetFileSize(FILE *xfile)
{
	long size;
	fseek(xfile, 0, SEEK_END);
	size = ftell(xfile);
	rewind(xfile);
	return size;
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
/*
 * For Bulk class drivers, the device is configured as
 * EP0IN, EP0OUT control transfer
 * EP1OUT - bulk out
 * (max packet size of 512 bytes)
 * EP2IN - bulk in
 * (max packet size of 512 bytes)
 */
int transfer(struct libusb_device_handle *h, int report, unsigned char *p, unsigned cnt, int* last_trans, struct usb_id *p_id)
{
	int err;
	if (cnt > p_id->max_transfer)
		cnt = p_id->max_transfer;
	if (p_id->mode == MODE_BULK) {
		*last_trans = 0;
		err = libusb_bulk_transfer(h, (report < 3) ? 1 : 2 + EP_IN, p, cnt, last_trans, 1000);
	} else {
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
			if (err >= 0) {
				if (tmp[0] == (unsigned char)report)
					if (*last_trans > 1)
						memcpy(p, &tmp[1], *last_trans - 1);
				else {
					printf("Unexpected report %i err=%i, cnt=%i, last_trans=%i, %02x %02x %02x %02x\n",
						tmp[0], err, cnt, *last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
					err = 0;
				}
			}
		}
	}
	return err;
}

struct boot_data {
	uint32_t dest;
	uint32_t image_len;
	uint32_t plugin;
};
struct ivt_header;

struct ivt_header {
#define IVT_BARKER 0x402000d1
	uint32_t barker;
	uint32_t start_addr;
	uint32_t reserv1;
	uint32_t dcd_ptr;
	uint32_t boot_data_ptr;		/* struct boot_data * */
	uint32_t self_ptr;		/* struct ivt_header *, this - boot_data.start = offset linked at */
	uint32_t app_code_csf;
	uint32_t reserv2;
};

#define V(a) (((a)>>24)&0xff),(((a)>>16)&0xff),(((a)>>8)&0xff), ((a)&0xff)


static unsigned read_memory(struct libusb_device_handle *h, struct usb_id *p_id, unsigned addr, unsigned char *dest, unsigned cnt)
{
//							address, format, data count, data, type
	static unsigned char read_reg_command[] = {1,1, V(0),   0x20, V(0x00000004), V(0), 0x00};
	unsigned val;
	int retry = 0;
	int last_trans;
	int err;
	unsigned char tmp[64];
	read_reg_command[2] = (unsigned char)(addr >> 24);
	read_reg_command[3] = (unsigned char)(addr >> 16);
	read_reg_command[4] = (unsigned char)(addr >> 8);
	read_reg_command[5] = (unsigned char)(addr);

	read_reg_command[7] = (unsigned char)(cnt >> 24);
	read_reg_command[8] = (unsigned char)(cnt >> 16);
	read_reg_command[9] = (unsigned char)(cnt >> 8);
	read_reg_command[10] = (unsigned char)(cnt);
	for (;;) {
		err = transfer(h, 1, read_reg_command, 16, &last_trans, p_id);
		if (!err)
			break;
		printf("reade_reg_command err=%i, last_trans=%i\n", err, last_trans);
		if (retry > 5) {
			return -4;
		}
		retry++;
	}
	err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
	if (err)
		printf("r3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
	if (p_id->mode == MODE_HID) {
		err = transfer(h, 4, tmp, sizeof(tmp), &last_trans, p_id);
		if (err)
			printf("r4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
	}
	memcpy(dest, tmp, cnt);
	return err;
}

//						address, format, data count, data, type
static unsigned char write_reg_command[] = {2,2, V(0),   0x20, V(0x00000004), V(0), 0x00};
static int write_memory(struct libusb_device_handle *h, struct usb_id *p_id, unsigned addr, unsigned val)
{
	int retry = 0;
	int last_trans;
	int err = 0;
	unsigned char tmp[64];
	write_reg_command[2] = (unsigned char)(addr >> 24);
	write_reg_command[3] = (unsigned char)(addr >> 16);
	write_reg_command[4] = (unsigned char)(addr >> 8);
	write_reg_command[5] = (unsigned char)(addr);

	write_reg_command[11] = (unsigned char)(val >> 24);
	write_reg_command[12] = (unsigned char)(val >> 16);
	write_reg_command[13] = (unsigned char)(val >> 8);
	write_reg_command[14] = (unsigned char)(val);
	for (;;) {
		err = transfer(h, 1, write_reg_command, 16, &last_trans, p_id);
		if (!err)
			break;
		printf("write_reg_command err=%i, last_trans=%i\n", err, last_trans);
		if (retry > 5) {
			return -4;
		}
		retry++;
	}
	memset(tmp, 0, sizeof(tmp));
	err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
	if (err)
		printf("w3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
	if (p_id->mode == MODE_HID) {
		memset(tmp, 0, sizeof(tmp));
		err = transfer(h, 4, tmp, sizeof(tmp), &last_trans, p_id);
		if (err)
			printf("w4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
	}
	return err;
}

static int write_dcd_table_ivt(struct libusb_device_handle *h, struct usb_id *p_id, struct ivt_header *hdr)
{
	unsigned char *dcd_end;
	unsigned m_length;
#define cvt_dest_to_src		(((unsigned char *)hdr) - hdr->self_ptr)
	unsigned char* dcd;
	int err = 0;
	if (!hdr->dcd_ptr) {
		printf("No dcd table, barker=%x\n", hdr->barker);
		return 0;	//nothing to do
	}
	dcd = hdr->dcd_ptr + cvt_dest_to_src;
	m_length = (dcd[1] << 8) + dcd[2];
	printf("main dcd length %x\n", m_length);
	if ((dcd[0] != 0xd2) || (dcd[3] != 0x40)) {
		printf("Unknown tag\n");
		return -1;
	}
	dcd_end = dcd + m_length;
	dcd += 4;
	while (dcd < dcd_end) {
		unsigned s_length = (dcd[1] << 8) + dcd[2];
		unsigned char *s_end = dcd + s_length;
		printf("sub dcd length %x\n", s_length);
		if ((dcd[0] != 0xcc) || (dcd[3] != 0x04)) {
			printf("Unknown sub tag\n");
			return -1;
		}
		dcd += 4;
		while (dcd < s_end) {
			unsigned addr = (dcd[0] << 24) + (dcd[1] << 16) | (dcd[2] << 8) + dcd[3];
			unsigned val = (dcd[4] << 24) + (dcd[5] << 16) | (dcd[6] << 8) + dcd[7];
			dcd += 8;
//			printf("*0x%08x = 0x%08x\n", addr, val);
			err = write_memory(h, p_id, addr, val);
			if (err < 0)
				return err;
		}
	}
	return err;
}

void dump_long(unsigned char *src, unsigned cnt, unsigned addr)
{
	unsigned *p = (unsigned *)src;
	while (cnt >= 32) {
		printf("%08x: %08x %08x %08x %08x  %08x %08x %08x %08x\n", addr, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
		p += 8;
		cnt -= 32;
		addr += 32;
	}
	if (cnt) {
		printf("%08x:", addr);
		while (cnt >= 4) {
			printf(" %08x", p[0]);
			p++;
			cnt -= 4;
		}
		printf("\n");
	}
}

int verify_memory(struct libusb_device_handle *h, struct usb_id *p_id, FILE *xfile, unsigned offset, unsigned addr, unsigned size)
{
	unsigned char file_buf[1024];
	fseek(xfile, offset, SEEK_SET);

	while (size) {
		unsigned char mem_buf[64];
		unsigned char *p = file_buf;
		int cnt = addr & 0x3f;
		int request = min(size, sizeof(file_buf));
		if (cnt) {
			cnt = 64 - cnt;
			if (request > cnt)
				request = cnt;
		}
		cnt = fread(p, 1, request, xfile);
		if (cnt <= 0) {
			printf("Unexpected end of file, request=0x%0x, size=0x%x, cnt=%i\n", request, size, cnt);
			return -1;
		}
		size -= cnt;
		while (cnt) {
			request = min(cnt, sizeof(mem_buf));
			read_memory(h, p_id, addr, mem_buf, request);
			if (memcmp(p, mem_buf, request)) {
				printf("!!!!mismatch addr=0x%08x, offset=0x%08x\n", addr, offset);
				dump_long(p, request, offset);
				printf("\n");
				dump_long(mem_buf, request, addr);
				printf("\n");
				return -1;
			}
			p += request;
			offset += request;
			addr += request;
			cnt -= request;
		}
	}
	printf("Verify success\n");
	return 0;
}

static const unsigned char statusCommand[]={5,5,0,0,0,0, 0, 0,0,0,0, 0,0,0,0, 0};
#define MAX_IN_LENGTH 100 // max length for user input strings

#define FT_APP	0xaa
#define FT_CSF	0xcc
#define FT_DCD	0xee
#define FT_LOAD_ONLY	0x00
int DoIRomDownload(struct libusb_device_handle *h, const char *defFilename, struct usb_id *p_id, int type)
{
	FILE* xfile = NULL;
	char filename[MAX_IN_LENGTH];
//							address, format, data count, data, type
	static unsigned char dlCommand[] =    {0x04,0x04, V(0),  0x00, V(0x00000020), V(0), 0xaa};
	static unsigned char jump_command[] = {0x0b,0x0b, V(0),  0x00, V(0x00000000), V(0), 0x00};
	dlCommand[15] = type;
	printf("%s\n", defFilename);
	if (!xfile) {
		if (defFilename) {
			strcpy(filename,defFilename);
			defFilename = NULL;
		} else {
			filename[0]=0;
			printf("\r\nenter binary file name: ");
//			if (my_gets(filename,MAX_IN_LENGTH-1))
				return -1;
		}
		xfile = fopen(filename, "rb" );
		if (!xfile)
			printf("\r\nerror, can not open input file: %s\r\n", filename);
	}

	if (xfile) {
		unsigned int dladdr = 0;
		int max = p_id->max_transfer;
		int last_trans, err;
#define MAX_PACKET_SIZE (1024*4)			//512	//1024
		unsigned char buf[MAX_PACKET_SIZE];
		unsigned transferSize=0;
		unsigned fsize = GetFileSize(xfile);
		unsigned char *p = buf;
		int cnt = fread(buf, 1 , MAX_PACKET_SIZE, xfile);
		unsigned char tmp[64];
		unsigned skip = 0;
		unsigned start_addr = 0;
		int retry = 0;
		if (cnt < 0x20) {
			fclose(xfile);
			return -2;
		}
		if (type == FT_APP) {
			while (skip <= 0x400) {
				switch (p_id->header_type) {
				case HDR_MX51:
					if (((unsigned *)p)[1] == 0xb1) {
						dladdr = ((unsigned *)p)[6];
					}
					break;
				case HDR_MX53:
					if (((unsigned *)p)[0] == IVT_BARKER) {
						struct ivt_header *hdr = (struct ivt_header *)p;
						dladdr = hdr->self_ptr;
						write_dcd_table_ivt(h, p_id, hdr);
						start_addr = hdr->self_ptr;	//hdr->start_addr; //
						printf("dcd_ptr=0x%08x\n", hdr->dcd_ptr);
						hdr->dcd_ptr = 0;	//don't init memory twice!!!
						hdr->boot_data_ptr = 0;
					}
					break;
				}
				if (dladdr)
					break;
				skip += 0x400;
				p += 0x400;
				cnt -= 0x400;
				fsize -= 0x400;
			}
		} else {
			dladdr = p_id->ram_base + 0x03f00000;
		}
		if (!dladdr) {
			printf("\nunknown load address\r\n");
			fclose(xfile);
			return -3;
		}
		printf("\nloading binary file(%s) to %08x\r\n", filename, dladdr);

		dlCommand[2] = (unsigned char)(dladdr>>24);
		dlCommand[3] = (unsigned char)(dladdr>>16);
		dlCommand[4] = (unsigned char)(dladdr>>8);
		dlCommand[5] = (unsigned char)(dladdr);

		dlCommand[7] = (unsigned char)(fsize>>24);
		dlCommand[8] = (unsigned char)(fsize>>16);
		dlCommand[9] = (unsigned char)(fsize>>8);
		dlCommand[10] = (unsigned char)(fsize);

		for (;;) {
			err = transfer(h, 1, dlCommand, 16, &last_trans, p_id);
			if (!err)
				break;
			printf("dlCommand err=%i, last_trans=%i\n", err, last_trans);
			if (retry > 5) {
				fclose(xfile);
				return -4;
			}
			retry++;
		}
		retry = 0;
		if (p_id->mode == MODE_BULK) {
			err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
			if (err)
				printf("in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		}

		while (1) {
			int retry;
			int c;
			if (cnt > (int)(fsize-transferSize)) cnt = (fsize-transferSize);
			if (cnt <= 0)
				break;
			retry = 0;
			c = cnt;
			while (c) {
				err = transfer(h, 2, p, min(c, max), &last_trans, p_id);
//				printf("err=%i, last_trans=0x%x, c=0x%x, max=0x%x\n", err, last_trans, c, max);
				if (err) {
					printf("out err=%i, last_trans=%i c=0x%x max=0x%x transferSize=0x%X retry=%i\n", err, last_trans, c, max, transferSize, retry);
					if (retry >= 10)
						break;
					if (max >= 16)
						max >>= 1;
					else
						max <<= 1;
//					err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
//					printf("in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
					usleep(10000);
					retry++;
					continue;
				}
				max = p_id->max_transfer;
				retry = 0;
				if (c < last_trans) {
					printf("error: last_trans=0x%x, attempted only=0%x\n", last_trans, c);
					c = last_trans;
				}
				if (!last_trans) {
					printf("Nothing last_trans, err=%i\n", err);
					break;
				}
				p += last_trans;
				c -= last_trans;
				transferSize += last_trans;
			}
			if (!last_trans) break;
			if (feof(xfile)) break;
			cnt = fread(buf, 1 , MAX_PACKET_SIZE, xfile);
			p = buf;
		}
		printf("\r\n<<<%i, %i bytes>>>\r\n", fsize, transferSize);

		if (p_id->mode == MODE_HID) {
			err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
			if (err)
				printf("3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
			err = transfer(h, 4, tmp, sizeof(tmp), &last_trans, p_id);
			if (err)
				printf("4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);

			if (type == FT_APP) {
//				verify_memory(h, p_id, xfile, skip + 20, dladdr + 20, fsize - 20);
				printf("jumping to 0x%08x\n", start_addr);
				jump_command[2] = (unsigned char)(start_addr >> 24);
				jump_command[3] = (unsigned char)(start_addr >> 16);
				jump_command[4] = (unsigned char)(start_addr >> 8);
				jump_command[5] = (unsigned char)(start_addr);
				retry = 0;
				for (;;) {
					err = transfer(h, 1, jump_command, 16, &last_trans, p_id);
					if (!err)
						break;
					printf("jump_command err=%i, last_trans=%i\n", err, last_trans);
					if (retry > 5) {
						return -4;
					}
					retry++;
				}
				memset(tmp, 0, sizeof(tmp));
				err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
				printf("j3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
				if (p_id->mode == MODE_HID) {
					memset(tmp, 0, sizeof(tmp));
					err = transfer(h, 4, tmp, sizeof(tmp), &last_trans, p_id);
					printf("j4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
				}
			}
		}
		fclose(xfile);
		return (fsize == transferSize) ? 0 : -6;
	}
	return -5;
}

int do_status(libusb_device_handle *h, struct usb_id *p_id)
{
	int last_trans;
	unsigned char tmp[64];
	int retry = 0;
	int err;
	for (;;) {
		err = transfer(h, 1, (unsigned char*)statusCommand, 16, &last_trans, p_id);
		printf("report 1, wrote %i bytes, err=%i\n", last_trans, err);
		memset(tmp, 0, sizeof(tmp));
		err = transfer(h, 3, tmp, 64, &last_trans, p_id);
		printf("report 3, read %i bytes, err=%i\n", last_trans, err);
		printf("read=%02x %02x %02x %02x\n", tmp[0], tmp[1], tmp[2], tmp[3]);
		if (!err)
			break;
		retry++;
		if (retry > 5)
			break;
	}
	if (p_id->mode == MODE_HID) {
		err = transfer(h, 4, tmp, sizeof(tmp), &last_trans, p_id);
		if (err)
			printf("4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
	}
	return err;
}

int main(int argc, char const *const argv[])
{
	struct usb_id *p_id;
	libusb_device **devs;
	libusb_device *dev;
	int r;
	int err;
	ssize_t cnt;
	libusb_device_handle *h = NULL;

	r = libusb_init(NULL);
	if (r < 0)
		return r;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0)
		return (int) cnt;

	print_devs(devs);
	dev = find_imx_dev(devs, &p_id);
	if (dev) {
		err = libusb_open(dev, &h);
		if (err)
			printf("Could not open device, err=%i\n", err);
	}
	libusb_free_device_list(devs, 1);

	if (h) {
		int config = 0;
		int err;
		libusb_get_configuration(h, &config);
		printf("%04x:%04x(%s) bConfigurationValue =%x\n", p_id->vid, p_id->pid, p_id->name, config);
		if (libusb_kernel_driver_active(h, 0))
			 libusb_detach_kernel_driver(h, 0);

		err = libusb_claim_interface(h, 0);
		if (!err) {
			int i;
			unsigned char tmp[MAX_IN_LENGTH];
			printf("Interface 0 claimed\n");
			err = do_status(h, p_id);
			if (!err) {
				if (1 == argc) {
					create_file_name(tmp, p_id, P_DDR_INIT);
				} else {
					strcpy(tmp,argv[1]);
				}
				err = DoIRomDownload(h, tmp, p_id, FT_APP);
				if (p_id->mode != MODE_HID) {
					do_status(h, p_id);
					if (err)
						goto exit;
					libusb_release_interface(h, 0);
					libusb_close(h);
					libusb_exit(NULL);
					printf("sleeping\n");
					sleep(10);
					printf("done sleeping\n");
					r = libusb_init(NULL);
					h = libusb_open_device_with_vid_pid(NULL, p_id->vid, p_id->pid);
					if (err) {
						printf("Could not open device, err=%i\n", err);
						goto exit;
					}
					if (libusb_kernel_driver_active(h, 0))
						 libusb_detach_kernel_driver(h, 0);
					err = libusb_claim_interface(h, 0);
					if (err) {
						printf("claim failed, err=%i\n", err);
						goto exit;
					}
					err = do_status(h, p_id);
					if (err) {
						printf("status failed, err=%i\n", err);
						goto exit;
					}
					create_file_name(tmp, p_id, P_FILE_TO_BURN);
					err = DoIRomDownload(h, tmp, p_id, FT_LOAD_ONLY);
					if (err)
						goto exit;

					create_file_name(tmp, p_id, P_BURN_PROGRAM);
					DoIRomDownload(h, tmp, p_id, FT_APP);
					do_status(h, p_id);
				}
			}
exit:
			libusb_release_interface(h, 0);
		} else {
			printf("Claim failed\n");
		}
		libusb_close(h);
	}
	libusb_exit(NULL);
	return 0;
}

