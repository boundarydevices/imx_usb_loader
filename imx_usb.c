/*
 * imx_usb:
 *
 * Program to download and execute an image over the USB boot protocol
 * on i.MX series processors.
 * 
 * Low-level SCSI and USB Mass Storage code borrowed from:
 *   http://git.libusb.org/?p=libusb-pbatard.git;a=blob;f=examples/xusb.c
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
#include <stdarg.h>
#include <libgen.h>

//#define DEBUG

#include <libusb.h>

#define RETRY_MAX                     5
#define REQUEST_SENSE_LENGTH          0x12

// Section 5.1: Command Block Wrapper (CBW)
struct command_block_wrapper {
	uint8_t dCBWSignature[4];
	uint32_t dCBWTag;
	uint32_t dCBWDataTransferLength;
	uint8_t bmCBWFlags;
	uint8_t bCBWLUN;
	uint8_t bCBWCBLength;
	uint8_t CBWCB[16];
};

// Section 5.2: Command Status Wrapper (CSW)
struct command_status_wrapper {
	uint8_t dCSWSignature[4];
	uint32_t dCSWTag;
	uint32_t dCSWDataResidue;
	uint8_t bCSWStatus;
};

static uint8_t cdb_length[256] = {
//	 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,  //  0
	06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,06,  //  1
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  2
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  3
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  4
	10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,  //  5
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  6
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  7
	16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,  //  8
	16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,  //  9
	12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,  //  A
	12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,  //  B
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  C
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  D
	00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  E
	16,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,  //  F
};

#define UTP_FLAG_COMMAND		0x00000001
#define UTP_FLAG_DATA			0x00000002
#define UTP_FLAG_STATUS			0x00000004    //indicate an error happens
#define UTP_FLAG_REPORT_BUSY	0x10000000

#define UTP_MAX_LEN 0x10000

#define GADGET_VID 0x066f
#define GADGET_PID 0x37ff
#define GADGET_EP_IN   0x81
#define GADGET_EP_OUT  0x01

#pragma pack(1)
/* the structure of utp message which is mapped to 16-byte SCSI CBW's CDB */
struct utp_msg {
	uint8_t  f0;
	uint8_t  utp_msg_type;
	uint32_t utp_msg_tag;
	union {
		struct {
			uint32_t param_lsb;
			uint32_t param_msb;
		};
		uint64_t param;
	};
};

/* the structure of utp response which is mapped to 16-byte SCSI 
 * fixed format sense data */
struct utp_resp {
	uint8_t  response_code;
	uint8_t  obsolete1;
	uint8_t sense_key;
	uint32_t utp_reply_info_lsb;
	uint8_t additional_sense_length1;
	uint32_t utp_reply_info_msb;
	uint8_t additional_sense_code1;
	uint8_t utp_reply_code; 	
	uint8_t pad[4];
};

enum utp_msg_type {
	UTP_POLL = 0,
	UTP_EXEC,
	UTP_GET,
	UTP_PUT,
};

enum utp_reply_code {
	UTP_PASS = 0,
	UTP_EXIT,
	UTP_BUSY,
	UTP_SIZE,
};
#pragma pack()

#define get_min(a, b) (((a) < (b)) ? (a) : (b))

struct mach_id;
struct mach_id {
	struct mach_id * next;
	unsigned short vid;
	unsigned short pid;
	unsigned char file_name[256];
};

inline static int perr(char const *format, ...)
{
	va_list args;
	int r;

	va_start (args, format);
	r = vfprintf(stderr, format, args);
	va_end(args);

	return r;
}

int send_mass_storage_command(libusb_device_handle *handle, uint8_t endpoint, uint8_t lun,
	uint8_t *cdb, uint8_t direction, int data_length, uint32_t *ret_tag)
{
	static uint32_t tag = 1;
	uint8_t cdb_len;
	int i, r, size;
	struct command_block_wrapper cbw;

	if (cdb == NULL) {
		return -1;
	}

	if (endpoint & LIBUSB_ENDPOINT_IN) {
		perr("send_mass_storage_command: cannot send command on IN endpoint\n");
		return -1;
	}

	cdb_len = cdb_length[cdb[0]];
	if ((cdb_len == 0) || (cdb_len > sizeof(cbw.CBWCB))) {
		perr("send_mass_storage_command: don't know how to handle this command (%02X, length %d)\n",
			cdb[0], cdb_len);
		return -1;
	}

	memset(&cbw, 0, sizeof(cbw));
	cbw.dCBWSignature[0] = 'U';
	cbw.dCBWSignature[1] = 'S';
	cbw.dCBWSignature[2] = 'B';
	cbw.dCBWSignature[3] = 'C';
	*ret_tag = tag;
	cbw.dCBWTag = tag++;
	cbw.dCBWDataTransferLength = data_length;
	cbw.bmCBWFlags = direction;
	cbw.bCBWLUN = lun;
	// Subclass is 1 or 6 => cdb_len
	cbw.bCBWCBLength = cdb_len;
	memcpy(cbw.CBWCB, cdb, cdb_len);

	i = 0;
	do {
		// The transfer length must always be exactly 31 bytes.
		r = libusb_bulk_transfer(handle, endpoint, (unsigned char*)&cbw, 31, &size, 1000);
		if (r == LIBUSB_ERROR_PIPE) {
			libusb_clear_halt(handle, endpoint);
		}
		i++;
	} while ((r == LIBUSB_ERROR_PIPE) && (i<RETRY_MAX));
	if (r != LIBUSB_SUCCESS) {
		perr("   send_mass_storage_command: %s\n", libusb_error_name(r));
		return -1;
	}

	return 0;
}

int get_mass_storage_status(libusb_device_handle *handle, uint8_t endpoint, uint32_t expected_tag)
{
	int i, r, size;
	struct command_status_wrapper csw;

	// The device is allowed to STALL this transfer. If it does, you have to
	// clear the stall and try again.
	i = 0;
	do {
		r = libusb_bulk_transfer(handle, endpoint, (unsigned char*)&csw, 13, &size, 1000);
		if (r == LIBUSB_ERROR_PIPE) {
			libusb_clear_halt(handle, endpoint);
		}
		i++;
	} while ((r == LIBUSB_ERROR_PIPE) && (i<RETRY_MAX));
	if (r != LIBUSB_SUCCESS) {
		perr("   get_mass_storage_status: %s\n", libusb_error_name(r));
		return -1;
	}
	if (size != 13) {
		perr("   get_mass_storage_status: received %d bytes (expected 13)\n", size);
		return -1;
	}
	if (csw.dCSWTag != expected_tag) {
		perr("   get_mass_storage_status: mismatched tags (expected %08X, received %08X)\n",
			expected_tag, csw.dCSWTag);
		return -1;
	}
	// For this test, we ignore the dCSWSignature check for validity...
	//printf("   Mass Storage Status: %02X (%s)\n", csw.bCSWStatus, csw.bCSWStatus?"FAILED":"Success");
	if (csw.dCSWTag != expected_tag)
		return -1;
	if (csw.bCSWStatus) {
		// REQUEST SENSE is appropriate only if bCSWStatus is 1, meaning that the
		// command failed somehow.  Larger values (2 in particular) mean that
		// the command couldn't be understood.
		if (csw.bCSWStatus == 1)
			return -2;	// request Get Sense
		else
			return -1;
	}

	// In theory we also should check dCSWDataResidue.  But lots of devices
	// set it wrongly.
	return 0;
}

void get_sense(libusb_device_handle *handle, uint8_t endpoint_in, uint8_t endpoint_out, uint8_t *data)
{
	uint8_t cdb[16];	// SCSI Command Descriptor Block
	uint8_t sense[18];
	uint32_t expected_tag;
	int size;

	// Request Sense
	memset(sense, 0, sizeof(sense));
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0x03;	// Request Sense
	cdb[4] = REQUEST_SENSE_LENGTH;

	send_mass_storage_command(handle, endpoint_out, 0, cdb, LIBUSB_ENDPOINT_IN, REQUEST_SENSE_LENGTH, &expected_tag);
	libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)&sense, REQUEST_SENSE_LENGTH, &size, 1000);

	if ((sense[0] != 0x70) && (sense[0] != 0x71)) {
		perr("   ERROR No sense data\n");
	}
	
	// Strictly speaking, the get_mass_storage_status() call should come
	// before these perr() lines.  If the status is nonzero then we must
	// assume there's no data in the buffer.  For xusb it doesn't matter.
	get_mass_storage_status(handle, endpoint_in, expected_tag);
	
	if (data)
	{
		memcpy(data, sense, REQUEST_SENSE_LENGTH);
	}
}

int dump_utp_resp(struct utp_resp *utp_rsp)
{
#ifdef DEBUG
	printf("UTP Extended Reply Info: %d\n",be32toh(utp_rsp->utp_reply_info_lsb));
	printf("UTP Extended Reply Code: ");
	switch (utp_rsp->utp_reply_code) {
		case UTP_PASS:
			printf("PASS");
			break;
		case UTP_EXIT:
			printf("EXIT");
			break;
		case UTP_BUSY:
			printf("BUSY");
			break;
		case UTP_SIZE:
			printf("SIZE");
			break;
		default:
			printf("Unknown!\n");
			break;
	}
	printf("\n");
#endif
}

int send_utp_command(
	libusb_device_handle *handle, uint8_t endpoint_in, uint8_t endpoint_out,
	enum utp_msg_type msg_type, uint64_t param, int block_size, char *buffer
)
{
	struct utp_msg utp_cmd;
	struct utp_resp utp_rsp;
	static uint32_t utp_tag = 0;
	uint32_t expected_tag;
	int err;
	int lun = 0;
	int size;
	int poll;
	int msec_sleep = 8;
	int ret = -1;

	utp_cmd.f0 = 0xF0;
	do {
		utp_tag++; poll = 0;
		utp_cmd.utp_msg_type = msg_type;
		utp_cmd.utp_msg_tag = htobe32(utp_tag);
		utp_cmd.param = htobe64(param);
		err = send_mass_storage_command(handle, endpoint_out, lun, (uint8_t *)&utp_cmd, LIBUSB_ENDPOINT_IN, block_size, &expected_tag);
		if (block_size > 0) {
			libusb_bulk_transfer(handle, endpoint_out, buffer, block_size, &size, 5000);
		}
		err = get_mass_storage_status(handle, endpoint_in, expected_tag);
		if (err == -2) {
			get_sense(handle, endpoint_in, endpoint_out, (uint8_t *)&utp_rsp);
			dump_utp_resp(&utp_rsp);
			if (utp_rsp.utp_reply_code == UTP_BUSY) {
				msg_type = UTP_POLL;
				param = 0;
				block_size = 0;
				poll = 1;
				/* Sleep with an exponential backoff */
				usleep(msec_sleep*1000); msec_sleep *= 2;
			}
			ret = utp_rsp.utp_reply_code;
		} else if (err == 0) {
			ret = UTP_PASS;
		} else {
			printf("Unknown UTP status (%d)!\n", err);
		}
	} while (poll);

	return(ret);
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
int get_val(char** pp, int base)
{
	int val = 0;
	char *p = *pp;
	while (*p==' ') p++;
	if (*p=='0') {
		p++;
		if ((*p=='x')||(*p=='X')) {
			p++;
			base = 16;
		}
	}
	while (*p) {
		char c = *p++;
		if ((c >= '0')&&(c <= '9')) {
			c -= '0';
		} else {
			c &= ~('a'-'A');
			if ((c >= 'A')&&(c <= 'F')) c -= ('A'-10);
			else {
				p--;
				break;
			}
		}
		if (c >= base) {
			printf("Syntax error: %s\n", p-1);
			val = -1;
			break;
		}
		val = (val * base) + c;
	}
	while (*p==' ') p++;
	*pp = p;
	return val;
}

unsigned char *move_string(unsigned char *dest, unsigned char *src, unsigned cnt)
{
	int i = 0;
	while (i < cnt) {
		char c = *src++;
		if ((!c) || (c == ' ') || (c == 0x0d) || (c == '\n') || (c == '#') || (c == ':')) {
			src--;
			break;
		}
		dest[i++] = c;
	}
	return src;
}

static struct mach_id *parse_imx_conf(char *filename)
{
	unsigned short vid;
	unsigned short pid;
	char line[512];
	struct mach_id *head = NULL;
	struct mach_id *tail = NULL;
	struct mach_id *curr = NULL;
	char *p;
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
//		printf("vid=0x%04x pid=0x%04x file_name=%s\n", curr->vid, curr->pid, curr->file_name);
	}
	fclose(xfile);
	return head;
}

struct ram_area {
	unsigned start;
	unsigned size;
};

struct mem_work {
	struct mem_work *next;
	unsigned type;
#define MEM_TYPE_READ		0
#define MEM_TYPE_WRITE		1
#define MEM_TYPE_MODIFY		2
	unsigned vals[3];
};

struct usb_work;
struct usb_work {
	struct usb_work *next;
	struct mem_work *mem;
	unsigned char filename[256];
	unsigned char target_filename[256];
	unsigned char dcd;
	unsigned char clear_dcd;	//means clear dcd_ptr
	unsigned char plug;
#define J_ADDR		1
#define J_HEADER	2
#define J_HEADER2	3
	unsigned char jump_mode;
	unsigned load_addr;
	unsigned jump_addr;
};

struct usb_id {
	unsigned short vid;
	unsigned short pid;
	unsigned char name[64];
	unsigned short max_transfer;
#define MODE_HID	0
#define MODE_BULK	1
	unsigned char mode;
#define HDR_NONE	0
#define HDR_MX51	1
#define HDR_MX53	2
	unsigned char header_type;
	struct ram_area ram[8];
	struct usb_work *work;
};

char *skip(char *p, char c)
{
	while (*p==' ') p++;
	if (*p == c) {
		p++;
	}
	while (*p==' ') p++;
	return p;
}

int end_of_line(char *p)
{
	while (*p == ' ') p++;
	if ((!p[0]) || (*p == '#') || (*p == '\n') || (*p == '\r'))
		return 1;
	return 0;
}


void parse_mem_work(struct usb_work *curr, struct mach_id *mach, char *p)
{
	struct mem_work *wp;
	struct mem_work **link;
	struct mem_work w;
	int i;
	char *start = p;

	p = skip(p,':');
	memset(&w, 0, sizeof(w));
	if (strncmp(p, "read", 4) == 0) {
		p += 4;
		p = skip(p,',');
		i = MEM_TYPE_READ;
	} else if (strncmp(p, "write", 5) == 0) {
		p += 5;
		p = skip(p,',');
		i = MEM_TYPE_WRITE;
	} else if (strncmp(p, "modify", 6) == 0) {
		p += 6;
		p = skip(p,',');
		i = MEM_TYPE_MODIFY;
	} else {
		printf("%s: syntax error: %s {%s}\n", mach->file_name, p, start);
	}
	w.type = i;
	i = 0;
	for (;;) {
		w.vals[i] = get_val(&p, 16);
		if (i >= w.type)
			break;
		p = skip(p,',');
		if ((*p == 0) || (*p == '#')) {
			printf("%s: missing argment: %s {%s}\n", mach->file_name, p, start);
			return;
		}
		i++;
	}
	if (!end_of_line(p)) {
		printf("%s: syntax error: %s {%s}\n", mach->file_name, p, start);
		return;
	}
	wp = (struct mem_work *)malloc(sizeof(struct mem_work));
	if (!wp)
		return;
	link = &curr->mem;
	while (*link)
		link = &(*link)->next;
	*wp = w;
	*link = wp;
}

void parse_file_work(struct usb_work *curr, struct mach_id *mach, char *p)
{
	char *start = p;

	p = move_string(curr->filename, p, sizeof(curr->filename) - 1);
	p = skip(p,':');
	for (;;) {
		char *q = p;
		if ((!*p) || (*p == '#')  || (*p == '\n') || (*p == 0x0d))
			break;
		if (strncmp(p, "dcd", 3) == 0) {
			p += 3;
			p = skip(p,',');
			curr->dcd = 1;
		}
		if (strncmp(p, "clear_dcd", 9) == 0) {
			p += 9;
			p = skip(p,',');
			curr->clear_dcd = 1;
//			printf("clear_dcd\n");
		}
		if (strncmp(p, "plug", 4) == 0) {
			p += 4;
			p = skip(p,',');
			curr->plug = 1;
//			printf("plug\n");
		}
		if (strncmp(p, "load", 4) == 0) {
			p += 4;
			curr->load_addr = get_val(&p, 16);
			p = skip(p,',');
		}
		if (strncmp(p, "jump", 4) == 0) {
			p += 4;
			curr->jump_mode = J_ADDR;
			curr->jump_addr = get_val(&p, 16);
			if (strncmp(p, "header2", 7) == 0) {
				p += 7;
				p = skip(p,',');
				curr->jump_mode = J_HEADER2;
			} else if (strncmp(p, "header", 6) == 0) {
				p += 6;
				p = skip(p,',');
				curr->jump_mode = J_HEADER;
			}
			p = skip(p,',');
//			printf("jump\n");
		}
		if (strncmp(p, "save", 4) == 0) {
			p += 4;
			p = skip(p,' ');
			p = move_string(curr->target_filename, p, sizeof(curr->target_filename) - 1);
			p = skip(p,',');
//			printf("save\n");
		}
		if (q == p) {
			printf("%s: syntax error: %s {%s}\n", mach->file_name, p, start);
			break;
		}
	}
}

/*
 * #hid/bulk,[old_header,]max packet size, {ram start, ram size}(repeat valid ram areas)
 *hid,1024,0x10000000,1G,0x00907000,0x31000
 *
 */
void parse_transfer_type(struct usb_id *usb, struct mach_id *mach, char *p)
{
	int i;

	if (strncmp(p, "hid", 3) == 0) {
		p += 3;
		p = skip(p,',');
		usb->mode = MODE_HID;
	} else if (strncmp(p, "bulk", 4) == 0) {
		p += 4;
		p = skip(p,',');
		usb->mode = MODE_BULK;
	} else {
		printf("%s: hid/bulk expected\n", mach->file_name);
	}
	if (strncmp(p, "old_header", 10) == 0) {
		p += 10;
		p = skip(p,',');
		usb->header_type = HDR_MX51;
	} else {
		usb->header_type = HDR_MX53;
	}
	usb->max_transfer = get_val(&p, 10);
	p = skip(p,',');
	for (i = 0; i < 8; i++) {
		usb->ram[i].start = get_val(&p, 10);
		p = skip(p,',');
		usb->ram[i].size = get_val(&p, 10);
		if ((*p == 'G') || (*p == 'g')) {
			usb->ram[i].size <<= 30;
			p++;
		} else if ((*p == 'M') || (*p == 'm')) {
			usb->ram[i].size <<= 20;
			p++;
		} else if ((*p == 'K') || (*p == 'k')) {
			usb->ram[i].size <<= 10;
			p++;
		}
		p = skip(p,',');
		if ((*p == '#') || (*p == '\n') || (!*p))
			break;
	}
}

static struct usb_id *parse_conf(struct mach_id *mach)
{
	char line[512];
	FILE *xfile;
	char *p;
	struct usb_work *tail = NULL;
	struct usb_work *curr = NULL;
	struct usb_id *usb = (struct usb_id *)malloc(sizeof(struct usb_id));
	if (!usb)
		return NULL;
	memset(usb, 0, sizeof(struct usb_id));

	xfile = fopen(mach->file_name, "rb" );
	if (!xfile) {
		printf("Could not open file: {%s}\n", mach->file_name);
		free(usb);
		return NULL;
	}
	printf("parse %s\n", mach->file_name);

	usb->vid = mach->vid;
	usb->pid = mach->pid;
	while (fgets(line, sizeof(line), xfile) != NULL) {
		p = line;
		while (*p==' ') p++;
		if (p[0] == '#')
			continue;
		if (p[0] == 0)
			continue;
		if (p[0] == '\n')
			continue;
		if (p[0] == 0x0d)
			continue;
		if (!usb->name[0]) {
			p = move_string(usb->name, p, sizeof(usb->name) - 1);
			continue;
		}
		if (!usb->max_transfer) {
			parse_transfer_type(usb, mach, p);
			continue;
		}
		/*
		 * #file:dcd,plug,load nnn,jump [nnn/header/header2]
		 */
		if (!curr) {
			curr = (struct usb_work *)malloc(sizeof(struct usb_work));
			if (!curr)
				break;
			memset(curr, 0, sizeof(struct usb_work));
			if (!usb->work)
				usb->work = curr;
			if (tail)
				tail->next = curr;
			tail = curr;
			curr->load_addr = usb->ram[0].start + 0x03f00000;	/* default */
		}

		if (p[0] == ':') {
			parse_mem_work(curr, mach, p);
		} else {
			parse_file_work(curr, mach, p);
			curr = NULL;
		}
	}
	return usb;
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
	*pp_id = NULL;
	return NULL;
}

long get_file_size(FILE *xfile)
{
	long size;
	fseek(xfile, 0, SEEK_END);
	size = ftell(xfile);
	rewind(xfile);
//	printf("filesize=%lx\n", size);
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
void dump_bytes(unsigned char *src, unsigned cnt, unsigned addr);

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
#ifdef DEBUG
	printf("report=%i\n", report);
	if (report < 3)
		dump_bytes(p, cnt, 0);
#endif
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
	}
#ifdef DEBUG
	if (report >= 3)
		dump_bytes(p, cnt, 0);
#endif
	return err;
}

struct boot_data {
	uint32_t dest;
	uint32_t image_len;
	uint32_t plugin;
};

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

/*
 * MX51 header type
 */
struct old_app_header {
	uint32_t app_start_addr;
#define APP_BARKER	0xb1
#define DCD_BARKER	0xb17219e9
	uint32_t app_barker;
	uint32_t csf_ptr;
	uint32_t dcd_ptr_ptr;
	uint32_t srk_ptr;
	uint32_t dcd_ptr;
	uint32_t app_dest_ptr;
};

#define V(a) (((a)>>24)&0xff),(((a)>>16)&0xff),(((a)>>8)&0xff), ((a)&0xff)


static int read_memory(struct libusb_device_handle *h, struct usb_id *p_id, unsigned addr, unsigned char *dest, unsigned cnt)
{
//							address, format, data count, data, type
	static unsigned char read_reg_command[] = {1,1, V(0),   0x20, V(0x00000004), V(0), 0x00};
	unsigned val;
	int retry = 0;
	int last_trans;
	int err;
	int rem;
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
		printf("read_reg_command err=%i, last_trans=%i\n", err, last_trans);
		if (retry > 5) {
			return -4;
		}
		retry++;
	}
	err = transfer(h, 3, tmp, 4, &last_trans, p_id);
	if (err) {
		printf("r3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		return err;
	}
	rem = cnt;
	while (rem) {
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
		err = transfer(h, 4, tmp, 64, &last_trans, p_id);
		if (err) {
			printf("r4 in err=%i, last_trans=%i  %02x %02x %02x %02x cnt=%d rem=%d\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3], cnt, rem);
			break;
		}
		if ((last_trans > rem) || (last_trans > 64)) {
			if ((last_trans == 64) && (cnt == rem)) {
				/* Last transfer is expected to be too large for HID */
			} else {
				printf("err: %02x %02x %02x %02x cnt=%d rem=%d last_trans=%i\n", tmp[0], tmp[1], tmp[2], tmp[3], cnt, rem, last_trans);
			}
			last_trans = rem;
			if (last_trans > 64)
				last_trans = 64;
		}
		memcpy(dest, tmp, last_trans);
		dest += last_trans;
		rem -= last_trans;
	}
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
	if (0) printf("err=%i, last_trans=%i  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
			err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3],
			tmp[4], tmp[5], tmp[6], tmp[7]);
	if (err) {
		printf("w3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		printf("addr=0x%08x, val=0x%08x\n", addr, val);
	}
	memset(tmp, 0, sizeof(tmp));
	err = transfer(h, 4, tmp, sizeof(tmp), &last_trans, p_id);
	if (0) printf("err=%i, last_trans=%i  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
			err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3],
			tmp[4], tmp[5], tmp[6], tmp[7]);
	if (err)
		printf("w4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
	return err;
}

int perform_mem_work(struct libusb_device_handle *h, struct usb_id *p_id, struct mem_work *mem)
{
	unsigned tmp, tmp2;

	while (mem) {
		switch (mem->type) {
		case MEM_TYPE_READ:
			read_memory(h, p_id, mem->vals[0], (unsigned char *)&tmp, 4);
			printf("*%x is %x\n", mem->vals[0], tmp);
			break;
		case MEM_TYPE_WRITE:
			write_memory(h, p_id, mem->vals[0], mem->vals[1]);
			printf("%x write %x\n", mem->vals[0], mem->vals[1]);
			break;
		case MEM_TYPE_MODIFY:
			read_memory(h, p_id, mem->vals[0], (unsigned char *)&tmp, 4);
			tmp2 = (tmp & ~mem->vals[1]) | mem->vals[2];
			printf("%x = %x to %x\n", mem->vals[0], tmp, tmp2);
			write_memory(h, p_id, mem->vals[0], tmp2);
			break;
		}
		mem = mem->next;
	}
}

static int write_dcd_table_ivt(struct libusb_device_handle *h, struct usb_id *p_id, struct ivt_header *hdr, unsigned char *file_start, unsigned cnt)
{
	unsigned char *dcd_end;
	unsigned m_length;
#define cvt_dest_to_src		(((unsigned char *)hdr) - hdr->self_ptr)
	unsigned char* dcd;
	unsigned char* file_end = file_start + cnt;
	int err = 0;
	if (!hdr->dcd_ptr) {
		printf("No dcd table, barker=%x\n", hdr->barker);
		return 0;	//nothing to do
	}
	dcd = hdr->dcd_ptr + cvt_dest_to_src;
	if ((dcd < file_start) || ((dcd + 4) > file_end)) {
		printf("bad dcd_ptr %08x\n", hdr->dcd_ptr);
		return -1;
	}
	m_length = (dcd[1] << 8) + dcd[2];
	printf("main dcd length %x\n", m_length);
	if ((dcd[0] != 0xd2) || (dcd[3] != 0x40)) {
		printf("Unknown tag\n");
		return -1;
	}
	dcd_end = dcd + m_length;
	if (dcd_end > file_end) {
		printf("bad dcd length %08x\n", m_length);
		return -1;
	}
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
		if (s_end > dcd_end) {
			printf("error s_end(%p) > dcd_end(%p)\n", s_end, dcd_end);
			return -1;
		}
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

static int get_dcd_range_old(struct old_app_header *hdr,
		unsigned char *file_start, unsigned cnt,
		unsigned char **pstart, unsigned char **pend)
{
	unsigned char *dcd_end;
	unsigned m_length;
#define cvt_dest_to_src_old		(((unsigned char *)&hdr->dcd_ptr) - hdr->dcd_ptr_ptr)
	unsigned char* dcd;
	unsigned val;
	unsigned char* file_end = file_start + cnt;
	int err = 0;

	if (!hdr->dcd_ptr) {
		printf("No dcd table, barker=%x\n", hdr->app_barker);
		*pstart = *pend = ((unsigned char *)hdr) + sizeof(struct old_app_header);
		return 0;	//nothing to do
	}
	dcd = hdr->dcd_ptr + cvt_dest_to_src_old;
	if ((dcd < file_start) || ((dcd + 8) > file_end)) {
		printf("bad dcd_ptr %08x\n", hdr->dcd_ptr);
		return -1;
	}
	val = (dcd[0] << 0) + (dcd[1] << 8) | (dcd[2] << 16) + (dcd[3] << 24);
	printf("main dcd length %x\n", m_length);
	if (val != DCD_BARKER) {
		printf("Unknown tag\n");
		return -1;
	}
	dcd += 4;
	m_length =  (dcd[0] << 0) + (dcd[1] << 8) | (dcd[2] << 16) + (dcd[3] << 24);
	dcd += 4;
	dcd_end = dcd + m_length;
	if (dcd_end > file_end) {
		printf("bad dcd length %08x\n", m_length);
		return -1;
	}
	*pstart = dcd;
	*pend = dcd_end;
	return 0;
}

static int write_dcd_table_old(struct libusb_device_handle *h, struct usb_id *p_id, struct old_app_header *hdr, unsigned char *file_start, unsigned cnt)
{
	unsigned val;
	unsigned char *dcd_end;
	unsigned char* dcd;
	int err = get_dcd_range_old(hdr, file_start, cnt, &dcd, &dcd_end);
	if (err < 0)
		return err;

	while (dcd < dcd_end) {
		unsigned type = (dcd[0] << 0) + (dcd[1] << 8) | (dcd[2] << 16) + (dcd[3] << 24);
		unsigned addr = (dcd[4] << 0) + (dcd[5] << 8) | (dcd[6] << 16) + (dcd[7] << 24);
		val = (dcd[8] << 0) + (dcd[9] << 8) | (dcd[10] << 16) + (dcd[11] << 24);
		dcd += 12;
		if (type!=4) {
			printf("!!!unknown type=%08x *0x%08x = 0x%08x\n", type, addr, val);
		} else {
			printf("type=%08x *0x%08x = 0x%08x\n", type, addr, val);
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

void dump_bytes(unsigned char *src, unsigned cnt, unsigned addr)
{
	unsigned char *p = src;
	int i;
	while (cnt >= 16) {
		printf("%08x: %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x\n", addr,
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		p += 16;
		cnt -= 16;
		addr += 16;
	}
	if (cnt) {
		printf("%08x:", addr);
		i = 0;
		while (cnt) {
			printf(" %02x", p[0]);
			p++;
			cnt--;
			i++;
			if (cnt) if (i == 4) {
				i = 0;
				printf(" ");
			}
		}
		printf("\n");
	}
}

int verify_memory(struct libusb_device_handle *h, struct usb_id *p_id,
		FILE *xfile, unsigned offset, unsigned addr, unsigned size,
		unsigned char *verify_buffer, unsigned verify_cnt)
{
	int mismatch = 0;
	unsigned char file_buf[1024];
	fseek(xfile, offset + verify_cnt, SEEK_SET);

	while (size) {
		unsigned char mem_buf[64];
		unsigned char *p = file_buf;
		int cnt = addr & 0x3f;
		int request = get_min(size, sizeof(file_buf));
		if (cnt) {
			cnt = 64 - cnt;
			if (request > cnt)
				request = cnt;
		}
		if (verify_cnt) {
			p = verify_buffer;
			cnt = get_min(request, verify_cnt);
			verify_buffer += cnt;
			verify_cnt -= cnt;
		} else {
			cnt = fread(p, 1, request, xfile);
			if (cnt <= 0) {
				printf("Unexpected end of file, request=0x%0x, size=0x%x, cnt=%i\n", request, size, cnt);
				return -1;
			}
		}
		size -= cnt;
		while (cnt) {
			int ret;
			request = get_min(cnt, sizeof(mem_buf));
			ret = read_memory(h, p_id, addr, mem_buf, request);
			if (ret < 0)
				return ret;
			if (memcmp(p, mem_buf, request)) {
				unsigned char * m = mem_buf;
				if (!mismatch)
					printf("!!!!mismatch\n");
				mismatch++;

				while (request) {
					unsigned req = get_min(request, 32);
					if (memcmp(p, m, req)) {
						dump_long(p, req, offset);
						dump_long(m, req, addr);
						printf("\n");
					}
					p += req;
					m+= req;
					offset += req;
					addr += req;
					cnt -= req;
					request -= req;
				}
				if (mismatch >= 5)
					return -1;
			}
			p += request;
			offset += request;
			addr += request;
			cnt -= request;
		}
	}
	if (!mismatch)
		printf("Verify success\n");
	return mismatch ? -1 : 0;
}

int is_header(struct usb_id *p_id, unsigned char *p)
{
	switch (p_id->header_type) {
	case HDR_MX51:
	{
		struct old_app_header *ohdr = (struct old_app_header *)p;
		if (ohdr->app_barker == 0xb1)
			return 1;
		break;
	}
	case HDR_MX53:
	{
		struct ivt_header *hdr = (struct ivt_header *)p;
		if (hdr->barker == IVT_BARKER)
			return 1;
	}
	}
	return 0;
}

int perform_dcd(struct libusb_device_handle *h, struct usb_id *p_id, unsigned char *p, unsigned char *file_start, unsigned cnt)
{
	int ret = 0;
	switch (p_id->header_type) {
	case HDR_MX51:
	{
		struct old_app_header *ohdr = (struct old_app_header *)p;
		ret = write_dcd_table_old(h, p_id, ohdr, file_start, cnt);
		printf("dcd_ptr=0x%08x\n", ohdr->dcd_ptr);
#if 1
		ohdr->dcd_ptr = 0;
#endif
		if (ret < 0)
			return ret;
		break;
	}
	case HDR_MX53:
	{
		struct ivt_header *hdr = (struct ivt_header *)p;
		ret = write_dcd_table_ivt(h, p_id, hdr, file_start, cnt);
		printf("dcd_ptr=0x%08x\n", hdr->dcd_ptr);
#if 1
		hdr->dcd_ptr = 0;
#endif
		if (ret < 0)
			return ret;
		break;
	}
	}
	return 0;
}

int clear_dcd_ptr(struct libusb_device_handle *h, struct usb_id *p_id, unsigned char *p, unsigned char *file_start, unsigned cnt)
{
	int ret = 0;
	switch (p_id->header_type) {
	case HDR_MX51:
	{
		struct old_app_header *ohdr = (struct old_app_header *)p;
		printf("clear dcd_ptr=0x%08x\n", ohdr->dcd_ptr);
		ohdr->dcd_ptr = 0;
		break;
	}
	case HDR_MX53:
	{
		struct ivt_header *hdr = (struct ivt_header *)p;
		printf("clear dcd_ptr=0x%08x\n", hdr->dcd_ptr);
		hdr->dcd_ptr = 0;
		break;
	}
	}
	return 0;
}

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
//#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

int get_dl_start(struct usb_id *p_id, unsigned char *p, unsigned char *file_start, unsigned cnt, unsigned *dladdr, unsigned *max_length, unsigned *plugin, unsigned *header_addr)
{
	unsigned char* file_end = file_start + cnt;
	switch (p_id->header_type) {
	case HDR_MX51:
	{
		struct old_app_header *ohdr = (struct old_app_header *)p;
		unsigned char *dcd_end;
		unsigned char* dcd;
		int err = get_dcd_range_old(ohdr, file_start, cnt, &dcd, &dcd_end);
		*dladdr = ohdr->app_dest_ptr;
		*header_addr = ohdr->dcd_ptr_ptr - offsetof(struct old_app_header, dcd_ptr);
		*plugin = 0;
		if (err >= 0) {
			*max_length = dcd_end[0] | (dcd_end[1] << 8) | (dcd_end[2] << 16) | (dcd_end[3] << 24);
		}
		break;
	}
	case HDR_MX53:
	{
		unsigned char *bd;
		struct ivt_header *hdr = (struct ivt_header *)p;
		*dladdr = hdr->self_ptr;
		*header_addr = hdr->self_ptr;
		bd = hdr->boot_data_ptr + cvt_dest_to_src;
		if ((bd < file_start) || ((bd + 4) > file_end)) {
			printf("bad boot_data_ptr %08x\n", hdr->boot_data_ptr);
			return -1;
		}
		*dladdr = ((struct boot_data *)bd)->dest;
		*max_length = ((struct boot_data *)bd)->image_len;
		*plugin = ((struct boot_data *)bd)->plugin;
		((struct boot_data *)bd)->plugin = 0;
#if 1
		hdr->boot_data_ptr = 0;
#endif
		break;
	}
	}
	return 0;
}

int do_status(libusb_device_handle *h, struct usb_id *p_id);

int process_header(struct libusb_device_handle *h, struct usb_id *p_id,
		struct usb_work *curr, unsigned char *buf, int cnt,
		unsigned *p_dladdr, unsigned *p_max_length, unsigned *p_plugin,
		unsigned *p_header_addr)
{
	int ret;
	unsigned header_max = 0x800;
	unsigned header_inc = 0x400;
	unsigned header_offset = 0;
	int header_cnt = 0;
	unsigned char *p = buf;

	while (header_offset < header_max) {
//		printf("header_offset=%x\n", header_offset);
		if (is_header(p_id, p)) {
			ret = get_dl_start(p_id, p, buf, cnt, p_dladdr, p_max_length, p_plugin, p_header_addr);
			if (ret < 0) {
				printf("!!get_dl_start returned %i\n", ret);
				return ret;
			}
			if (curr->dcd) {
				ret = perform_dcd(h, p_id, p, buf, cnt);
				if (ret < 0) {
					printf("!!perform_dcd returned %i\n", ret);
					return ret;
				}
				curr->dcd = 0;
				if ((!curr->jump_mode) && (!curr->plug)) {
					printf("!!dcd done, nothing else requested\n", ret);
					return 0;
				}
			}
			if (curr->clear_dcd) {
				ret = clear_dcd_ptr(h, p_id, p, buf, cnt);
				if (ret < 0) {
					printf("!!clear_dcd returned %i\n", ret);
					return ret;
				}
			}
			if (*p_plugin && (!curr->plug) && (!header_cnt)) {
				header_cnt++;
				header_max = header_offset + *p_max_length + 0x400;
				if (header_max > cnt - 32)
					header_max = cnt - 32;
				printf("header_max=%x\n", header_max);
				header_inc = 4;
			} else {
				if (!*p_plugin)
					curr->plug = 0;
				break;
			}
		}
		header_offset += header_inc;
		p += header_inc;
	}
	return header_offset;
}

int load_file(struct libusb_device_handle *h, struct usb_id *p_id,
		unsigned char *p, int cnt, unsigned char *buf, unsigned buf_cnt,
		unsigned dladdr, unsigned fsize, unsigned char type, FILE* xfile)
{
//							address, format, data count, data, type
	static unsigned char dlCommand[] =    {0x04,0x04, V(0),  0x00, V(0x00000020), V(0), 0xaa};
	int last_trans, err;
	int retry = 0;
	unsigned transferSize=0;
	int max = p_id->max_transfer;
	unsigned char tmp[64];

	dlCommand[2] = (unsigned char)(dladdr>>24);
	dlCommand[3] = (unsigned char)(dladdr>>16);
	dlCommand[4] = (unsigned char)(dladdr>>8);
	dlCommand[5] = (unsigned char)(dladdr);

	dlCommand[7] = (unsigned char)(fsize>>24);
	dlCommand[8] = (unsigned char)(fsize>>16);
	dlCommand[9] = (unsigned char)(fsize>>8);
	dlCommand[10] = (unsigned char)(fsize);
	dlCommand[15] =  type;

	for (;;) {
		err = transfer(h, 1, dlCommand, 16, &last_trans, p_id);
		if (!err)
			break;
		printf("dlCommand err=%i, last_trans=%i\n", err, last_trans);
		if (retry > 5)
			return -4;
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
		if (cnt > (int)(fsize-transferSize)) cnt = (fsize-transferSize);
		if (cnt <= 0)
			break;
		retry = 0;
		while (cnt) {
			err = transfer(h, 2, p, get_min(cnt, max), &last_trans, p_id);
//			printf("err=%i, last_trans=0x%x, cnt=0x%x, max=0x%x\n", err, last_trans, cnt, max);
			if (err) {
				printf("out err=%i, last_trans=%i cnt=0x%x max=0x%x transferSize=0x%X retry=%i\n", err, last_trans, cnt, max, transferSize, retry);
				if (retry >= 10) {
					printf("Giving up\n");
					return err;
				}
				if (max >= 16)
					max >>= 1;
				else
					max <<= 1;
//				err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
//				printf("in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
				usleep(10000);
				retry++;
				continue;
			}
			max = p_id->max_transfer;
			retry = 0;
			if (cnt < last_trans) {
				printf("error: last_trans=0x%x, attempted only=0%x\n", last_trans, cnt);
				cnt = last_trans;
			}
			if (!last_trans) {
				printf("Nothing last_trans, err=%i\n", err);
				break;
			}
			p += last_trans;
			cnt -= last_trans;
			transferSize += last_trans;
		}
		if (!last_trans) break;
		if (feof(xfile)) break;
		cnt = fsize - transferSize;
		if (cnt <= 0)
			break;
		cnt = fread(buf, 1 , get_min(cnt, buf_cnt), xfile);
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
	} else {
//		err = transfer(h, 3, tmp, sizeof(tmp), &last_trans, p_id);
//		if (err)
//			printf("3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		do_status(h, p_id);
	}
	return transferSize;
}

static const unsigned char statusCommand[]={5,5,0,0,0,0, 0, 0,0,0,0, 0,0,0,0, 0};
#define MAX_IN_LENGTH 100 // max length for user input strings

#define FT_APP	0xaa
#define FT_CSF	0xcc
#define FT_DCD	0xee
#define FT_LOAD_ONLY	0x00
int DoIRomDownload(struct libusb_device_handle *h, struct usb_id *p_id, struct usb_work *curr, int verify)
{
//							address, format, data count, data, type
	static unsigned char jump_command[] = {0x0b,0x0b, V(0),  0x00, V(0x00000000), V(0), 0x00};

	int ret;
	FILE* xfile;
	unsigned char type;
	unsigned fsize;
	unsigned header_offset;
	int cnt;
	struct ivt_header *hdr;
	struct old_app_header *ohdr;
	unsigned file_base;
	int last_trans, err;
#define BUF_SIZE (1024*16)
	unsigned char *buf = NULL;
	unsigned char *verify_buffer = NULL;
	unsigned verify_cnt;
	unsigned char *p;
	unsigned char tmp[64];
	unsigned dladdr = 0;
	unsigned max_length;
	unsigned plugin = 0;
	unsigned header_addr = 0;

	unsigned skip = 0;
	unsigned transferSize=0;
	int retry = 0;

	printf("%s\n", curr->filename);
	xfile = fopen(curr->filename, "rb" );
	if (!xfile) {
		printf("\r\nerror, can not open input file: %s\r\n", curr->filename);
		return -5;
	}
	buf = malloc(BUF_SIZE);
	if (!buf) {
		printf("\r\nerror, out of memory\r\n");
		ret = -2;
		goto cleanup;
	}

	if ((p_id->vid == GADGET_VID) && ( p_id->pid == GADGET_PID)) {
		sprintf(buf, "%s", "send");
		ret = send_utp_command(h, GADGET_EP_IN, GADGET_EP_OUT, UTP_EXEC, 1, strlen(buf), buf);
		cnt = fread(buf, 1 , BUF_SIZE, xfile);
		while ((cnt > 0) || !feof(xfile)) {
			if (cnt > 0) {
				send_utp_command(h, GADGET_EP_IN, GADGET_EP_OUT, UTP_PUT, 1, cnt, buf);
			}
			cnt = fread(buf, 1 , BUF_SIZE, xfile);
		};
		if (curr->target_filename[0] == 0) {
			snprintf(curr->target_filename,sizeof(curr->target_filename),
				"/tmp/%s",basename(curr->filename));
		}
		sprintf(buf,"save %s", curr->target_filename);
		ret = send_utp_command(h, GADGET_EP_IN, GADGET_EP_OUT, UTP_EXEC, 1, strlen(buf), buf);
		ret = 0;
	} else {
		fsize = get_file_size(xfile);
		cnt = fread(buf, 1 , BUF_SIZE, xfile);

		if (cnt < 0x20) {
			printf("\r\nerror, file: %s is too small\r\n", curr->filename);
			ret = -2;
			goto cleanup;
		}
		max_length = fsize;
		if (curr->dcd || curr->clear_dcd || curr->plug || (curr->jump_mode >= J_HEADER)) {
			ret = process_header(h, p_id, curr, buf, cnt,
					&dladdr, &max_length, &plugin, &header_addr);
			if (ret < 0)
				goto cleanup;
			header_offset = ret;
			if ((!curr->jump_mode) && (!curr->plug)) {
				/*  nothing else requested */
				ret = 0;
				goto cleanup;
			}
		} else {
			dladdr = curr->load_addr;
			printf("load_addr=%x\n", curr->load_addr);
			header_addr = dladdr;
			header_offset = 0;
		}
		if (plugin && (!curr->plug)) {
			printf("Only plugin header found\n");
			ret = -1;
			goto cleanup;
		}
		if (!dladdr) {
			printf("\nunknown load address\r\n");
			ret = -3;
			goto cleanup;
		}
		file_base = header_addr - header_offset;
		type = (curr->plug || curr->jump_mode) ? FT_APP : FT_LOAD_ONLY;
		if (p_id->mode == MODE_BULK) if (type == FT_APP) {
			/* No jump command, dladdr should point to header */
			dladdr = header_addr;
		}
		if (file_base > dladdr) {
			max_length -= (file_base - dladdr);
			dladdr = file_base;
		}
		skip = dladdr - file_base;
		if (skip > cnt) {
			if (skip > fsize) {
				printf("skip(0x%08x) > fsize(0x%08x) file_base=0x%08x, header_offset=0x%x\n", skip, fsize, file_base, header_offset);
				ret = -4;
				goto cleanup;
			}
			fseek(xfile, skip, SEEK_SET);
			cnt -= skip;
			fsize -= skip;
			skip = 0;
			cnt = fread(buf, 1 , BUF_SIZE, xfile);
		}
		p = &buf[skip];
		cnt -= skip;
		fsize -= skip;
		if (fsize > max_length)
			fsize = max_length;
		if (verify) {
			/*
			 * we need to save header for verification
			 * because some of the file is changed
			 * before download
			 */
			verify_buffer = malloc(cnt);
			verify_cnt = cnt;
			if (!verify_buffer) {
				printf("\r\nerror, out of memory\r\n");
				ret = -2;
				goto cleanup;
			}
			memcpy(verify_buffer, p, cnt);
			if ((type == FT_APP) && (p_id->mode != MODE_HID)) {
				type = FT_LOAD_ONLY;
				verify = 2;
			}
		}
		printf("\nloading binary file(%s) to %08x, skip=%x, fsize=%x type=%x\r\n", curr->filename, dladdr, skip, fsize, type);
		ret = load_file(h, p_id, p, cnt, buf, BUF_SIZE,
				dladdr, fsize, type, xfile);
		if (ret < 0)
			goto cleanup;
		transferSize = ret;
	
		if (verify) {
			ret = verify_memory(h, p_id, xfile, skip, dladdr, fsize, verify_buffer, verify_cnt);
			if (ret < 0)
				goto cleanup;
			if (verify == 2) {
				if (verify_cnt > 64)
					verify_cnt = 64;
				ret = load_file(h, p_id, verify_buffer, verify_cnt,
						buf, BUF_SIZE, dladdr, verify_cnt,
						FT_APP, xfile);
				if (ret < 0)
					goto cleanup;
	
			}
		}
		if (p_id->mode == MODE_HID) if (type == FT_APP) {
			printf("jumping to 0x%08x\n", header_addr);
			jump_command[2] = (unsigned char)(header_addr >> 24);
			jump_command[3] = (unsigned char)(header_addr >> 16);
			jump_command[4] = (unsigned char)(header_addr >> 8);
			jump_command[5] = (unsigned char)(header_addr);
			//Any command will initiate jump for mx51, jump address is ignored by mx51
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
			if (err)
				printf("j3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
			if (0) if (p_id->mode == MODE_HID) {
				memset(tmp, 0, sizeof(tmp));
				err = transfer(h, 4, tmp, sizeof(tmp), &last_trans, p_id);
				printf("j4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
			}
		}
		ret = (fsize == transferSize) ? 0 : -16;
	}
cleanup:
	fclose(xfile);
	free(verify_buffer);
	free(buf);
	return ret;
}

int do_status(libusb_device_handle *h, struct usb_id *p_id)
{
	int last_trans;
	unsigned char tmp[64];
	int retry = 0;
	int err;
	
	if ((p_id->vid == GADGET_VID) && ( p_id->pid == GADGET_PID)) {
		err = send_utp_command(h, GADGET_EP_IN, GADGET_EP_OUT, UTP_POLL, 1, 0, NULL);
		if (err > 0) {
			err = 0;
		} else {
			err = -1;
		}
	} else {
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
	}
	return err;
}

libusb_device_handle * open_vid_pid(struct usb_id *p_id)
{
	int r = libusb_init(NULL);
	int err;
	libusb_device_handle *h;
	h = libusb_open_device_with_vid_pid(NULL, p_id->vid, p_id->pid);
	if (!h) {
		printf("%s:Could not open device vid=0x%x pid=0x%x\n", __func__, p_id->vid, p_id->pid);
		goto err1;
	}
	if (libusb_kernel_driver_active(h, 0))
		libusb_detach_kernel_driver(h, 0);
	err = libusb_claim_interface(h, 0);
	if (err) {
		printf("claim failed, err=%i\n", err);
		goto err2;
	}
	err = do_status(h, p_id);
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

int main(int argc, char const *const argv[])
{
	struct usb_id *p_id;
	struct mach_id *mach;
	libusb_device **devs;
	libusb_device *dev;
	int r;
	int err;
	int ret=1;
	int single = 0;
	ssize_t cnt;
	libusb_device_handle *h = NULL;
	int config = 0;
	int verify = 0;
	struct usb_work w;
	struct usb_work *curr;
	int i = 1;

	struct mach_id *list = parse_imx_conf("imx_usb.conf");
	if (!list)
		goto out;
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
	p_id = parse_conf(mach);
	if (!p_id)
		goto out;
	libusb_get_configuration(h, &config);
	printf("%04x:%04x(%s) bConfigurationValue =%x\n", p_id->vid, p_id->pid, p_id->name, config);
	if (libusb_kernel_driver_active(h, 0))
		 libusb_detach_kernel_driver(h, 0);

	err = libusb_claim_interface(h, 0);
	if (err) {
		printf("Claim failed\n");
		goto out;
	}
	printf("Interface 0 claimed\n");
	err = do_status(h, p_id);
	if (err) {
		printf("status failed\n");
		goto out;
	}
	curr = p_id->work;
	single = 0;
	if (argc > i) {
		if (!strcmp(argv[i], "-v")) {
			verify = 1;
			i++;
		}
	}
	if (argc > i) {
		memset(&w, 0, sizeof(struct usb_work));
		w.plug = 1;
		w.dcd = 1;
		w.jump_mode = J_HEADER;
		strncpy(w.filename, argv[i], sizeof(w.filename) - 1);
		curr = &w;
		single = 1;
		i++;
	}
	if (argc > i) {
		if (!strcmp(argv[i], "-v")) {
			verify = 1;
			i++;
		}
	}
	while (curr) {
		if (curr->mem)
			perform_mem_work(h, p_id, curr->mem);
//		printf("jump_mode %x\n", curr->jump_mode);
		if (curr->filename[0])
			err = DoIRomDownload(h, p_id, curr, verify);
		if (err) {
			err = do_status(h, p_id);
			break;
		}
		if (!curr->next && (!curr->plug || !single))
			break;
		err = do_status(h, p_id);
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
				h = open_vid_pid(p_id);
				if (h)
					break;
			}
			if (!h)
				goto out;
		}
		if (single && curr->plug) {
			curr->plug = 0;
			continue;
		}
		curr = curr->next;
	}
	ret = 0;
exit:
	libusb_release_interface(h, 0);
out:
	if (h)
		libusb_close(h);
	libusb_exit(NULL);
	return ret;
}
