/*
 * imx_sdp:
 * Interface of the Serial Download Protocol (SDP) for i.MX/Vybrid
 * series processors.
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

#ifndef __IMX_SDP_H__
#define __IMX_SDP_H__

#include <libusb-1.0/libusb.h>
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

struct sdp_work;
struct sdp_work {
	struct sdp_work *next;
	struct mem_work *mem;
	unsigned char filename[256];
	unsigned char dcd;
	unsigned char clear_dcd;	//means clear dcd_ptr
	unsigned char plug;
#define J_ADDR		1
#define J_HEADER	2
#define J_HEADER2	3
	unsigned char jump_mode;
	unsigned load_addr;
	unsigned jump_addr;
	unsigned load_size;
};

struct sdp_dev {
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
	struct sdp_work *work;
};

int get_val(const char** pp, int base);
const unsigned char *move_string(unsigned char *dest, const unsigned char *src, unsigned cnt);

char const *conf_file_name(char const *base, int argc, char const * const *argv);

struct sdp_dev *parse_conf(const char *filename, int argc, char const * const *argv);

int DoIRomDownload(struct libusb_device_handle *h, struct sdp_dev *p_id, struct sdp_work *curr, int verify);


#endif /* __IMX_SDP_H__ */
