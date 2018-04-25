/*
 * imx_sdp:
 * Implementation of the Serial Download Protocol (SDP) for i.MX/Vybrid
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
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "portable.h"
#include "imx_sdp.h"
#include "image.h"

#define FT_APP	0xaa
#define FT_CSF	0xcc
#define FT_DCD	0xee
#define FT_LOAD_ONLY	0x00

int debugmode = 0;

#ifdef __GNUC__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BE32(x) __builtin_bswap32(x)
#define BE16(x) __builtin_bswap16(x)
#else
#define BE32(x) x
#define BE16(x) x
#endif
#elif _MSC_VER // assume little endian...
#define BE32(x) _byteswap_ulong(x)
#define BE16(x) _byteswap_ushort(x)
#endif

#define get_min(a, b) (((a) < (b)) ? (a) : (b))
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
//#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

struct load_desc {
	struct sdp_work *curr;
	FILE* xfile;
	unsigned fsize;
	int verify;
	unsigned char *buf_start;
	unsigned buf_size;
	unsigned buf_cnt;
	unsigned buf_offset;
	unsigned dladdr;
	unsigned max_length;
	unsigned plugin;
	unsigned header_addr;
	unsigned header_offset;
	unsigned char writeable_header[1024];
};



void print_sdp_work(struct sdp_work *curr)
{
	printf("== work item\n");
	printf("filename %s\n", curr->filename);
	printf("load_size %d bytes\n", curr->load_size);
	printf("load_addr 0x%08x\n", curr->load_addr);
	printf("dcd %u\n", curr->dcd);
	printf("clear_dcd %u\n", curr->clear_dcd);
	printf("plug %u\n", curr->plug);
	printf("jump_mode %d\n", curr->jump_mode);
	printf("jump_addr 0x%08x\n", curr->jump_addr);
	printf("== end work item\n");
	return;
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

struct boot_data {
	uint32_t dest;
	uint32_t image_len;
	uint32_t plugin;
};

/* Command tags and parameters */
#define IVT_HEADER_TAG			0xD1
#define IVT_VERSION			0x40
#define IVT_VERSION_IMX8M		0x41
#define DCD_HEADER_TAG			0xD2
#define DCD_VERSION			0x40
#define DCD_VERSION_IMX8M		0x41

#pragma pack (1)
struct ivt_header {
        uint8_t tag;
        uint16_t length;
        uint8_t version;
};
#pragma pack ()

struct flash_header_v2 {
	struct ivt_header header;
	uint32_t start_addr;
	uint32_t reserv1;
	uint32_t dcd_ptr;
	uint32_t boot_data_ptr;		/* struct boot_data * */
	uint32_t self_ptr;		/* struct flash_header_v2 *, this - boot_data.start = offset linked at */
	uint32_t app_code_csf;
	uint32_t reserv2;
};

#pragma pack (1)
struct write_dcd_command {
	uint8_t tag;
	uint16_t length;
	uint8_t param;
};
#pragma pack ()

struct dcd_v2 {
	struct ivt_header header;
	struct write_dcd_command write_dcd_command;
	unsigned char *addr_data;
};


/*
 * MX51 header type
 */
struct flash_header_v1 {
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

static int do_response(struct sdp_dev *dev, int report, unsigned int *result,
		bool silent)
{
	unsigned char tmp[64] =  { 0 };
	int last_trans, err;

	err = dev->transfer(dev, report, tmp, sizeof(tmp), 4, &last_trans);
	if ((!silent && err) || debugmode)
		printf("report %d in err=%i, last_trans=%i  %02x %02x %02x %02x\n",
			report, err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);

	/* At least 4 bytes required for a valid result */
	if (last_trans < 4)
		return -1;

	/*
	 * Most results are symetric, but likely are meant to be big endian
	 * as everything else is...
	 */
	*result = BE32(*((unsigned int*)tmp));

	return err;
}

static int do_command(struct sdp_dev *dev, struct sdp_command *cmd, int retry)
{
	int last_trans, err = -4;

	dbg_printf("sending command cmd=%04x\n", cmd->cmd);
	while (retry) {
		err = dev->transfer(dev, 1, (unsigned char *)cmd,
				    sizeof(*cmd), 0, &last_trans);
		if (err || debugmode)
			printf("%s err=%i, last_trans=%i\n", __func__, err, last_trans);
		if (!err)
			return 0;

		retry--;
	}

	return err;
}

static int read_memory(struct sdp_dev *dev, unsigned addr, unsigned char *dest, unsigned cnt)
{
	struct sdp_command read_reg_command = {
		.cmd = SDP_READ_REG,
		.addr = BE32(addr),
		.format = 0x20,
		.cnt = BE32(cnt),
		.data = BE32(0),
		.rsvd = 0x00};
	int retry = 0;
	int last_trans;
	int err;
	int rem;
	unsigned char tmp[64];
	unsigned int sec;

	dbg_printf("%s: addr=%08x, cnt=%08x\n", __func__, addr, cnt);
	err = do_command(dev, &read_reg_command, 5);
	if (err)
		return err;

	err = do_response(dev, 3, &sec, false);
	if (err)
		return err;

	rem = cnt;
	retry = 0;
	while (rem) {
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
		err = dev->transfer(dev, 4, tmp, 64, rem > 64 ? 64 : rem, &last_trans);
		if (err) {
			printf("r4 in err=%i, last_trans=%i  %02x %02x %02x %02x cnt=%d rem=%d\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3], cnt, rem);
			if (retry++ > 8)
				break;
			continue;
		}
		retry = 0;
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
	dbg_printf("%s: %d addr=%08x, val=%02x %02x %02x %02x\n", __func__, err, addr, dest[0], dest[1], dest[2], dest[3]);
	return err;
}

static int write_memory(struct sdp_dev *dev, unsigned addr, unsigned val)
{
	struct sdp_command write_reg_command = {
		.cmd = SDP_WRITE_REG,
		.addr = BE32(addr),
		.format = 0x20,
		.cnt = BE32(0x00000004),
		.data = BE32(val),
		.rsvd = 0x00};
	int last_trans;
	int err = 0;
	unsigned char tmp[64] = { 0 };
	unsigned int sec;

	dbg_printf("%s: addr=%08x, val=%08x\n", __func__, addr, val);
	err = do_command(dev, &write_reg_command, 5);
	if (err)
		return err;

	err = do_response(dev, 3, &sec, false);
	if (err)
		return err;

	err = dev->transfer(dev, 4, tmp, sizeof(tmp), 4, &last_trans);
	dbg_printf("report 4, err=%i, last_trans=%i  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
			err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3],
			tmp[4], tmp[5], tmp[6], tmp[7]);
	if (err)
		printf("w4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
	return err;
}

void perform_mem_work(struct sdp_dev *dev, struct mem_work *mem)
{
	unsigned tmp, tmp2;

	while (mem) {
		switch (mem->type) {
		case MEM_TYPE_READ:
			read_memory(dev, mem->vals[0], (unsigned char *)&tmp, 4);
			printf("*%x is %x\n", mem->vals[0], tmp);
			break;
		case MEM_TYPE_WRITE:
			write_memory(dev, mem->vals[0], mem->vals[1]);
			printf("%x write %x\n", mem->vals[0], mem->vals[1]);
			break;
		case MEM_TYPE_MODIFY:
			read_memory(dev, mem->vals[0], (unsigned char *)&tmp, 4);
			tmp2 = (tmp & ~mem->vals[1]) | mem->vals[2];
			printf("%x = %x to %x\n", mem->vals[0], tmp, tmp2);
			write_memory(dev, mem->vals[0], tmp2);
			break;
		}
		mem = mem->next;
	}
}

static int do_data_transfer(struct sdp_dev *dev, unsigned char *buf, int len)
{
	int err;
	int retry = 10;
	int max = dev->max_transfer;
	int last_trans;
	int cnt;
	int transferSize = 0;

	while (retry) {
		cnt = get_min(len, max);
		err = dev->transfer(dev, 2, buf, cnt, 0, &last_trans);
		if (!err) {
			if (cnt > last_trans)
				cnt = last_trans;
			if (!cnt) {
				printf("Nothing transferred, err=%i transferSize=%i\n", err, transferSize);
				return -EIO;
			}
			transferSize += cnt;
			buf += cnt;
			len -= cnt;
			if (!len)
				return transferSize;
			retry = 10;
			max = dev->max_transfer;
			continue;
		}

		printf("report 2 out err=%i, last_trans=%i len=0x%x max=0x%x retry=%i\n",
			err, last_trans, len, max, retry);

		if (max >= 16)
			max >>= 1;
		else
			max <<= 1;

		/* Wait a few ms before retrying transfer */
		msleep(10);
		retry--;
	}

	printf("Giving up\n");
	return err;
}

static int write_dcd(struct sdp_dev *dev, struct dcd_v2 *dcd)
{
	struct sdp_command dl_command = {
		.cmd = SDP_WRITE_DCD,
		.addr = BE32(dev->dcd_addr),
		.format = 0,
		.cnt = 0,
		.data = 0,
		.rsvd = 0};

	int length = BE16(dcd->header.length);

	int err;
	unsigned transferSize=0;

	if (length > HAB_MAX_DCD_SIZE) {
		printf("DCD is too big (%d bytes)\n", length);
		return -1;
	}

	dl_command.cnt = BE32(length);

	printf("loading DCD table @%#x\n", dev->dcd_addr);
	err = do_command(dev, &dl_command, 5);
	if (err)
		return err;

	err = do_data_transfer(dev, (unsigned char *)dcd, length);
	if (err < 0)
		return err;
	transferSize = err;

	printf("\n<<<%i, %i bytes>>>\n", length, transferSize);
	if (dev->mode == MODE_HID) {
		unsigned int sec, status;

		err = do_response(dev, 3, &sec, false);
		if (err)
			return err;

		err = do_response(dev, 4, &status, false);
		if (err)
			return err;

		if (status == 0x128a8a12UL)
			printf("succeeded");
		else
			printf("failed");
		printf(" (security 0x%08x, status 0x%08x)\n", sec, status);
	} else {
		do_status(dev);
	}
	return transferSize;
}

static int write_dcd_table_ivt(struct sdp_dev *dev, struct dcd_v2 *dcdhdr)
{
	int length = BE16(dcdhdr->header.length);
	unsigned char *dcd = (unsigned char *)&dcdhdr->write_dcd_command;
	unsigned char *dcd_end;
	int err = 0;

	printf("main dcd length %x\n", length);
	dcd_end = ((unsigned char *)dcdhdr) + length;

	while (dcd < dcd_end) {
		unsigned s_length = (dcd[1] << 8) + dcd[2];
		unsigned sub_tag = (dcd[0] << 24) + (dcd[3] & 0x7);
		unsigned flags = (dcd[3] & 0xf8);
		unsigned char *s_end = dcd + s_length;
		printf("sub dcd length %x\n", s_length);
		switch(sub_tag) {
		/* Write Data Command */
		case 0xcc000004:
			if (flags & 0xe8) {
				printf("error: Write Data Command with unsupported flags, flags %x.\n", flags);
				return -1;
			}
			dcd += 4;
			if (s_end > dcd_end) {
				printf("error s_end(%p) > dcd_end(%p)\n", s_end, dcd_end);
				return -1;
			}
			while (dcd < s_end) {
				unsigned addr = (dcd[0] << 24) + (dcd[1] << 16) + (dcd[2] << 8) + dcd[3];
				unsigned val = (dcd[4] << 24) + (dcd[5] << 16) + (dcd[6] << 8) + dcd[7];
				dcd += 8;
				dbg_printf("write data *0x%08x = 0x%08x\n", addr, val);
				err = write_memory(dev, addr, val);
				if (err < 0)
					return err;
			}
			break;
		/* Check Data Command */
		case 0xcf000004: {
			unsigned addr, count, mask, val;
			dcd += 4;
			addr = (dcd[0] << 24) + (dcd[1] << 16) + (dcd[2] << 8) + dcd[3];
			mask = (dcd[4] << 24) + (dcd[5] << 16) + (dcd[6] << 8) + dcd[7];
			count = 10000;
			switch (s_length) {
			case 12:
				dcd += 8;
				break;
			case 16:
				count = (dcd[8] << 24) + (dcd[9] << 16) + (dcd[10] << 8) + dcd[11];
				dcd += 12;
				break;
			default:
				printf("error s_end(%p) > dcd_end(%p)\n", s_end, dcd_end);
				return -1;
			}
			dbg_printf("Check Data Command, at addr %x, mask %x\n",addr, mask);
			while (count) {
				val = 0;
				err = read_memory(dev, addr, (unsigned char*)&val, 4);
				if (err < 0) {
					printf("Check Data Command(%x) error(%d) @%x=%x mask %x\n", flags, err, addr, val, mask);
					return err;
				}
				if ((flags == 0x00) && ((val & mask) == 0) )
					break;
				else if ((flags == 0x08) && ((val & mask) != mask) )
					break;
				else if ((flags == 0x10) && ((val & mask) == mask) )
					break;
				else if ((flags == 0x18) && ((val & mask) != 0) )
					break;
				else if (flags & 0xe0) {
					printf("error: Check Data Command with unsupported flags, flags %x.\n", flags);
					return -1;
				}
				count--;
			}
			if (!count)
				printf("!!!Check Data Command(%x) expired without condition met @%x=%x mask %x\n", flags, addr, val, mask);
			else
				printf("Check Data Command(%x) success @%x=%x mask %x\n", flags, addr, val, mask);

			break;
		}
		default:
			printf("Unknown sub tag, dcd[0] 0x%2x, dcd[3] 0x%2x\n", dcd[0], dcd[3]);
					return -1;
		}
	}
	return err;
}

static int get_dcd_range_old(struct flash_header_v1 *hdr,
		unsigned char *file_start, unsigned cnt,
		unsigned char **pstart, unsigned char **pend)
{
	unsigned char *dcd_end;
	unsigned m_length;
#define cvt_dest_to_src_old		(((unsigned char *)&hdr->dcd_ptr) - hdr->dcd_ptr_ptr)
	unsigned char* dcd;
	unsigned val;
	unsigned char* file_end = file_start + cnt;

	if (!hdr->dcd_ptr) {
		printf("No dcd table, barker=%x\n", hdr->app_barker);
		*pstart = *pend = ((unsigned char *)hdr) + sizeof(struct flash_header_v1);
		return 0;	//nothing to do
	}
	dcd = hdr->dcd_ptr + cvt_dest_to_src_old;
	if ((dcd < file_start) || ((dcd + 8) > file_end)) {
		printf("bad dcd_ptr %08x\n", hdr->dcd_ptr);
		return -1;
	}
	val = (dcd[0] << 0) + (dcd[1] << 8) + (dcd[2] << 16) + (dcd[3] << 24);
	if (val != DCD_BARKER) {
		printf("Unknown tag\n");
		return -1;
	}
	dcd += 4;
	m_length =  (dcd[0] << 0) + (dcd[1] << 8) + (dcd[2] << 16) + (dcd[3] << 24);
	printf("main dcd length %x\n", m_length);
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

static int write_dcd_table_old(struct sdp_dev *dev, struct flash_header_v1 *hdr, unsigned char *file_start, unsigned cnt)
{
	unsigned val;
	unsigned char *dcd_end;
	unsigned char* dcd;
	int err = get_dcd_range_old(hdr, file_start, cnt, &dcd, &dcd_end);
	if (err < 0)
		return err;

	while (dcd < dcd_end) {
		unsigned type = (dcd[0] << 0) + (dcd[1] << 8) + (dcd[2] << 16) + (dcd[3] << 24);
		unsigned addr = (dcd[4] << 0) + (dcd[5] << 8) + (dcd[6] << 16) + (dcd[7] << 24);
		val = (dcd[8] << 0) + (dcd[9] << 8) + (dcd[10] << 16) + (dcd[11] << 24);
		dcd += 12;
		if (type!=4) {
			printf("!!!unknown type=%08x *0x%08x = 0x%08x\n", type, addr, val);
		} else {
			printf("type=%08x *0x%08x = 0x%08x\n", type, addr, val);
			err = write_memory(dev, addr, val);
			if (err < 0)
				return err;
		}
	}
	return err;
}

void diff_long(unsigned char *src1, unsigned char *src2, unsigned cnt, unsigned skip)
{
	unsigned char buf[8*9 + 2];
	unsigned *s1 = (unsigned *)src1;
	unsigned *s2 = (unsigned *)src2;
	unsigned i, j;
	while (cnt >= 4) {
		unsigned char *p = buf;
		unsigned max = get_min(cnt >> 2, 8);
		for (i = 0; i < (skip >> 2); i++) {
			for (j=0; j < 9; j++)
				*p++ = ' ';
		}
		for (; i < max; i++) {
			unsigned s1v = *s1++;
			unsigned diff = s1v ^ *s2++;
			unsigned c;
			*p++ = ' ';
			if (i == 4)
				*p++ = ' ';
			for (j = 0; j < 8; j++) {
				unsigned changed = diff & 0xf0000000;
				c = ' ';
				if (changed) {
					if ((s1v & changed) == 0)
						c = '^';
					else if ((s1v & changed) == changed)
						c = 'v';
					else
						c = '-';
				}
				*p++ = c;
				diff <<= 4;
				s1v <<= 4;
			}
		}
		*p = 0;
		printf("         %s\n", buf);
		cnt -= max << 2;
	}
}

void dump_long(unsigned char *src, unsigned cnt, unsigned addr, unsigned skip)
{
	unsigned *p = (unsigned *)src;
	int i = skip >> 2;

	while (cnt >= 4) {
		printf("%08x:", addr);
		while (skip >= 4) {
			printf("         ");
			skip -= 4;
		}
		while (cnt >= 4) {
			printf((i==4) ? "  %08x":" %08x", p[0]);
			p++;
			cnt -= 4;
			addr += 4;
			i++;
			if (i==8)
				break;
		}
		printf("\n");
		i = 0;
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

void fetch_data(struct load_desc *ld, unsigned foffset, unsigned char **p, unsigned *cnt)
{
	unsigned skip = foffset - ld->header_offset;
	unsigned buf_cnt = ld->buf_cnt;

	if ((ld->curr->jump_mode >= J_ADDR_HEADER) &&
			(skip < sizeof(ld->writeable_header))) {
		*p = &ld->writeable_header[skip];
		*cnt = sizeof(ld->writeable_header) - skip;
		return;
	}
	skip = foffset - ld->buf_offset;
	if (skip >= buf_cnt) {
		fseek(ld->xfile, foffset, SEEK_SET);
		ld->buf_offset = foffset;
		buf_cnt = ld->buf_cnt = fread(ld->buf_start, 1, ld->buf_size, ld->xfile);
		skip = 0;
	}
	if ((foffset < ld->header_offset) &&
	    (ld->header_offset < ld->buf_offset + buf_cnt))
		buf_cnt = ld->header_offset - ld->buf_offset;
	*p = &ld->buf_start[skip];
	*cnt = buf_cnt - skip;
}

int verify_memory(struct sdp_dev *dev, struct load_desc *ld, unsigned foffset,
		unsigned size)
{
	int mismatch = 0;
	unsigned verified = 0;
	unsigned total = size;
	unsigned addr = ld->dladdr;

	while (size) {
		unsigned char *p;
		unsigned cnt;
		unsigned char mem_buf[64];
		int align_cnt = foffset & 0x3f;
		unsigned offset = foffset;

		fetch_data(ld, foffset, &p, &cnt);
		if (align_cnt) {
			align_cnt = 64 - align_cnt;
			if (cnt > align_cnt)
				cnt = align_cnt;
		}
		if (cnt <= 0) {
			printf("Unexpected end of file, size=0x%x, cnt=%i\n", size, cnt);
			return -1;
		}
		if (cnt > size)
			cnt = size;
		size -= cnt;
		foffset += cnt;
		while (cnt) {
			int ret;
			unsigned request = get_min(cnt, sizeof(mem_buf));

			ret = read_memory(dev, addr, mem_buf, request);
			if (ret < 0) {
				printf("verified 0x%x of 0x%x before usb error\n", verified, total);
				return ret;
			}
			if (memcmp(p, mem_buf, request)) {
				unsigned char * m = mem_buf;
				if (!mismatch)
					printf("!!!!mismatch\n");
				mismatch++;

				while (request) {
					unsigned skip = addr & 0x1f;
					unsigned max = 0x20 - skip;
					unsigned req = get_min(request, (int)max);
					if (memcmp(p, m, req)) {
						dump_long(p, req, offset, skip);
						dump_long(m, req, addr, skip);
						diff_long(p, m, req, skip);
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
			verified += request;
		}
	}
	if (!mismatch)
		printf("Verify success\n");
	return mismatch ? -1 : 0;
}

int load_file(struct sdp_dev *dev, struct load_desc *ld, unsigned foffset,
		unsigned fsize, unsigned char type)
{
	struct sdp_command dl_command = {
		.cmd = SDP_WRITE_FILE,
		.addr = BE32(ld->dladdr),
		.format = 0,
		.cnt = BE32(fsize),
		.data = 0,
		.rsvd = type};
	int err;
	unsigned transferSize=0;
	unsigned char *p;
	unsigned cnt;
	unsigned char combine_buf[1024];

	do_command(dev, &dl_command, 5);

	if (dev->mode == MODE_BULK) {
		unsigned int sec;
		err = do_response(dev, 3, &sec, false);
		if (err)
			return err;
	}

	while (transferSize < fsize) {
		unsigned remaining = (fsize-transferSize);

		fetch_data(ld, foffset, &p, &cnt);
		/* Avoid short packets, they may signal end of transfer */
		if (cnt < sizeof(combine_buf)) {
			unsigned next_cnt;

			memcpy(combine_buf, p, cnt);
			while (cnt < sizeof(combine_buf)) {
				fetch_data(ld, foffset + cnt, &p, &next_cnt);
				if (!next_cnt)
					break;
				if (next_cnt > sizeof(combine_buf) - cnt)
					next_cnt = sizeof(combine_buf) - cnt;
				memcpy(&combine_buf[cnt], p, next_cnt);
				cnt += next_cnt;
			}
			p = combine_buf;
			dbg_dump_long(p, cnt, ld->dladdr + transferSize, 0);
		} else {
			cnt &= -sizeof(combine_buf);	/* round down to multiple of 1024 */
		}
		if (cnt > remaining)
			cnt = remaining;
		if (!cnt)
			break;
		dbg_printf("%s:foffset=%x, cnt=%x, remaining=%x\n", __func__, foffset, cnt, remaining);
		err = do_data_transfer(dev, p, cnt);
		if (err < 0)
			return err;
		if (!err)
			break;
		transferSize += err;
		foffset += err;
	}
	printf("\n<<<%i, %i bytes>>>\n", fsize, transferSize);
	if (dev->mode == MODE_HID) {
		unsigned int sec, status;

		err = do_response(dev, 3, &sec, false);
		if (err)
			return err;

		err = do_response(dev, 4, &status, false);
		if (err)
			return err;

		if (status == 0x88888888UL)
			printf("succeeded");
		else
			printf("failed");
		printf(" (security 0x%08x, status 0x%08x)\n", sec, status);
	} else {
		do_status(dev);
	}
	return transferSize;
}

int jump(struct sdp_dev *dev, unsigned int header_addr)
{
	int err;
	struct sdp_command jump_command = {
		.cmd = SDP_JUMP_ADDRESS,
		.addr = BE32(header_addr),
		.format = 0,
		.cnt = 0,
		.data = 0,
		.rsvd = 0x00};
	unsigned int sec, status;

	printf("jumping to 0x%08x\n", header_addr);
	err = do_command(dev, &jump_command, 5);
	if (err)
		return err;

	err = do_response(dev, 3, &sec, false);
	if (err)
		return err;

	err = do_response(dev, 4, &status, true);
	/*
	 * Documentation says: "This report is sent by device only in case of
	 * an error jumping to the given address..."
	 * If Report 4 fails, this is a good sign
	 * If Report 4 responds, there has been something gone wrong...
	 */
	if (!err) {
		printf("failed (security 0x%08x, status 0x%08x)\n", sec, status);
		return err;
	}

	return 0;
}

int load_file_from_desc(struct sdp_dev *dev, struct sdp_work *curr,
		struct load_desc *ld)
{
	int ret;
	unsigned file_base;
	unsigned char type;
	unsigned skip = 0;
	unsigned fsize;
	unsigned transferSize=0;
	unsigned cnt;

	if (!ld->dladdr) {
		printf("\nunknown load address\n");
		return -3;
	}

	type = (curr->plug || curr->jump_mode) ? FT_APP : FT_LOAD_ONLY;
	if (dev->mode == MODE_BULK && type == FT_APP) {
		/*
		 * There is no jump command.  boot ROM requires the download
		 * to start at header address
		 */
		ld->dladdr = ld->header_addr;
	}
	if (ld->verify) {
		if ((type == FT_APP) && (dev->mode != MODE_HID)) {
			type = FT_LOAD_ONLY;
			ld->verify = 2;
		}
	}
	file_base = ld->header_addr - ld->header_offset;
	if (file_base > ld->dladdr) {
		ld->max_length -= (file_base - ld->dladdr);
		ld->dladdr = file_base;
	}
	dbg_printf("skip=%x cnt=%x dladdr=%x file_base=%x fsize=%x max_length=%x\n", skip, ld->buf_cnt, ld->dladdr, file_base, ld->fsize, ld->max_length);
	skip = ld->dladdr - file_base;
	fsize = ld->fsize;
	if (skip > fsize) {
		printf("skip(0x%08x) > fsize(0x%08x) file_base=0x%08x, header_offset=0x%x\n",
				skip, fsize, file_base, ld->header_offset);
		ret = -4;
		goto cleanup;
	}
	fsize -= skip;
	if (fsize > ld->max_length)
		fsize = ld->max_length;
	printf("\nloading binary file(%s) to %08x, skip=%x, fsize=%x type=%x\n", curr->filename, ld->dladdr, skip, fsize, type);

	ret = load_file(dev, ld, skip, fsize, type);
	if (ret < 0)
		goto cleanup;
	transferSize = ret;

	if (ld->verify) {
		ret = verify_memory(dev, ld, skip, fsize);
		if (ret < 0)
			goto cleanup;
		if (ld->verify == 2) {
			cnt = fsize;
			if (cnt > 64)
				cnt = 64;
			/*
			 * This will set the right header address
			 * for bulk mode, which has no jump command
			 */
			ret = load_file(dev, ld, ld->header_offset, cnt,
					FT_APP);
			if (ret < 0)
				goto cleanup;

		}
	}

	ret = (fsize <= transferSize) ? 0 : -16;
cleanup:
	return ret;
}

int is_header(struct sdp_dev *dev, unsigned char *p)
{
	switch (dev->header_type) {
	case HDR_MX51:
	{
		struct flash_header_v1 *hdr = (struct flash_header_v1 *)p;
		if (hdr->app_barker == 0xb1)
			return 1;
		break;
	}
	case HDR_MX53:
	{
		struct flash_header_v2 *hdr = (struct flash_header_v2 *)p;
		struct ivt_header *ivt = &hdr->header;
		if (ivt->tag == IVT_HEADER_TAG &&
		    (ivt->version == IVT_VERSION || ivt->version == IVT_VERSION_IMX8M))
			return 1;
	}
	case HDR_UBOOT:
	{
		image_header_t *image = (image_header_t *)p;
		if (BE32(image->ih_magic) == IH_MAGIC)
			return 1;
	}
	}
	return 0;
}

void init_header(struct sdp_dev *dev, struct load_desc *ld)
{
	struct sdp_work *curr = ld->curr;

	memset(ld->writeable_header, 0, sizeof(ld->writeable_header));

	switch (dev->header_type) {
	case HDR_MX51:
	{
		struct flash_header_v1 *hdr = (struct flash_header_v1 *)ld->writeable_header;
		unsigned char *p = (unsigned char *)(hdr + 1);
		unsigned size;
		unsigned extra_space = ((sizeof(struct flash_header_v1) + 4 - 1) | 0x3f) + 1;

		ld->max_length += extra_space;
		size = ld->max_length;

		hdr->app_start_addr = curr->jump_addr;
		hdr->app_barker = APP_BARKER;
		hdr->dcd_ptr_ptr = ld->header_addr + offsetof(struct flash_header_v1, dcd_ptr);
		hdr->app_dest_ptr = ld->dladdr;

		*p++ = (unsigned char)size;
		size >>= 8;
		*p++ = (unsigned char)size;
		size >>= 8;
		*p++ = (unsigned char)size;
		size >>= 8;
		*p = (unsigned char)size;
		break;
	}
	case HDR_MX53:
	{
		struct flash_header_v2 *hdr = (struct flash_header_v2 *)ld->writeable_header;
		struct boot_data *bd = (struct boot_data *)(hdr+1);
		unsigned extra_space = ((sizeof(struct flash_header_v2) + sizeof(struct boot_data) - 1) | 0x3f) + 1;

		hdr->header.tag = IVT_HEADER_TAG;
		hdr->header.length = BE16(sizeof(*hdr));
		hdr->header.version = IVT_VERSION;
		hdr->start_addr = curr->jump_addr;
		hdr->boot_data_ptr = ld->header_addr + sizeof(*hdr);
		hdr->self_ptr = ld->header_addr;
		bd->dest = ld->dladdr;
		ld->max_length += extra_space;
		bd->image_len = ld->max_length;
		break;
	}
	case HDR_UBOOT:
	{
		break;
	}
	}
}

/*
 * Apply/load DCD table for v1 and v2 flash headers
 *
 * Returns 0 if successful or if there was no DCD table to download
 * Returns -1 if the DCD table is invalid
 */
int perform_dcd(struct sdp_dev *dev, unsigned char *p, unsigned char *file_start, unsigned cnt)
{
	int ret = 0;
	switch (dev->header_type) {
	case HDR_MX51:
	{
		struct flash_header_v1 *hdr = (struct flash_header_v1 *)p;
		ret = write_dcd_table_old(dev, hdr, file_start, cnt);
		dbg_printf("dcd_ptr=0x%08x\n", hdr->dcd_ptr);
		if (ret < 0)
			return ret;
		break;
	}
	case HDR_MX53:
	{
#define cvt_dest_to_src		(((unsigned char *)hdr) - hdr->self_ptr)
		struct flash_header_v2 *hdr = (struct flash_header_v2 *)p;
		unsigned char* file_end = file_start + cnt;
		unsigned char *dcd_end, *dcd_start;
		struct dcd_v2 *dcd;
		int length;

		if (!hdr->dcd_ptr) {
			printf("No DCD table\n");
			return 0;	//nothing to do
		}

		dcd_start = hdr->dcd_ptr + cvt_dest_to_src;
		if ((dcd_start < file_start) || (dcd_start + 4) > file_end) {
			printf("bad dcd_ptr %08x\n", hdr->dcd_ptr);
			return -1;
		}

		dcd = (struct dcd_v2 *)dcd_start;
		if (dcd->header.tag != DCD_HEADER_TAG ||
		    dcd->header.version != DCD_VERSION) {
			printf("Unknown DCD header tag/version\n");
			return -1;
		}

		length = BE16(dcd->header.length);
		if (length == 0) {
			printf("No DCD table, skip\n");
			return 0;
		}

		/* Check whether DCD length is longer than file */
		dcd_end = ((unsigned char *)dcd) + length;
		if (dcd_end > file_end) {
			printf("Bad dcd length 0x%08x\n", length);
			return -1;
		}

		if (dev->mode == MODE_HID) {
			ret = write_dcd(dev, dcd);
		} else {
			// For processors that don't support the WRITE_DCD command (i.MX5x)
			ret = write_dcd_table_ivt(dev, dcd);
		}
		dbg_printf("dcd_ptr=0x%08x\n", hdr->dcd_ptr);
		if (ret < 0)
			return ret;
		break;
	}
	}
	return 0;
}

int clear_dcd_ptr(struct sdp_dev *dev, unsigned char *p)
{
	switch (dev->header_type) {
	case HDR_MX51:
	{
		struct flash_header_v1 *hdr = (struct flash_header_v1 *)p;
		if (hdr->dcd_ptr) {
			printf("clear dcd_ptr=0x%08x\n", hdr->dcd_ptr);
			hdr->dcd_ptr = 0;
		}
		break;
	}
	case HDR_MX53:
	{
		struct flash_header_v2 *hdr = (struct flash_header_v2 *)p;
		if (hdr->dcd_ptr) {
			printf("clear dcd_ptr=0x%08x\n", hdr->dcd_ptr);
			hdr->dcd_ptr = 0;
		}
		break;
	}
	}
	return 0;
}

int get_dl_start(struct sdp_dev *dev, unsigned char *p,
	struct load_desc *ld, unsigned int clear_boot_data)
{
	unsigned char* file_end = ld->buf_start + ld->buf_cnt;
	switch (dev->header_type) {
	case HDR_MX51:
	{
		struct flash_header_v1 *hdr = (struct flash_header_v1 *)p;
		unsigned char *dcd_end;
		unsigned char* dcd;
		int err = get_dcd_range_old(hdr, ld->buf_start, ld->buf_cnt, &dcd, &dcd_end);
		ld->dladdr = hdr->app_dest_ptr;
		ld->header_addr = hdr->dcd_ptr_ptr - offsetof(struct flash_header_v1, dcd_ptr);
		ld->plugin = 0;
		if (err >= 0) {
			ld->max_length = dcd_end[0] | (dcd_end[1] << 8) | (dcd_end[2] << 16) | (dcd_end[3] << 24);
		}
		break;
	}
	case HDR_MX53:
	{
		struct boot_data *bd;
		unsigned char* p1;
		uint32_t *bd1;
		unsigned offset;
		struct flash_header_v2 *hdr = (struct flash_header_v2 *)p;

		ld->dladdr = hdr->self_ptr;
		ld->header_addr = hdr->self_ptr;
		p1 = (hdr->boot_data_ptr + cvt_dest_to_src);

		if ((p1 < ld->buf_start) || ((p1 + 4) > file_end)) {
			printf("bad boot_data_ptr %08x\n", hdr->boot_data_ptr);
			return -1;
		}
		bd = (struct boot_data *)p1;
		ld->dladdr = bd->dest;
		ld->max_length = bd->image_len;
		ld->plugin = bd->plugin;
		offset = ((unsigned char *)&bd->plugin) - p;
		if (offset <= sizeof(ld->writeable_header) - 4) {
			bd1 = (uint32_t *)(ld->writeable_header + offset);
			*bd1 = 0;
		} else {
			printf("Can't clear plugin flag\n");
		}
		if (clear_boot_data) {
			printf("Setting boot_data_ptr to 0\n");
			hdr->boot_data_ptr = 0;
		}
		break;
	}
	case HDR_UBOOT:
	{
		image_header_t *hdr = (image_header_t *)p;
		ld->dladdr = BE32(hdr->ih_load) - sizeof(image_header_t);
		ld->header_addr = ld->dladdr;
	}
	}
	return 0;
}

int do_status(struct sdp_dev *dev)
{
	struct sdp_command status_command = {
		.cmd = SDP_ERROR_STATUS,
		.addr = 0,
		.format = 0,
		.cnt = 0,
		.data = 0,
		.rsvd = 0};
	unsigned int hab_security, status;
	int retry = 0;
	int err;

	err = do_command(dev, &status_command, 5);
	if (err)
		return err;

	while (retry < 5) {
		err = do_response(dev, 3, &hab_security, false);
		if (!err)
			break;

		retry++;
	}

	if (err)
		return err;

	printf("HAB security state: %s (0x%08x)\n", hab_security == HAB_SECMODE_PROD ?
			"production mode" : "development mode", hab_security);

	if (dev->mode == MODE_HID) {
		err = do_response(dev, 4, &status, false);
		if (err)
			return err;
	}

	return 0;
}

unsigned offset_search_list[] = {0, 0x400, 0x8400};

int process_header(struct sdp_dev *dev, struct sdp_work *curr,
		struct load_desc *ld)
{
	int ret;
	unsigned header_max = 0x800 + curr->load_skip;
	unsigned header_inc = 0;
	unsigned search_index = 0;
	int header_cnt = 0;
	unsigned char *p;
	int hdmi_ivt = 0;
	int save_verify;
	int found = 0;

	while (1) {
		if (header_inc) {
			ld->header_offset += header_inc;
			if (ld->header_offset >= header_max)
				break;
		} else {
			if (search_index >= ARRAY_SIZE(offset_search_list))
				break;
			ld->header_offset = curr->load_skip + offset_search_list[search_index++];
		}
		if ((ld->header_offset < ld->buf_offset) ||
				(ld->header_offset - ld->buf_offset + 32 > ld->buf_cnt)) {
			fseek(ld->xfile, ld->header_offset, SEEK_SET);
			ld->buf_offset = ld->header_offset;
			ld->buf_cnt = fread(ld->buf_start, 1, ld->buf_size, ld->xfile);
			if (ld->buf_cnt < 32)
				break;
		}
		p = ld->buf_start + ld->header_offset - ld->buf_offset;
		if (!is_header(dev, p))
			continue;
		dbg_printf("%s: header_offset=%x, %02x%02x%02x%02x\n", __func__,
			ld->header_offset, p[3], p[2], p[1], p[0]);

		memcpy(ld->writeable_header, p,
				sizeof(ld->writeable_header));
		ret = get_dl_start(dev, p, ld, curr->clear_boot_data);
		if (ret < 0) {
			printf("!!get_dl_start returned %i\n", ret);
			return ret;
		}
		if (curr->dcd) {
			ret = perform_dcd(dev, p, ld->buf_start, ld->buf_cnt);
#if 1
			clear_dcd_ptr(dev, ld->writeable_header);
#endif
			if (ret < 0) {
				printf("!!perform_dcd returned %i\n", ret);
				return ret;
			}
			curr->dcd = 0;
			if ((!curr->jump_mode) && (!curr->plug)) {
				printf("!!dcd done, nothing else requested\n");
				return 0;
			}
		}
		if (curr->clear_dcd) {
			ret = clear_dcd_ptr(dev, ld->writeable_header);
			if (ret < 0) {
				printf("!!clear_dcd returned %i\n", ret);
				return ret;
			}
		}
		if (ld->plugin == 2) {
			if (!hdmi_ivt) {
				hdmi_ivt++;
				header_inc = 0x1c00 - 0x1000 + ld->max_length;
				header_max = ld->header_offset + header_inc + 0x400;
				continue;
			}
			if (curr->plug) {
				save_verify = ld->verify;
				/* Trying to verify hdmi firmware gives errors! */
				ld->verify = 0;
				ret = load_file_from_desc(dev, curr, ld);
				ld->verify = save_verify;
			}
			header_inc = ld->dladdr - ld->header_addr + ld->max_length + 0x400;
			header_max = ld->header_offset + header_inc + 0x400;
			continue;
		}
		if (ld->plugin && (!curr->plug) && (!header_cnt)) {
			header_cnt++;
			header_max = ld->header_offset + ld->max_length + 0x400;
			printf("header_max=%x\n", header_max);
			header_inc = 4;
		} else {
			if (!ld->plugin)
				curr->plug = 0;
			if (curr->jump_mode == J_HEADER2) {
				if (!found) {
					found++;
					ld->header_offset += ld->dladdr - ld->header_addr + ld->max_length;
					header_inc = 0x400;
					header_max = ld->header_offset + 0x400 * 128;
					continue;
				}
			}
			return 0;
		}
	}
	printf("header not found %x:%x, %x\n", ld->header_offset, *(unsigned int *)p, ld->buf_cnt);
	return -EINVAL;
}

#define MAX_IN_LENGTH 100 // max length for user input strings

int DoIRomDownload(struct sdp_dev *dev, struct sdp_work *curr, int verify)
{
	int ret;
	struct load_desc ld = {};

	print_sdp_work(curr);
	ld.curr = curr;
	ld.verify = verify;
	ld.xfile = fopen(curr->filename, "rb" );
	if (!ld.xfile) {
		printf("\nerror, can not open input file: %s\n", curr->filename);
		return -5;
	}
	ld.buf_size = (1024*16);
	ld.buf_start = malloc(ld.buf_size);
	if (!ld.buf_start) {
		printf("\nerror, out of memory\n");
		ret = -2;
		goto cleanup;
	}
	ld.fsize = get_file_size(ld.xfile);
	ld.max_length = ld.fsize;
	if (ld.max_length > curr->load_skip) {
		ld.max_length -= curr->load_skip;
	} else {
		printf("error, skipping past end of file\n");
		ret = -1;
		goto cleanup;
	}
	if (curr->load_size && (ld.max_length > curr->load_size))
		ld.max_length = curr->load_size;
	if (curr->dcd || curr->clear_dcd || curr->plug || (curr->jump_mode >= J_HEADER)) {
		ret = process_header(dev, curr, &ld);
		if (ret < 0)
			goto cleanup;
		if ((!curr->jump_mode) && (!curr->plug)) {
			/*  nothing else requested */
			ret = 0;
			goto cleanup;
		}
	} else {
		ld.dladdr = curr->load_addr;
		ld.header_addr = ld.dladdr + ld.max_length;
		ld.header_offset = curr->load_skip + ld.max_length;
		if (curr->jump_mode == J_ADDR_HEADER) {
			unsigned cnt = ld.max_length;

			init_header(dev, &ld);
			/* If the header is at EOF, fsize needs increased */
			ld.fsize += ld.max_length - cnt;
			dbg_dump_long((unsigned char *)ld.writeable_header, ld.max_length - cnt, ld.header_addr, 0);
		} else if (curr->jump_mode == J_ADDR_DIRECT) {
			ld.header_addr = curr->jump_addr;
			ld.header_offset = 0;
		}
	}
	if (ld.plugin && (!curr->plug)) {
		printf("Only plugin header found\n");
		ret = -1;
		goto cleanup;
	}
	ret = load_file_from_desc(dev, curr, &ld);
	/*
	 * Any command will initiate jump for bulk devices, no need to
	 * explicitly send a jump command
	 */
	if (dev->mode == MODE_HID && (curr->plug || curr->jump_mode)) {
		ret = jump(dev, ld.header_addr);
		if (ret < 0)
			goto cleanup;
	}

cleanup:
	fclose(ld.xfile);
	free(ld.buf_start);
	return ret;
}

struct sim_memory *head;
struct sim_memory {
	struct sim_memory *next;
	unsigned int addr;
	unsigned int len;
	unsigned char *buf;
	int offset;
};

int do_simulation(struct sdp_dev *dev, int report, unsigned char *p, unsigned int cnt,
		unsigned int expected, int* last_trans)
{
	static struct sdp_command cur_cmd;
	static struct sim_memory *cur_mem;
	unsigned int offset;
	unsigned mem_addr;

	switch (report) {
	case 1:
		/* Copy command */
		cur_cmd = *((struct sdp_command *)p);
		printf("cmd: %04x\n", cur_cmd.cmd);
		switch (cur_cmd.cmd) {
		case SDP_WRITE_FILE:
		case SDP_WRITE_DCD:
			if (!head) {
				cur_mem = head = malloc(sizeof(*cur_mem));
			} else {
				cur_mem = head;
				while (cur_mem->next)
					cur_mem = cur_mem->next;

				cur_mem->next = malloc(sizeof(*cur_mem));
				cur_mem = cur_mem->next;
			}

			cur_mem->next = NULL;
			cur_mem->addr = BE32(cur_cmd.addr);
			cur_mem->len = BE32(cur_cmd.cnt);
			cur_mem->buf = malloc(cur_mem->len);
			cur_mem->offset = 0;
			break;
		case SDP_READ_REG:
			cur_mem = head;
			while (cur_mem) {
				if (cur_mem->addr <= BE32(cur_cmd.addr) &&
				    cur_mem->addr + cur_mem->len > BE32(cur_cmd.addr)) {
					break;
				}

				cur_mem = cur_mem->next;
			}
			break;
		}
		break;
	case 2:
		/* Data phase, ignore */
		memcpy(cur_mem->buf + cur_mem->offset, p, cnt);
		cur_mem->offset += cnt;
		break;
	case 3:
		/* Simulate security configuration open */
		*((unsigned int *)p) = BE32(0x56787856);
		break;
	case 4:
		/* Return sensible status */
		switch (cur_cmd.cmd) {
		case SDP_WRITE_FILE:
			*((unsigned int *)p) = BE32(0x88888888UL);
			break;
		case SDP_WRITE_DCD:
			*((unsigned int *)p) = BE32(0x128a8a12UL);
			break;
		case SDP_READ_REG:
			cur_mem = head;
			mem_addr = BE32(cur_cmd.addr);
			while (cur_mem) {
				if (cur_mem->addr <=  mem_addr &&
				    cur_mem->addr + cur_mem->len > mem_addr) {
					if ((mem_addr + cnt) > (cur_mem->addr + cur_mem->len))
						return -EIO;
					break;
				}
				cur_mem = cur_mem->next;
			}
			if (!cur_mem)
				return -EIO;
			offset = mem_addr - cur_mem->addr;
			memcpy(p, cur_mem->buf + offset, cnt);
			break;
		case SDP_JUMP_ADDRESS:
			/* A successful jump returns nothing on Report 4 */
			return -7;
		}
		break;
	default:
		break;
	}

	return 0;
}

void do_simulation_cleanup(void)
{
	struct sim_memory *cur_mem = head;

	while (cur_mem) {
		struct sim_memory *free_mem = cur_mem;
		cur_mem = cur_mem->next;
		free(free_mem);
	}
}
