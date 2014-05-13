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

#ifndef WIN32
#include <unistd.h>
#else
#include <windows.h>
#include <stddef.h>
#endif
#include <ctype.h>
#ifndef WIN32
#include <sys/io.h>
#else
#include <io.h>
#endif
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


#include "imx_sdp.h"

#ifndef WIN32

#ifdef DEBUG
#define dbg_printf(fmt, args...)	fprintf(stderr, fmt, ## args)
#else
#define dbg_printf(fmt, args...)    /* Don't do anything in release builds */
#endif
#else

#ifdef DEBUG
#define dbg_printf(fmt, ...)	fprintf(stderr, fmt, __VA_ARGS__)
#else
#define dbg_printf(fmt, ...)    /* Don't do anything in release builds */

#define R_OK	04
#define access(filename,oflag)	_access(filename,oflag)

#endif

#define usleep(us)	Sleep((us+999)/1000)
#endif


#define get_min(a, b) (((a) < (b)) ? (a) : (b))

int get_val(const char** pp, int base)
{
	int val = 0;
	const char *p = *pp;
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

const unsigned char *move_string(unsigned char *dest, const unsigned char *src, unsigned cnt)
{
	unsigned i = 0;
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

char const *get_base_path(char const *argv0)
{
	static char base_path[512];
	char *e;

	strncpy(base_path, argv0, sizeof(base_path));
	e = strrchr(base_path, PATH_SEPARATOR);
#ifdef  __unix__
	if (!e) {
		readlink("/proc/self/exe", base_path,sizeof(base_path));
		e = strrchr(base_path, PATH_SEPARATOR);
	}
#endif
	if (e) {
		dbg_printf( "trailing slash == %p:%s\n", e, e);
		e[1] = 0;
	} else {
		dbg_printf( "no trailing slash\n");
	}

	return base_path;
}

char const *conf_path_ok(char const *conf_path, char const *conf_file)
{
	static char conf[512];

	strncpy(conf, conf_path, sizeof(conf));
	strncat(conf, conf_file, sizeof(conf));
	if (access(conf, R_OK) != -1) {
		printf("config file <%s>\n", conf);
		return conf;
	}
	return NULL;
}

char const *conf_file_name(char const *file, char const *base_path, char const *conf_path)
{
	char const *conf;

	// First priority, base path, relative path of binary...
	dbg_printf("checking with base_path %s\n", base_path);
	conf = conf_path_ok(base_path, file);
	if (conf != NULL)
		return conf;

	// Second priority, conf path... (either -c, binary or /etc/imx-loader.d/)
	dbg_printf("checking with conf_path %s\n", base_path);
	conf = conf_path_ok(conf_path, file);
	if (conf != NULL)
		return conf;

	printf("%s not found\n", file);
	return NULL;
}

char const *skip(const char *p, char c)
{
	while (*p==' ') p++;
	if (*p == c) {
		p++;
	}
	while (*p==' ') p++;
	return p;
}

int end_of_line(const char *p)
{
	while (*p == ' ') p++;
	if ((!p[0]) || (*p == '#') || (*p == '\n') || (*p == '\r'))
		return 1;
	return 0;
}


void parse_mem_work(struct sdp_work *curr, const char *filename, const char *p)
{
	struct mem_work *wp;
	struct mem_work **link;
	struct mem_work w;
	unsigned int i;
	const char *start = p;

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
		printf("%s: syntax error: %s {%s}\n", filename, p, start);
	}
	w.type = i;
	i = 0;
	for (;;) {
		w.vals[i] = get_val(&p, 16);
		if (i >= w.type)
			break;
		p = skip(p,',');
		if ((*p == 0) || (*p == '#')) {
			printf("%s: missing argment: %s {%s}\n", filename, p, start);
			return;
		}
		i++;
	}
	if (!end_of_line(p)) {
		printf("%s: syntax error: %s {%s}\n", filename, p, start);
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

void parse_file_work(struct sdp_work *curr, const char *filename, const char *p)
{
	const char *start = p;

	p = move_string(curr->filename, p, sizeof(curr->filename) - 1);
	p = skip(p,':');
	for (;;) {
		const char *q = p;
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
		if (q == p) {
			printf("%s: syntax error: %s {%s}\n", filename, p, start);
			break;
		}
	}
}

/*
 * #hid/bulk,[old_header,]max packet size, {ram start, ram size}(repeat valid ram areas)
 *hid,1024,0x10000000,1G,0x00907000,0x31000
 *
 */
void parse_transfer_type(struct sdp_dev *usb, const char *filename, const char *p)
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
		printf("%s: hid/bulk expected\n", filename);
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

struct sdp_dev *parse_conf(const char *filename)
{
	char line[512];
	FILE *xfile;
	const char *p;
	struct sdp_work *tail = NULL;
	struct sdp_work *curr = NULL;
	struct sdp_dev *usb = (struct sdp_dev *)malloc(sizeof(struct sdp_dev));
	if (!usb)
		return NULL;
	memset(usb, 0, sizeof(struct sdp_dev));

	xfile = fopen(filename, "rb" );
	if (!xfile) {
		printf("Could not open file: {%s}\n", filename);
		free(usb);
		return NULL;
	}
	printf("parse %s\n", filename);

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
			parse_transfer_type(usb, filename, p);
			continue;
		}
		/*
		 * #file:dcd,plug,load nnn,jump [nnn/header/header2]
		 */
		if (!curr) {
			curr = (struct sdp_work *)malloc(sizeof(struct sdp_work));
			if (!curr)
				break;
			memset(curr, 0, sizeof(struct sdp_work));
			if (!usb->work)
				usb->work = curr;
			if (tail)
				tail->next = curr;
			tail = curr;
			curr->load_addr = usb->ram[0].start + 0x03f00000;	/* default */
		}

		if (p[0] == ':') {
			parse_mem_work(curr, filename, p);
		} else {
			parse_file_work(curr, filename, p);
			curr = NULL;
		}
	}
	return usb;
}

struct sdp_work *parse_cmd_args(int argc, char * const *argv)
{
	int i = 0;
	struct sdp_work *prev = NULL;
	struct sdp_work *w = NULL;
	struct sdp_work *head = NULL;

	while (argc > i) {
		const char *p = argv[i];
		if (*p == '-') {
			char c;
			p++;
			c = *p++;
			if (w == NULL) {
				printf("specify file first\n");
				exit(1);
			}
			if (!*p) {
				i++;
				p = argv[i];
			}
			if (c == 's') {
				w->load_size = get_val(&p, 10);
				if (!w->load_addr)
					w->load_addr = 0x10800000;
				w->plug = 0;
				w->jump_mode = 0;
				i++;
				continue;
			}
			if (c == 'l') {
				w->load_addr = get_val(&p, 16);
				w->plug = 0;
				w->jump_mode = 0;
				i++;
				continue;
			}
			fprintf(stderr, "Unknown option %s\n", p);
			exit(1);
		}

		// Initialize work structure..
		w = malloc(sizeof(struct sdp_work));
		memset(w, 0, sizeof(struct sdp_work));
		strncpy(w->filename, argv[i], sizeof(w->filename) - 1);
		if (access(w->filename, R_OK) == -1) {
			fprintf(stderr, "cannot read from file %s\n",
					w->filename);
			exit(1);
		}


		if (head == NULL) {
			// Special settings for first work...
			w->dcd = 1;
			w->plug = 1;
			w->jump_mode = J_HEADER;
			head = w;
		}

		if (prev != NULL)
			prev->next = w;
		prev = w;

		i++;
	}

	return head;
}

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


static int read_memory(struct sdp_dev *dev, unsigned addr, unsigned char *dest, unsigned cnt)
{
//							address, format, data count, data, type
	static unsigned char read_reg_command[] = {1,1, V(0),   0x20, V(0x00000004), V(0), 0x00};
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
		err = dev->transfer(dev, 1, read_reg_command, 16, 0, &last_trans);
		if (!err)
			break;
		printf("read_reg_command err=%i, last_trans=%i\n", err, last_trans);
		if (retry > 5) {
			return -4;
		}
		retry++;
	}
	err = dev->transfer(dev, 3, tmp, 4, 4, &last_trans);
	if (err) {
		printf("r3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		return err;
	}
	rem = cnt;
	while (rem) {
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
		err = dev->transfer(dev, 4, tmp, 64, rem > 64 ? 64 : rem, &last_trans);
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
static int write_memory(struct sdp_dev *dev, unsigned addr, unsigned val)
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
		err = dev->transfer(dev, 1, write_reg_command, 16, 0, &last_trans);
		if (!err)
			break;
		printf("write_reg_command err=%i, last_trans=%i\n", err, last_trans);
		if (retry > 5) {
			return -4;
		}
		retry++;
	}

	memset(tmp, 0, sizeof(tmp));
	err = dev->transfer(dev, 3, tmp, sizeof(tmp), 4, &last_trans);
	dbg_printf("report 3, err=%i, last_trans=%i  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
			err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3],
			tmp[4], tmp[5], tmp[6], tmp[7]);
	if (err) {
		printf("w3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		printf("addr=0x%08x, val=0x%08x\n", addr, val);
	}
	memset(tmp, 0, sizeof(tmp));
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

static int write_dcd_table_ivt(struct sdp_dev *dev, struct ivt_header *hdr, unsigned char *file_start, unsigned cnt)
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
			err = write_memory(dev, addr, val);
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
	if (val != DCD_BARKER) {
		printf("Unknown tag\n");
		return -1;
	}
	dcd += 4;
	m_length =  (dcd[0] << 0) + (dcd[1] << 8) | (dcd[2] << 16) + (dcd[3] << 24);
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

static int write_dcd_table_old(struct sdp_dev *dev, struct old_app_header *hdr, unsigned char *file_start, unsigned cnt)
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
		char *p = buf;
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

int verify_memory(struct sdp_dev *dev, FILE *xfile, unsigned offset,
		unsigned addr, unsigned size, unsigned char *verify_buffer,
		unsigned verify_cnt)
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
			cnt = (int)get_min(request, (int)verify_cnt);
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
			ret = read_memory(dev, addr, mem_buf, request);
			if (ret < 0)
				return ret;
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
		}
	}
	if (!mismatch)
		printf("Verify success\n");
	return mismatch ? -1 : 0;
}

int is_header(struct sdp_dev *dev, unsigned char *p)
{
	switch (dev->header_type) {
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

int perform_dcd(struct sdp_dev *dev, unsigned char *p, unsigned char *file_start, unsigned cnt)
{
	int ret = 0;
	switch (dev->header_type) {
	case HDR_MX51:
	{
		struct old_app_header *ohdr = (struct old_app_header *)p;
		ret = write_dcd_table_old(dev, ohdr, file_start, cnt);
		dbg_printf("dcd_ptr=0x%08x\n", ohdr->dcd_ptr);
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
		ret = write_dcd_table_ivt(dev, hdr, file_start, cnt);
		dbg_printf("dcd_ptr=0x%08x\n", hdr->dcd_ptr);
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

int clear_dcd_ptr(struct sdp_dev *dev, unsigned char *p, unsigned char *file_start, unsigned cnt)
{
	int ret = 0;
	switch (dev->header_type) {
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

int get_dl_start(struct sdp_dev *dev, unsigned char *p, unsigned char *file_start, unsigned cnt, unsigned *dladdr, unsigned *max_length, unsigned *plugin, unsigned *header_addr)
{
	unsigned char* file_end = file_start + cnt;
	switch (dev->header_type) {
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

int do_status(struct sdp_dev *dev)
{
	static const unsigned char statusCommand[]={5,5,0,0,0,0, 0, 0,0,0,0, 0,0,0,0, 0};

	int last_trans;
	unsigned int *hab_security;
	unsigned char tmp[64];
	int retry = 0;
	int err;
	int cnt = 64;

	for (;;) {
		err = dev->transfer(dev, 1, (unsigned char*)statusCommand, 16, 0, &last_trans);
		dbg_printf("report 1, wrote %i bytes, err=%i\n", last_trans, err);
		memset(tmp, 0, sizeof(tmp));


		err = dev->transfer(dev, 3, tmp, cnt, 4, &last_trans);
		dbg_printf("report 3, read %i bytes, err=%i\n", last_trans, err);
		dbg_printf("read=%02x %02x %02x %02x\n", tmp[0], tmp[1], tmp[2], tmp[3]);
		if (!err)
			break;
		retry++;
		if (retry > 5)
			break;
	}

	hab_security = (unsigned int *)tmp;
	printf("HAB security state: %s (0x%08x)\n", *hab_security == 0x12343412 ?
			"production mode" : "development mode", *hab_security);

	if (dev->mode == MODE_HID) {
		err = dev->transfer(dev, 4, tmp, cnt, 4, &last_trans);
		dbg_printf("report 4, read %i bytes, err=%i\n", last_trans, err);
		dbg_printf("read=%02x %02x %02x %02x\n", tmp[0], tmp[1], tmp[2], tmp[3]);
	}
	return err;
}

int process_header(struct sdp_dev *dev, struct sdp_work *curr,
		unsigned char *buf, int cnt, unsigned *p_dladdr,
		unsigned *p_max_length, unsigned *p_plugin,
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
		if (is_header(dev, p)) {
			ret = get_dl_start(dev, p, buf, cnt, p_dladdr, p_max_length, p_plugin, p_header_addr);
			if (ret < 0) {
				printf("!!get_dl_start returned %i\n", ret);
				return ret;
			}
			if (curr->dcd) {
				ret = perform_dcd(dev, p, buf, cnt);
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
				ret = clear_dcd_ptr(dev, p, buf, cnt);
				if (ret < 0) {
					printf("!!clear_dcd returned %i\n", ret);
					return ret;
				}
			}
			if (*p_plugin && (!curr->plug) && (!header_cnt)) {
				header_cnt++;
				header_max = header_offset + *p_max_length + 0x400;
				if (header_max > (unsigned)(cnt - 32))
					header_max = (unsigned)(cnt - 32);
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

int load_file(struct sdp_dev *dev,
		unsigned char *p, int cnt, unsigned char *buf, unsigned buf_cnt,
		unsigned dladdr, unsigned fsize, unsigned char type, FILE* xfile)
{
//							address, format, data count, data, type
	static unsigned char dlCommand[] =    {0x04,0x04, V(0),  0x00, V(0x00000020), V(0), 0xaa};
	unsigned int *status;
	int last_trans, err;
	int retry = 0;
	unsigned transferSize=0;
	int max = dev->max_transfer;
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
		err = dev->transfer(dev, 1, dlCommand, 16, 0, &last_trans);
		if (!err)
			break;
		printf("dlCommand err=%i, last_trans=%i\n", err, last_trans);
		if (retry > 5)
			return -4;
		retry++;
	}
	retry = 0;
	if (dev->mode == MODE_BULK) {
		err = dev->transfer(dev, 3, tmp, sizeof(tmp), 4, &last_trans);
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
			err = dev->transfer(dev, 2, p, get_min(cnt, max), 0, &last_trans);
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
				usleep(10000);
				retry++;
				continue;
			}
			max = dev->max_transfer;
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
		cnt = fread(buf, 1 , get_min(cnt, (int)buf_cnt), xfile);
		p = buf;
	}
	printf("\r\n<<<%i, %i bytes>>>\r\n", fsize, transferSize);
	if (dev->mode == MODE_HID) {
		err = dev->transfer(dev, 3, tmp, sizeof(tmp), 4, &last_trans);
		if (err)
			printf("report 3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		err = dev->transfer(dev, 4, tmp, sizeof(tmp), 4, &last_trans);
		if (err)
			printf("report 4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		status = (unsigned int*)tmp;
		if (*status == 0x88888888UL)
			printf("succeeded (status 0x%08x)\n", *status);
		else
			printf("failed (status 0x%08x)\n", *status);
	} else {
		do_status(dev);
	}
	return transferSize;
}

#define MAX_IN_LENGTH 100 // max length for user input strings

#define FT_APP	0xaa
#define FT_CSF	0xcc
#define FT_DCD	0xee
#define FT_LOAD_ONLY	0x00
int DoIRomDownload(struct sdp_dev *dev, struct sdp_work *curr, int verify)
{
//							address, format, data count, data, type
	static unsigned char jump_command[] = {0x0b,0x0b, V(0),  0x00, V(0x00000000), V(0), 0x00};

	int ret;
	FILE* xfile;
	unsigned char type;
	unsigned fsize;
	unsigned header_offset;
	int cnt;
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

	print_sdp_work(curr);
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
	fsize = get_file_size(xfile);
	if (curr->load_size && (fsize > curr->load_size))
		fsize = curr->load_size;
	cnt = fread(buf, 1 , BUF_SIZE, xfile);

	if (cnt < 0x20) {
		printf("\r\nerror, file: %s is too small\r\n", curr->filename);
		ret = -2;
		goto cleanup;
	}
	max_length = fsize;
	if (curr->dcd || curr->clear_dcd || curr->plug || (curr->jump_mode >= J_HEADER)) {
		ret = process_header(dev, curr, buf, cnt,
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
	if (dev->mode == MODE_BULK) if (type == FT_APP) {
		/* No jump command, dladdr should point to header */
		dladdr = header_addr;
	}
	if (file_base > dladdr) {
		max_length -= (file_base - dladdr);
		dladdr = file_base;
	}
	skip = dladdr - file_base;
	if ((int)skip > cnt) {
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
		if ((type == FT_APP) && (dev->mode != MODE_HID)) {
			type = FT_LOAD_ONLY;
			verify = 2;
		}
	}
	printf("\nloading binary file(%s) to %08x, skip=%x, fsize=%x type=%x\r\n", curr->filename, dladdr, skip, fsize, type);
	ret = load_file(dev, p, cnt, buf, BUF_SIZE,
			dladdr, fsize, type, xfile);
	if (ret < 0)
		goto cleanup;
	transferSize = ret;

	if (verify) {
		ret = verify_memory(dev, xfile, skip, dladdr, fsize, verify_buffer, verify_cnt);
		if (ret < 0)
			goto cleanup;
		if (verify == 2) {
			if (verify_cnt > 64)
				verify_cnt = 64;
			ret = load_file(dev, verify_buffer, verify_cnt,
					buf, BUF_SIZE, dladdr, verify_cnt,
					FT_APP, xfile);
			if (ret < 0)
				goto cleanup;

		}
	}
	if (dev->mode == MODE_HID) if (type == FT_APP) {
		printf("jumping to 0x%08x\n", header_addr);
		jump_command[2] = (unsigned char)(header_addr >> 24);
		jump_command[3] = (unsigned char)(header_addr >> 16);
		jump_command[4] = (unsigned char)(header_addr >> 8);
		jump_command[5] = (unsigned char)(header_addr);
		//Any command will initiate jump for mx51, jump address is ignored by mx51
		retry = 0;
		for (;;) {
			err = dev->transfer(dev, 1, jump_command, 16, 0, &last_trans);
			if (!err)
				break;
			printf("jump_command err=%i, last_trans=%i\n", err, last_trans);
			if (retry > 5) {
				return -4;
			}
			retry++;
		}
		memset(tmp, 0, sizeof(tmp));
		err = dev->transfer(dev, 3, tmp, sizeof(tmp), 4, &last_trans);
		if (err)
			printf("j3 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		if (0) if (dev->mode == MODE_HID) {
			memset(tmp, 0, sizeof(tmp));
			err = dev->transfer(dev, 4, tmp, sizeof(tmp), 4, &last_trans);
			printf("j4 in err=%i, last_trans=%i  %02x %02x %02x %02x\n", err, last_trans, tmp[0], tmp[1], tmp[2], tmp[3]);
		}
	}
	ret = (fsize == transferSize) ? 0 : -16;
cleanup:
	fclose(xfile);
	free(verify_buffer);
	free(buf);
	return ret;
}

