/*
 * imx_loader_config:
 * Configuration file parser for imx_usb/imx_uart loader
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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "portable.h"
#include "imx_sdp.h"
#include "image.h"

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

const char *move_string(char *dest, const char *src, unsigned cnt)
{
	unsigned i = 0;
	while (i < cnt) {
		char c = *src++;
		if ((!c) || (c == ' ') || (c == 0x0d) || (c == '\n') ||
		    (c == '#') || (c == ':') || (c == ',')) {
			src--;
			break;
		}
		dest[i++] = c;
	}
	dest[i] = '\0';
	return src;
}

char const *get_base_path(char const *argv0)
{
	static char base_path[PATH_MAX];
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

char const *get_global_conf_path(void)
{
#ifdef WIN32
	static char conf[PATH_MAX];
	static char sep = PATH_SEPARATOR;
	const char *subdir = "imx_loader";
	char const *progdata = getenv("ProgramData");

	strncpy(conf, progdata, sizeof(conf));
	strncat(conf, &sep, sizeof(conf));
	strncat(conf, subdir, sizeof(conf));
	return conf;
#else
	char const *global_conf_path = SYSCONFDIR "/imx-loader.d/";
	return global_conf_path;
#endif
}

char const *conf_path_ok(char const *conf_path, char const *conf_file)
{
	static char conf[PATH_MAX];
	static char sep = PATH_SEPARATOR;

	strncpy(conf, conf_path, sizeof(conf));
	strncat(conf, &sep, sizeof(conf) - strlen(conf) - 1);
	strncat(conf, conf_file, sizeof(conf) - strlen(conf) - 1);
	if (access(conf, R_OK) != -1) {
		printf("config file <%s>\n", conf);
		return conf;
	}
	return NULL;
}

char const *conf_file_name(char const *file, char const *base_path, char const *conf_path)
{
	char const *conf;
	char path[PATH_MAX];

	// First priority, conf path... (either -c, binary or /etc/imx-loader.d/)
	dbg_printf("checking with conf_path %s\n", conf_path);
	conf = conf_path_ok(conf_path, file);
	if (conf != NULL)
		return conf;

	// Second priority, base path, relative path of binary...
	dbg_printf("checking with base_path %s\n", base_path);
	conf = conf_path_ok(base_path, file);
	if (conf != NULL)
		return conf;

	// Third priority, working directory...
	getcwd(path, PATH_MAX);
	dbg_printf("checking with cwd %s\n", path);
	conf = conf_path_ok(path, file);
	if (conf != NULL)
		return conf;

#ifndef WIN32
	// Fourth priority, conf path relative to base path...
	snprintf(path, sizeof(path), "%s/%s", base_path, REL_SYSCONFDIR "/imx-loader.d");
	dbg_printf("checking with rel_base_path %s\n", path);
	conf = conf_path_ok(path, file);
	if (conf != NULL)
		return conf;
#endif

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
		if (strncmp(p, "clear_boot_data", 15) == 0) {
			p += 15;
			p = skip(p,',');
			curr->clear_boot_data = 1;
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
		if (strncmp(p, "size", 4) == 0) {
			p += 4;
			curr->load_size = get_val(&p, 16);
			p = skip(p,',');
		}
		if (strncmp(p, "skip", 4) == 0) {
			p += 4;
			curr->load_skip = get_val(&p, 16);
			p = skip(p,',');
		}
		if (strncmp(p, "jump_direct", 11) == 0) {
			p += 11;
			curr->jump_mode = J_ADDR_DIRECT;
			curr->jump_addr = get_val(&p, 16);
			p = skip(p,',');
		}
		if (strncmp(p, "jump", 4) == 0) {
			p += 4;
			curr->jump_mode = J_ADDR_HEADER;
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
	} else if (strncmp(p, "uboot_header", 12) == 0) {
		p += 12;
		p = skip(p,',');
		usb->header_type = HDR_UBOOT;
	} else {
		usb->header_type = HDR_MX53;
	}
	usb->max_transfer = get_val(&p, 10);
	p = skip(p,',');
	usb->dcd_addr = get_val(&p, 16);
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
