/*
 * imx_sdp_simulation:
 * A simple client side implementation of the Serial Download Protocol (SDP)
 * for testing.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "portable.h"
#include "imx_sdp.h"
#include "image.h"

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
