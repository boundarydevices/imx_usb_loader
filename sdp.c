#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include "imx_sdp.h"
#include "portable.h"

#pragma pack (1)
struct sdp_command {
	uint16_t cmd;
	uint32_t addr;
	uint8_t format;
	uint32_t cnt;
	uint32_t data;
	uint8_t rsvd;
};
#pragma pack ()

#define SDP_READ_REG     0x0101
#define SDP_WRITE_REG    0x0202
#define SDP_WRITE_FILE   0x0404
#define SDP_ERROR_STATUS 0x0505
#define SDP_WRITE_DCD    0x0a0a
#define SDP_JUMP_ADDRESS 0x0b0b

static int sdp_fill_read_reg(unsigned char *buf, unsigned addr, unsigned cnt)
{
	struct sdp_command read_reg_command = {
		.cmd = SDP_READ_REG,
		.addr = BE32(addr),
		.format = 0x20,
		.cnt = BE32(cnt),
		.data = BE32(0),
		.rsvd = 0x00
	};
	int cmd_size = sizeof(struct sdp_command);

	memcpy(buf, &read_reg_command, cmd_size);
	return cmd_size;
}

static int sdp_fill_write_reg(unsigned char *buf, unsigned addr, unsigned val)
{
	struct sdp_command write_reg_command = {
		.cmd = SDP_WRITE_REG,
		.addr = BE32(addr),
		.format = 0x20,
		.cnt = BE32(4),
		.data = BE32(val),
		.rsvd = 0x00
	};
	int cmd_size = sizeof(struct sdp_command);

	memcpy(buf, &write_reg_command, cmd_size);
	return cmd_size;
}

static int sdp_fill_status(unsigned char *buf)
{
	struct sdp_command status_command = {
		.cmd = SDP_ERROR_STATUS,
		.addr = 0,
		.format = 0,
		.cnt = 0,
		.data = 0,
		.rsvd = 0
	};
	int cmd_size = sizeof(struct sdp_command);

	memcpy(buf, &status_command, cmd_size);
	return cmd_size;
}

static int sdp_fill_dl_dcd(unsigned char *buf, unsigned dcd_addr, int length)
{
	struct sdp_command dl_command = {
		.cmd = SDP_WRITE_DCD,
		.addr = BE32(dcd_addr),
		.format = 0,
		.cnt = BE32(length),
		.data = 0,
		.rsvd = 0
	};
	int cmd_size = sizeof(struct sdp_command);

	memcpy(buf, &dl_command, cmd_size);
	return cmd_size;
}

static int sdp_fill_write_file(unsigned char *buf, unsigned dladdr, unsigned fsize, unsigned char type)
{
	struct sdp_command dl_command = {
		.cmd = SDP_WRITE_FILE,
		.addr = BE32(dladdr),
		.format = 0,
		.cnt = BE32(fsize),
		.data = 0,
		.rsvd = type
	};
	int cmd_size = sizeof(struct sdp_command);

	memcpy(buf, &dl_command, cmd_size);
	return cmd_size;
}

static int sdp_fill_jump(unsigned char *buf, unsigned header_addr)
{
	struct sdp_command jump_command = {
		.cmd = SDP_JUMP_ADDRESS,
		.addr = BE32(header_addr),
		.format = 0,
		.cnt = 0,
		.data = 0,
		.rsvd = 0x00
	};
	int cmd_size = sizeof(struct sdp_command);

	memcpy(buf, &jump_command, cmd_size);
	return cmd_size;
}

static int sdp_get_cmd_addr_cnt(unsigned char *buf,
		uint16_t *cmd, uint32_t *addr, uint32_t *cnt)
{
	struct sdp_command *p = (struct sdp_command *)buf;
	uint16_t c = p->cmd;
	uint16_t tc = CMD_INVAL;

	switch (c) {
	case SDP_READ_REG:
		tc = CMD_READ_REG;
		break;
	case SDP_WRITE_REG:
		tc = CMD_WRITE_REG;
		break;
	case SDP_WRITE_FILE:
		tc = CMD_WRITE_FILE;
		break;
	case SDP_ERROR_STATUS:
		tc = CMD_ERROR_STATUS;
		break;
	case SDP_WRITE_DCD:
		tc = CMD_WRITE_DCD;
		break;
	case SDP_JUMP_ADDRESS:
		tc = CMD_JUMP_ADDRESS;
		break;
	}
	*cmd = tc;
	*addr = BE32(p->addr);
	*cnt = BE32(p->cnt);
	return sizeof(struct sdp_command);
}

static struct protocol_ops sdp_protocol_ops = {
	.fill_read_reg = sdp_fill_read_reg,
	.fill_write_reg = sdp_fill_write_reg,
	.fill_status = sdp_fill_status,
	.fill_dl_dcd = sdp_fill_dl_dcd,
	.fill_write_file = sdp_fill_write_file,
	.fill_jump = sdp_fill_jump,
	.get_cmd_addr_cnt = sdp_get_cmd_addr_cnt,
};

void sdp_init_ops(struct sdp_dev *dev)
{
	dev->ops = &sdp_protocol_ops;
}
