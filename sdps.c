#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "imx_sdp.h"
#include "portable.h"

#pragma pack (1)

struct spds
{
	unsigned	signature;        // Signature: 0x43544C42:1129598018, o "BLTC" (little endian) for the BLTC CBW
	unsigned	tag;              // Tag: to be returned in the csw
	unsigned	xfer_length;       // XferLength: number of bytes to transfer
	unsigned char	flags;            // Flags:
	//   Bit 7: direction - device shall ignore this bit if the
	//     XferLength field is zero, otherwise:
	//     0 = data-out from the host to the device,
	//     1 = data-in from the device to the host.
	//   Bits 6..0: reserved - shall be zero.
	unsigned char	reserved[2];       // Reserved - shall be zero.
	unsigned char	command;
	unsigned	length;
	unsigned char	reserved2[11];
};

#pragma pack ()

static int sdps_fill_read_reg(unsigned char *buf, unsigned addr, unsigned cnt)
{
	return 0;
}

static int sdps_fill_write_reg(unsigned char *buf, unsigned addr, unsigned cnt)
{
	return 0;
}

static int sdps_fill_status(unsigned char *buf)
{
	return 0;
}

static int sdps_fill_dl_dcd(unsigned char *buf, unsigned dcd_addr, int length)
{
	return 0;
}

static int sdps_fill_write_file(unsigned char *buf, unsigned dladdr, unsigned fsize, unsigned char type)
{
	struct spds dl_command = {
		.signature = 0x43544C42,	/* "BLTC" */
		.tag = 1,
		.xfer_length = fsize,
		.flags = 0,	/* Data In to device */
		.command = 2,	/* download firmware */
		.length = BE32(fsize),
	};
	int cmd_size = sizeof(struct spds);

	memcpy(buf, &dl_command, cmd_size);
	return cmd_size;
}

static int sdps_fill_jump(unsigned char *buf, unsigned header_addr)
{
	return 0;
}

static struct protocol_ops sdps_protocol_ops = {
	.fill_read_reg = sdps_fill_read_reg,
	.fill_write_reg = sdps_fill_write_reg,
	.fill_status = sdps_fill_status,
	.fill_dl_dcd = sdps_fill_dl_dcd,
	.fill_write_file = sdps_fill_write_file,
	.fill_jump = sdps_fill_jump,
};

void sdps_init_ops(struct sdp_dev *dev)
{
	dev->ops = &sdps_protocol_ops;
}
