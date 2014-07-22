/*
 * imx_uart:
 *
 * Program to download and execute an image over the serial boot protocol
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

#ifndef WIN32
#include <unistd.h>
#else
#include <Windows.h>
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

#ifndef WIN32
#include <getopt.h>
#else
#include "getopt.h"	// use local re-implementation of getopt
#endif

#include <fcntl.h>

#ifndef WIN32
#include <termios.h>

#include <sys/ioctl.h>
#include <linux/serial.h>
#else

#define open(filename,oflag)	_open(filename,oflag)
#define write(fd,buffer,count)	_write(fd,buffer,count)
#define read(fd,buffer,count)	_read(fd,buffer,count)
#define close(fd)				_close(fd)

#endif

#include "imx_sdp.h"

#define get_min(a, b) (((a) < (b)) ? (a) : (b))

int transfer_uart(struct sdp_dev *dev, int report, unsigned char *p, unsigned size,
		unsigned int expected, int* last_trans)
{
	int fd = *(int *)dev->priv;

	if (report < 3) {
		*last_trans = write(fd, p, size);
	} else {
		// Read...
		int ret;
		*last_trans = 0;
		while (*last_trans < (int)expected)
		{
			ret = read(fd, p, expected - *last_trans);
			if (ret < 0)
				return ret;

			// err is transfered bytes...
			*last_trans += ret;
			p += ret;
		}
	}

	return 0;
}

#ifndef WIN32
int uart_connect(int *uart_fd, char const *tty, int usertscts, struct termios *orig)
#else
int uart_connect(int *uart_fd, char const *tty, int usertscts, DCB* orig)
#endif
{
	int err = 0, count = 0;
	int i;
	int retry = 10;
#ifndef WIN32
	int flags = O_RDWR | O_NOCTTY | O_SYNC;
	struct termios key;
	struct serial_struct ser_info; 
#else
	int flags = O_RDWR | _O_BINARY;
	DCB dcb;
	COMMTIMEOUTS timeouts;
	HANDLE handle;
#endif
	char magic[] = { 0x23, 0x45, 0x45, 0x23 };
	char magic_response[4];
	char *buf;
#ifndef WIN32
	memset(&key,0,sizeof(key));
#endif
	memset(&magic_response,0,sizeof(magic_response));

	*uart_fd = open(tty, flags);
	if (*uart_fd < 0) {
		printf("tty %s\n", tty);
		fprintf(stdout, "open() failed: %s\n", strerror(errno));
		return *uart_fd;
	}

#ifndef WIN32
	// Get original terminal settings
	err = tcgetattr(*uart_fd, orig);

	// 8 data bits
	key.c_cflag |= CS8;
	key.c_cflag |= CLOCAL | CREAD;
	if (usertscts)
		key.c_cflag |= CRTSCTS;
	key.c_cflag |= B115200;

	// Enable blocking read, 0.5s timeout...
	key.c_lflag &= ~ICANON; // Set non-canonical mode
	key.c_cc[VTIME] = 5;

	err = tcsetattr(*uart_fd, TCSANOW, &key);
	if (err < 0) {
		fprintf(stdout, "tcsetattr() failed: %s\n", strerror(errno));
		close(*uart_fd);
		return err;
	}

	err = tcflush(*uart_fd, TCIOFLUSH);
#else
	handle=(HANDLE)_get_osfhandle(*uart_fd);

	orig->DCBlength=sizeof(DCB);

	GetCommState(handle,orig);

	memset(&dcb,0,sizeof(DCB));

	dcb.DCBlength=sizeof(DCB);
	dcb.fBinary=TRUE;
	dcb.fParity=FALSE;
	dcb.BaudRate=CBR_115200;
	dcb.ByteSize=8;

	if (usertscts)
	{
		dcb.fRtsControl=RTS_CONTROL_ENABLE;
		dcb.fOutxCtsFlow=TRUE;
	}

	if (!SetCommState(handle,&dcb))
	{
		fprintf(stdout, "SetCommState() failed: %d\n", GetLastError());
		close(*uart_fd);
		return err;
	}

	memset(&timeouts,0,sizeof(COMMTIMEOUTS));

	timeouts.ReadIntervalTimeout=MAXDWORD;
	timeouts.ReadTotalTimeoutMultiplier=MAXDWORD;
	timeouts.ReadTotalTimeoutConstant=500;

	if (!SetCommTimeouts(handle,&timeouts))
	{
		fprintf(stdout, "SetCommTimeouts() failed: %d\n", GetLastError());
		close(*uart_fd);
		return err;
	}

	if (!PurgeComm(handle,PURGE_TXABORT|PURGE_RXABORT))
	{
		fprintf(stdout, "PurgeComm() failed: %d\n", GetLastError());
		close(*uart_fd);
		return err;
	}


#endif
	// Association phase, send and receive 0x23454523
	printf("starting associating phase");
	while(retry--) {
		// Flush again before retring
		err = tcflush(*uart_fd, TCIOFLUSH);

		write(*uart_fd, magic, sizeof(magic));

		buf = magic_response;

		count = 0;
		while (count < 4) {
			err = read(*uart_fd, buf, 4 - count);

			/* read timeout.. */
			if (err <= 0)
				break;

			count += err;
			buf += err;
		}

		if (!memcmp(magic, magic_response, sizeof(magic_response)))
			break;

		printf(".");
		fflush(stdout);
#ifdef WIN32
		Sleep(1000);
#else
		// Flush again before retring
		err = tcflush(*uart_fd, TCIOFLUSH);
		sleep(1);
#endif
	}

	printf("\n");
	fflush(stdout);

	if (!retry) {
		fprintf(stderr, "associating phase failed, make sure the device"
		       " is in recovery mode\n");
		return -2;
	}

	err = 0;

	if (memcmp(magic, magic_response, sizeof(magic_response))) {
		fprintf(stderr, "magic missmatch, response was 0x%08x\n",
				*(uint32_t *)magic_response);
		return -3;
	}

	fprintf(stderr, "association phase succeeded, response was 0x%08x\n",
				*(uint32_t *)magic_response);

	return err;
}

#ifndef WIN32
void uart_close(int *uart_fd, struct termios *orig)
#else
void uart_close(int *uart_fd, DCB* orig)
#endif
{
#ifndef WIN32
	int err;

	// Restore original terminal settings
	err = tcsetattr(*uart_fd, TCSAFLUSH, orig);
	if (err < 0)
		fprintf(stdout, "tcsetattr() failed: %s\n", strerror(errno));
#else
	HANDLE handle;

	handle=(HANDLE)_get_osfhandle(*uart_fd);

	SetCommState(handle,orig);
#endif

	close(*uart_fd);
}

void print_usage(void)
{
	printf("Usage: imx_uart [OPTIONS...] UART CONFIG [JOBS...]\n"
#ifndef WIN32
		"  e.g. imx_uart -n /dev/ttyUSB0 vybrid_usb_work.conf u-boot.imx\n"
#else
		"  e.g. imx_uart -n COM1: vybrid_uart_work.conf eboot.img\n"
#endif
		"Load data on target connected to UART using serial download protocol as\n"
		"configured in CONFIG file.\n"
		"\n"
		"Where OPTIONS are\n"
		"   -h --help		Show this help\n"
		"   -v --verify		Verify downloaded data\n"
		"   -n --no-rtscts	Do not use RTS/CTS flow control\n"
		"			Default is to use RTS/CTS, Vybrid requires them\n"
		"\n"
		"And where [JOBS...] are\n"
		"   FILE [-lLOADADDR] [-sSIZE] ...\n"
		"Multiple jobs can be configured. The first job is treated special, load\n"
		"address, jump address, and length are read from the IVT header. If no job\n"
		"is specified, the jobs definied in the target specific configuration file\n"
		"is being used.\n");
}

int parse_opts(int argc, char * const *argv, char const **ttyfile,
		char const **conffile, int *verify, int *usertscts,
		struct sdp_work **cmd_head)
{
	char c;
	*conffile = NULL;
	*ttyfile = NULL;

	static struct option long_options[] = {
		{"help",	no_argument, 	0, 'h' },
		{"verify",	no_argument, 	0, 'v' },
		{"no-rtscts",	no_argument, 	0, 'n' },
		{0,		0,		0, 0 },
	};

	while ((c = getopt_long(argc, argv, "+hvn", long_options, NULL)) != -1) {
		switch (c)
		{
		case 'h':
		case '?':
			print_usage();
			return -1;
		case 'n':
			*usertscts = 0;
			break;
		case 'v':
			*verify = 1;
			break;
		}
	}

	// Options parsed, get mandatory arguments...
	if (optind >= argc) {
		fprintf(stderr, "non optional argument UART is missing\n");
		return -1;
	}

	*ttyfile = argv[optind];
	optind++;

	if (optind >= argc) {
		fprintf(stderr, "non optional argument CONFIG is missing\n");
		return -1;
	}

	*conffile = argv[optind];
	optind++;

	if (optind < argc) {
		// Parse optional job arguments...
		*cmd_head = parse_cmd_args(argc - optind, &argv[optind]);
	}

	return 0;
}

#define ARRAY_SIZE(w) sizeof(w)/sizeof(w[0])

int main(int argc, char * const argv[])
{
	struct sdp_dev *p_id;
	int err = 0;
	int config = 0;
	int verify = 0;
	int usertscts = 1;
	int uart_fd;
	struct sdp_work *curr;
	char const *conf;
	char const *ttyfile;
	char const *conffilepath;
	char const *conffile;
	char const *basepath;
#ifndef WIN32
	struct termios orig;
#else
	DCB orig;
#endif

	curr=NULL;

	err = parse_opts(argc, argv, &ttyfile, &conffilepath, &verify, &usertscts, &curr);

	if (err < 0)
		return err;

	// Get machine specific configuration file..
	if ((conffile = strrchr(conffilepath, PATH_SEPARATOR)) == NULL) {
		// Only a file was given as configuration
		basepath = get_base_path(argv[0]);
		conffile = conffilepath;
	} else {
		// A whole path is given as configuration
		basepath = get_base_path(conffilepath);
		conffile++; // Filename starts after slash
	}

	conf = conf_file_name(conffile, basepath, "/etc/imx-loader.d/");
	if (conf == NULL)
		return -1;

	p_id = parse_conf(conf);
	if (!p_id)
		return -1;

	// Open UART and start associating phase...
	err = uart_connect(&uart_fd, ttyfile, usertscts, &orig);

	if (err < 0)
		goto out;

	p_id->transfer = &transfer_uart;

	// UART private pointer is TTY file descriptor...
	p_id->priv = &uart_fd;

	err = do_status(p_id);
	if (err) {
		printf("status failed\n");
		goto out;
	}

	// By default, use work from config file...
	if (curr == NULL)
		curr = p_id->work;

	while (curr) {
		if (curr->mem)
			perform_mem_work(p_id, curr->mem);
//		printf("jump_mode %x\n", curr->jump_mode);
		if (curr->filename[0]) {
			err = DoIRomDownload(p_id, curr, verify);
		}
		if (err) {
			err = do_status(p_id);
			break;
		}
		if (!curr->next && !curr->plug)
			break;
		err = do_status(p_id);
		printf("jump_mode %x plug=%i err=%i\n", curr->jump_mode, curr->plug, err);

		if (err)
			goto out;

		if (curr->plug) {
			curr->plug = 0;
			continue;
		}
		curr = curr->next;
	}

out:
	uart_close(&uart_fd, &orig);
	return err;
}
