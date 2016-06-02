/*
 * avrdude - A Downloader/Uploader for AVR device programmers
 * Copyright (C) 2003-2004  Theodore A. Roth  <troth@openavr.org>
 * Copyright (C) 2005, 2007 Joerg Wunsch <j@uriah.heep.sax.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* $Id$ */

/*
 * avrdude interface for the i2cbridge
 */


#include "ac_cfg.h"

#if HAVE_LINUX_I2C_DEV_H && HAVE_LINUX_I2C_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "avrdude.h"
#include "libavrdude.h"

#include "pii2c.h"


static unsigned int current_addr = 0xffff;

/*
 * Private data for this programmer.
 */
struct pdata
{
    unsigned short device;
    unsigned short buffersize;
    unsigned short memsize;
    char address[64];
    int fd;
};

#define PDATA(pgm) ((struct pdata *) (pgm->cookie))

static short swabs(short in)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    union
    {
        short x;
        uint8_t y[2];
    } swap;

    swap.x = in;
    uint8_t tmp = swap.y[0];
    swap.y[0] = swap.y[1];
    swap.y[1] = tmp;

    in = swap.x;
#endif

    return in;
}

static void pii2c_setup(PROGRAMMER *pgm)
{
    if ((pgm->cookie = malloc(sizeof(struct pdata))) == 0)
    {
        avrdude_message(MSG_INFO, "%s: pii2c_setup(): Out of memory allocating private data\n",
                        progname);
        exit(1);
    }
    memset(pgm->cookie, 0, sizeof(struct pdata));
}

static void pii2c_teardown(PROGRAMMER *pgm)
{
    free(pgm->cookie);
}

#if 0
static void pii2c_hexdump(uint8_t *data, int len)
{
    int i;

    for (i = 0 ; i < len ; i++)
        printf("%02x ", data[i]);

    printf("\n");
}
#endif

static int pii2c_comm(PROGRAMMER *pgm, uint8_t *buf, int len, uint8_t * reply, int reply_len)
{
    struct i2c_msg msgs[2];
    struct i2c_rdwr_ioctl_data rdwr;

    rdwr.msgs = msgs;
    rdwr.nmsgs = 2;

    msgs[0].addr = PDATA(pgm)->device;
    msgs[0].flags = 0;
    msgs[0].len = len;
    msgs[0].buf = buf;

    msgs[1].addr = PDATA(pgm)->device;
    msgs[1].flags = I2C_M_RD;
    msgs[1].len = reply_len;
    msgs[1].buf = reply;

	memset(reply, 0, reply_len);

    //printf("Send: "); pii2c_hexdump(buf, len);

    int cc;
    if ((cc =ioctl(PDATA(pgm)->fd, I2C_RDWR, &rdwr)) < 0)
    {
        printf("Error in ioctl: %d\n", errno);
        return -1;
    }

    //printf("Recv: "); pii2c_hexdump(reply, reply_len);

    return 0;
}

static int pii2c_send_16(PROGRAMMER *pgm, uint8_t command, uint16_t param, uint8_t *reply, int reply_len)
{
	char buffer[3];
	buffer[0] = command;
	*(uint16_t *)&buffer[1] = swabs(param);
	if( pii2c_comm(pgm, buffer, 3, reply, reply_len) < 0 )
		return -1;
	return 0;
}

static int pii2c_send_8(PROGRAMMER *pgm, uint8_t command, uint8_t param, uint8_t *reply, int reply_len)
{
	char buffer[2];
	buffer[0] = command;
	buffer[1] = param;
	if( pii2c_comm(pgm, buffer, 2, reply, reply_len) < 0 )
		return -1;
	return 0;
	return -1;
}

static int pii2c_send_command(PROGRAMMER *pgm, uint8_t command, uint8_t *reply, int reply_len)
{
	char cmd  = command;
	return pii2c_comm(pgm, &cmd, 1, reply, reply_len);
}

static int pii2c_send_clear_command(PROGRAMMER *pgm)
{
	uint8_t code;

	if (pii2c_send_command(pgm, CLEAR_BUFFER, &code, 1) < 0)
		return -1;
	if (code)
		return -1;
	return 0;
}

static int pii2c_send_info_command(PROGRAMMER *pgm, uint16_t *blocksize, uint16_t *memsize)
{
#pragma pack(1)
	struct
	{
		uint8_t code;
		uint16_t blocksize;
		uint16_t memsize;
	} reply;
#pragma pack()

	if (pii2c_send_command(pgm, GET_PAGE_SIZE, (uint8_t *)&reply, sizeof(reply)) < 0)
		return -1;

	if (reply.code != 0)
	{
		printf("DEBUG reply code: %d\n", reply.code);
		return -1;
	}
	// TODO: Byte swap these on big endian platforms
	*blocksize = swabs(reply.blocksize);
	*memsize = swabs(reply.memsize);

	return 0;
}

static int pii2c_send_write_command(PROGRAMMER *pgm)
{
	uint8_t code;

	if (pii2c_send_command(pgm, WRITE_PAGE, &code, 1) < 0)
		return -1;
	if (code)
		return -1;
	return 0;
}

static int pii2c_send_read_command(PROGRAMMER *pgm, uint8_t count, uint8_t *buf)
{
	uint8_t reply[17];

	if (pii2c_send_8(pgm, READ_MEMORY, count, reply, count + 1) < 0)
		return -1;
	if (reply[0])
		return -1;

	memcpy(buf, reply + 1 , count);

	return 0;
}

static int pii2c_send_prog_enable_command(PROGRAMMER *pgm)
{
	uint8_t cmd[2] = {0x7f, 0x55};
	uint8_t dummy;

	if (pii2c_comm(pgm, cmd, 2, &dummy, 1) < 0)
		return -1;
	usleep(500);
	return 0;
}

static int pii2c_send_prog_exit_command(PROGRAMMER *pgm)
{
	uint8_t code;

	if (pii2c_send_command(pgm, EXIT_PROG_MODE, &code, 1) < 0)
		return -1;
	if (code)
		return -1;
	return 0;
}

static int pii2c_send_data_block(PROGRAMMER *pgm, uint16_t offset, uint8_t *data)
{
	uint8_t buf[32];

	buf[0] = WRITE_DATA_BYTES;
	*(uint16_t *)&buf[1] = swabs(offset);
	memcpy(&buf[3], data, 16);

	uint8_t reply;

	if (pii2c_comm(pgm, buf, 19, &reply, 1) < 0)
		return -1;

	if (reply)
		return -1;

	return 0;
}


static int pii2c_rdy_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int pii2c_err_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int pii2c_pgm_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int pii2c_vfy_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


/*
 * issue the 'chip erase' command to the pii2c board
 */
static int pii2c_chip_erase(PROGRAMMER *pgm, AVRPART *p)
{
	uint8_t reply = 0xff;
    if (pii2c_send_command(pgm, ERASE_CHIP, &reply, 1) < 0)
    {
        sleep(2);
        if (pii2c_send_command(pgm, ERASE_CHIP, &reply, 1) < 0)
        {
            sleep(2);
            if (pii2c_send_command(pgm, ERASE_CHIP, &reply, 1) < 0)
            return -1;
        }
    }

    return 0;
}


static void pii2c_enter_prog_mode(PROGRAMMER *pgm)
{
}


static void pii2c_leave_prog_mode(PROGRAMMER *pgm)
{
}


/*
 * issue the 'program enable' command to the AVR device
 */
static int pii2c_program_enable(PROGRAMMER *pgm, AVRPART *p)
{
    return -1;
}


/*
 * apply power to the AVR processor
 */
static void pii2c_powerup(PROGRAMMER *pgm)
{
    /* Do nothing. */

    return;
}


/*
 * remove power from the AVR processor
 */
static void pii2c_powerdown(PROGRAMMER *pgm)
{
    /* Do nothing. */

    return;
}

static int pii2c_parseextparms(PROGRAMMER * pgm, LISTID extparms)
{
    LNODEID ln;
    const char *extended_param;

    for (ln = lfirst(extparms); ln; ln = lnext(ln))
    {
        extended_param = ldata(ln);
        if (!strncmp(extended_param, "device=", 7))
        {
            int dev;
            int cc = sscanf(extended_param + 7, "%x", &dev);

            if (cc != 1 || dev < 1 || dev > 0x7f)
            {
                avrdude_message(MSG_INFO, "Device number out of range\n", extended_param);
                return -1;
            }

            PDATA(pgm)->device = dev;
        }
    }
    return 0;
}

/*
 * initialize the AVR device and prepare it to accept commands
 */
static int pii2c_initialize(PROGRAMMER *pgm, AVRPART *p)
{
    avrdude_message(MSG_INFO, "Programmer supports buffered memory access with buffersize=%i bytes.\n",
                    PDATA(pgm)->buffersize);
    avrdude_message(MSG_INFO, "Device free=%i bytes.\n",
                    PDATA(pgm)->memsize);

    pii2c_enter_prog_mode(pgm);

    return 0;
}



static void pii2c_disable(PROGRAMMER *pgm)
{
    pii2c_leave_prog_mode(pgm);

    return;
}


static void pii2c_enable(PROGRAMMER *pgm)
{
    return;
}


static int pii2c_open(PROGRAMMER *pgm, char *port)
{
    if (PDATA(pgm)->device == 0)
    {
        avrdude_message(MSG_INFO, "Device address not set, use -x device=<addr>\n");
        return -1;
    }

    strcpy(pgm->port, port);

    PDATA(pgm)->fd = open(pgm->port, O_RDWR);

    if (PDATA(pgm)->fd < 0)
    {
        avrdude_message(MSG_INFO, "Could not open bus %s\n", port);
        return -1;
    }

//    if (ioctl(PDATA(pgm)->fd, I2C_SLAVE, PDATA(pgm)->device) < 0)
//    {
//        avrdude_message(MSG_INFO, "Slave %02x is invalid or in use by another program\n", PDATA(pgm)->device);
//        return -1;
//    }

    int i;
    for (i = 0 ; i < MAX_OPEN_RETRIES ; i++)
    {
		if ( pii2c_send_prog_enable_command(pgm) < 0 )
			printf("DEBUG prog enable failed!\n");

		if (pii2c_send_info_command(pgm, &(PDATA(pgm)->buffersize), &(PDATA(pgm)->memsize)) == 0)
		{
			if (PDATA(pgm)->buffersize != 65535)
				break;
		}

		sleep(2);
    }
    if (i == 3)
    {
    	avrdude_message(MSG_INFO, "Timeout while waiting to open device\n");
    	return -1;
    }
    avrdude_message(MSG_INFO, "Device reports blocksize %d and memsize %d\n", PDATA(pgm)->buffersize, PDATA(pgm)->memsize);

    if (pii2c_send_clear_command(pgm) < 0)
        return -1;

//    sleep(1);
    return 0;
}




static void pii2c_close(PROGRAMMER *pgm)
{
    pii2c_send_prog_exit_command(pgm);
    close(PDATA(pgm)->fd);
    pgm->fd.ifd = -1;
}


static void pii2c_display(PROGRAMMER *pgm, const char *p)
{
    return;
}


static void pii2c_set_addr(PROGRAMMER *pgm, unsigned long addr)
{
    uint8_t ret = 0xff;

    if (addr == current_addr)
        return;
    pii2c_send_16(pgm, SET_ADDRESS, addr, &ret, 1);
    current_addr = addr;
}


static int pii2c_write_byte(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char value)
{
    return -1;
}


static int pii2c_read_byte_flash(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char *value)
{
    return -1;
}


static int pii2c_page_erase(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m, unsigned int addr)
{
    if (strcmp(m->desc, "flash") == 0)
        return 0;        /* assume good */
    if (strcmp(m->desc, "eeprom") == 0)
        return -1;         /* nothing to do */
    avrdude_message(MSG_INFO, "%s: pii2c_page_erase() called on memory type \"%s\"\n",
                    progname, m->desc);
    return -1;
}

static int pii2c_read_byte(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char *value)
{
    if (strcmp(m->desc, "flash") == 0)
    {
        return pii2c_read_byte_flash(pgm, p, m, addr, value);
    }
    else
        return -1;
}



static int pii2c_paged_write(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned int page_size,unsigned int addr, unsigned int n_bytes)
{
    if (n_bytes % 16)
    {
        avrdude_message(MSG_INFO, "Error in block size, must be a multiple of 16, size is %d\n", n_bytes);
        return -1;
    }

    pii2c_set_addr(pgm, addr);

    while (n_bytes)
    {
    	if (pii2c_send_data_block(pgm, addr, &m->buf[addr]) < 0)
    		return -1;

        addr += 16;
        n_bytes -= 16;
    }

    if (pii2c_send_write_command(pgm) < 0)
    	return -1;

    current_addr = addr + n_bytes;

    return addr + n_bytes;
}



static int pii2c_paged_load(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned int page_size,unsigned int addr, unsigned int n_bytes)
{
    pii2c_set_addr(pgm, addr);

    while (n_bytes)
    {
    	if (pii2c_send_read_command(pgm, 16, &m->buf[addr]) < 0)
    		return -1;

        addr += 16;
        n_bytes -= 16;
    }

    //avrdude_message(MSG_INFO, "page_size %d\n", page_size);
    //avrdude_message(MSG_INFO, "addr %04x\n", addr);
    //avrdude_message(MSG_INFO, "n_bytes %d\n", n_bytes);

    current_addr = addr + n_bytes;

    return addr + n_bytes;
}


/* Signature byte reads are always 3 bytes. */
static int pii2c_read_sig_bytes(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m)
{
    if (m->size < 3)
    {
        avrdude_message(MSG_INFO, "%s: memsize too small for sig byte read", progname);
        return -1;
    }

    m->buf[0] = p->signature[0];
    m->buf[1] = p->signature[1];
    m->buf[2] = p->signature[2];

    return 3;
}

const char pii2c_desc[] = "Atmel Butterfly evaluation board; Atmel AppNotes AVR109, AVR911";

void pii2c_initpgm(PROGRAMMER *pgm)
{
    strcpy(pgm->type, "pii2c");

    /*
     * mandatory functions
     */
    pgm->rdy_led        = pii2c_rdy_led;
    pgm->err_led        = pii2c_err_led;
    pgm->pgm_led        = pii2c_pgm_led;
    pgm->vfy_led        = pii2c_vfy_led;
    pgm->initialize     = pii2c_initialize;
    pgm->display        = pii2c_display;
    pgm->enable         = pii2c_enable;
    pgm->disable        = pii2c_disable;
    pgm->powerup        = pii2c_powerup;
    pgm->powerdown      = pii2c_powerdown;
    pgm->program_enable = pii2c_program_enable;
    pgm->chip_erase     = pii2c_chip_erase;
    pgm->open           = pii2c_open;
    pgm->close          = pii2c_close;
    pgm->read_byte      = pii2c_read_byte;
    pgm->write_byte     = pii2c_write_byte;

    /*
     * optional functions
     */

    pgm->page_erase = pii2c_page_erase;
    pgm->paged_write = pii2c_paged_write;
    pgm->paged_load = pii2c_paged_load;
    pgm->parseextparams = pii2c_parseextparms;

    pgm->read_sig_bytes = pii2c_read_sig_bytes;

    pgm->setup          = pii2c_setup;
    pgm->teardown       = pii2c_teardown;
    pgm->flag = 0;
}

#endif // HAVE_LINUX_I2C_DEV_H && HAVE_LINUX_I2C_H
