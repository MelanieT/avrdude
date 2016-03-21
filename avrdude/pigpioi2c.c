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

#if HAVE_PIGPIOD_IF2_H || HAVE_PIGPIO_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#if HAVE_PIGPIOD_IF2_H
#include <pigpiod_if2.h>
#elif HAVE_PIGPIO_H
#include <pigpio.h>
#endif

#include "avrdude.h"
#include "libavrdude.h"

#include "pigpioi2c.h"


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
    char port[16];
    int handle;
    int target_dev;
};

#define PDATA(pgm) ((struct pdata *) (pgm->cookie))

static void pigpioi2c_setup(PROGRAMMER *pgm)
{
    if ((pgm->cookie = malloc(sizeof(struct pdata))) == 0)
    {
        avrdude_message(MSG_INFO, "%s: pigpioi2c_setup(): Out of memory allocating private data\n",
                        progname);
        exit(1);
    }
    memset(pgm->cookie, 0, sizeof(struct pdata));
}

static void pigpioi2c_teardown(PROGRAMMER *pgm)
{
    free(pgm->cookie);
}

#if HAVE_LIBPIGPIOD_IF2
static int pigpioi2c_comm(PROGRAMMER *pgm, uint8_t *buf, int len, uint8_t * reply, int reply_len)
{
	memset(reply, 0, reply_len);
	uint8_t send_buffer[32];
	int send_len = len + 8;
	send_buffer[0] = 2; //combined mode on
	send_buffer[1] = 4; // set address
	send_buffer[2] = PDATA(pgm)->device;
	send_buffer[3] = 7; //write
	send_buffer[4] = len;
	memcpy(&send_buffer[5], buf, len);
	send_buffer[5 + len] = 6; //read
	send_buffer[5 + len + 1] = reply_len;
	send_buffer[5 + len + 2] = 0; //end
	int ret = i2c_zip(PDATA(pgm)->handle, PDATA(pgm)->target_dev, send_buffer, send_len, reply, reply_len);
	printf("DEBUG i2c_zip return %d on %02x reply ", ret, buf[0]);
	int i = 0;
	for(i = 0; i < reply_len; i++)
	{
		printf("%02x ", reply[i]);
	}
	printf(" ##\n");
	if (ret < 0 && buf[0] != EXIT_PROG_MODE)
	{
		printf("ERROR: %d\n", ret);
		return -1;
	}
	return 0;
}
#endif

#if HAVE_LIBPIGPIO
static int pigpioi2c_comm(PROGRAMMER *pgm, uint8_t *buf, int len, uint8_t * reply, int reply_len)
{
    i2cSwitchCombined(1);
    if (i2cWriteDevice(PDATA(pgm)->target_dev, buf, len) < 0)
        return -1;
    if (i2cReadDevice(PDATA(pgm)->target_dev, reply, reply_len) < 0)
        return -1;
    return 0;
}
#endif


static int pigpioi2c_send_16(PROGRAMMER *pgm, uint8_t command, uint16_t param, uint8_t *reply, int reply_len)
{
	char buffer[3];
	buffer[0] = command;
	*(uint16_t *)&buffer[1] = param;
	if( pigpioi2c_comm(pgm, buffer, 3, reply, reply_len) < 0 )
		return -1;
	return 0;
}

static int pigpioi2c_send_8(PROGRAMMER *pgm, uint8_t command, uint8_t param, uint8_t *reply, int reply_len)
{
	char buffer[2];
	buffer[0] = command;
	buffer[1] = param;
	if( pigpioi2c_comm(pgm, buffer, 2, reply, reply_len) < 0 )
		return -1;
	return 0;
	return -1;
}

static int pigpioi2c_send_command(PROGRAMMER *pgm, uint8_t command, uint8_t *reply, int reply_len)
{
	char cmd  = command;
	return pigpioi2c_comm(pgm, &cmd, 1, reply, reply_len);
}

static int pigpioi2c_send_clear_command(PROGRAMMER *pgm)
{
	uint8_t code;

	if (pigpioi2c_send_command(pgm, CLEAR_BUFFER, &code, 1) < 0)
		return -1;
	if (code)
		return -1;
	return 0;
}

static int pigpioi2c_send_info_command(PROGRAMMER *pgm, uint16_t *blocksize, uint16_t *ramsize)
{
#pragma pack(1)
	struct
	{
		uint8_t code;
		uint16_t blocksize;
		uint16_t ramsize;
	} reply;
#pragma pack()

	if (pigpioi2c_send_command(pgm, GET_PAGE_SIZE, (uint8_t *)&reply, sizeof(reply)) < 0)
		return -1;

	if (reply.code != 0)
	{
		printf("DEBUG reply code: %d\n", reply.code);
		return -1;
	}
	// TODO: Byte swap these on big endian platforms
	*blocksize = reply.blocksize;
	*ramsize = reply.ramsize;

	return 0;
}

static int pigpioi2c_send_write_command(PROGRAMMER *pgm)
{
	uint8_t code;

	if (pigpioi2c_send_command(pgm, WRITE_PAGE, &code, 1) < 0)
		return -1;
	if (code)
		return -1;
	return 0;
}

static int pigpioi2c_send_read_command(PROGRAMMER *pgm, uint8_t count, uint8_t *buf)
{
	uint8_t reply[17];

	if (pigpioi2c_send_8(pgm, READ_MEMORY, count, reply, count + 1) < 0)
		return -1;
	if (reply[0])
		return -1;

	memcpy(buf, reply + 1 , count);

	return 0;
}

static int pigpioi2c_send_prog_enable_command(PROGRAMMER *pgm)
{
	uint8_t cmd[2] = {0x7f, 0x55};
	uint8_t dummy;

	if (pigpioi2c_comm(pgm, cmd, 2, &dummy, 1) < 0)
		return -1;
	usleep(500);
	return 0;
}

static int pigpioi2c_send_prog_exit_command(PROGRAMMER *pgm)
{
	uint8_t code;

	if (pigpioi2c_send_command(pgm, EXIT_PROG_MODE, &code, 1) < 0)
		return -1;
	if (code)
		return -1;
	return 0;
}

static int pigpioi2c_send_data_block(PROGRAMMER *pgm, uint16_t offset, uint8_t *data)
{
	uint8_t buf[32];

	buf[0] = WRITE_DATA_BYTES;
	*(uint16_t *)&buf[1] = offset;
	memcpy(&buf[3], data, 16);

	uint8_t reply;

	if (pigpioi2c_comm(pgm, buf, 19, &reply, 1) < 0)
		return -1;

	if (reply)
		return -1;

	return 0;
}


static int pigpioi2c_rdy_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int pigpioi2c_err_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int pigpioi2c_pgm_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int pigpioi2c_vfy_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


/*
 * issue the 'chip erase' command to the pigpioi2c board
 */
static int pigpioi2c_chip_erase(PROGRAMMER *pgm, AVRPART *p)
{
	uint8_t reply = 0xff;
    if (pigpioi2c_send_command(pgm, ERASE_CHIP, &reply, 1) < 0)
    {
        sleep(2);
        if (pigpioi2c_send_command(pgm, ERASE_CHIP, &reply, 1) < 0)
        {
            sleep(2);
            if (pigpioi2c_send_command(pgm, ERASE_CHIP, &reply, 1) < 0)
            return -1;
        }
    }

    return 0;
}


static void pigpioi2c_enter_prog_mode(PROGRAMMER *pgm)
{
}


static void pigpioi2c_leave_prog_mode(PROGRAMMER *pgm)
{
}


/*
 * issue the 'program enable' command to the AVR device
 */
static int pigpioi2c_program_enable(PROGRAMMER *pgm, AVRPART *p)
{
    return -1;
}


/*
 * apply power to the AVR processor
 */
static void pigpioi2c_powerup(PROGRAMMER *pgm)
{
    /* Do nothing. */

    return;
}


/*
 * remove power from the AVR processor
 */
static void pigpioi2c_powerdown(PROGRAMMER *pgm)
{
    /* Do nothing. */

    return;
}

static int pigpioi2c_parseextparms(PROGRAMMER * pgm, LISTID extparms)
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
        else if (!strncmp(extended_param, "host=", 5))
        {
        	strcpy(PDATA(pgm)->address, extended_param + 5);
        }
        else if (!strncmp(extended_param, "port=", 5))
        {
        	strcpy(PDATA(pgm)->port, extended_param + 5);
        }
    }
    return 0;
}

/*
 * initialize the AVR device and prepare it to accept commands
 */
static int pigpioi2c_initialize(PROGRAMMER *pgm, AVRPART *p)
{
    avrdude_message(MSG_INFO, "Programmer supports buffered memory access with buffersize=%i bytes.\n",
                    PDATA(pgm)->buffersize);
    avrdude_message(MSG_INFO, "Device free=%i bytes.\n",
                    PDATA(pgm)->memsize);

    pigpioi2c_enter_prog_mode(pgm);

    return 0;
}



static void pigpioi2c_disable(PROGRAMMER *pgm)
{
    pigpioi2c_leave_prog_mode(pgm);

    return;
}


static void pigpioi2c_enable(PROGRAMMER *pgm)
{
    return;
}


static int pigpioi2c_open(PROGRAMMER *pgm, char *port)
{
    if (PDATA(pgm)->device == 0)
    {
        avrdude_message(MSG_INFO, "Device address not set, use -x device=<addr>\n");
        return -1;
    }
#if HAVE_LIBPIGPIOD_IF2
    if (PDATA(pgm)->address[0] == 0)
    {
        avrdude_message(MSG_INFO, "Host address not set, use -x host=<addr>\n");
        return -1;
    }
    if (PDATA(pgm)->port[0] == 0)
    {
        avrdude_message(MSG_INFO, "Port not set, use -x port=<port>\n");
        return -1;
    }
#endif

    strcpy(pgm->port, port);

    //initialise pigpiod
#if HAVE_LIBPIGPIO
    gpioInitialise();
    PDATA(pgm)->target_dev = i2cOpen(1, PDATA(pgm)->device, 0);
#endif
#if HAVE_LIBPIGPIOD_IF2
    PDATA(pgm)->handle = pigpio_start(PDATA(pgm)->address, PDATA(pgm)->port);
    if (PDATA(pgm)->handle < 0)
    {
        avrdude_message(MSG_INFO, "Could not get handle");
        return -1;
    }
    PDATA(pgm)->target_dev = i2c_open(PDATA(pgm)->handle, 1, PDATA(pgm)->device, 0);
#endif
    if (PDATA(pgm)->target_dev < 0 )
    {
    	//TODO: add more specific error reporting
        avrdude_message(MSG_INFO, "Error aquiring i2c device");
        return -1;
    }

    int i;
    for (i = 0 ; i < MAX_OPEN_RETRIES ; i++)
    {
		if ( pigpioi2c_send_prog_enable_command(pgm) < 0 )
			printf("DEBUG prog enable failed!\n");

		if (pigpioi2c_send_info_command(pgm, &(PDATA(pgm)->buffersize), &(PDATA(pgm)->memsize)) == 0)
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
    avrdude_message(MSG_INFO, "Device reports blocksize %d and ramsize %d\n", PDATA(pgm)->buffersize, PDATA(pgm)->memsize);

    if (pigpioi2c_send_clear_command(pgm) < 0)
        return -1;

//    sleep(1);
    return 0;
}




static void pigpioi2c_close(PROGRAMMER *pgm)
{
    pigpioi2c_send_prog_exit_command(pgm);
#if HAVE_LIBPIGPIOD_IF2
    pigpio_stop(PDATA(pgm)->handle);
    i2c_close(PDATA(pgm)->handle, PDATA(pgm)->target_dev);
#endif
#if HAVE_LIBPIGPIO
    i2cClose(PDATA(pgm)->target_dev);
    gpioTerminate();
#endif
    pgm->fd.ifd = -1;
}


static void pigpioi2c_display(PROGRAMMER *pgm, const char *p)
{
    return;
}


static void pigpioi2c_set_addr(PROGRAMMER *pgm, unsigned long addr)
{
    uint8_t ret = 0xff;

    if (addr == current_addr)
        return;
    pigpioi2c_send_16(pgm, SET_ADDRESS, addr, &ret, 1);
    current_addr = addr;
}


static int pigpioi2c_write_byte(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char value)
{
    return -1;
}


static int pigpioi2c_read_byte_flash(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char *value)
{
    return -1;
}


static int pigpioi2c_page_erase(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m, unsigned int addr)
{
    if (strcmp(m->desc, "flash") == 0)
        return 0;        /* assume good */
    if (strcmp(m->desc, "eeprom") == 0)
        return -1;         /* nothing to do */
    avrdude_message(MSG_INFO, "%s: pigpioi2c_page_erase() called on memory type \"%s\"\n",
                    progname, m->desc);
    return -1;
}

static int pigpioi2c_read_byte(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char *value)
{
    if (strcmp(m->desc, "flash") == 0)
    {
        return pigpioi2c_read_byte_flash(pgm, p, m, addr, value);
    }
    else
        return -1;
}



static int pigpioi2c_paged_write(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned int page_size,unsigned int addr, unsigned int n_bytes)
{
    if (n_bytes % 16)
    {
        avrdude_message(MSG_INFO, "Error in block size, must be a multiple of 16, size is %d\n", n_bytes);
        return -1;
    }

    pigpioi2c_set_addr(pgm, addr);

    while (n_bytes)
    {
    	if (pigpioi2c_send_data_block(pgm, addr, &m->buf[addr]) < 0)
    		return -1;

        addr += 16;
        n_bytes -= 16;
    }

    if (pigpioi2c_send_write_command(pgm) < 0)
    	return -1;

    current_addr = addr + n_bytes;

    return addr + n_bytes;
}



static int pigpioi2c_paged_load(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned int page_size,unsigned int addr, unsigned int n_bytes)
{
    pigpioi2c_set_addr(pgm, addr);

    while (n_bytes)
    {
    	if (pigpioi2c_send_read_command(pgm, 16, &m->buf[addr]) < 0)
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
static int pigpioi2c_read_sig_bytes(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m)
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

const char pigpioi2c_desc[] = "Atmel Butterfly evaluation board; Atmel AppNotes AVR109, AVR911";

void pigpioi2c_initpgm(PROGRAMMER *pgm)
{
    strcpy(pgm->type, "pigpioi2c");

    /*
     * mandatory functions
     */
    pgm->rdy_led        = pigpioi2c_rdy_led;
    pgm->err_led        = pigpioi2c_err_led;
    pgm->pgm_led        = pigpioi2c_pgm_led;
    pgm->vfy_led        = pigpioi2c_vfy_led;
    pgm->initialize     = pigpioi2c_initialize;
    pgm->display        = pigpioi2c_display;
    pgm->enable         = pigpioi2c_enable;
    pgm->disable        = pigpioi2c_disable;
    pgm->powerup        = pigpioi2c_powerup;
    pgm->powerdown      = pigpioi2c_powerdown;
    pgm->program_enable = pigpioi2c_program_enable;
    pgm->chip_erase     = pigpioi2c_chip_erase;
    pgm->open           = pigpioi2c_open;
    pgm->close          = pigpioi2c_close;
    pgm->read_byte      = pigpioi2c_read_byte;
    pgm->write_byte     = pigpioi2c_write_byte;

    /*
     * optional functions
     */

    pgm->page_erase = pigpioi2c_page_erase;
    pgm->paged_write = pigpioi2c_paged_write;
    pgm->paged_load = pigpioi2c_paged_load;
    pgm->parseextparams = pigpioi2c_parseextparms;

    pgm->read_sig_bytes = pigpioi2c_read_sig_bytes;

    pgm->setup          = pigpioi2c_setup;
    pgm->teardown       = pigpioi2c_teardown;
    pgm->flag = 0;
}

#endif // HAVE_PIGPIOD_IF2_H
