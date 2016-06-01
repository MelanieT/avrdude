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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include "avrdude.h"
#include "libavrdude.h"

#include "i2cbridge.h"

static int use_extended_addr = 0;
static unsigned int current_addr = 0xffff;

/*
 * Private data for this programmer.
 */
struct pdata
{
    unsigned int device;
    unsigned int buffersize;
    unsigned int memsize;
};

#define PDATA(pgm) ((struct pdata *) (pgm->cookie))

static void i2cbridge_setup(PROGRAMMER *pgm)
{
    if ((pgm->cookie = malloc(sizeof(struct pdata))) == 0)
    {
        avrdude_message(MSG_INFO, "%s: i2cbridge_setup(): Out of memory allocating private data\n",
                        progname);
        exit(1);
    }
    memset(pgm->cookie, 0, sizeof(struct pdata));
}

static void i2cbridge_teardown(PROGRAMMER *pgm)
{
    free(pgm->cookie);
}

static int i2cbridge_drain(PROGRAMMER *pgm, int display)
{
    return serial_drain(&pgm->fd, display);
}

static int i2cbridge_recv_line(PROGRAMMER *pgm, char *buf, int len)
{
    char *bufptr = buf;
    int chars = 0;

    do
    {
        if (serial_recv(&pgm->fd, (unsigned char *) bufptr, 1) < 0)
            return -1;

        if (len == 0 && (buf[0] == '\r' || buf[0] == '\n'))
            continue;

        if (*bufptr == '\n')
        {
            *++bufptr = 0;
            return 0;
        }

        bufptr++;
        chars++;
    }
    while (chars < (len - 1));

    *bufptr = 0;

    return 0;
}

static int i2cbridge_send_command(PROGRAMMER *pgm, char *buf, char *reply, int len)
{
    int debug = 0;

    if (debug) printf(">>> %s\n", buf);

    if (serial_send(&pgm->fd, (unsigned char *)buf, strlen(buf)) < 0)
    {
        printf("Serial timeout\n");
        return -1;
    }

    if (reply)
    {
        if (i2cbridge_recv_line(pgm, reply, len) < 0)
        {
            printf("Serial timeout\n");
            return -1;
        }

        if (!strcmp(reply, "ERROR\r\n"))
        {
            if (debug) printf("<<< ERROR\n");
            return -1;
        }

        if (debug) printf("<<< %s", reply);
    }

    char okbuf[128];
    if (i2cbridge_recv_line(pgm, okbuf, sizeof(okbuf)) < 0)
    {
        printf("Serial timeout\n");
        return -1;
    }

    if (strcmp(okbuf, "OK\r\n"))
    {
        if (debug) printf("<<< %s (expected OK)\n", okbuf);
        return -1;
    }

    if (debug) printf("<<< %s", okbuf);

    return 0;
}

static int i2cbridge_rdy_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int i2cbridge_err_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int i2cbridge_pgm_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


static int i2cbridge_vfy_led(PROGRAMMER *pgm, int value)
{
    /* Do nothing. */

    return 0;
}


/*
 * issue the 'chip erase' command to the i2cbridge board
 */
static int i2cbridge_chip_erase(PROGRAMMER *pgm, AVRPART *p)
{
    if (i2cbridge_send_command(pgm, "erase\r", NULL, 0) < 0)
    {
        sleep(2);
        if (i2cbridge_send_command(pgm, "erase\r", NULL, 0) < 0)
        {
            sleep(2);
            if (i2cbridge_send_command(pgm, "erase\r", NULL, 0) < 0)
            {
                avrdude_message(MSG_INFO, "Failed to erase chip\n");
                return -1;
            }
        }
    }

    return 0;
}


static void i2cbridge_enter_prog_mode(PROGRAMMER *pgm)
{
}


static void i2cbridge_leave_prog_mode(PROGRAMMER *pgm)
{
}


/*
 * issue the 'program enable' command to the AVR device
 */
static int i2cbridge_program_enable(PROGRAMMER *pgm, AVRPART *p)
{
    return -1;
}


/*
 * apply power to the AVR processor
 */
static void i2cbridge_powerup(PROGRAMMER *pgm)
{
    /* Do nothing. */

    return;
}


/*
 * remove power from the AVR processor
 */
static void i2cbridge_powerdown(PROGRAMMER *pgm)
{
    /* Do nothing. */

    return;
}

static int i2cbridge_parseextparms(PROGRAMMER * pgm, LISTID extparms)
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
static int i2cbridge_initialize(PROGRAMMER *pgm, AVRPART *p)
{
    char buf[128];
    int i;
    for (i = 0 ; i < 3 ; i++)
    {
        if (i2cbridge_send_command(pgm, "info\r", buf, sizeof(buf)) < 0)
            return -1;

        char *token = strtok(buf, " ");
        do
        {
            if (!strncmp(token, "PAGESIZE=", 9))
                PDATA(pgm)->buffersize = atoi(token + 9);
            else if (!strncmp(token, "RAMSIZE=", 8))
                PDATA(pgm)->memsize = atoi(token + 8);
        } while ((token = strtok(NULL, " ")) != NULL);

        if (PDATA(pgm)->buffersize < 65535)
            break;

        sleep(2);
    }
    if (i == 3)
    {
        avrdude_message(MSG_INFO, "Programmer returned invalid data\n");
        return -1;
    }

    //PDATA(pgm)->buffersize = (unsigned int) (unsigned char) c << 8;

    avrdude_message(MSG_INFO, "Programmer supports buffered memory access with buffersize=%i bytes.\n",
                    PDATA(pgm)->buffersize);
    avrdude_message(MSG_INFO, "Device free=%i bytes.\n",
                    PDATA(pgm)->memsize);

    i2cbridge_enter_prog_mode(pgm);
    i2cbridge_drain(pgm, 0);

    return 0;
}



static void i2cbridge_disable(PROGRAMMER *pgm)
{
    i2cbridge_leave_prog_mode(pgm);

    return;
}


static void i2cbridge_enable(PROGRAMMER *pgm)
{
    return;
}


static int i2cbridge_open(PROGRAMMER *pgm, char *port)
{
    if (PDATA(pgm)->device == 0)
    {
        avrdude_message(MSG_INFO, "Device address not set, use -x device=<addr>\n");
        return -1;
    }

    union pinfo pinfo;

    strcpy(pgm->port, port);
    /*
     *  If baudrate was not specified use 19200 Baud
     */
    if (pgm->baudrate == 0)
    {
        pgm->baudrate = 19200;
    }
    pinfo.baud = pgm->baudrate;
    if (serial_open(port, pinfo, &pgm->fd) == -1)
    {
        return -1;
    }

    avrdude_message(MSG_INFO, "Connecting to programmer\n");

    /*
     * drain any extraneous input
     */
    i2cbridge_drain (pgm, 0);

    char buf[128];
    sprintf(buf, "dev %02x\r", PDATA(pgm)->device);

    if (i2cbridge_send_command(pgm, buf, NULL, 0) < 0)
        return -1;

    avrdude_message(MSG_INFO, "Device address sent\n");

    i2cbridge_send_command(pgm, "open\r", NULL, 0);
    i2cbridge_send_command(pgm, "open\r", NULL, 0);
    if (i2cbridge_send_command(pgm, "open\r", NULL, 0) < 0)
    {
        avrdude_message(MSG_INFO, "Unable to open programmer\n");
        return -1;
    }

    if (i2cbridge_send_command(pgm, "clear\r", NULL, 0) < 0)
    {
        avrdude_message(MSG_INFO, "Clearing buffer failed\n");
        return -1;
    }

    sleep(1);

    i2cbridge_drain(pgm, 0);

    return 0;
}


static void i2cbridge_close(PROGRAMMER *pgm)
{
    i2cbridge_drain(pgm, 0);
    i2cbridge_send_command(pgm, "close\r", NULL, 0);
    
    serial_close(&pgm->fd);
    pgm->fd.ifd = -1;
}


static void i2cbridge_display(PROGRAMMER *pgm, const char *p)
{
    return;
}


static void i2cbridge_set_addr(PROGRAMMER *pgm, unsigned long addr)
{
    if (addr == current_addr)
        return;

    char buf[128];

    sprintf(buf, "addr %ld\r", addr);

    i2cbridge_send_command(pgm, buf, NULL, 0);
    current_addr = addr;
}


static int i2cbridge_write_byte(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char value)
{
    return -1;
}


static int i2cbridge_read_byte_flash(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char *value)
{
    return -1;
}


static int i2cbridge_page_erase(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m, unsigned int addr)
{
    if (strcmp(m->desc, "flash") == 0)
        return 0;        /* assume good */
    if (strcmp(m->desc, "eeprom") == 0)
        return -1;         /* nothing to do */
    avrdude_message(MSG_INFO, "%s: i2cbridge_page_erase() called on memory type \"%s\"\n",
                    progname, m->desc);
    return -1;
}

static int i2cbridge_read_byte(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned long addr, unsigned char *value)
{
    char cmd;

    if (strcmp(m->desc, "flash") == 0)
    {
        return i2cbridge_read_byte_flash(pgm, p, m, addr, value);
    }
    else
        return -1;
}



static int i2cbridge_paged_write(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned int page_size,unsigned int addr, unsigned int n_bytes)
{
    if (n_bytes % 16)
    {
        avrdude_message(MSG_INFO, "Error in block size, must be a multiple of 16, size is %d\n", n_bytes);
        return -1;
    }

    i2cbridge_set_addr(pgm, addr);

    char buf[128];

    while (n_bytes)
    {
        sprintf(buf, "data %d %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\r",
            addr,
            m->buf[addr],
            m->buf[addr + 1],
            m->buf[addr + 2],
            m->buf[addr + 3],
            m->buf[addr + 4],
            m->buf[addr + 5],
            m->buf[addr + 6],
            m->buf[addr + 7],
            m->buf[addr + 8],
            m->buf[addr + 9],
            m->buf[addr + 10],
            m->buf[addr + 11],
            m->buf[addr + 12],
            m->buf[addr + 13],
            m->buf[addr + 14],
            m->buf[addr + 15]);

        i2cbridge_send_command(pgm, buf, NULL, 0);

        addr += 16;
        n_bytes -= 16;
    }

    i2cbridge_send_command(pgm, "write\r", NULL, 0);

    current_addr = addr + n_bytes;

    return addr + n_bytes;
}



static int i2cbridge_paged_load(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m,unsigned int page_size,unsigned int addr, unsigned int n_bytes)
{
    i2cbridge_set_addr(pgm, addr);

    char buf[128];

    while (n_bytes)
    {
        sprintf(buf, "read 16\r");
        if (i2cbridge_send_command(pgm, buf, buf, sizeof(buf)) < 0)
            return -1;

        if (strncmp(buf, "DATA ", 5))
            return -1;

        int i;
        int byte;

        for (i = 0 ; i < 16 ; i++)
        {
            sscanf(buf + 5 + 2 * i, "%2x", &byte);
            m->buf[addr + i] = (unsigned char)byte;
        }

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
static int i2cbridge_read_sig_bytes(PROGRAMMER *pgm, AVRPART *p, AVRMEM *m)
{
    unsigned char tmp;

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

const char i2cbridge_desc[] = "Atmel Butterfly evaluation board; Atmel AppNotes AVR109, AVR911";

void i2cbridge_initpgm(PROGRAMMER *pgm)
{
    strcpy(pgm->type, "i2cbridge");

    /*
     * mandatory functions
     */
    pgm->rdy_led        = i2cbridge_rdy_led;
    pgm->err_led        = i2cbridge_err_led;
    pgm->pgm_led        = i2cbridge_pgm_led;
    pgm->vfy_led        = i2cbridge_vfy_led;
    pgm->initialize     = i2cbridge_initialize;
    pgm->display        = i2cbridge_display;
    pgm->enable         = i2cbridge_enable;
    pgm->disable        = i2cbridge_disable;
    pgm->powerup        = i2cbridge_powerup;
    pgm->powerdown      = i2cbridge_powerdown;
    pgm->program_enable = i2cbridge_program_enable;
    pgm->chip_erase     = i2cbridge_chip_erase;
    pgm->open           = i2cbridge_open;
    pgm->close          = i2cbridge_close;
    pgm->read_byte      = i2cbridge_read_byte;
    pgm->write_byte     = i2cbridge_write_byte;

    /*
     * optional functions
     */

    pgm->page_erase = i2cbridge_page_erase;
    pgm->paged_write = i2cbridge_paged_write;
    pgm->paged_load = i2cbridge_paged_load;
    pgm->parseextparams = i2cbridge_parseextparms;

    pgm->read_sig_bytes = i2cbridge_read_sig_bytes;

    pgm->setup          = i2cbridge_setup;
    pgm->teardown       = i2cbridge_teardown;
    pgm->flag = 0;
}
