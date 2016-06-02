/*
 * avrdude - A Downloader/Uploader for AVR device programmers
 * Copyright (C) 2003-2004  Theodore A. Roth  <troth@openavr.org>
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

#ifndef pigpioi2c_h
#define pigpioi2c_h

#include "ac_cfg.h"

#if HAVE_PIGPIOD_IF2_H || HAVE_PIGPIO_H

#ifdef __cplusplus
extern "C" {
#endif

extern const char pigpioi2c_desc[];
void pigpioi2c_initpgm (PROGRAMMER *pgm);

#define MAX_OPEN_RETRIES	3

#define GET_PAGE_SIZE		0x71
#define ERASE_CHIP			0x72
#define SET_ADDRESS			0x73
#define WRITE_DATA_BYTES	0x74
#define CLEAR_BUFFER		0x75
#define WRITE_PAGE			0x76
#define READ_MEMORY			0x77
#define EXIT_PROG_MODE		0x78 // 1 byte ret value data irrelevant
#define ENTER_PROG_MODE		0x7f // 1 byte ret value data irrelevant

#ifdef __cplusplus
}
#endif

#endif // HAVE_PIGPIOD_IF2_H
#endif /* pigpioi2c_h */
