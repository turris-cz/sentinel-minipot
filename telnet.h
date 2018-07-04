/*
 * Copyright 2018, CZ.NIC z.s.p.o. (http://www.nic.cz/)
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file is part of sentinel-minipot.
 */

#ifndef __SENTINEL_MINIPOT_TELNET_H__
#define __SENTINEL_MINIPOT_TELNET_H__

#define MAX_CONN_COUNT 5
#define S_LINE_MAX 256
#define DENIAL_TIMEOUT 1
#define MAX_ATTEMPTS 3

int setnonblock(int fd);

void handle_telnet(unsigned port, int reporting_fd);

#endif /*__SENTINEL_MINIPOT_TELNET_H__*/
