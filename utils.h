/*
 *  Turris:Sentinel Minipot - password Honeypot
 *  Copyright (C) 2019-2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __SENTINEL_MINIPOT_UTILS_H__
#define __SENTINEL_MINIPOT_UTILS_H__

#define DEBUG 1
#include <stdio.h>

#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINT(...) do { } while (0);
#endif

#define CHECK_ERR(CMD, NAME) do { \
    if (CMD) { \
        perror(NAME); \
        exit(EXIT_FAILURE); \
    }} while (0)

#define PACK_STR(packer, str) {msgpack_pack_str(packer, strlen(str)); msgpack_pack_str_body(packer, str, strlen(str));}
int setnonblock(int fd);
void sockaddr_to_string(struct sockaddr_storage *connection_addr, char *str);

#endif /*__SENTINEL_MINIPOT_UTILS_H__*/
