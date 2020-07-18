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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <msgpack.h>

#define IP_ADDR_LEN INET6_ADDRSTRLEN

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

struct strpair {
    char *key;
    char *value;
};

int setnonblock(int fd);
void sockaddr_to_string(struct sockaddr_storage *connection_addr, char *str);

char *skip_prec_ws(char *str, size_t len);
void strip_trail_ws(char *str, size_t len);
bool is_empty_str(const char *const str);

bool base64_is_valid(const char *data, size_t len);
bool send_all(int fd, const char *data, size_t amount);
bool write_all(int fd, const void *data, size_t len);

bool proxy_report(int fd, struct strpair *data, size_t strpair_num, char *action, char *ip);
int range_rand(int min, int max);
void copy_util(char *src, size_t src_len, char *dest, size_t dest_len);

#endif /*__SENTINEL_MINIPOT_UTILS_H__*/
