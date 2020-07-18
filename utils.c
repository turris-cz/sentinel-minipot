/*
 *  Turris:Sentinel Minipot - Telnet password honeypot for Sentinel
 *  Copyright (C) 2018 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "utils.h"

int setnonblock(int fd) {
    int flags;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return flags;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;
    return 0;
}

void sockaddr_to_string(struct sockaddr_storage *connection_addr, char *str) {
    struct in6_addr *v6;
    if (connection_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *connection_addr6 = (struct sockaddr_in6 *)connection_addr;
        v6 = &(connection_addr6->sin6_addr);
        if (v6->s6_addr32[0] == 0 && v6->s6_addr32[1] == 0 && v6->s6_addr16[4] == 0 && v6->s6_addr16[5] == 0xFFFF)
            inet_ntop(AF_INET, &v6->s6_addr32[3], str, INET_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, v6, str, INET6_ADDRSTRLEN);
    } else if (connection_addr->ss_family == AF_INET) {
        struct sockaddr_in *connection_addr4 = (struct sockaddr_in *)connection_addr;
        inet_ntop(AF_INET, &connection_addr4->sin_addr, str, INET_ADDRSTRLEN);
    }
}
