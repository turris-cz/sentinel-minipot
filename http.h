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

#ifndef __SENTINEL_MINIPOT_HTTP_H__
#define __SENTINEL_MINIPOT_HTTP_H__

#define HTTP_MAX_CONN_COUNT 5
// Maximal allowed request message length in bytes
#define HTTP_MAX_REQ_MESG_LEN 65536
// Maximal allowed time for one connection in seconds
#define HTTP_REQ_MSG_TIMEOUT 5

#define HTTP_MAX_TOKEN_BUFFER_LEN 4096
#define HTTP_MAX_URI_LEN 8192
#define HTTP_IP_ADDR_LEN INET6_ADDRSTRLEN

#define HTTP_TRANSFER_ENCODING_SIZE 8
#define HTTP_CONTENT_LENGTH_SIZE 8
// min, max values for generating number of tries for attacker
// -> how many times the credentials are asked before 403 forbidden
#define HTTP_CRED_MIN_RANGE 100
#define HTTP_CRED_MAX_RANGE 1000

#define HTTP_400_REP "HTTP/1.1 400 Bad Request\r\n\r\n"
// TODO realm
#define HTTP_401_REP "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"simple\"\r\n\r\n"
#define HTTP_403_REP "HTTP/1.1 403 Forbidden\r\n\r\n"
#define HTTP_405_REP "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\n\r\n"

void handle_http(unsigned port, int reporting_fd);

#endif /*__SENTINEL_MINIPOT_HTTP_H__*/
