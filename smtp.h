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

#ifndef __SENTINEL_MINIPOT_SMTP__
#define __SENTINEL_MINIPOT_SMTP__

#define SMTP_MAX_CONN_COUNT 5
#define SMTP_CONN_TIMEOUT 5

#define SMTP_TOKEN_BUFF_LEN 4096
#define SMTP_MAX_COMMAND_LEN 4096
#define SMTP_DECODE_BUFF_LEN SMTP_TOKEN_BUFF_LEN


#define SMTP_LOGIN_USER_LEN SMTP_TOKEN_BUFF_LEN
#define SMTP_LOGIN_PASSW_LEN SMTP_TOKEN_BUFF_LEN
#define SMTP_PLAIN_AUTHZID_LEN SMTP_TOKEN_BUFF_LEN
#define SMTP_PLAIN_AUTHCID_LEN SMTP_TOKEN_BUFF_LEN
#define SMTP_PLAIN_PASSW_LEN SMTP_TOKEN_BUFF_LEN

#define SMTP_CRED_MIN_RANGE 100
#define SMTP_CRED_MAX_RANGE 1000


#define SMTP_220_WELCOME_REP "220 <service> service reday\r\n"
#define SMTP_221_200_REP "221 2.0.0 <service> closing connection\r\n"
#define SMTP_250_EHLO_REP "250-<service> Hello\r\n250-SIZE 100000\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"
#define SMTP_250_HELO_REP "250-<service> Hello\r\n"
#define SMTP_250_200_NOOP_REP "250 2.0.0 OK\r\n"
#define SMTP_250_200_RSET_REP "250 2.0.0 Flushed\r\n"
#define SMTP_334_LOG_USER_REP "334 VXNlcm5hbWU6\r\n"
#define SMTP_334_LOG_PASS_REP "334 UGFzc3dvcmQ6\r\n"
#define SMTP_334_PL_REP "334 \r\n"
#define SMTP_421_REP "421 <service not available. Closing connection\r\n>"
#define SMTP_500_REP "500 Unrecognized command\r\n"
#define SMTP_501_HELO_REP "501  Invalid domain name\r\n"
#define SMTP_501_554_REP "501 5.5.4 Malformed authentication data\r\n"
#define SMTP_504_576_REP "504 5.7.6 Authentication mechanism not supported\r\n"
#define SMTP_530_570_REP "530 5.7.0 Authentication required\r\n"
#define SMTP_535_578_REP "535 5.7.8 Authentication credentials invalid\r\n"

void handle_smtp(unsigned port, int reporting_fd);

#endif /*__SENTINEL_MINIPOT_SMTP__*/