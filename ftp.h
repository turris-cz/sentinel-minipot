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

#ifndef __SENTINEL_MINIPOT_FTP_
#define __SENTINEL_MINIPOT_FTP_

#define FTP_MAX_CONN_COUNT 5
#define FTP_CONN_TIMEOUT 5
#define FTP_TOKEN_BUFFER_LEN 4096
#define FTP_MAX_COMMAND_LEN 4096
#define FTP_USER_LEN 4096
#define FTP_PASSWORD_LEN 4096
#define FTP_CRED_MIN_RANGE 100
#define FTP_CRED_MAX_RANGE 1000

#define FTP_200_RESP "200 COMMAND OK\r\n"
#define FTP_211_FEAT_RESP "211 FEATURES\r\n EPRT\r\n EPSV\r\n SIZE\r\n OPTS\r\n MLST\r\n MLSD\r\n MDTM\r\n LPRT\r\n LPSV\r\n211 END\r\n"
#define FTP_220_WELCOME_RESP "220 SERVICE READY\r\n"
#define FTP_220_REIN_RESP "220 READY FOR A NEW USER\r\n"
#define FTP_221_RESP "221 CLOSING CONTROL CONNECTION\r\n"
#define FTP_331_RESP "331 NEED PASSWORD FOR LOGIN\r\n"
#define FTP_421_RESP "421 CLOSING CONTROL CONNECTION\r\n"
#define FTP_500_RESP "500 SYNTAX ERROR, UNRECOGNIZED COMMAND\r\n"
#define FTP_501_RESP "501 SYNTAX ERROR, NO ARGUMENT ALLOWED\r\n"
#define FTP_503_RESP "503 BAD SEQUENCE OF COMMANDS\r\n"
#define FTP_530_RESP "530 PLEASE ENTER USER AND PASSWORD\r\n"

void handle_ftp(unsigned port, int reporting_fd);

#endif /*__SENTINEL_MINIPOT_FTP_*/
