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
#include <stdint.h>

// Runs FTP minipot.
// listen_fd: FD of socket listening for attacker connections
// pipe_erite_end: FD for sending Sentinel messages
// Returns minipot exit code: EXIT_FAILURE or EXIT_SUCCES.
int handle_ftp(int listen_fd, int pipe_write_fd);

#endif /*__SENTINEL_MINIPOT_FTP_*/
