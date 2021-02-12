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

#ifndef __SENTINEL_MINIPOT_MASTER_PIPE_H__
#define __SENTINEL_MINIPOT_MASTER_PIPE_H__

#include "minipot_config.h"

// Allocates memory of master process (event base, events structs, buffers etc.)
// side for gathering data from child processes and sending them to ZMQ socket.
// conf: pointer to configuration struct
// Returns MP_ERR_OK or MP_ERR_PIPE_MALLOC.
int master_pipe_alloc(struct configuration *conf);

// Frees memory allocated by master_pipe_alloc.
void master_pipe_free();

// Registers child process in master process for receiving data from pipe.
// read_fd: FD of read end of master-child process pipe
void master_pipe_register_child(int read_fd);

// Connects to ZMQ socket, runs event base loop, start receiving data from pipes.
// conf: pointer to configuration struct
// Returns MP_ERR_PROXY_CONN or MP_ERR_OK.
int master_pipe_run(struct configuration *conf);

// Breaks event base loop started by master_pipe_run.
// Sets return code which is returned by master_pipe_run.
void master_pipe_break(int ret);

#endif /*__SENTINEL_MINIPOT_MASTER_PIPE_H__*/
