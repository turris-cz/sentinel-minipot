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

int master_pipe_alloc(struct configuration *conf);
void master_pipe_free();
void master_pipe_register_child(int read_fd);
int master_pipe_run(struct configuration *conf);
void master_pipe_break();

#endif /*__SENTINEL_MINIPOT_MASTER_PIPE_H__*/
