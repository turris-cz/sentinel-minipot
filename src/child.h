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

#ifndef __SENTINEL_MINIPOT_CHILD_H__
#define __SENTINEL_MINIPOT_CHILD_H__

#include <stdint.h>

#include "service_data.h"

// General child process handler implementing common setup. It runs particular
// minipot handler and passes its return code to master process.
// data: pointer to struct storing minipot configuration
int handle_child(struct service_data *data);

#endif /*__SENTINEL_MINIPOT_CHILD_H__*/
