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

#ifndef __SENTINEL_MINIPOT_PROXY_H__
#define __SENTINEL_MINIPOT_PROXY_H__

#include "minipot_config.h"

/*
 * Initializes connection to Sentinel Proxy - messages relaying component.
 */
int proxy_init(struct event_base *ev_base, struct configuration *conf);

/*
 * Adds message for sending to Proxy component.
 */
void proxy_add(msgpack_sbuffer *sbuf);

/*
 * Frees Proxy communication related resources.
 */
void proxy_exit();

#endif /*__SENTINEL_MINIPOT_PROXY_H__*/
