/*
 *  Turris:Sentinel Minipot - password Honeypot
 *  Copyright (C) 2019-2021 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#include "log.h"
#include "czmq_logc.h"
#include "event2/logc.h"

APP_LOG(sentinel_minipots);


__attribute__((constructor))
static void log_constructor() {
	logc_czmq_init();
	logc_event_init();
}

__attribute__((destructor))
static void log_destructor() {
	logc_czmq_cleanup();
	logc_event_cleanup();
}
