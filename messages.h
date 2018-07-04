/*
 * Copyright 2018, CZ.NIC z.s.p.o. (http://www.nic.cz/)
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file is part of sentinel-minipot.
 */

#ifndef __SENTINEL_MINIPOT_MESSAGES_H__
#define __SENTINEL_MINIPOT_MESSAGES_H__

#include <msgpack.h>

#define MSG_MAX_SIZE 4096
#define MAX_WAITING_MESSAGES 10
#define MAX_WAIT_TIME 10

#define PACK_STR(packer, str) {msgpack_pack_str(packer, strlen(str)); msgpack_pack_str_body(packer, str, strlen(str));}

struct pipe_data_t{
    const char *name;
    enum {Data, Action, Ip} state;
    int remaining;
    msgpack_sbuffer *sbuf;
    msgpack_packer pk;
};

void log_init(struct event_base* ev_base, const char * socket, const char * topic);
void log_exit();

void reset_pipe_data(struct pipe_data_t *msg);
void handle_pipe_protocol(char **buffer, ssize_t *nbytes, struct pipe_data_t *msg);

#endif /*__SENTINEL_MINIPOT_MESSAGES_H__*/
