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

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <msgpack.h>
#include <time.h>
#include "utils.h"

int setnonblock(int fd) {
    int flags;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return flags;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;
    return 0;
}

void sockaddr_to_string(struct sockaddr_storage *connection_addr, char *str) {
    struct in6_addr *v6;
    if (connection_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *connection_addr6 = (struct sockaddr_in6 *)connection_addr;
        v6 = &(connection_addr6->sin6_addr);
        if (v6->s6_addr32[0] == 0 && v6->s6_addr32[1] == 0 && v6->s6_addr16[4] == 0 && v6->s6_addr16[5] == 0xFFFF)
            inet_ntop(AF_INET, &v6->s6_addr32[3], str, INET_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, v6, str, INET6_ADDRSTRLEN);
    } else if (connection_addr->ss_family == AF_INET) {
        struct sockaddr_in *connection_addr4 = (struct sockaddr_in *)connection_addr;
        inet_ntop(AF_INET, &connection_addr4->sin_addr, str, INET_ADDRSTRLEN);
    }
}

/* Strips trailing whitespaces SP, TAB from end of the given string.
It changes SP, TAB to NULL char starting at the last char of the string.
It changes at most length of the string characters. */
void strip_trail_ws(char *str, size_t len) {
    if (!str)
        return;
    char *end_ptr = str + len -1;
    while ((*end_ptr == '\x20' || *end_ptr == '\x09') && (end_ptr >= str)) {
        // set SP and HTAB as string termination
        *end_ptr = '\x00';
        end_ptr--;
    }
}


/* Skips preceding whitespaces - SP, TAB for given string starting from given pointer.
It skips at most length of the given string. In case str is NULL returns NULL.
Returns pointer to first char which is not SP and TAB or to the last char.
*/
char *skip_prec_ws(char *str, size_t len) {
    if (!str)
        return NULL;
    char *end_ptr = str + len - 1; 
    while ((*str == '\x20' || *str == '\x09') && (str < end_ptr))
        // skip SP and HTAB
        str++;
    return str;
}

/* Returns true if given string is empty and false otherwise.
Does NOT check for NULL. */
bool is_empty_str(const char *const str) {
    if (str[0] != '\0')
        return false;
    else
        return true;
}

/* Returns true if char is valid base64 char and false if it is not.
Does NOT check for PADDING char, because it can be only at 2 last positions! */
bool base64_is_valid_mid_char(const char c) {
    return \
    (c >= '0' && c <= '9') || \
    (c >= 'A' && c <= 'Z') || \
    (c >= 'a' && c <= 'z') || \
    (c == '+' || c == '/');
}

/* Returns true if data is valid base64 string and false otherwise. */
bool base64_is_valid(const char *const data, size_t len) {
    /* Minimum size of the data is 4 chars if we omit 2 padding chars.
    Size of the data should be also multiple of 4,
    but padding is in some cases ignored. 
    */
    if (!data || len < 2)
        return false;
    for (size_t i = 0; i < len - 2; i++)
        if (!base64_is_valid_mid_char(data[i]))
            return false;
    // last two chars can also contain PADDING
    if ((!base64_is_valid_mid_char(data[len - 2]) && data[len - 2] != '=') ||
        (!base64_is_valid_mid_char(data[len - 1]) && data[len - 1] != '='))
        return false;
    return true;
}

bool send_all(int fd, const char *data, size_t amount) {
    while (amount) {
        ssize_t sent = send(fd, data, amount, MSG_NOSIGNAL);
        if (sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            DEBUG_PRINT("send_all - could not send to peer!\n");
            return false;
        }
        data += (size_t)sent;
        amount -= (size_t)sent;
    }
    return true;
}

// for pipe to parent process
bool write_all(int fd, const void *data, size_t len) {
    while (len) {
        ssize_t sent = write(fd, data, len);
        if (sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            DEBUG_PRINT("write_all - could not write to pipe\n");
            return false;
        }
        data += (size_t)sent;
        len -= (size_t)sent;
    }
    return true;
}

bool proxy_report(int fd, struct strpair *data, size_t pair_num, char *action, char *ip) {
    unsigned len = 0;
    // DATA
    if (data) {
        // count non-empty data
        size_t data_len = 0;
        for (size_t i = 0; i < pair_num; i++)
            if ((!is_empty_str(data[i].key)) && (!is_empty_str(data[i].value)))
                data_len++;
        // simple buffer
        msgpack_sbuffer sbuf;
        msgpack_sbuffer_init(&sbuf);
        // packer
        msgpack_packer pk;
        msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
        msgpack_pack_map(&pk, data_len);
        // pack only non-empty data
        for (size_t i = 0; i < pair_num; i++)
            if ((!is_empty_str(data[i].key)) && (!is_empty_str(data[i].value))) {
                PACK_STR(&pk, data[i].key);
                PACK_STR(&pk, data[i].value);
            }
        len = sbuf.size;
        if((!write_all(fd, &len, sizeof(len))) || (!write_all(fd, sbuf.data, len))) {
            msgpack_sbuffer_destroy(&sbuf);
            return false;
        }
        msgpack_sbuffer_destroy(&sbuf);
    } else {
        if (!write_all(fd, &len, sizeof(len)))
            return false;
    }
    // ACTION
    len = strlen(action);
    if((!write_all(fd, &len, sizeof(len))) || (!write_all(fd, action, len)))
        return false;
    // IP
    len = strlen(ip);
    if((!write_all(fd, &len, sizeof(len))) || (!write_all(fd, ip, len)))
        return false;
    return true;
}

int range_rand(int min, int max) {
    if (min < 0 || max < 0 || (min > max))
        return -1;
    // http://c-faq.com/lib/randrange.html
    srand(time(NULL));
    return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

/* Copy from src to dest. At most len of dest bytes are copied. */
void copy_util(char *src, size_t src_len, char *dest, size_t dest_len) {
    if (!src || src_len < 1 || !dest || dest_len < 1)
        return;
    if (src_len <= dest_len)
        memcpy(dest, src, src_len);
    else
        memcpy(dest, src, dest_len);
}