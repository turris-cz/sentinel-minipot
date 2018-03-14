#ifndef __INCLUDE_TELNET_H__
#define __INCLUDE_TELNET_H__

#define MAX_CONN_COUNT 5
#define S_LINE_MAX 256
#define DENIAL_TIMEOUT 1
#define MAX_ATTEMPTS 3

int setnonblock(int fd);

void handle_telnet(int listen_fd, int reporting_fd);

#endif /*__INCLUDE_TELNET_H__*/
