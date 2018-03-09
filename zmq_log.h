#ifndef __INCLUDE_ZMQ_LOG_H__
#define __INCLUDE_ZMQ_LOG_H__

#define MAX_WAITING_MESSAGES 10
#define MAX_WAIT_TIME 10

void log_init(const char * socket, const char * topic);
void log_exit();
void log_send_waiting();
void log_add(char * msg, unsigned len);

#endif /*__INCLUDE_ZMQ_LOG_H__*/
