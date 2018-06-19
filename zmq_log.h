#ifndef __ZMQ_LOG_H__
#define __ZMQ_LOG_H__

#define MSG_MAX_SIZE 4096
#define MAX_WAITING_MESSAGES 10
#define MAX_WAIT_TIME 10

void log_init(struct event_base* ev_base, const char * socket, const char * topic);
void log_exit();
void log_send_waiting();
void log_add(char * msg, unsigned len);

#endif /*__ZMQ_LOG_H__*/
