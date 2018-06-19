#ifndef __UTILS_H__
#define __UTILS_H__

#define DEBUG 1

#define DEBUG_PRINT(fmt, ...) do { if (DEBUG) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

int setnonblock(int fd);

#endif /*__UTILS_H__*/
