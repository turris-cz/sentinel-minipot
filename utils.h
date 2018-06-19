#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINT(...) do { } while (0);
#endif

int setnonblock(int fd);

#endif /*__UTILS_H__*/
