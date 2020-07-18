bin_PROGRAMS = sentinel_minipot
sentinel_minipot_SOURCES = main.c messages.c utils.c telnet.c http.c
sentinel_minipot_CFLAGS = ${czmq_CFLAGS} ${libevent_CFLAGS} ${msgpack_CFLAGS} -std=c99
sentinel_minipot_LDADD  = ${czmq_LIBS} ${libevent_LIBS} ${msgpack_LIBS}
