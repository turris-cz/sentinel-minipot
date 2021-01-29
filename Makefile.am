bin_PROGRAMS = sentinel-minipot

minipot_sources = \
	master_pipe.c \
	utils.c \
	telnet.c \
	http.c \
	ftp.c \
	smtp.c \
	cli_opts.c \
	minipot_pipe.c \
	child.c \
	log.c

sentinel_minipot_SOURCES = \
	main.c \
	${minipot_sources}

sentinel_minipot_CFLAGS = \
	${czmq_CFLAGS} \
	${msgpack_CFLAGS} \
	${libevent_CFLAGS} \
	${base64c_CFLAGS} \
	${logc_CFLAGS}

sentinel_minipot_LDADD = \
	${czmq_LIBS} \
	${msgpack_LIBS} \
	${libevent_LIBS} \
	${base64c_LIBS} \
	${logc_LIBS}

gperf_files =  \
	http_header.gperf.c \
	http_tr_enc.gperf.c \
	ftp_commands.gperf.c \
	smtp_commands.gperf.c \
	sasl_mechanisms.gperf.c
$(sentinel_minipot_OBJECTS): $(gperf_files)
include $(srcdir)/gperf.am


if ENABLE_LINTERS
linted_files = $(sentinel_minipot_SOURCES)
include $(srcdir)/lint.am
endif

include $(srcdir)/tests/Makefile.am
