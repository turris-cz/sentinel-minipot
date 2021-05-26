bin_PROGRAMS += sentinel-minipot

minipot_sources = \
	%reldir%/char_consts.h \
	%reldir%/child.h \
	%reldir%/child.c \
	%reldir%/cli_opts.h \
	%reldir%/cli_opts.c \
	%reldir%/log.h \
	%reldir%/log.c \
	%reldir%/master_pipe.h \
	%reldir%/master_pipe.c \
	%reldir%/minipot_config.h \
	%reldir%/minipot_pipe.h \
	%reldir%/minipot_pipe.c \
	%reldir%/service_data.h \
	%reldir%/utils.h \
	%reldir%/utils.c \
	%reldir%/ftp.h \
	%reldir%/ftp.c \
	%reldir%/http.h \
	%reldir%/http.c \
	%reldir%/smtp.h \
	%reldir%/smtp.c \
	%reldir%/telnet.h \
	%reldir%/telnet.c

sentinel_minipot_SOURCES = \
	%reldir%/main.c \
	${minipot_sources}

sentinel_minipot_CFLAGS = \
	-I '$(builddir)/src' \
	${czmq_CFLAGS} \
	${msgpack_CFLAGS} \
	${libevent_CFLAGS} \
	${base64c_CFLAGS} \
	${logc_CFLAGS} \
	${czmq_logc_CFLAGS} \
	${libevent_logc_CFLAGS} \
	${CODE_COVERAGE_CFLAGS}

sentinel_minipot_LDADD = \
	${czmq_LIBS} \
	${msgpack_LIBS} \
	${libevent_LIBS} \
	${base64c_LIBS} \
	${logc_LIBS} \
	${czmq_logc_LIBS} \
	${libevent_logc_LIBS} \
	${CODE_COVERAGE_LIBS}

minipot_gperf = \
	%reldir%/http_header.gperf.c \
	%reldir%/http_tr_enc.gperf.c \
	%reldir%/ftp_commands.gperf.c \
	%reldir%/smtp_commands.gperf.c \
	%reldir%/sasl_mechanisms.gperf.c
$(sentinel_minipot_OBJECTS): $(minipot_gperf)
gperf_files += ${minipot_gperf}


linted_files += $(sentinel_minipot_SOURCES)
