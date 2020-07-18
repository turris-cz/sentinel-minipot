bin_PROGRAMS = sentinel-minipot

sentinel_minipot_SOURCES = \
	main.c \
	proxy.c \
	utils.c \
	telnet.c \
	http.c \
	ftp.c \
	smtp.c \
	cli_opts.c \
	minipot_pipe.c \
	base64/base64.c

sentinel_minipot_CFLAGS = \
	${czmq_CFLAGS} \
	${libevent_CFLAGS} \
	${msgpack_CFLAGS} \
	-std=c99

sentinel_minipot_LDADD = \
	${czmq_LIBS} \
	${libevent_LIBS} \
	${msgpack_LIBS}


gperf_files =  \
	http_header.gperf.c \
	http_tr_enc.gperf.c \
	ftp_commands.gperf.c \
	smtp_commands.gperf.c \
	sasl_mechanisms.gperf.c

sentinel_minipot-http.$(OBJEXT): http_header.gperf.c http_tr_enc.gperf.c
sentinel_minipot-ftp.$(OBJEXT): ftp_commands.gperf.c
sentinel_minipot-smtp.$(OBJEXT): smtp_commands.gperf.c sasl_mechanisms.gperf.c

%.gperf.c: %.gperf
	$(GPERF) --output-file=$@ $<

CLEANFILES = $(gperf_files)

.PHONY: gen-gperf
gen-gperf: $(gperf_files)
