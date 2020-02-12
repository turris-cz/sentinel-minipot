# names for gperf files
HTTP_METH_GPERF = http_method.gperf
HTTP_HEAD_GPERF = http_header.gperf
HTTP_TR_ENC_GPERF = http_tr_enc.gperf
FTP_COMM_GPERF = ftp_commands.gperf
SMTP_COMM_GPERF = smtp_commands.gperf
SASL_MECH_GPERF = sasl_mechanisms.gperf

# names for generated source code files
HTTP_METH_C = http_method.c
HTTP_HEAD_C = http_header.c
HTTP_TR_ENC_C = http_tr_enc.c
SMTP_COMM_C = smtp_commands.c
FTP_COMM_C = ftp_commands.c
GPERF_FLAGS = --output-file=

bin_PROGRAMS = sentinel_minipot
sentinel_minipot_SOURCES = main.c messages.c utils.c telnet.c http.c ftp.c smtp.c
sentinel_minipot_CFLAGS = ${czmq_CFLAGS} ${libevent_CFLAGS} ${msgpack_CFLAGS} -std=c99
sentinel_minipot_LDADD  = ${czmq_LIBS} ${libevent_LIBS} ${msgpack_LIBS}
BUILT_SOURCES = $(HTTP_METH_C) $(HTTP_HEAD_C) $(HTTP_TR_ENC_C) $(FTP_COMM_C) $(SMTP_COMM_C) $(SASL_MECH_C)

# gperf additional rules
$(HTTP_METH_C): $(HTTP_METH_GPERF)
	$(GPERF) $(GPERF_FLAGS)$(HTTP_METH_C) $(HTTP_METH_GPERF)
$(HTTP_HEAD_C): $(HTTP_HEAD_GPERF)
	$(GPERF) $(GPERF_FLAGS)$(HTTP_HEAD_C) $(HTTP_HEAD_GPERF)
$(HTTP_TR_ENC_C): $(HTTP_TR_ENC_GPERF)
	$(GPERF) $(GPERF_FLAGS)$(HTTP_TR_ENC_C) $(HTTP_TR_ENC_GPERF)
$(FTP_COMM_C): $(FTP_COMM_GPERF)
	$(GPERF) $(GPERF_FLAGS)$(FTP_COMM_C) $(FTP_COMM_GPERF)
$(SMTP_COMM_C): $(SMTP_COMM_GPERF)
	$(GPERF) $(GPERF_FLAGS)$(SMTP_COMM_C) $(SMTP_COMM_GPERF)
$(SASL_MECH_C): $(SASL_MECH_GPERF)
	$(GPERF) $(GPERF_FLAGS)$(SASL_MECH_C) $(SASL_MECH_GPERF)
# to remove generated gperf files
clean-local:
	rm -f $(BUILT_SOURCES)

# to generate code from gperf manualy
gen-gperf: $(BUILT_SOURCES)