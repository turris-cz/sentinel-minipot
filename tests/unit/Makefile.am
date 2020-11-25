TESTS += %reldir%/tests

check_PROGRAMS = %reldir%/tests
%canon_reldir%_tests_SOURCES = \
	$(minipot_sources) \
	%reldir%/tests.c \
	%reldir%/utils.c
%canon_reldir%_tests_CFLAGS = \
	$(sentinel_minipot_CFLAGS) \
	$(CHECK_FLAGS)
%canon_reldir%_tests_LDADD = \
	$(sentinel_minipot_LDADD) \
	$(CHECK_LIBS)
