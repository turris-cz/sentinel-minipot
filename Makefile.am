bin_PROGRAMS =
EXTRA_DIST =
gperf_files =
linted_files =

include src/Makefile.am

include utils/gperf.am


if ENABLE_LINTERS
include utils/lint.am
endif

if ENABLE_TESTS
DISTCHECK_CONFIGURE_FLAGS = --enable-tests
include tests/Makefile.am
endif
