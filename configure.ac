AC_INIT([sentinel-minipot], [2.2.0], [tech.support@turris.cz])
AC_CONFIG_MACRO_DIRS([.m4])
AC_CONFIG_AUX_DIR([.aux])

AM_INIT_AUTOMAKE([
  foreign silent-rules subdir-objects
  -Wall -Wno-portability
  dist-zip dist-xz
])
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_GNU_SOURCE

dnl Libraries
PKG_CHECK_MODULES([czmq], [libczmq])
PKG_CHECK_MODULES([msgpack], [msgpack])
PKG_CHECK_MODULES([libevent], [libevent])
PKG_CHECK_MODULES([base64c], [base64c])
PKG_CHECK_MODULES([logc], [logc logc_argp])

AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <argp.h>],[argp_parse(0,1,NULL,0,0,0);])],,
  [argp_standalone_required="yes"]
)
AS_IF([test "$argp_standalone_required" = "yes"],
  AC_CHECK_LIB([argp], [argp_parse], , AC_MSG_ERROR([Unable to find libargp])))

dnl Build helpers
AC_PATH_PROG([GPERF], [gperf])
AS_IF([test -z "$GPERF"], [AC_MSG_ERROR([Missing gperf generator])])


dnl Tests
AC_ARG_ENABLE([tests], AC_HELP_STRING([--enable-tests], [Whether to enable tests]))
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" = "xyes"])
AS_IF([test "x$enable_tests" = "xyes"], [
  PKG_CHECK_MODULES([CHECK], [check >= 0.11])
  AC_REQUIRE_AUX_FILE([tap-driver.sh])
])
AX_VALGRIND_CHECK

dnl Linters
AC_ARG_ENABLE([linters], AC_HELP_STRING([--enable-linters], [Whether to enable linters (cppcheck)]))
AM_CONDITIONAL([ENABLE_LINTERS], [test "x$enable_linters" = "xyes"])
AS_IF([test "x$enable_linters" = "xyes"], [
  AC_PATH_PROG([CPPCHECK], [cppcheck])
])

dnl Coverage
AX_CODE_COVERAGE


AC_CONFIG_FILES([Makefile])

AC_OUTPUT
