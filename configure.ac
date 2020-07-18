AC_INIT([sentinel-minipot], [2.0], [tech.support@turris.cz])

AM_INIT_AUTOMAKE([foreign -Wall -Wno-portability])
AC_PROG_CC
AC_GNU_SOURCE

PKG_CHECK_MODULES([czmq], [libczmq])
PKG_CHECK_MODULES([libevent], [libevent])
PKG_CHECK_MODULES([msgpack], [msgpack])
AC_CHECK_LIB([b64],[base64_init_decodestate],[],
			 [AC_MSG_ERROR([unable to find base64_init_decodestate function])],[])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <argp.h>],[argp_parse(0,1,NULL,0,0,0);])],,
  [argp_standalone_required="yes"]
)
AS_IF([test "$argp_standalone_required" = "yes"],
  AC_CHECK_LIB([argp], [argp_parse], , AC_MSG_ERROR([Unable to find libargp])))


AC_PATH_PROG([GPERF], [gperf])
AS_IF([test -z "$GPERF"], [AC_MSG_ERROR([Missing gperf generator])])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
