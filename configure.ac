AC_INIT([sentinel-minipot], [1.0], [])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
		  Makefile
		   ])
PKG_CHECK_MODULES([czmq], [libczmq])
PKG_CHECK_MODULES([libevent], [libevent])
PKG_CHECK_MODULES([msgpack], [msgpack])
AC_CHECK_HEADER([argp.h],
                [],
                [AC_SEARCH_LIBS([argp_parse],[argp-standalone],[],[],[])],
                [])
AC_OUTPUT
