#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([PcapParseC],[0.3.1],[fujiwara@jprs.co.jp])
AM_INIT_AUTOMAKE([foreign no-installinfo dist-bzip2 no-dist-gzip])
AC_CONFIG_SRCDIR([])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
APR_FIND_APR([], [], 1, 1)
APR_SETIFNULL(CC, `$apr_config --cc`)
APR_SETIFNULL(APRCC, `$apr_config --cc`)
APR_SETIFNULL(CPP, `$apr_config --cpp`)
APR_ADDTO(CPPFLAGS, `$apr_config --cppflags --includes`)
APR_ADDTO(LDFLAGS, `$apr_config --ldflags`)
APR_ADDTO(LIBS, `$apr_config --libs --link-ld`)
AM_CONDITIONAL(APRexist, test x$APRCC != x)
# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h time.h fcntl.h netinet/in.h stdlib.h sys/socket.h unistd.h string.h stdarg.h errno.h apr.h])

# Checks for typedefs, structures, and compiler characteristics.
#AC_TYPE_INT32_T

# Checks for library functions.
#AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup inet_pton])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
