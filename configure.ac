#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([PcapParseC],[0.5.0],[fujiwara@jprs.co.jp])
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([])
AM_INIT_AUTOMAKE([foreign no-installinfo dist-bzip2 no-dist-gzip])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([maxminddb.h arpa/inet.h assert.h ctype.h err.h errno.h netinet/in.h stdarg.h stdio.h stdlib.h string.h sys/resource.h sys/socket.h sys/stat.h sys/time.h sys/types.h time.h unistd.h])

AC_CHECK_PROG(fetch, wget)
AC_CHECK_LIB(maxminddb,MMDB_open)
#AC_SEARCH_LIBS ([MMDB_open],[libmaxminddb], [
#  AC_MSG_ERROR([unable to find the MMDB_open() function])
#])
# Checks for library functions.
#AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup inet_pton err sqrt])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
