#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([dnsquery], m4_esyscmd([ tr -d '\n' < version ]))

CPPFLAGS=""
CXXFLAGS=""
LDFLAGS=""

AC_ARG_WITH([test],
        [AS_HELP_STRING([    --with-test], [Test mode On])],
        [],
        [with_test=no])

AS_IF([test "x$with_test" != xno],
        [
        AM_CONDITIONAL(WITH_TEST, true)
        AC_DEFINE(WITH_TEST,[],[Use Test Mode])
        ], [
        AM_CONDITIONAL(WITH_TEST, false)
        ])


AC_CONFIG_SRCDIR([src/dns_cl_main.cpp])

AC_CONFIG_HEADER([include/config.h])

LT_INIT
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([disable])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile
            src/Makefile])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

AC_CANONICAL_HOST
case $host_os in
  darwin* )
              OPTIMIZATION="-O2 "
              if test "x$CC" = xgcc; then
                    CXXFLAGS=" -std=c++20 -g -Weverything \
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security \
                             -Wno-deprecated-declarations -Wno-documentation -Wno-c++98-compat \
                             -Wno-padded -Wno-c++98-compat-pedantic -Wno-undefined-func-template "
		            LDFLAGS="$LDFLAGS "
              else
                    CXXFLAGS=" -std=c++20 -O2 -g -Wall "
		            LDFLAGS="$LDFLAGS  "
              fi
        ;;
  linux*)
              OPTIMIZATION="-O2 "
              if test "x$CC" = xgcc; then
                    CXXFLAGS=" -std=c++20 -g -Wall -Wextra  -DLINUX_OS \
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector   \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security "
                    LDFLAGS=" $LDFLAGS -Wl,-z,relro  "
              else
                    CXXFLAGS="-DLINUX_OS -std=c++20 -O2 -g -Wall  "
		        LDFLAGS=" $LDFLAGS  "
              fi

              AC_CHECK_HEADERS([sys/capability.h],[],[AC_MSG_FAILURE([could not find lib cap-dev])],[])
        ;;
    *)
            CXXFLAGS=" -std=c++20  -O2 -g -Wall  "
	      LDFLAGS=" $LDFLAGS   "
            #AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

# Libs list autmatically generated prom dependecy script
AC_CHECK_LIB([readline],[readline],[],[AC_MSG_FAILURE([could not find lib readline])])

AC_OUTPUT
