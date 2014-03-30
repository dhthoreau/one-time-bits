AC_INIT([one-time-bits], [0.0])
AM_CONDITIONAL([EXPORTABLE], [test -e src/secure-using-real-openssl-functions.c])
AC_CONFIG_AUX_DIR([auxiliaryconfig])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])
AM_PROG_AR
LT_INIT
AC_PROG_CC
AC_PROG_CC_C99
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
 po/Makefile.in
 tests/Makefile
])
IT_PROG_INTLTOOL([0.35.0])
AM_GLIB_GNU_GETTEXT
GETTEXT_PACKAGE=one-time-bits
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Define to the Gettext package name])
AC_SYS_LARGEFILE
AC_TYPE_OFF_T
AC_PROG_CC_STDC
PKG_PROG_PKG_CONFIG(0.26)
PKG_CHECK_MODULES([libglib], [glib-2.0 >= 2.28])
PKG_CHECK_MODULES([libgobject], [gobject-2.0 >= 2.28])
PKG_CHECK_MODULES([libuuid], [uuid])
PKG_CHECK_MODULES([openssl], [openssl >= 0.9.7])
AC_OUTPUT
