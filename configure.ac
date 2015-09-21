AC_PREREQ([2.63])
AC_INIT([ostree-docker-builder], [0.1], [giuseppe@scrivano.org])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.13 -Wno-portability foreign no-define tar-ustar no-dist-gzip dist-xz
                  color-tests parallel-tests subdir-objects])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AC_PROG_CC
AM_PROG_CC_C_O

changequote(,)dnl
if test "x$GCC" = "xyes"; then
  WARN_CFLAGS="-Wall -Wstrict-prototypes -Werror=missing-prototypes \
		-Werror=implicit-function-declaration \
		-Werror=pointer-arith -Werror=init-self -Werror=format=2 \
		-Werror=format-security \
		-Werror=missing-include-dirs -Werror=aggregate-return \
		-Werror=declaration-after-statement"
fi
changequote([,])dnl
AC_SUBST(WARN_CFLAGS)

# Initialize libtool
LT_PREREQ([2.2.4])
LT_INIT([disable-static])

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(PKGDEP_OSTREE_DOCKER_BUILDER, [libgsystem >= 2015.1 gio-unix-2.0 >= 2.40.0])
PKG_CHECK_MODULES(PKGDEP_OSTREE, [ostree-1 >= 2015.1])

# check for gtk-doc
m4_ifdef([GTK_DOC_CHECK], [
GTK_DOC_CHECK([1.15], [--flavour no-tmpl])
],[
enable_gtk_doc=no
AM_CONDITIONAL([ENABLE_GTK_DOC], false)
])

GIO_DEPENDENCY="gio-unix-2.0 >= 2.40.0 libgsystem >= 2015.1"
PKG_CHECK_MODULES(OT_DEP_GIO_UNIX, $GIO_DEPENDENCY)

LIBARCHIVE_DEPENDENCY="libarchive >= 2.8.0"

PKG_CHECK_MODULES(OT_DEP_LIBARCHIVE, $LIBARCHIVE_DEPENDENCY)
save_LIBS=$LIBS
LIBS=$OT_DEP_LIBARCHIVE_LIBS
AC_CHECK_FUNCS(archive_read_support_filter_all, [],
        [AC_MSG_ERROR([libarchive is enabled but could not be found])])

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT
