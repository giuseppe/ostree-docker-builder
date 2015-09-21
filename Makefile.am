EXTRA_DIST =

bin_PROGRAMS = ostree-docker-builder
noinst_LTLIBRARIES = libglnx.la

ostree_docker_builder_SOURCES = src/ostree-docker-builder.c

libglnx_srcpath := $(srcdir)/libglnx
libglnx_cflags := $(PKGDEP_OSTREE_DOCKER_BUILDER_CFLAGS) -I$(libglnx_srcpath) -fvisibility=hidden
libglnx_ldflags := $(PKGDEP_OSTREE_DOCKER_BUILDER_LDFLAGS)
libglnx_libs := $(PKGDEP_OSTREE_DOCKER_BUILDER_LIBS)

include libglnx/Makefile-libglnx.am.inc

ACLOCAL_AMFLAGS = -I m4

ostree_docker_builder_CFLAGS = $(PKGDEP_OSTREE_DOCKER_BUILDER_CFLAGS) $(PKGDEP_OSTREE_CFLAGS) $(PKGDEP_LIBARCHIVE_LDFLAGS) -I libglnx  -fvisibility=hidden
ostree_docker_builder_LDFLAGS = $(PKGDEP_LIBARCHIVE_LDFLAGS) $(PKGDEP_OSTREE_DOCKER_BUILDER_LDFLAGS) $(PKGDEP_OSTREE_LDFLAGS)
ostree_docker_builder_LDADD = $(PKGDEP_OSTREE_LIBS) $(PKGDEP_LIBARCHIVE_LIBS) $(PKGDEP_OSTREE_DOCKER_BUILDER_LIBS)
