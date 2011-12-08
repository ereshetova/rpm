# Makefile for rpm library.

include $(top_srcdir)/rpm.am

AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_builddir)/include/
AM_CPPFLAGS += -I$(top_srcdir)/misc
AM_CPPFLAGS += -DLOCALEDIR="\"$(localedir)\""
AM_CPPFLAGS += -DSYSCONFDIR="\"$(sysconfdir)\""
AM_CPPFLAGS += -DLOCALSTATEDIR="\"$(localstatedir)\""
AM_CPPFLAGS += -DLIBRPMALIAS_FILENAME="\"rpmpopt-${VERSION}\""
if MSM
AM_CPPFLAGS += @WITH_MSM_INCLUDE@
endif
AM_LDFLAGS = -avoid-version -module -shared

pluginsdir = $(libdir)/rpm-plugins

if MSM
plugins_LTLIBRARIES = msm.la
endif
if MSM
msm_la_SOURCES = security.h msm.h msm.c msmconfig.c msmmanifest.c msmxattr.c msmmatch.c
msm_la_LIBADD = $(top_builddir)/lib/librpm.la $(top_builddir)/rpmio/librpmio.la  @WITH_MSM_LIB@
endif
