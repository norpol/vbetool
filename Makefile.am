AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = vbetool

vbetool_LDADD = $(VBETOOL_LIBS) -lpciaccess -lz

man_MANS = vbetool.1
vbetool_SOURCES = vbetool.c $(x86)
noinst_HEADERS = vbetool.h

EXTRA_DIST = vbetool.1 udev-video-post-example.rules

maintainer-clean-local: 
	$(RM) Makefile.in aclocal.m4 config.h.in stamp-h.in configure

AM_CFLAGS = -g -Wall -pedantic -std=gnu99
AM_LDFLAGS = -lz -lx86
