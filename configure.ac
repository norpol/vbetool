dnl Copyright © 2008 Tiago Vignatti
dnl
dnl Permission is hereby granted, free of charge, to any person obtaining a
dnl copy of this software and associated documentation files (the "Software"),
dnl to deal in the Software without restriction, including without limitation
dnl on the rights to use, copy, modify, merge, publish, distribute, sub
dnl license, and/or sell copies of the Software, and to permit persons to whom
dnl the Software is furnished to do so, subject to the following conditions:
dnl
dnl The above copyright notice and this permission notice (including the next
dnl paragraph) shall be included in all copies or substantial portions of the
dnl Software.
dnl
dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
dnl IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
dnl FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.  IN NO EVENT SHALL
dnl IBM AND/OR THEIR SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
dnl LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
dnl FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
dnl DEALINGS IN THE SOFTWARE.
dnl
dnl Process this file with autoconf to create configure.

AC_PREREQ(2.57)
AC_INIT([vbetool], 1.2.0, [not yet], vbetool)
AM_INIT_AUTOMAKE([dist-bzip2])
AM_MAINTAINER_MODE

AM_CONFIG_HEADER(config.h)

dnl Checks for programs

AC_PROG_CC
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(LIBPCIACCESS, pciaccess)

# Checks for pkg-config packages
PKG_CHECK_MODULES(LIBX86, x86)

SAVE_CFLAGS=$CFLAGS
CFLAGS=$LIBPCIACCESS_CFLAGS
LIBS=$LIBPCIACCESS_LIBS
AC_CHECK_FUNCS([pci_device_vgaarb_init])
LIBS=$SAVE_LIBS
CFLAGS=$SAVE_CFLAGS

VBETOOL_LIBS="$LIBPCIACCESS_LIBS $LIBX86_LIBS"
VBETOOL_CFLAGS="$LIBPCIACCESS_CFLAGS $LIBX86_CFLAGS"
AC_SUBST(VBETOOL_CFLAGS)
AC_SUBST(VBETOOL_LIBS)

dnl Simple, huh?

AC_OUTPUT([Makefile])
