# -*- coding: utf-8 -*-
#
#                     -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([new-session], [0.9.0])

AC_CONFIG_MACRO_DIR([m4])

LT_PREREQ([2.4.2])
LT_INIT()

AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE()
AC_CONFIG_SRCDIR([new-session.cxx])

# Checks for programs.
AC_PROG_CXX
AC_PROG_LIBTOOL

AX_CXX_COMPILE_STDCXX_11(noext, mandatory)

AC_CHECK_HEADERS([\
	linux/vt.h \
	sys/ioctl.h \
	sys/stat.h \
	fcntl.h \
	sys/types.h \
	sys/wait.h \
	termios.h \
	unistd.h \
	pwd.h \
	grp.h \
	security/pam_appl.h\
])

AC_SEARCH_LIBS([pam_start], [pam], [], [
	AC_MSG_ERROR([unable to find PAM functions])
])

AC_CONFIG_FILES([
  Makefile
])

AC_OUTPUT
