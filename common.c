/* $Id: common.c,v 0.8 2003/10/16 11:55:00 kjc Exp $ */
/*
 *  Copyright (c) 1996-2000
 *	Sony Computer Science Laboratories, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms of parts of or the
 * whole original or derived work are permitted provided that the above
 * copyright notice is retained and the original work is properly
 * attributed to the author. The name of the author may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
/* common.c -- globals and routines common to all ttt programs.  */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>

#include "ttt.h"

#ifndef NULL
#define NULL	0
#endif

char *ttt_version = TTT_VERSION;

/* globals which can set by tcl */
int ttt_interval = 1000;	/* 1 sec interval to update graph */
int ttt_nohostname = 0;		/* don't lookup host names */
int ttt_filter = 0;		/* trace filter */

/* only used at startup */
const char *ttt_interface = NULL;  /* interface name for packet capturing */
char *ttt_dumpfile = NULL;	/* tcpdump file to replay */
int ttt_speed = 1;		/* replay speed */
struct timeval ttt_dumptime;
const char *ttt_viewname = NULL;
char *ttt_mcastif = NULL;
int ttt_portno = TTT_PORT;	/* receiver's port number */
int ttt_yscale = 1000000;	/* scale of y axis (Mbps by default) */
char *ttt_pcapcmd = NULL;	/* pcap filter command */

void fatal_error(const char *fmt, ...)
{
    va_list ap;

    if (errno != 0)
	perror("fatal_error");
    else
	fprintf(stderr, "fatal_error: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

