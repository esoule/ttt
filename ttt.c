/* $Id: ttt.c,v 0.9 2003/06/25 09:38:28 kjc Exp $ */
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
/* ttt.c -- ttt stand alone program main module */
#include <sys/time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ttt.h"

static void usage(void)
{
    printf("usage: ttt [options]\n");
    printf(" options:\n");
    printf("	[-interface device]\n");
    printf("    [-interval ms]\n");
    printf("    [-dumpfile filename [-speed N]]\n");
    printf("    [-filter filter_value]\n");
    printf("    [-pcap pcap_cmd]\n");
    printf("    [-yscale 'K'|'M'|n]\n");
    exit(1);
}

void ttt_parseargs(int argc, char **argv)
{
    int i;

    for (i=1; i<argc; i++)
	if (strcmp(argv[i], "-interface") == 0 && ++i < argc)
	    ttt_interface = argv[i];
	else if (strcmp(argv[i], "-interval") == 0 && ++i < argc)
	    ttt_interval = atoi(argv[i]);
	else if (strcmp(argv[i], "-dumpfile") == 0 && ++i < argc)
	    ttt_dumpfile = argv[i];
	else if (strcmp(argv[i], "-speed") == 0 && ++i < argc)
	    ttt_speed = atoi(argv[i]);
	else if (strcmp(argv[i], "-filter") == 0 && ++i < argc)
	    ttt_filter = strtol(argv[i], NULL, 0);
	else if (strcmp(argv[i], "-pcap") == 0 && ++i < argc)
	    ttt_pcapcmd = argv[i];
	else if (strcmp(argv[i], "-yscale") == 0 && ++i < argc) {
	    if (toupper(argv[i][0]) == 'K')
		ttt_yscale = 1000;
	    else if (toupper(argv[i][0]) == 'M')
		ttt_yscale = 1000000;
	    else
		ttt_yscale = strtol(argv[i], NULL, 0);
	}
	else if (strcmp(argv[i], "-help") == 0 ||
		 strcmp(argv[i], "--help") == 0 ||
		 strcmp(argv[i], "-h") == 0)
	    usage();
	else if (strncmp(argv[i], "-version", 4) == 0) {
	    printf("%s\n", ttt_version);
	    exit(0);
	}
}

double get_timeindouble(void)
{
    double sec;
    struct timeval cur_time;
    static struct timeval start;
    static int first = 1;

    if (ttt_dumpfile == NULL)
	    gettimeofday(&cur_time, NULL);
    else
	    cur_time = ttt_dumptime;

    if (first) {
	start = cur_time;
	first = 0;
    }
    
    sec = (double)(cur_time.tv_sec - start.tv_sec)
	+ (double)(cur_time.tv_usec - start.tv_usec) / 1000000.0;
    return sec;
}

