/* $Id: ttt.h,v 0.8 1999/03/21 11:17:06 kjc Exp $ */
/*
 *  Copyright (c) 1996
 *	Sony Computer Science Laboratory Inc.  All rights reserved.
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
/* ttt.h -- common header for all ttt programs */
#ifndef _TTT_H_
#define _TTT_H_

#include <sys/types.h>

#define TTT_MAJOR	1
#define TTT_MINOR	3
#define TTT_VERSION	"1.3"

/* default path for ttt.tcl */
#ifndef TTT_LIBRARY
#define TTT_LIBRARY	"/usr/local/lib/ttt"
#endif

/* uncommnet the following line not to lookup hostnames. */
/*
 * #define DONT_LOOKUP_HOSTNAME 
 */

/* ttt protocol types */
#define TTTTYPE_PROTO		0	/* wild card for protocol type */
#define TTTTYPE_ETHER		1
#define TTTTYPE_FDDI		2
#define TTTTYPE_IP		8
#define TTTTYPE_TCP		16
#define TTTTYPE_UDP		17
#define TTTTYPE_IPV6		32
#define TTTTYPE_UDPV6		40
#define TTTTYPE_TCPV6		41

/* all protocols should be below TTTTYPE_HOST */
/* ttt host types */
#define TTTTYPE_HOST		128	/* wild card for host type */
#define TTTTYPE_IPHOST		129
#define TTTTYPE_IPV6HOST	130

/* trace filter */
#define TTTFILTER_SRCHOST	0x01
#define TTTFILTER_DSTHOST	0x02
#define TTTFILTER_SRCPORT	0x04
#define TTTFILTER_DSTPORT	0x08

/* for remote monitoring */
#define TTT_PORT		7288		/* receiver port */
#define TTT_MCASTADDR		"224.8.8.0"	/* default multicast address */

/* parameters */
#define TTT_MAX_NODES		1000

/* globals */
extern char *ttt_version;
extern int ttt_interval;	/* graph update interval in ms */
extern char *ttt_interface;	/* interface name for packet capture */
extern int ttt_max_nodes;	/* limit of max nodes */
extern char *ttt_viewname;	/* view address */
extern char *ttt_mcastif;	/* multicast interface address */
extern int ttt_portno;		/* viewer's port number */
extern int ttt_nohostname;	/* don't lookup host names */
extern int ttt_filter;		/* trace filter */
extern char *ttt_dumpfile;	/* tcpdump file to replay */
extern int ttt_speed;		/* replay speed */
extern struct timeval ttt_dumptime;

extern void fatal_error(/*const char *fmt, ...*/);

/* function prototypes */

/* ttt.c */
extern void ttt_parseargs(int argc, char **argv);
extern double get_timeindouble(void);

/* display.c */
extern void display_init(void);
extern void ttt_display(int time_tick);

/* net_names.c */
extern void netname_init(unsigned long netaddr, unsigned long netmask);
extern char *net_getname(long type, long *id);

/* net_read.c */
extern int open_pf(char *interface);
extern void close_pf(void);
extern int open_dump(char *file, char *interface);
extern int get_pcapstat(u_long *recvp, u_long *dropp, u_long *lostp);
extern int dumpfile_read(void);

/* viewer.c */
extern int view_opensock(void);
extern void view_closesock(int sockfd);
/* int get_pcapstat(u_long *recvp, u_long *dropp, u_long *lostp); */

/* textview.c */
extern void ttt_textview(int seq_no);

/* endian defines in case they are missing from the system headers */
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#define LITTLE_ENDIAN 1234
#endif
#ifndef BYTE_ORDER
#if defined(_BIG_ENDIAN) || defined(sparc)
#define BYTE_ORDER BIG_ENDIAN
#endif
#if defined(_LITTLE_ENDIAN) || defined(i386)
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif /* BYTE_ORDER */

#endif /* _TTT_H_ */
