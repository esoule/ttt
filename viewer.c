/* $Id: viewer.c,v 0.5 1998/07/09 10:07:03 kjc Exp kjc $ */
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
/* viewer.c -- a viewer module for remote-monitoring.  this module is
   shared by tttview and ttttextview but TTT_TEXT flag is set for
   ttttextview. */
#include <stdio.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "ttt.h"
#include "ttt_node.h"
#include "ttt_remote.h"

#define BUFFER_SIZE	4096	/* big enough */
static char buffer[BUFFER_SIZE];	/* receive buffer */

static struct sockaddr_in probe_addr;
static char *probe_name = NULL;
static int packets_received;
static struct timeval remote_time;
static int shared_port = 1;		/* share the multicast port */
static int multicast = 0;		/* use multicast */

void view_sockread(int clientdata, int mask);
static int check_seqno(int seq_no);
static int read_record(struct ttt_record *trp);

double get_remotetime(void);

extern char *pcap_lookupdev(char *errbuf);
extern int pcap_lookupnet(char *device, u_long *netp, u_long *maskp, char *errbuf);

static void usage()
{
    printf("usage: tttview [options]\n");
    printf(" options:\n");
    printf("	[-multicast]\n");
    printf("    [-addr recv_addr]\n");
    printf("    [-mcastifaddr mcast_if_addr]\n");
    printf("	[-port recv_port]\n");
    printf("	[-probe probe_addr]\n");
    exit(1);
}

void view_parseargs(int argc, char **argv)
{
    int i;

    for (i=1; i<argc; i++)
	if (strncmp(argv[i], "-multicast", 4) == 0)
	    ttt_viewname = TTT_MCASTADDR;
	else if (strncmp(argv[i], "-addr", 4) == 0 && ++i < argc)
	    ttt_viewname = argv[i];
	else if (strncmp(argv[i], "-mcastifaddr", 4) == 0 && ++i < argc)
	    ttt_mcastif = argv[i];
	else if (strncmp(argv[i], "-port", 4) == 0 && ++i < argc)
	    ttt_portno = atoi(argv[i]);
        else if (strncmp(argv[i], "-probe", 4) == 0 && ++i < argc)
	    probe_name = argv[i];
	else if (strcmp(argv[i], "-help") == 0 ||
		 strcmp(argv[i], "--help") == 0 ||
		 strcmp(argv[i], "-h") == 0)
	    usage();
	else if (strncmp(argv[i], "-version", 4) == 0) {
	    printf("%s\n", ttt_version);
	    exit(0);
	}
}

int view_opensock(void)
{
    char my_name[MAXHOSTNAMELEN];
    struct sockaddr_in my_addr;
    int sockfd;
    
    if (ttt_viewname == NULL) {
	/* use my host name */
	if (gethostname(my_name, MAXHOSTNAMELEN) == -1)
	    fatal_error("no host_name");
    }
    else
	strcpy(my_name, ttt_viewname);
    if (name2sockaddrin(my_name, ttt_portno, &my_addr) < 0)
	fatal_error("can't get my address!");

#ifdef IN_MULTICAST
    if (IN_MULTICAST(ntohl(my_addr.sin_addr.s_addr)))
	multicast = 1;
#endif
    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	fatal_error("receiver: can't open socket");

    if (multicast) {
#ifdef IP_ADD_MEMBERSHIP
	struct ip_mreq mreq;
	struct sockaddr_in ifaddr;

	mreq.imr_multiaddr.s_addr = my_addr.sin_addr.s_addr;
	if (ttt_mcastif == NULL) {
	    mreq.imr_interface.s_addr = htonl(INADDR_ANY); /* use default if */
	}
	else {
	    if (name2sockaddrin(ttt_mcastif, ttt_portno, &ifaddr) < 0)
		fatal_error("can't get local address!");
	    mreq.imr_interface.s_addr = ifaddr.sin_addr.s_addr;
	}

	if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		       (char *)&mreq, sizeof(mreq)) < 0)
	    fatal_error("can't join group");
	
	printf("joined multicast group: %s\n", ttt_viewname);
#else
	fatal_error("IP multicat not supported!");
#endif /* IP_ADD_MEMBERSHIP */
    }

    if (shared_port) {
	int one = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&one, sizeof(one)) < 0)
	    fatal_error("can't share the port");
	printf("port %d is shared.\n", ttt_portno);
    }

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0)
	fatal_error("receiver: can't bind");

    if (!multicast)
	printf("viewer started. reading from %s:%d ....\n",
	       inet_ntoa(my_addr.sin_addr), ttt_portno);

    /* get local network address to look up local host names */
    {
	char *device;
	u_long localnet, netmask;
	struct in_addr inaddr;
	
	if ((device = pcap_lookupdev(buffer)) == NULL)
	    fatal_error(buffer);
	if (pcap_lookupnet(device, &localnet, &netmask, buffer) < 0)
	    fatal_error(buffer);
	netname_init(localnet, netmask);
	inaddr.s_addr = localnet;
	printf("local network is %s", inet_ntoa(inaddr));
	inaddr.s_addr = netmask;
	printf(" netmask is %s\n", inet_ntoa(inaddr));
    }

    if (probe_name != NULL) {
	if (name2sockaddrin(probe_name, 0, &probe_addr) < 0)
	    fatal_error("can't get probe address!");
	printf("reading from [%s] ....\n", probe_name);
    }
    else
	bzero(&probe_addr, sizeof(probe_addr));

    return sockfd;
}

void view_closesock(int sockfd)
{
#ifdef IP_ADD_MEMBERSHIP
    if (multicast) {
	char my_name[MAXHOSTNAMELEN];
	struct sockaddr_in my_addr;
	struct ip_mreq mreq;
	
	if (ttt_viewname == NULL) {
	    /* use my host name */
	    if (gethostname(my_name, MAXHOSTNAMELEN) == -1)
		fatal_error("no host_name");
	}
	else
	    strcpy(my_name, ttt_viewname);
	if (name2sockaddrin(my_name, ttt_portno, &my_addr) < 0)
	    fatal_error("can't get my address!");

	mreq.imr_multiaddr.s_addr = my_addr.sin_addr.s_addr;
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);

	if (setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		       (char *)&mreq, sizeof(mreq)) < 0)
	    perror("can't drop group");
    }
#endif /* IP_ADD_MEMBERSHIP */
    close(sockfd);
}

/* statistics info */
static u_long lost_packets;	/* total reports lost */
static u_long out_of_order;	/* total out of order report */

/* report of the pcap statistics at the probe */
static u_long pcap_stats_recv;  /* received packets */
static u_long pcap_stats_drop;	/* dropped packets */

int get_pcapstat(u_long *recvp, u_long *dropp, u_long *lostp)
{
    *recvp = pcap_stats_recv;
    *dropp = pcap_stats_drop;
    *lostp = lost_packets;
    return 0;
}

static int check_seqno(int seq_no)
{
    int lost_count;
    static u_long last_seqno; 
#ifndef TTT_TEXT
    char buf[128];
#endif
    
    if (seq_no == last_seqno+1) {
	/* normal case */
	last_seqno = seq_no;
	return 0;
    }
    else if (seq_no > last_seqno+1) {
	/* packet loss */
	lost_count = seq_no - last_seqno -1;
	if (last_seqno == 0) {
	    /* this is the first packet */
	    lost_packets = 0;
	}
	else {
	    lost_packets += lost_count;
#ifdef REMOTE_DEBUG
	    printf("[warning] lost %d packets\n", lost_count);
#endif
	}
	last_seqno = seq_no;
	return (lost_count);
    }
    else {
	/* out of order report */
	if (seq_no < 10 || (last_seqno - seq_no) > 100) {
	    /* seq_no gets too small. the probe must have restarted.  */
#ifdef TTT_TEXT
	    printf("[warning] probe seems to have restarted.\n");
#else
	    sprintf(buf, "probe[%s] seems to have restarted.",
		    inet_ntoa(probe_addr.sin_addr));
	    ttt_showmessage(buf);
#endif
	    last_seqno = seq_no;
	    lost_packets = out_of_order = 0;
	    return 9999;
	}
	out_of_order++;
#ifdef REMOTE_DEBUG
	printf("[warning] got out-of-order packet\n");
#endif
	return (-1);
    }
}


void view_sockread(int clientdata, int mask)
{
    int sockfd, nbytes, fromlen, rsize, seq_no, nrecords, i;
    struct sockaddr_in from_addr;
    struct ttt_hdr *hdr;
    char *cp;

    sockfd = (int)clientdata;
    fromlen = sizeof(from_addr);
    if ((nbytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
			   (struct sockaddr *)&from_addr, &fromlen)) == -1) {
	perror("recvfrom");
	return;
    }

    if (probe_addr.sin_addr.s_addr == 0) {
	probe_addr = from_addr;
	printf("reading from probe [%s] ....\n",
	       inet_ntoa(from_addr.sin_addr));
    }

    /* is this the probe we are reading from? */
    if (from_addr.sin_addr.s_addr != probe_addr.sin_addr.s_addr) {
	static int warned = 0;
	if (!warned) {
	    printf("[warning] there are multiple probes.\n");
	    printf("\tignoring probe: %s\n",
		   inet_ntoa(from_addr.sin_addr));
	    warned = 1;
	}
	return;
    }

    if (nbytes < sizeof(struct ttt_hdr)) {
	printf("sockread: packet too short size=%d\n", nbytes);
	return;
    }
    
    hdr = (struct ttt_hdr *)buffer;
    if (ntohs(hdr->th_magic) != TTT_MAGIC) {
	printf("[warning] bad magic!\n");
	return;
    }

    pcap_stats_recv = ntohl(hdr->th_recvpkts);
    pcap_stats_drop = ntohl(hdr->th_droppkts);

    seq_no = ntohl(hdr->th_seqno);
    if (check_seqno(seq_no) < 0) 
	return;

    nrecords = ntohl(hdr->th_nrecords);
    remote_time.tv_sec = ntohl(hdr->th_tvsec);
    remote_time.tv_usec = ntohl(hdr->th_tvusec);

    cp = buffer + sizeof(struct ttt_hdr);
    for (i=0; i<nrecords; i++) {
	if ((rsize = read_record((struct ttt_record *)cp)) < 0)
	    break;
	cp += rsize;
    }

#ifdef TTT_TEXT
    ttt_textview(packets_received++);
#else
    /* call ttt_display to update the graph */
    ttt_display(packets_received++);
#endif
}

/* write node info to ttt_record */
static int read_record(struct ttt_record *trp)
{
    int size, rval;
    long type, id[4];
    struct ttt_record6 *tr6p;

    if (trp->tr_type != TTTTYPE_IPV6HOST) {
	type = ntohl(trp->tr_type);
	size = ntohl(trp->tr_size);
	id[0] = ntohl(trp->tr_id[0]);
#ifdef IPV6
	id[1] = 0;
	id[2] = 0;
	id[3] = 0;
#endif
	rval = sizeof(struct ttt_record);
    }
    else {
	tr6p = (struct ttt_record6 *)trp;
	type = ntohl(tr6p->tr_type);
	size = ntohl(tr6p->tr_size);
	id[0] = ntohl(tr6p->tr_id[0]);
#ifdef IPV6
	id[1] = ntohl(tr6p->tr_id[1]);
	id[2] = ntohl(tr6p->tr_id[2]);
	id[3] = ntohl(tr6p->tr_id[3]);
#endif
	rval = sizeof(struct ttt_record6);
    }

    node_record(type, id, size);
    
    return rval;
}

double get_timeindouble(void)
{
    double sec;
    static struct timeval start;
    static int first = 1;

    if (first) {
	start = remote_time;
	first = 0;
    }
    
    sec = (double)(remote_time.tv_sec - start.tv_sec)
	+ (double)(remote_time.tv_usec - start.tv_usec) / 1000000.0;
    return sec;
}

