/* $Id: probe.c,v 0.2 2000/12/20 14:29:45 kjc Exp kjc $ */
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
/* probe.c -- a probe program main module for remote-monitoring. */
#include <stdio.h>
#include <signal.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "ttt.h"
#include "ttt_node.h"
#include "ttt_remote.h"

#include <pcap.h>

extern pcap_t *pd;
extern void (*ttt_netreader)(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

static int sockfd;
static struct sockaddr_in view_addr;
static u_long f_localnet, f_netmask;

static void probe_loop(int pcapfd, int sock_fd);
static int send_report(int sock_fd, int seq_no, struct timeval *tvp);
static int write_record(struct t_node *np, struct ttt_record *trp);
static void probe_cleanup(void);

/* a net_subr compatible procudure just to save localnet address */
void netname_init(u_long netaddr, u_long netmask)
{
    /* save localnet address and netmask */
    f_localnet = netaddr;
    f_netmask = netmask;
}

static void usage(void)
{
    printf("usage: probe [options] dest\n");
    printf(" or    probe [options] -multicast\n");
    printf(" options:\n");
    printf("    [-interface device]\n");
    printf("    [-port dest_port]\n");
    printf("    [-ttl time-to-live]\n");
    printf("    [-interval msec]\n");
    exit(1);
}

int main(int argc, char **argv)
{
    struct sockaddr_in my_addr;
    int pcapfd;
    u_char ttl = 1;			/* time-to-live field for mcast */
    int port_no = TTT_PORT;		/* receiver's port number */
    int multicast = 0;	/* use multicast */
    char *view_name = NULL;
    char *my_name = NULL;

    while (--argc > 0) {
	if (strcmp(*++argv, "-interface") == 0 && --argc > 0)
	    ttt_interface = *++argv;
	else if (strncmp(*argv, "-multicast", 4) == 0)
	    view_name = TTT_MCASTADDR;
	else if (strncmp(*argv, "-port", 4) == 0 && --argc > 0)
	    port_no = atoi(*++argv);
	else if (strcmp(*argv, "-interval") == 0 && --argc > 0)
	    ttt_interval = atoi(*++argv);
	else if (strcmp(*argv, "-ttl") == 0 && --argc > 0)
	    ttl = atoi(*++argv);
	else if (view_name == NULL)
	    view_name = *argv;
	else
	    usage();
    }
    if (view_name == NULL) {
	printf("no destination specified!\n");
	usage();
    }

    if (name2sockaddrin(my_name, 0, &my_addr) < 0)
	fatal_error("can't get my address!");

    if (name2sockaddrin(view_name, port_no, &view_addr) < 0)
	fatal_error("can't get viewer's address!");

#ifdef IN_MULTICAST
    if (IN_MULTICAST(ntohl(view_addr.sin_addr.s_addr)))
	multicast = 1;
#endif
    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	fatal_error("sender: can't open socket");

#ifdef IP_MULTICAST_TTL
    if (multicast && ttl != 1)
	if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL,
		       &ttl, sizeof(ttl)) < 0)
	    fatal_error("can't set ttl");
#endif
    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0)
	fatal_error("sender: can't bind");

    netacc_init();
    pcapfd = open_pf(ttt_interface);

    printf("probe started. sending to %s:%d ....\n",
	   inet_ntoa(view_addr.sin_addr), port_no);

    probe_loop(pcapfd, sockfd);
    /* never returns */

    probe_cleanup();
    return 0;
}

static void probe_cleanup(void)
{
    close(sockfd);
    close_pf();
    netacc_cleanup();
}

#define BUFFER_SIZE	4096	/* big enough */
static char buffer[BUFFER_SIZE];

/* timeval macros from Xt */

#define ADD_TIME(dest, src1, src2) { \
	if(((dest).tv_usec = (src1).tv_usec + (src2).tv_usec) >= 1000000) {\
	      (dest).tv_usec -= 1000000;\
	      (dest).tv_sec = (src1).tv_sec + (src2).tv_sec + 1 ; \
	} else { (dest).tv_sec = (src1).tv_sec + (src2).tv_sec ; \
	   if(((dest).tv_sec >= 1) && (((dest).tv_usec <0))) { \
	    (dest).tv_sec --;(dest).tv_usec += 1000000; } } }


#define TIMEDELTA(dest, src1, src2) { \
	if(((dest).tv_usec = (src1).tv_usec - (src2).tv_usec) < 0) {\
	      (dest).tv_usec += 1000000;\
	      (dest).tv_sec = (src1).tv_sec - (src2).tv_sec - 1;\
	} else 	(dest).tv_sec = (src1).tv_sec - (src2).tv_sec;  }

#define IS_AFTER(t1, t2) (((t2).tv_sec > (t1).tv_sec) \
	|| (((t2).tv_sec == (t1).tv_sec)&& ((t2).tv_usec > (t1).tv_usec)))

#define IS_AT_OR_AFTER(t1, t2) (((t2).tv_sec > (t1).tv_sec) \
	|| (((t2).tv_sec == (t1).tv_sec)&& ((t2).tv_usec >= (t1).tv_usec)))

static void probe_loop(int pcapfd, int sock_fd)
{
    struct timeval cur_time, wait_time, expr_time, interval;
    fd_set rmaskfd;
    int seq_no, nfound;

    interval.tv_sec = ttt_interval/1000;
    interval.tv_usec = (ttt_interval%1000)*1000;
    (void) gettimeofday(&cur_time, NULL);
    ADD_TIME(expr_time, cur_time, interval);

    seq_no = 1;
    while (1) {
	(void) gettimeofday(&cur_time, NULL);

	/* check time to send a ttt report */
	if (IS_AT_OR_AFTER(expr_time, cur_time)) {
	    if (send_report(sockfd, seq_no, &cur_time) > 0)
		seq_no++;
	    ADD_TIME(expr_time, cur_time, interval);
	}

	wait_time.tv_sec = wait_time.tv_usec = 0;
	TIMEDELTA(wait_time, expr_time, cur_time);
	FD_ZERO(&rmaskfd);
	FD_SET(pcapfd, &rmaskfd);
	nfound = select(pcapfd+1, &rmaskfd, NULL, NULL, &wait_time);
	if (nfound == -1) {
	    /* interrupt occured recalculate time value and select again. */
	    perror("select");
	    continue;
	}
	if (FD_ISSET(pcapfd, &rmaskfd)) {
	    if (pcap_dispatch(pd, 1, ttt_netreader, 0) < 0)
		(void)fprintf(stderr, "pcap_dispatch:%s\n", pcap_geterr(pd));
	}
    }
}

/* create a report packet and send it out */
static int send_report(int sock_fd, int seq_no, struct timeval *tvp)
{
    struct ttt_hdr *hdr;
    int protos, hosts, rsize, rval;
    char *cp;
    struct t_node *np;
    struct pcap_stat pc_stat;
    static int last_sent = 1;  /* how many records sent last time.
				  initial value 1 is to send first packet */
    
    hdr = (struct ttt_hdr *)buffer;
    hdr->th_magic = htons(TTT_MAGIC);
    hdr->th_version = htons((TTT_MAJOR<<8) | TTT_MINOR);
    hdr->th_network = f_localnet;
    hdr->th_seqno = htonl(seq_no);
    hdr->th_tvsec = htonl(tvp->tv_sec);
    hdr->th_tvusec = htonl(tvp->tv_usec);

    /* get pcap statistics */
    if (pcap_stats(pd, &pc_stat) == 0) {
	hdr->th_recvpkts = htonl(pc_stat.ps_recv);
	hdr->th_droppkts = htonl(pc_stat.ps_drop);
    }
    else {
	hdr->th_recvpkts = 0;
	hdr->th_droppkts = 0;
    }

    /* get the top 10 traffic of this interval.  */
    cp = buffer + sizeof(struct ttt_hdr);
    for (protos=0, np = node_getbiggest(TTTTYPE_PROTO);
	 protos<10 && np != NULL; protos++, np = node_getnext(np)) {
	rsize = write_record(np, (struct ttt_record *)cp);
	cp += rsize;
    }
    for (hosts=0, np = node_getbiggest(TTTTYPE_HOST);
	 hosts<10 && np != NULL; hosts++, np = node_getnext(np)) {
	rsize = write_record(np, (struct ttt_record *)cp);
	cp += rsize;
    }

    hdr->th_nrecords = htonl(protos + hosts);

    node_bumptime();	/* give a time tick to the node module */

#if 0  /* if the traffic is this low, why bothering to send a packet? */
    if ((protos+hosts) == 0 && last_sent == 0) {
	/* no traffic, nothing to send */
	return 0;
    }
    last_sent = protos + hosts;
#endif

    if ((rval = sendto(sock_fd, buffer, cp - buffer, 0,
		       (struct sockaddr *)&view_addr, sizeof(view_addr))) < 0)
	perror("sendto");
    return rval;
}

/* write node info to ttt_record */
static int write_record(struct t_node *np, struct ttt_record *trp)
{
    struct ttt_record6 *tr6p;
    
    if (np->t_type != TTTTYPE_IPV6HOST) {
	trp->tr_type = htonl(np->t_type);
	trp->tr_size = htonl(np->t_size);
	trp->tr_id[0] = htonl(np->t_id[0]);
	    
	return sizeof(struct ttt_record);
    }
    else {
	tr6p = (struct ttt_record6 *)trp;
	tr6p->tr_type = htonl(np->t_type);
	tr6p->tr_size = htonl(np->t_size);
	tr6p->tr_id[0] = htonl(np->t_id[0]);
	tr6p->tr_id[1] = htonl(np->t_id[1]);
	tr6p->tr_id[2] = htonl(np->t_id[2]);
	tr6p->tr_id[3] = htonl(np->t_id[3]);
	return sizeof(struct ttt_record6);
    }
}

