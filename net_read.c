/* $Id: net_read.c,v 0.13 2000/12/20 14:29:45 kjc Exp kjc $ */
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
/* net_read.c -- a module to read ethernet packets.
   most parts are derived from tcpdump. */
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
#ifndef lint
char copyright[] =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994\nThe Regents of the University of California.  All rights reserved.\n";
#endif

/*
 * tcpdump - monitor tcp/ip traffic on an ethernet.
 *
 * First written in 1987 by Van Jacobson, Lawrence Berkeley Laboratory.
 * Mercilessly hacked and occasionally improved since then via the
 * combined efforts of Van, Steve McCanne and Craig Leres of LBL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pcap.h>
#ifdef PCAP_HEADERS
#include "llc.h"
#include "fddi.h"
#else
#include "ttt_pcap.h"
#endif
#include "ttt.h"
#include "ttt_account.h"
#ifdef IPV6
#include "ttt_ipv6.h"
#endif
/* for tailqueue macros */
#if defined(HAVE_SYS_QUEUE_H) && !defined(__linux__)
#include <sys/queue.h>
#else
#include "bsd_sys_queue.h"
#endif

/*
 * The default snapshot length.  This value allows most printers to print
 * useful information while keeping the amount of unwanted data down.
 * In particular, it allows for an ethernet header, tcp/ip header, and
 * 14 bytes of data (assuming no ip options).
 */
#ifdef IPV6
#define DEFAULT_SNAPLEN (68+20)		/* is this big enough? */
#else
#define DEFAULT_SNAPLEN 68
#endif
#ifndef ETHERTYPE_PPPOE
#define	ETHERTYPE_PPPOE		0x8864	/* PPP Over Ethernet Session Stage */
#endif

char errbuf[PCAP_ERRBUF_SIZE];
char *device;
char *cmdbuf;
pcap_t *pd;
int pcapfd;

static int packet_length;		/* length of current packet */

/* a function switch to read different types of frames */
void (*ttt_netreader)(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

/* needed by libpacp */
int	fddipad = FDDIPAD;	/* for proper alignment of header */

struct ip4_frag {
    TAILQ_ENTRY(ip4_frag) ip4f_chain;
    char    ip4f_valid;
    u_char ip4f_proto;
    u_short ip4f_id;
    struct in_addr ip4f_src, ip4f_dst;
    struct udphdr ip4f_udphdr;
};

static TAILQ_HEAD(ip4f_list, ip4_frag) ip4f_list; /* IPv4 fragment cache */

#define IP4F_TABSIZE		8	/* IPv4 fragment cache size */

/*
 * the following macros are FreeBSD extension.  there are two incompatible
 * TAILQ_LAST defines in FreeBSD (changed after 2.2.6), so use the new one.
 */
#ifndef TAILQ_EMPTY
#define	TAILQ_EMPTY(head) ((head)->tqh_first == NULL)
#endif
#undef TAILQ_LAST
#define	TAILQ_LAST(head, headname) \
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

void net_read(int clientdata, int mask);
static void ttt_dumpreader(u_char *user, const struct pcap_pkthdr *h,
			   const u_char *p);
static void ether_if_read(u_char *user, const struct pcap_pkthdr *h,
			  const u_char *p);
static void fddi_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static void atm_if_read(u_char *user, const struct pcap_pkthdr *h,
			const u_char *p);
static void sl_if_read(u_char *user, const struct pcap_pkthdr *h,
		       const u_char *p);
static void ppp_if_read(u_char *user, const struct pcap_pkthdr *h,
			const u_char *p);
#ifdef DLT_RAW
static void raw_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			const u_char *p);
#endif
#ifdef DLT_PPP_BSDOS
static void ppp_bsdos_if_read(u_char *user, const struct pcap_pkthdr *h,
			      const u_char *p);
#endif
#ifdef DLT_PPP_SERIAL	/* netbsd specific */
static void ppp_netbsd_serial_if_read(u_char *user,
			      const struct pcap_pkthdr *h, const u_char *p);
#endif
static void null_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static int ether_encap_read(const u_short ethtype, const u_char *p,
			    const int length, const int caplen);
static int llc_read(const u_char *p, const int length, const int caplen);
static int pppoe_read(const u_char *bp, const int length, const int caplen);
static int ip_read(const u_char *bp, const int length, const int caplen);
static void ip4f_cache(struct ip *, struct udphdr *);
static struct udphdr *ip4f_lookup(struct ip *);
static int ip4f_init(void);
static struct ip4_frag *ip4f_alloc(void);
static void ip4f_free(struct ip4_frag *);
#ifdef IPV6
static int ipv6_read(const u_char *bp, const int length, const int caplen);
static int read_ipv6hdr(struct ipv6 *ipv6, int *proto, int caplen);
#endif

/* wrapper for tcl callback */
void net_read(int clientdata, int mask)
{
    if (pcap_dispatch(pd, 1, ttt_netreader, 0) < 0)
	(void)fprintf(stderr, "pcap_dispatch:%s\n", pcap_geterr(pd));
}

int dumpfile_read(void)
{
    struct timeval end;
    int rval;

    end = ttt_dumptime;
    end.tv_sec += ttt_interval / 1000;
    end.tv_usec += (ttt_interval % 1000) * 1000;
    if (end.tv_usec > 1000000) {
	end.tv_sec++;
	end.tv_usec -= 1000000;
    }

    while ((rval = pcap_dispatch(pd, 1, ttt_dumpreader, 0)) > 0) {
	if (ttt_dumptime.tv_sec > end.tv_sec ||
	    (ttt_dumptime.tv_sec == end.tv_sec &&
	     ttt_dumptime.tv_usec >= end.tv_usec))
	    /* end of the interval */
	       return (rval);
    }
    if (rval < 0)
	(void)fprintf(stderr, "pcap_dispatch:%s\n", pcap_geterr(pd));

    return (rval);
}

static void ttt_dumpreader(u_char *user, const struct pcap_pkthdr *h,
			   const u_char *p) 
{
    ttt_dumptime = h->ts;

    (*ttt_netreader)(user, h, p);
}

static void ether_if_read(u_char *user, const struct pcap_pkthdr *h,
			  const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    struct ether_header *ep;
    u_short ether_type;

    packet_length = length;  /* save data link level packet length */
    if (caplen < sizeof(struct ether_header)) {
	return;
    }

    ep = (struct ether_header *)p;
    p += sizeof(struct ether_header);
    length -= sizeof(struct ether_header);
    caplen -= sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);
    if (ether_type < ETHERMTU) {
	if (llc_read(p, length, caplen) == 0) {
	    /* ether_type not known */
	}
    }
    else if (ether_encap_read(ether_type, p, length, caplen) == 0) {
	/* ether_type not known */
    }
}

static int ether_encap_read(const u_short ethtype, const u_char *p,
			    const int length, const int caplen)
{
#if 0
    /* people love to see the total traffic! */
    if (ethtype != ETHERTYPE_IP)
#endif
	eth_addsize(ethtype, packet_length);

 recurse:
    switch (ethtype) {
    case ETHERTYPE_IP:
	ip_read(p, length, caplen);
	break;
#ifdef IPV6
    case ETHERTYPE_IPV6:
	ipv6_read(p, length, caplen);
	break;
#endif
#ifdef ETHERTYPE_8021Q
	case ETHERTYPE_8021Q:
		ethtype = ntohs(*(unsigned short*)(p+2));
		p += 4;
		length -= 4;
		caplen -= 4;
		if (ethtype <= ETHERMTU)
			/* ether_type not known */
			break;
		goto recurse;
	break;
#endif
    case ETHERTYPE_PPPOE:
	    pppoe_read(p, length, caplen);
	    break;
    default:
	    break;
    }
    return (1);
}


static void fddi_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			 const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    const struct fddi_header *fddip = (struct fddi_header *)p;

    packet_length = length;  /* save data link level packet length */
    if (caplen < FDDI_HDRLEN)
	return;
    
    /* Skip over FDDI MAC header */
    length -= FDDI_HDRLEN;
    p += FDDI_HDRLEN;
    caplen -= FDDI_HDRLEN;
    
    /* Frame Control field determines interpretation of packet */
    if ((fddip->fddi_fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
	/* Try to print the LLC-layer header & higher layers */
	if (llc_read(p, length, caplen) == 0) {
	    /* some kinds of LLC packet we cannot handle intelligently */
	}
    }
    else {
	/* Some kinds of FDDI packet we cannot handle intelligently */
    }
}

#ifndef min
#define min(a, b)	(((a)<(b))?(a):(b))
#endif

static int llc_read(const u_char *p, const int length, const int caplen)
{
    struct llc llc;
    register u_short et;
    register int ret;
    
    if (caplen < 3) {
	return(0);
    }

    /* Watch out for possible alignment problems */
    bcopy((char *)p, (char *)&llc, min(caplen, sizeof(llc)));

#if 0  /* we are not interested in these */
    if (llc.ssap == LLCSAP_GLOBAL && llc.dsap == LLCSAP_GLOBAL) {
	/* ipx */
	return (1);
    }
    else if (p[0] == 0xf0 && p[1] == 0xf0) {
	/* netbios */
    }
    if (llc.ssap == LLCSAP_ISONS && llc.dsap == LLCSAP_ISONS
	&& llc.llcui == LLC_UI) {
	/* iso */
    }
#endif /* 0 */

    if (llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
	&& llc.llcui == LLC_UI) {
	/* snap */
	if (caplen < sizeof(llc)) {
	    return (0);
	}
	/* This is an encapsulated Ethernet packet */
#ifdef ALIGN_WORD
    {
	u_short tmp;
	bcopy(&llc.ethertype[0], &tmp, sizeof(u_short));
	et = ntohs(tmp);
    }
#else
	et = ntohs(*(u_short *)&llc.ethertype[0]);
#endif
	ret = ether_encap_read(et, p + sizeof(llc),
			       length - sizeof(llc), caplen - sizeof(llc));
	if (ret)
	    return (ret);
    }
    /* llcsap */
    return(0);
}

static void atm_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    u_short ether_type;

    packet_length = length;  /* save data link level packet length */
    if (caplen < 8)
	return;

    if (p[0] != 0xaa || p[1] != 0xaa || p[2] != 0x03) {
	/* unknown format! */
	return;
    }
    ether_type = p[6] << 8 | p[7];

    eth_addsize(ether_type, packet_length);
    
    length -= 8;
    caplen -= 8;
    p += 8;

    switch (ether_type) {
    case ETHERTYPE_IP:
	ip_read(p, length, caplen);
	break;
#ifdef IPV6
    case ETHERTYPE_IPV6:
	ipv6_read(p, length, caplen);
	break;
#endif
    }
}

#ifndef SLIP_HDRLEN
#define SLIP_HDRLEN 16
#endif

static void
sl_if_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;

    packet_length = length;  /* save data link level packet length */
    if (caplen < SLIP_HDRLEN)
	return;

    length -= SLIP_HDRLEN;
    caplen -= SLIP_HDRLEN;
    p += SLIP_HDRLEN;

    ip_read(p, length, caplen);
}

#ifndef PPP_HDRLEN
#define PPP_HDRLEN 4
#endif
#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */

static void ppp_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    const struct ip *ip;
    u_int proto;

    packet_length = length;  /* save data link level packet length */
    if (caplen < PPP_HDRLEN)
	return;

    proto = ntohs(*(u_short *)&p[2]);

    length -= PPP_HDRLEN;
    caplen -= PPP_HDRLEN;
    p += PPP_HDRLEN;

    ip = (struct ip *)p;
    switch (proto) {
    case ETHERTYPE_IP:
    case PPP_IP:
	ip_read(p, length, caplen);
	break;
#ifdef IPV6
    case ETHERTYPE_IPV6:
    case PPP_IPV6:
	ipv6_read(p, length, caplen);
	break;
#endif
    }
}

#ifdef DLT_PPP_BSDOS
/* BSD/OS specific PPP printer */
#ifndef PPP_BSDI_HDRLEN
#define PPP_BSDI_HDRLEN 24
#endif
#define PPP_ADDRESS	0xff	/* The address byte value */
#define PPP_CONTROL	0x03	/* The control byte value */

/* BSD/OS specific PPP printer */

static void ppp_bsdos_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			      const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    int hdrlength;
    u_short ptype;

    packet_length = length;  /* save data link level packet length */
    if (caplen < PPP_BSDI_HDRLEN)
	return;

    hdrlength = 0;
    if (p[0] == PPP_ADDRESS && p[1] == PPP_CONTROL) {
	p += 2;
	hdrlength = 2;
    }
    /* Retrieve the protocol type */
    if (*p & 01) {
	/* Compressed protocol field */
	ptype = *p;
	p++;
	hdrlength += 1;
    } else {
	/* Un-compressed protocol field */
	ptype = ntohs(*(u_short *)p);
	p += 2;
	hdrlength += 2;
    }

    length -= hdrlength;
    caplen -= hdrlength;

    switch (ptype) {
    case PPP_IP:
	ip_read(p, length, caplen);
	break;
#ifdef IPV6
    case PPP_IPV6:
	ipv6_read(p, length, caplen);
	break;
#endif
    }
}
#endif /* DLT_PPP_BSDOS */

#ifdef DLT_PPP_SERIAL	/* netbsd specific */
/*
 * NetBSD-specific PPP printers.  Handles multiple PPP encaps, and
 * Cisco frames.
 */
#define	PPP_NETBSD_SERIAL_HDRLEN	4
/* Actual address byte values */
#define	PPP_ADDR_ALLSTATIONS	0xff	/* all stations broadcast addr */
#define	PPP_ADDR_CISCO_MULTICAST 0x8f	/* Cisco multicast address */
#define	PPP_ADDR_CISCO_UNICAST	0x0f	/* Cisco unicast address */
/*
 * XXX Note, this is overloaded with VINESCP, but we can tell based on
 * XXX the address byte if we're using Cisco protocol numbers (i.e.
 * XXX Ethertypes).
 */
#define	PPP_CISCO_KEEPALIVE 0x8035 /* Cisco keepalive protocol */

static void ppp_netbsd_serial_if_read(u_char *pcap,
			      const struct pcap_pkthdr *h, const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    u_short ptype;
    u_char addr, ctrl;

    packet_length = length;  /* save data link level packet length */
    if (caplen < PPP_NETBSD_SERIAL_HDRLEN)
	return;

    addr = p[0];
    ctrl = p[1];

    switch (addr) {
    case PPP_ADDR_ALLSTATIONS:
	/*
	 * Regular serial PPP packet.
	 */
	ptype = (p[2] << 8) | p[3];

	p += PPP_NETBSD_SERIAL_HDRLEN;
	length -= PPP_NETBSD_SERIAL_HDRLEN;
	caplen -= PPP_NETBSD_SERIAL_HDRLEN;

	switch (ptype) {
	case PPP_IP:
	    ip_read(p, length, caplen);
	    break;
#ifdef IPV6
	case PPP_IPV6:
	    ipv6_read(p, length, caplen);
	    break;
#endif
	}
	break;

    case PPP_ADDR_CISCO_MULTICAST:
    case PPP_ADDR_CISCO_UNICAST:
	ptype = (p[2] << 8) | p[3];

	p += PPP_NETBSD_SERIAL_HDRLEN;
	length -= PPP_NETBSD_SERIAL_HDRLEN;
	caplen -= PPP_NETBSD_SERIAL_HDRLEN;

	switch (ptype) {
	case PPP_CISCO_KEEPALIVE:
	    break;
	default:
	    if (ether_encap_read(ptype, p, length, caplen) == 0) {
		/* ether_type not known */
	    }
	}
	break;

    default:
	/* Address not known, print raw packet. */
	break;
    }
}
#endif /* DLT_PPP_SERIAL */

#ifndef NULL_HDRLEN
#define	NULL_HDRLEN 4	/* DLT_NULL header length */
#endif
static void null_if_read(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int length = h->len;
	int caplen = h->caplen;
	const struct ip *ip;

	packet_length = length;  /* save data link level packet length */
	length -= NULL_HDRLEN;
	caplen -= NULL_HDRLEN;
	ip = (struct ip *)(p + NULL_HDRLEN);

	switch (ip->ip_v) {
	case 4:
	    ip_read((const u_char *)ip, length, caplen);
	    break;
#ifdef IPV6
	case 6:
	    ipv6_read((const u_char *)ip, length, caplen);
	    break;
#endif
	}
}

#ifdef DLT_RAW
static void raw_if_read(u_char *pcap, const struct pcap_pkthdr *h, const u_char *p)
{
	packet_length = h->len;  /* save data link level packet length */

	switch (((struct ip *)p)->ip_v) {
	case 4:
	    ip_read(p, h->len, h->caplen);
	    break;
#ifdef IPV6
	case 6:
	    ipv6_read(p, h->len, h->caplen);
	    break;
#endif
	}
}
#endif

#ifndef PPPOE_HDRLEN
#define PPPOE_HDRLEN	6
#endif
static int pppoe_read(const u_char *bp, const int length, const int caplen)
{
    u_short version, type, code, ptype;
    const u_char *p;
    int hdrlen;

    if (caplen < PPPOE_HDRLEN)
	return (0);

    p = bp;
    version = p[0] & 0xf0;
    type    = p[0] & 0x0f;
    code    = p[1];

    if (version != 1 || type != 1 || code != 0)
	return (0);

    hdrlen = PPPOE_HDRLEN;
    p += PPPOE_HDRLEN;

    if (p[0] & 0x1) {
	ptype = p[0];
	hdrlen += 1;
    }
    else if (p[1] & 0x1) {
	ptype = ntohs(*(u_short *)p);
	hdrlen += 2;
    }
    else
	return (0);

    if (caplen < hdrlen)
	return (0);

    switch (ptype) {
    case PPP_IP:
	ip_read(bp + hdrlen, length - hdrlen, caplen - hdrlen);
	break;
#ifdef IPV6
    case PPP_IPV6:
	ipv6_read(bp + hdrlen, length - hdrlen, caplen - hdrlen);
	break;
#endif
    }
    return (1);
}

static int ip_read(const u_char *bp, const int length, const int caplen)
{
    struct ip *ip;
    int hlen, len, proto, off;
    u_long srcaddr, dstaddr;
    u_short srcport, dstport;
    struct tcphdr *tcp;
    struct udphdr *udp;

    ip = (struct ip *)bp;
    if (length < sizeof (struct ip))
	return 0;
#ifdef ALIGN_WORD
    /*
     * The IP header is not word aligned, so copy into abuf.
     * This will never happen with BPF.  It does happen raw packet
     * dumps from -r.
     */
    if ((int)ip & (sizeof(long)-1)) {
	static u_char *abuf;

	if (abuf == 0)
	    abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
	bcopy((char *)ip, (char *)abuf, caplen);
	ip = (struct ip *)abuf;
    }
#endif /* ALIGN_WORD */

    hlen = ip->ip_hl * 4;
    len = min(ntohs(ip->ip_len), length);
    len -= hlen;
    if (len < 0)
	return 0;
    bp = (u_char *)ip + hlen;

    srcaddr = ntohl(ip->ip_src.s_addr);
    dstaddr = ntohl(ip->ip_dst.s_addr);
    proto = ip->ip_p;

    if (!(ttt_filter & TTTFILTER_SRCHOST)) {
	host_addsize(srcaddr, packet_length);
	if (!(ttt_filter & TTTFILTER_DSTHOST) && srcaddr != dstaddr)
	    host_addsize(dstaddr, packet_length);
    }
    else if (!(ttt_filter & TTTFILTER_DSTHOST))
	host_addsize(dstaddr, packet_length);

    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) 
	ip_addsize(proto, packet_length);
    else {
	/* if this is fragment zero, hand it to the next higher
	   level protocol. */
	off = ntohs(ip->ip_off);
	if (off & 0x1fff) {
	    /* process fragments */
	    if ((bp = (u_char *)ip4f_lookup(ip)) == NULL)
		/* lookup failed */
		return 1;
	}

	if (proto == IPPROTO_TCP) {
	    if (len < sizeof (struct tcphdr))
		return 0;
	    tcp = (struct tcphdr *)bp;
	    srcport = ntohs(tcp->th_sport);
	    dstport = ntohs(tcp->th_dport);
	    if (!(ttt_filter & TTTFILTER_SRCPORT)) {
		tcp_addsize(srcport, packet_length);
		if (dstport != srcport
		    && !(ttt_filter & TTTFILTER_DSTPORT))
		    tcp_addsize(dstport, packet_length);
	    }
	    else if (!(ttt_filter & TTTFILTER_DSTPORT))
		tcp_addsize(dstport, packet_length);
	}
	else {
	    if (len < sizeof (struct udphdr))
		return 0;
	    udp = (struct udphdr *)bp;
	    srcport = ntohs(udp->uh_sport);
	    dstport = ntohs(udp->uh_dport);
	    if (!(ttt_filter & TTTFILTER_SRCPORT)) {
		udp_addsize(srcport, packet_length);
		if (dstport != srcport
		    && !(ttt_filter & TTTFILTER_DSTPORT))
		    udp_addsize(dstport, packet_length);
	    }
	    else if (!(ttt_filter & TTTFILTER_DSTPORT))
		udp_addsize(dstport, packet_length);
	}

	/* if this is a first fragment, cache it. */
	if ((off & IP_MF) && (off & 0x1fff) == 0)
	    ip4f_cache(ip, (struct udphdr *)bp);
    }
#ifdef IPV6
    /* sould we do this?  or is it better to see only that ipv6 being
       encapsulated?  another idea is to make another class
       TTTTYPE_IPV6INIP. */
    if (proto == IPPROTO_IPV6) {
	/* ipv6 in ipv4 */
	ipv6_read(bp, len, caplen-hlen);
    }
#endif /* IPV6 */
    return 1;
}

/*
 * helper functions to handle IPv4 fragments.
 * currently only in-sequence fragments are handled.
 *	- fragment info is cached in a LRU list.
 *	- when a first fragment is found, cache its flow info.
 *	- when a non-first fragment is found, lookup the cache.
 */
static void ip4f_cache(ip, udp)
    struct ip *ip;
    struct udphdr *udp;
{
    struct ip4_frag *fp;

    if (TAILQ_EMPTY(&ip4f_list)) {
	/* first time call, allocate fragment cache entries. */
	if (ip4f_init() < 0)
	    /* allocation failed! */
	    return;
    }

    fp = ip4f_alloc();
    fp->ip4f_proto = ip->ip_p;
    fp->ip4f_id = ip->ip_id;
    fp->ip4f_src = ip->ip_src;
    fp->ip4f_dst = ip->ip_dst;
    fp->ip4f_udphdr.uh_sport = udp->uh_sport;
    fp->ip4f_udphdr.uh_dport = udp->uh_dport;
}

static struct udphdr *ip4f_lookup(ip)
    struct ip *ip;
{
    struct ip4_frag *fp;
    struct udphdr *udphdr;
    
    for (fp = TAILQ_FIRST(&ip4f_list); fp != NULL && fp->ip4f_valid;
	 fp = TAILQ_NEXT(fp, ip4f_chain))
	if (ip->ip_id == fp->ip4f_id &&
	    ip->ip_src.s_addr == fp->ip4f_src.s_addr &&
	    ip->ip_dst.s_addr == fp->ip4f_dst.s_addr &&
	    ip->ip_p == fp->ip4f_proto) {

	    /* found the matching entry */
	    udphdr = &fp->ip4f_udphdr;
	    if ((ntohs(ip->ip_off) & IP_MF) == 0)
		/* this is the last fragment, release the entry. */
		ip4f_free(fp);

	    return (udphdr);
	}

    /* no matching entry found */
    return (NULL);
}

static int ip4f_init(void)
{
    struct ip4_frag *fp;
    int i;
    
    TAILQ_INIT(&ip4f_list);
    for (i=0; i<IP4F_TABSIZE; i++) {
	fp = (struct ip4_frag *)malloc(sizeof(struct ip4_frag));
	if (fp == NULL) {
	    printf("ip4f_initcache: can't alloc cache entry!\n");
	    return (-1);
	}
	fp->ip4f_valid = 0;
	TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
    }
    return (0);
}

static struct ip4_frag *ip4f_alloc(void)
{
    struct ip4_frag *fp;

    /* reclaim an entry at the tail, put it at the head */
    fp = TAILQ_LAST(&ip4f_list, ip4f_list);
    TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
    fp->ip4f_valid = 1;
    TAILQ_INSERT_HEAD(&ip4f_list, fp, ip4f_chain);
    return (fp);
}

static void ip4f_free(fp)
    struct ip4_frag *fp;
{
    TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
    fp->ip4f_valid = 0;
    TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
}

#ifdef IPV6
/* this version doesn't handle fragments */
static int ipv6_read(const u_char *bp, const int length, const int caplen)
{
    struct ipv6 *ipv6;
    int hlen, len, proto;
    u_long srcaddr[4], dstaddr[4];
    u_short srcport, dstport;
    struct tcphdr *tcp;
    struct udphdr *udp;

    ipv6 = (struct ipv6 *)bp;
    if (length < sizeof (struct ipv6))
	return 0;
#ifdef ALIGN_WORD
    /*
     * The IP header is not word aligned, so copy into abuf.
     * This will never happen with BPF.  It does happen raw packet
     * dumps from -r.
     */
    if ((int)ipv6 & (sizeof(long)-1)) {
	static u_char *abuf;

	if (abuf == 0)
	    abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
	bcopy((char *)ipv6, (char *)abuf, caplen);
	ipv6 = (struct ipv6 *)abuf;
    }
#endif /* ALIGN_WORD */

    hlen = read_ipv6hdr(ipv6, &proto, caplen);
    len = min(ntohs(ipv6->ipv6_len) + sizeof(struct ipv6), length) - hlen;
    if (len < 0)
	return 0;
    bp = (u_char *)ipv6 + hlen;

    bcopy(&ipv6->ipv6_src, srcaddr, sizeof(struct in6_addr));
    srcaddr[0] = ntohl(srcaddr[0]);
    srcaddr[1] = ntohl(srcaddr[1]);
    srcaddr[2] = ntohl(srcaddr[2]);
    srcaddr[3] = ntohl(srcaddr[3]);

    bcopy(&ipv6->ipv6_dst, dstaddr, sizeof(struct in6_addr));
    dstaddr[0] = ntohl(dstaddr[0]);
    dstaddr[1] = ntohl(dstaddr[1]);
    dstaddr[2] = ntohl(dstaddr[2]);
    dstaddr[3] = ntohl(dstaddr[3]);

    if (!(ttt_filter & TTTFILTER_SRCHOST)) {
	hostv6_addsize(srcaddr, packet_length);
	if (!(ttt_filter & TTTFILTER_DSTHOST)
	    && bcmp(srcaddr, dstaddr, sizeof(srcaddr)))
	    hostv6_addsize(dstaddr, packet_length);
    }
    else if (!(ttt_filter & TTTFILTER_DSTHOST))
	hostv6_addsize(dstaddr, packet_length);

    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) 
	ipv6_addsize(proto, packet_length);
    else if (proto == IPPROTO_TCP) {
	if (len < sizeof (struct tcphdr))
	    return 0;
	tcp = (struct tcphdr *)bp;
	srcport = ntohs(tcp->th_sport);
	dstport = ntohs(tcp->th_dport);
	if (!(ttt_filter & TTTFILTER_SRCPORT)) {
	    tcpv6_addsize(srcport, packet_length);
	    if (dstport != srcport
		&& !(ttt_filter & TTTFILTER_DSTPORT))
		tcpv6_addsize(dstport, packet_length);
	}
	else if (!(ttt_filter & TTTFILTER_DSTPORT))
	    tcpv6_addsize(dstport, packet_length);
    }
    else {
	if (len < sizeof (struct udphdr))
	    return 0;
	udp = (struct udphdr *)bp;
	srcport = ntohs(udp->uh_sport);
	dstport = ntohs(udp->uh_dport);
	if (!(ttt_filter & TTTFILTER_SRCPORT)) {
	    udpv6_addsize(srcport, packet_length);
	    if (dstport != srcport
		&& !(ttt_filter & TTTFILTER_DSTPORT))
		udpv6_addsize(dstport, packet_length);
	}
	else if (!(ttt_filter & TTTFILTER_DSTPORT))
	    udpv6_addsize(dstport, packet_length);
    }
    return 1;
}

static int read_ipv6hdr(struct ipv6 *ipv6, int *proto, int caplen)
{
    int hlen, opt_len;
    struct ipv6_ext *ipv6ext;
    u_char nh;

    hlen = sizeof(struct ipv6);
    caplen -= hlen;
    nh = ipv6->ipv6_nh;
    ipv6ext = (struct ipv6_ext *)(ipv6 + 1);
    while (nh == IPV6_NH_HOP || nh == IPV6_NH_RT ||
	   nh == IPV6_NH_AUTH || nh == IPV6_NH_DST) {
	if (nh == IPV6_NH_AUTH)
	    opt_len = 8 + (ipv6ext->i6ext_len * 4);
	else
	    opt_len = (ipv6ext->i6ext_len + 1) * 8;
	hlen += opt_len;
	if ((caplen -= opt_len) < 0)
	    break;
	nh = ipv6ext->i6ext_nh;
	ipv6ext = (struct ipv6_ext *)((caddr_t)ipv6ext  + opt_len);
    }
    *proto = (int)nh;
    return hlen;
}

#endif /* IPV6 */

struct printer {
	pcap_handler f;
	int type;
};

static struct printer printers[] = {
	{ ether_if_read,	DLT_EN10MB },
	{ fddi_if_read,	DLT_FDDI },
#ifdef DLT_ATM_RFC1483
	{ atm_if_read,	DLT_ATM_RFC1483 },
#endif
	{ sl_if_print,	DLT_SLIP },
	{ ppp_if_read,	DLT_PPP },
#ifdef DLT_PPP_BSDOS
	{ ppp_bsdos_if_read,  DLT_PPP_BSDOS },
#endif
#ifdef DLT_PPP_SERIAL	/* netbsd specific */
	{ ppp_netbsd_serial_if_read,  DLT_PPP_SERIAL },
#endif
	{ null_if_read,	DLT_NULL },
#ifdef DLT_RAW
	{ raw_if_read,  DLT_RAW },
#endif
	{ NULL,			0 },
};

static pcap_handler
lookup_printer(int type)
{
	struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;

	fatal_error("lookup_printer: unknown data link type 0x%x", type);
	/* NOTREACHED */
	return NULL;
}

int open_pf(char *interface)
{
    int snaplen, fd;
    struct bpf_program fcode;
    u_int localnet, netmask;
    struct in_addr inaddr;

    if (interface == NULL) {
	device = pcap_lookupdev(errbuf);
	if (device == NULL)
	    fatal_error(errbuf);
    }
    else
	device = interface;
    printf("packet filter: using device %s\n", device);
    snaplen = DEFAULT_SNAPLEN;
    pd = pcap_open_live(device, snaplen, 1, 0, errbuf);
    if (pd == NULL)
	fatal_error(errbuf);
    if (pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0)
	fatal_error(errbuf);
    netname_init(localnet, netmask);
    inaddr.s_addr = localnet;
    printf("local network is %s", inet_ntoa(inaddr));
    inaddr.s_addr = netmask;
    printf(" netmask is %s\n", inet_ntoa(inaddr));
    /*
     * Let user own process after socket has been opened.
     */
    setuid(getuid());

#ifdef notyet  /* bpfcode not yet supported */
    if (pcap_compile(pd, &fcode, cmdbuf, 1, localnetmask.s_addr) < 0)
	fatal_error(pcap_geterr(pd));

    if (pcap_setfilter(pd, &fcode) < 0)
	fatal_error(pcap_geterr(pd));
#endif /* noyet */

    ttt_netreader = lookup_printer(pcap_datalink(pd));

    fd = pcap_fileno(pd);

#if defined(BSD) && defined(BPF_MAXBUFSIZE)
    {
	/* check the buffer size */
	u_int bufsize;
	
	if (ioctl(fd, BIOCGBLEN, (caddr_t)&bufsize) < 0)
	    perror("BIOCGBLEN");
	else
	    printf("bpf buffer size is %d\n", bufsize);
    }
#endif /* BSD */

    return fd;
}

void close_pf(void)
{
    pcap_close(pd);
}

int open_dump(char *file, char *interface)
{
    int fd;
    struct bpf_program fcode;
    u_int localnet, netmask;
    struct in_addr inaddr;

    printf("packet filter: using dump file %s\n", file);
    pd = pcap_open_offline(file, errbuf);
    if (pd == NULL)
	fatal_error(errbuf);

    /* try to get local network address to print host names */
    localnet = 0;
    netmask = 0xffffffff;
    if (interface == NULL) {
	device = pcap_lookupdev(errbuf);
    }
    else
	device = interface;
    if (device != NULL)
	(void)pcap_lookupnet(device, &localnet, &netmask, errbuf);

    netname_init(localnet, netmask);
    inaddr.s_addr = localnet;
    printf("local network is %s", inet_ntoa(inaddr));
    inaddr.s_addr = netmask;
    printf(" netmask is %s\n", inet_ntoa(inaddr));

#ifdef notyet  /* bpfcode not yet supported */
    if (pcap_compile(pd, &fcode, cmdbuf, 1, localnetmask.s_addr) < 0)
	fatal_error(pcap_geterr(pd));

    if (pcap_setfilter(pd, &fcode) < 0)
	fatal_error(pcap_geterr(pd));
#endif /* noyet */

    ttt_netreader = lookup_printer(pcap_datalink(pd));

    fd = fileno(pcap_file(pd));

    return fd;
}


int get_pcapstat(u_long *recvp, u_long *dropp, u_long *lostp)
{
    struct pcap_stat pc_stat;

    if (pcap_stats(pd, &pc_stat) == 0) {
	*recvp = pc_stat.ps_recv;
	*dropp = pc_stat.ps_drop;
	*lostp = 0;	/* no lost report for ttt */
	return 0;
    }
    return (-1);
}
