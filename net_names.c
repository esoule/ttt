/* $Id: net_names.c,v 0.8 2003/10/16 11:55:00 kjc Exp kjc $ */
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
/* net_names.c -- a module to translate ids to name strings.  */
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#if STDC_HEADERS
#include <string.h>
#else
#include <strings.h>
#endif

#include "ttt.h"
#include "ttt_account.h"
#ifdef IPV6
#include "ttt_ipv6.h"
#endif

#ifdef HAVE_GETHOSTENT
/* some systems (e.g. bsd) don't have gethostent(3) any more, assuming
   dns be a way to lookup host names. but some systems (e.g. sunos)
   still have it.  if it does, it may be a good idea to initialize the
   name table at the startup.
 */
#define INIT_HOSTNAME_TAB	/* create host name table beforehand */
#endif

static u_long f_localnet, f_netmask;

static char *tcpport_string(u_short port);
static char *udpport_string(register u_short port);
static void init_servarray(void);
#ifdef INIT_HOSTNAME_TAB
static void init_hostarray(void);
#endif
static char *getname(const u_long addr);
static char *intoa(u_long addr);

void netname_init(u_long netaddr, u_long netmask)
{
    /* save localnet address and netmask */
    f_localnet = netaddr;
    f_netmask = netmask;

    /* initialize tcp/udp service table */
    init_servarray();
#ifdef INIT_HOSTNAME_TAB
    /* initialize host name table */
    if (!ttt_nohostname)
	init_hostarray();
#endif
}

#ifndef	ETHERTYPE_LOOPBACK
#define	ETHERTYPE_LOOPBACK	0x9000
#endif
#ifndef ETHERTYPE_ATALK
#define ETHERTYPE_ATALK		0x809b
#endif

struct pname_tab {
    char *pn_name;
    int pn_value;
};

static struct pname_tab eth_tab[] = 
{
    { "ip",	ETHERTYPE_IP },			/* IP protocol */
    { "arp",	ETHERTYPE_ARP },		/* Addr. resolution protocol */
#ifdef IPV6
    { "ipv6",	ETHERTYPE_IPV6 },		/* IPv6 protocol */
#endif
    { "pup",	ETHERTYPE_PUP },		/* PUP protocol */
    { "revarp",	ETHERTYPE_REVARP },		/* Reverse ARP */
    { "loop",	ETHERTYPE_LOOPBACK },		/* Loopback */
    { "atalk",	ETHERTYPE_ATALK },		/* AppleTalk */
    { NULL,	0 }
};

/* stick to RFC1700.  some systems has wrong numbers.  */
#undef IPPROTO_IP
#define IPPROTO_IP		4   /* IP in IP (encasulation) */
#undef IPPROTO_IPIP
#define IPPROTO_IPIP		94  /* IP-within-IP Encapsulation Protocol */
#undef IPPROTO_ENCAP
#define IPPROTO_ENCAP		98  /* Encapsulation Header */

/* other protocols we are interested in */
#ifndef IPPROTO_RSVP
#define IPPROTO_RSVP		46  /* RSVP Reservation Protocol */
#endif
#ifndef IPPROTO_GRE
#define IPPROTO_GRE		47  /* General Routing Encapsulation */
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP		50  /* encapsulating security payload */
#endif
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP		89  /* OSPFIGP */
#endif

static struct pname_tab ip_tab[] =
{
    { "tcp",	IPPROTO_TCP },		/* tcp */
    { "udp",	IPPROTO_UDP },		/* user datagram protocol */
    { "icmp",	IPPROTO_ICMP },		/* control message protocol */
    { "igmp",	IPPROTO_IGMP },		/* group control protocol */
#ifdef IPPROTO_GGP
    { "ggp",	IPPROTO_GGP }, 		/* gateway^2 (deprecated) */
#endif
    { "egp",	IPPROTO_EGP },		/* exterior gateway protocol */
    { "pup",	IPPROTO_PUP },		/* pup */
    { "ospf",	IPPROTO_OSPFIGP },	/* OSPFIGP */
    { "rsvp",	IPPROTO_RSVP },		/* RSVP */
    { "gre",	IPPROTO_GRE },		/* GRE */
    { "esp",	IPPROTO_ESP },		/* encapsulating security payload */
    { "ip", 	IPPROTO_IP },		/* IP in IP */
    { "ipip", 	IPPROTO_IPIP },		/* IP-within-IP */
    { "encap",	IPPROTO_ENCAP },	/* Encapsulation Header */
#ifdef IPV6
    { "icmp6",	IPPROTO_ICMPV6 },	/* ICMP version 6 */
#endif
    { NULL,	0 }
};

static char *pname_lookup(struct pname_tab *tab, long id)
{
    struct pname_tab *tp = tab;
    while (tp->pn_name != NULL) {
	if (tp->pn_value == id)
	    return (tp->pn_name);
	tp++;
    }
    return NULL;
}

char *net_getname(long type, long *id)
{
    char *buf, *name;
    u_short portno;

    switch(type) {
    case TTTTYPE_ETHER:
	if ((buf = malloc(sizeof("revarp/ether  "))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	name = pname_lookup(eth_tab, id[0]);
	if (name != NULL)
	    sprintf(buf, "%s/ether", name);
	else
	    sprintf(buf, "0x%lx/ether", id[0]);
	break;
    case TTTTYPE_IP:
	if ((buf = malloc(sizeof("encap/ip  "))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	name = pname_lookup(ip_tab, id[0]);
	if (name != NULL)
	    sprintf(buf, "%s/ip", name);
	else
	    sprintf(buf, "%lu/ip", id[0]);
	break;
    case TTTTYPE_UDP:
	if ((buf = malloc(sizeof("some-long-service-name/udp"))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	portno = id[0];
	if ((name = udpport_string(portno)) != NULL)
	    sprintf(buf, "%s/udp", name);
	else
	    sprintf(buf, "%lu/udp", id[0]);
	break;
    case TTTTYPE_TCP:
	if ((buf = malloc(sizeof("some-long-service-name/tcp"))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	portno = id[0];
	if ((name = tcpport_string(portno)) != NULL)
	    sprintf(buf, "%s/tcp", name);
	else
	    sprintf(buf, "%lu/tcp", id[0]);
	break;
    case TTTTYPE_IPHOST:
    {
	u_long addr;

	if ((buf = malloc(sizeof("xxx.xxx.xxx.xxx"))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	addr = htonl(id[0]);
#ifdef DONT_LOOKUP_HOSTNAME
	if (!ttt_nohostname && (name = getname(addr)) != NULL) {
#else
	/* lookup the hostname only when
	   (1) the address is local. (otherwise, it might take a long time
	   			      to lookup dns)
	   (2) the host portion is not 0 (i.e., a network address).
	   (3) the host portion is not broadcast.
	 */
	if (!ttt_nohostname && (addr & f_netmask) == f_localnet
	    && (addr &~ f_localnet) != 0
	    && (addr | f_netmask) != 0xffffffff
	    && ((name = getname(addr)) != NULL)) {
#endif /* !DONT_LOOKUP_HOSTNAME */
	    strcpy(buf, name);
	}
	else
	    sprintf(buf, "%s", intoa(addr));
    }
	break;
#ifdef IPV6
    case TTTTYPE_IPV6:
	if ((buf = malloc(sizeof("icmp6/ip6  "))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	name = pname_lookup(ip_tab, id[0]);
	if (name != NULL)
	    sprintf(buf, "%s/ip6", name);
	else
	    sprintf(buf, "%lu/ip6", id[0]);
	break;
    case TTTTYPE_UDPV6:
	if ((buf = malloc(sizeof("some-long-service-name/udp6"))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	portno = id[0];
	if ((name = udpport_string(portno)) != NULL)
	    sprintf(buf, "%s/udp6", name);
	else
	    sprintf(buf, "%lu/udp6", id[0]);
	break;
    case TTTTYPE_TCPV6:
	if ((buf = malloc(sizeof("some-long-service-name/tcp6"))) == NULL)
	    fatal_error("get_protoname: no memory\n");
	portno = id[0];
	if ((name = tcpport_string(portno)) != NULL)
	    sprintf(buf, "%s/tcp6", name);
	else
	    sprintf(buf, "%lu/tcp6", id[0]);
	break;
    case TTTTYPE_IPV6HOST:
    {
	u_long tmp[4];
	static char *inet6_ntoa(u_long *addr);  /* should be replaced
						   by addr2ascii */
	if ((buf = malloc(sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx")))
	    == NULL)
	    fatal_error("get_protoname: no memory\n");
	tmp[0] = htonl(id[0]);
	tmp[1] = htonl(id[1]);
	tmp[2] = htonl(id[2]);
	tmp[3] = htonl(id[3]);
	sprintf(buf, "%s", inet6_ntoa(tmp));
    }
	break;
#endif /* IPV6 */
    default:
	if ((buf = malloc(sizeof("unknown"))) == NULL)
	sprintf(buf, "unknown");
	break;
    }
    return buf;
}

/*
   cache tables for udp/tcp services and host names derived from tcpdump.

   we don't manage memory space since
   	- tcp/udp services has limited entries.
	- only local host names are looked up.

 */
/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994
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
 *
 *  Internet, ethernet, port, and protocol string to address
 *  and address to string conversion routines
 */

typedef unsigned long u_int32;

/*
 * hash tables for whatever-to-name translations
 */

#define HASHNAMESIZE 4096

struct hnamemem {
	u_int32 addr;
	char *name;
	struct hnamemem *nxt;
};

static struct hnamemem hnametable[HASHNAMESIZE];
static struct hnamemem tporttable[HASHNAMESIZE];
static struct hnamemem uporttable[HASHNAMESIZE];

static char *tcpport_string(u_short port)
{
    struct hnamemem *tp;
    u_long i = port;

    for (tp = &tporttable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
	if (tp->addr == i)
	    return (tp->name);
    return NULL;
}

static char *udpport_string(register u_short port)
{
    struct hnamemem *tp;
    u_long i = port;

    for (tp = &uporttable[i & (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
	if (tp->addr == i)
	    return (tp->name);
    return NULL;
}

static void init_servarray(void)
{
    struct servent *sv;
    struct hnamemem *table;
    int i, n = 0;

    setservent(1);
    while ((sv = getservent()) != NULL) {
	int port = ntohs(sv->s_port);
	i = port & (HASHNAMESIZE-1);
	if (strcmp(sv->s_proto, "tcp") == 0)
	    table = &tporttable[i];
	else if (strcmp(sv->s_proto, "udp") == 0)
	    table = &uporttable[i];
	else
	    continue;

	while (table->name) {
	    if (table->addr == port) {
		/* dup entry! */
		break;
	    }
	    table = table->nxt;
	}
	if (table->name == NULL) {
	    table->name = strdup(sv->s_name);
	    table->addr = port;
	    table->nxt = (struct hnamemem *)calloc(1, sizeof(*table));
	    n++;
	}
    }
    endservent();
#ifdef REMOTE_DEBUG
    printf("[debug] initialized serv table %d entries\n", n);
#endif
}

#ifdef INIT_HOSTNAME_TAB

static void init_hostarray(void)
{
    struct hostent *hp;
    struct hnamemem *p;
    int n = 0;

    sethostent(1);
    while ((hp = gethostent()) != NULL) {
	u_int32 addr;
	if (hp->h_length != 4)
	    continue;
	memcpy(&addr, hp->h_addr, hp->h_length);
	addr = ntohl(addr);
	p = &hnametable[addr & (HASHNAMESIZE-1)];

	while (p->name) {
	    if (p->addr == addr) {
		/* dup entry! */
		break;
	    }
	    p = p->nxt;
	}
	if (p->name == NULL) {
	    char *dotp;
	    p->name = strdup(hp->h_name);
	    p->addr = addr;
	    p->nxt = (struct hnamemem *)calloc(1, sizeof(*p));
	    /* Remove domain qualifications */
	    dotp = strchr(p->name, '.');
	    if (dotp)
		*dotp = 0;
	    n++;
	}
    }
    endhostent();
#ifdef REMOTE_DEBUG
    printf("[debug] initialized host name table %d entries\n", n);
#endif
}

#endif /* INIT_HOSTNAME_TAB */

/*
 * Return a name for the IP address.  This address
 * is assumed to be in network byte order.
 */
static char *getname(const u_int32 addr)
{
    struct hnamemem *p;

    p = &hnametable[addr & (HASHNAMESIZE-1)];
    for (; p->nxt; p = p->nxt) {
	if (p->addr == addr)
	    return (p->name);
    }
#ifndef DONT_LOOKUP_HOSTNAME
    {
	struct hostent *hp;

	p->addr = addr;
	p->nxt = (struct hnamemem *)calloc(1, sizeof (*p));

	hp = gethostbyaddr((char *)&addr, 4, AF_INET);
	if (hp) {
	    char *dotp;
		
	    p->name = strdup(hp->h_name);
	    /* Remove domain qualifications */
	    dotp = strchr(p->name, '.');
	    if (dotp)
		*dotp = 0;
	    return (p->name);
	}
    }
#endif /* DONT_LOOKUP_HOSTNAME */

    return NULL;
}

/*
 * A faster replacement for inet_ntoa().
 */
static char *intoa(u_int32 addr)
{
    register char *cp;
    register u_int byte;
    register int n;
    static char buf[sizeof(".xxx.xxx.xxx.xxx")];

    addr = ntohl(addr);
    cp = &buf[sizeof buf];
    *--cp = '\0';

    n = 4;
    do {
	byte = addr & 0xff;
	*--cp = byte % 10 + '0';
	byte /= 10;
	if (byte > 0) {
	    *--cp = byte % 10 + '0';
	    byte /= 10;
	    if (byte > 0)
		*--cp = byte + '0';
	}
	*--cp = '.';
	addr >>= 8;
    } while (--n > 0);
    
    return cp + 1;
}

#ifdef IPV6
/* derived from ascii_addr.c */
#if !defined(BSD4_4) && !(defined(__linux__) && defined(__USE_BSD))
typedef u_long	u_int32_t;
typedef u_short	u_int16_t;
#endif
/*
 * Copyright (c) 1994 Bell Communications Research Inc. (Bellcore).
 *
 * Permission to use, copy, modify and distribute this material for any
 * purpose and without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies,
 * and the name of Bellcore not be used in  advertising or publicity
 * pertaining to this material without the specific, prior written
 * permission of an authorized representative of Bellcore. BELLCORE
 * MAKES NO REPRESENTATIONS ABOUT THE SUITABILITY OF THIS MATERIAL
 * FOR ANY PURPOSE. IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES.
 */

static char digits[] = "0123456789abcdef";
static char buf[128];

static char *
inet6_ntoa(u_int32_t *addr)
{
        register int i;
	register char *cp = buf;
        register u_int16_t *a = (u_int16_t *)addr;
        register u_char *d;
        int zeros, h, dcolon = 0;

        for (i = 0; i < 8; i++) {
                if (dcolon == 1) {
                        if (*a == 0) {
				/* trailing zeros */
				if (i == 7)
					*cp++ = ':';
                                a++;
                                continue;
                        } else
                                dcolon = 2;
                }
                if (*a == 0) {
                        if (dcolon == 0 && *(a + 1) == 0) {
				/* leading zeros */
				if (i == 0)
	                                *cp++ = ':';
                                *cp++ = ':';
                                dcolon = 1;
                        } else {
                                *cp++ = '0';
                                *cp++ = ':';
                        }
			a++;
                        continue;
                }
                d = (u_char *)a;
		zeros = 0;
		if ((h = (*d >> 4)) == 0)
			zeros = 1;
		else
	                *cp++ = digits[h];
		if (((h = (*d++ & 0xf)) == 0) && (zeros == 1))
			zeros = 2;
		else
			*cp++ = digits[h];
		if (((h = (*d >> 4)) == 0) && (zeros == 2))
			zeros = 3;
		else
			*cp++ = digits[h];
                *cp++ = digits[*d & 0xf];
                *cp++ = ':';
                a++;
        }
        *--cp = 0;
        return (buf);
}

#endif /* IPV6 */

