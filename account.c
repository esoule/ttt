/* $Id: account.c,v 0.2 1996/09/03 09:11:40 kjc Exp $ */
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
/*  account.c -- a simple wrapper of the node module for network accounting. */
#include <sys/types.h>

#include "ttt.h"
#include "ttt_node.h"
#include "ttt_account.h"

static struct t_node *eth_root, *ip_root, *udp_root, *tcp_root, *host_root;
#ifdef IPV6
static struct t_node *ip6_root, *udp6_root, *tcp6_root, *host6_root;
#endif

void netacc_init(void)
{
    node_init();

    eth_root = node_createroot(TTTTYPE_ETHER);
    ip_root = node_createroot(TTTTYPE_IP);
    udp_root = node_createroot(TTTTYPE_UDP);
    tcp_root = node_createroot(TTTTYPE_TCP);
    host_root = node_createroot(TTTTYPE_IPHOST);
#ifdef IPV6
    ip6_root = node_createroot(TTTTYPE_IPV6);
    udp6_root = node_createroot(TTTTYPE_UDPV6);
    tcp6_root = node_createroot(TTTTYPE_TCPV6);
    host6_root = node_createroot(TTTTYPE_IPV6HOST);
#endif
}

void netacc_cleanup(void)
{
    node_cleanup();
    node_destroyroot(eth_root);
    node_destroyroot(ip_root);
    node_destroyroot(udp_root);
    node_destroyroot(tcp_root);
    node_destroyroot(host_root);
#ifdef IPV6
    node_destroyroot(ip6_root);
    node_destroyroot(udp6_root);
    node_destroyroot(tcp6_root);
    node_destroyroot(host6_root);
#endif
}

int eth_addsize(int etype, int pkt_len)
{
    struct t_node *np;
    long id[4];

    id[0] = etype;
#ifdef IPV6
    id[1] = id[2] = id[3] = 0;
#endif
    np = node_findnode(eth_root, TTTTYPE_ETHER, id);
    return node_addsize(np, pkt_len);
}

int ip_addsize(int proto, int pkt_len)
{
    struct t_node *np;
    long id[4];

    id[0] = proto;
#ifdef IPV6
    id[1] = id[2] = id[3] = 0;
#endif

    np = node_findnode(ip_root, TTTTYPE_IP, id);
    return node_addsize(np, pkt_len);
}

int udp_addsize(int port, int pkt_len)
{
    struct t_node *np;
    long id[4];

    id[0] = port;
#ifdef IPV6
    id[1] = id[2] = id[3] = 0;
#endif

    np = node_findnode(udp_root, TTTTYPE_UDP, id);
    return node_addsize(np, pkt_len);
}

int tcp_addsize(int port, int pkt_len)
{
    struct t_node *np;
    long id[4];

    id[0] = port;
#ifdef IPV6
    id[1] = id[2] = id[3] = 0;
#endif

    np = node_findnode(tcp_root, TTTTYPE_TCP, id);
    return node_addsize(np, pkt_len);
}

int host_addsize(u_long addr, int pkt_len)
{
    struct t_node *np;
    u_long id[4];

    id[0] = addr;
#ifdef IPV6
    id[1] = id[2] = id[3] = 0;
#endif

    np = node_findnode(host_root, TTTTYPE_IPHOST, id);
    return node_addsize(np, pkt_len);
}

#ifdef IPV6

int ipv6_addsize(int proto, int pkt_len)
{
    struct t_node *np;
    long id[4];

    id[0] = proto;
    id[1] = id[2] = id[3] = 0;

    np = node_findnode(ip6_root, TTTTYPE_IPV6, id);
    return node_addsize(np, pkt_len);
}

int udpv6_addsize(int port, int pkt_len)
{
    struct t_node *np;
    long id[4];

    id[0] = port;
    id[1] = id[2] = id[3] = 0;

    np = node_findnode(udp6_root, TTTTYPE_UDPV6, id);
    return node_addsize(np, pkt_len);
}

int tcpv6_addsize(int port, int pkt_len)
{
    struct t_node *np;
    long id[4];

    id[0] = port;
    id[1] = id[2] = id[3] = 0;

    np = node_findnode(tcp6_root, TTTTYPE_TCPV6, id);
    return node_addsize(np, pkt_len);
}

int hostv6_addsize(u_long *addr, int pkt_len)
{
    struct t_node *np;

    np = node_findnode(host6_root, TTTTYPE_IPV6HOST, addr);
    return node_addsize(np, pkt_len);
}


#endif /* IPV6 */
