/* $Id: textview.c,v 0.2 1998/04/03 09:18:59 kjc Exp $ */
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
/* textview.c -- a text-based viewer program.  just for debug */
#include <stdio.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "ttt.h"
#include "ttt_node.h"
#include "ttt_remote.h"

static int sockfd;
static void cleanup(void);

int main(int argc, char **argv)
{
    view_parseargs(argc, argv);

    sockfd = view_opensock();

    while (1) {
	view_sockread(sockfd, 0);
    }

    cleanup();
}

static void cleanup(void)
{
    close(sockfd);
}

void ttt_textview(int seq_no)
{
    struct t_node *np;
    int i;
    double cur_time, get_timeindouble();
    u_long recvpkts, droppkts, lostpkts;
    
    cur_time = get_timeindouble();

    printf("ranking at time %.2f\n", cur_time);
    if (get_pcapstat(&recvpkts, &droppkts, &lostpkts) == 0)
	printf("pcap stat: recv[%d] drop[%d]  ttt report: drop[%d]\n",
	       recvpkts, droppkts, lostpkts);

    printf("proto ranking");
    for (i=0, np = node_getbiggest(TTTTYPE_PROTO);
	 i<10 && np != NULL; i++, np = node_getnext(np)) {
	printf("rank[%d]: [%d:%6d] size=%d\n",
	       i+1, np->t_type, np->t_id[0], np->t_size);
    }
    printf("host ranking\n");
    for (i=0, np = node_getbiggest(TTTTYPE_HOST);
	 i<10 && np != NULL; i++, np = node_getnext(np)) {
	struct in_addr inaddr;
	inaddr.s_addr = htonl(np->t_id[0]);
	printf("rank[%d]: [%d:%15s] size=%d\n",
	       i+1, np->t_type, inet_ntoa(inaddr), np->t_size);
    }
    printf("\n");

    node_bumptime();
}
