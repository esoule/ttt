/* $Id: node_emu.c,v 0.1 1996/06/30 12:52:56 kjc Exp kjc $ */
/* node_emu.c -- dummy routines of node.c used by viewers */
#include <stdio.h>
#include "ttt.h"
#include "ttt_node.h"

static int nhosts, nprotos, rhosts, rprotos;
static struct t_node node_tab[2][30];

void node_bumptime(void)
{
    nprotos = nhosts = 0;
}

void node_record(long type, long *id, int size)
{
    struct t_node *np;

    if (type < TTTTYPE_HOST) {
	if (nprotos >= 30)
	    return;
	np = &node_tab[0][nprotos++];
    }
    else {
	if (nhosts >= 30)
	    return;
	np = &node_tab[1][nhosts++];
    }

    np->t_type = type;
    np->t_size = size;
    np->t_id[0] = id[0];
#ifdef IPV6
    np->t_id[1] = id[1];
    np->t_id[2] = id[2];
    np->t_id[3] = id[3];
#endif
}

struct t_node *node_getbiggest(long type)
{
    if (type < TTTTYPE_HOST) {
	if (nprotos == 0)
	    return NULL;
	rprotos = 1;
	return &node_tab[0][0];
    }
    else {
	if (nhosts == 0)
	    return NULL;
	rhosts = 1;
	return &node_tab[1][0];
    }
}

struct t_node *node_getnext(struct t_node *np)
{
    if (np->t_type < TTTTYPE_HOST) {
	if (rprotos >= nprotos)
	    return NULL;
	return &node_tab[0][rprotos++];
    }
    else {
	if (rhosts >= nhosts)
	    return NULL;
	return &node_tab[1][rhosts++];
    }
}

