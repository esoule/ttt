/* $Id: ttt_node.h,v 0.2 2000/12/20 14:29:45 kjc Exp kjc $ */
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
/* ttt_node.h -- node module header */
#ifndef _TTT_NODE_H_
#define _TTT_NODE_H_

/* node structure to hold accounting info */
struct t_node {
    /* fields for the protocol binary tree */
    struct t_node *t_left;
    struct t_node *t_right;
    struct t_node *t_parent;
    long t_type;		/* ttt types defined in ttt.h */
#ifdef IPV6
    long t_id[4];		/* all id is 16 byte long */
#else
    long t_id[1];		/* type specific id (e.g. proto number) */
#endif

    /* fields for the size table */
    struct t_node *t_bigger;
    struct t_node *t_smaller;
    long t_size;		/* total packet size */
    long t_time;		/* time stamp */
};

#ifdef IPV6
#define ISSAME_ID(a, b)	((a)[0] == (b)[0] && \
			 (a)[1] == (b)[1] && \
			 (a)[2] == (b)[2] && \
			 (a)[3] == (b)[3])
#define COMP_ID(a, b)	node_comp_id(a, b)
#else
#define ISSAME_ID(a, b)	((a)[0] == (b)[0])
#define COMP_ID(a, b)	(((a)[0]<(b)[0])?-1:((a)==(b))?0:1)
#endif

/* public function prototypes */
void node_init(void);
void node_cleanup(void);
struct t_node *node_createroot(long type);
void node_destroyroot(struct t_node *root);
int node_addsize(struct t_node *np, int delta);
struct t_node *node_findnode(struct t_node *root, long type, long *id);
struct t_node *node_getbiggest(long type);
struct t_node *node_getnext(struct t_node *np);
void node_bumptime(void);
void node_collectgarbage(void);

void node_record(long type, long *id, int size);  /* node_emu only */

#endif /* _TTT_NODE_H_ */
