/* $Id: node.c,v 0.5 2004/05/19 10:20:35 kjc Exp kjc $ */
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
/*

   node mudule:
				
    each node keeps total packet size of the corresponding protocol or host
    during a time interval.
    implementation requiremets:
        (1) quick search by its id.
	    for each incoming packet, the corresponding node should be
	    searched by its id.
	(2) quick search by size order.
	    after each interval cycle, nodes should be sorted by size.
	(3) I don't want to clear all nodes at the end of each interval.
    so, I decided to implement the node structure as a combination of
    tree and list.
        (1) nodes are stored in a binary tree by its id.
	(2) nodes are also stored in lists sorted by its size.
	    the size table holds 32 bucket heads for log2(size).
	(3) a node which has old timestatmp gets cleared only when it is
	    accessed.
	for each incoming packet, the corresponding node is binary
	searched by its id, and then, the node is pulled from the size
	list, added the packet size and stored back to the size list.

				kjc@csl.sony.co.jp
				96/06/11

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ttt.h"
#include "ttt_node.h"

#define SIZETAB_SIZE	(sizeof(int)*8)

#ifdef IPV6
static long minus_one[4] = {-1, -1, -1, -1};
#else
static long minus_one[1] = {-1};
#endif

/* 2 independent tables for protocol-info and host-info */
static struct t_node size_tab[2][SIZETAB_SIZE];

/* macro to select protocol-table or host-table */
#define TYPE2TAB(type)  	((type) >= TTTTYPE_HOST)
#define NODE2TAB(np) 		TYPE2TAB((np)->t_type)

static int current_time = 0;
static int nodes_allocated[2];
#ifdef NODE_DEBUG
static int node_in_use = 0;
#endif

/* private function prototypes */
static void t_init(void);
static void t_remtree(struct t_node *node);
static struct t_node *t_newnode(struct t_node *parent, long type, long *id);
static void t_deletenode(struct t_node *np);
static void t_makefree(int tab_no);
static struct t_node *t_findnode(struct t_node *root, long type, long *id);
static int b_alloc_nodes(int tab_no, int n);
static void b_init_tab(void);
static void b_resettime (struct t_node *np);
static int b_addsize(struct t_node *np, int delta);
static void b_insbucket(struct t_node *np);
static void b_insq(struct t_node *prev, struct t_node *np);
static struct t_node *b_remq(struct t_node *np);
struct t_node *b_getbiggest(int tab_no);
struct t_node *b_getnext(struct t_node *np);
static int b_collectgarbage(int tab_no);
static int b_countfree(int tab_no);
static struct t_node *b_getfree(int tab_no);
static int fls(int i);
#ifdef IPV6
static int node_comp_id(long *a, long *b);
#endif
#ifdef NODE_DEBUG
static void dumptree(struct t_node *root);
#endif

void node_init(void)
{
    t_init();
}

/* discard all nodes */
void node_cleanup(void)
{
    int tab_no;
    struct t_node *np;

    for (tab_no=0; tab_no<2; tab_no++)
	while ((np = b_getfree(tab_no)) != NULL)
	    t_deletenode(np);
}

struct t_node *node_getbiggest(long type)
{
    return b_getbiggest(TYPE2TAB(type));
}
struct t_node *node_getnext(struct t_node *np)
{
    return b_getnext(np);
}

struct t_node *node_findnode(struct t_node *root, long type, long *id)
{
    return t_findnode(root, type, id);
}

int node_addsize(struct t_node *np, int delta)
{
    return b_addsize(np, delta);
}

struct t_node *node_createroot(long type)
{
    struct t_node *np;

    np = t_newnode(NULL, type, minus_one);
    b_remq(np);  /* remove the root node from size_tab */
#ifdef NODE_DEBUG
    np->t_bigger = np->t_smaller = np;
#endif
    return np;
}

void node_destroyroot(struct t_node *root)
{
    int tab_no = NODE2TAB(root);

    assert(root->t_left == NULL && root->t_right == NULL);
    free(root);
    --nodes_allocated[tab_no];
#ifdef NODE_DEBUG
    printf("node_destroyroot: total nodes=%d for tab[%d]\n",
	   nodes_allocated[tab_no], tab_no);
#endif
}

void node_bumptime(void)
{
    current_time++;

    /* do garbage collection every 5 minutes */
    if ((current_time % 300) == 0)
	node_collectgarbage();
}

void node_collectgarbage(void)
{
    int tab_no, n, i;
    struct t_node *np;

    for (tab_no=0; tab_no<2; tab_no++) {
	n = b_collectgarbage(tab_no);

	/* count the nodes on the free list.  if more than 100 nodes
	   are free, keep 50 and discard the rest.  */
	n = b_countfree(tab_no);
	if (n > 100) {
#ifdef NODE_DEBUG
	    printf("[debug] too much nodes. discard %d nodes\n", n-50);
#endif
	    for (i=0; i<n-50; i++) {
		np = b_getfree(tab_no);
		t_deletenode(np);
	    }
#ifdef NODE_DEBUG
	    printf("\ttotal nodes=%d for %s tab\n",
		   nodes_allocated[tab_no], (tab_no?"proto":"host"));
#endif
	}
    }
}

/*

binary tree implementation:
	
*/

int ttt_max_nodes = TTT_MAX_NODES;

static void t_init(void)
{
    b_init_tab();
}

/* remove a node from a tree:
   if the node has no child or a single child, just splice out the node.
   if the node has two child, find its successor node (which should have
   no left child) and splice out this succesor and replace the node with
   the successor.  */
static void t_remtree(struct t_node *np)
{
    struct t_node *victim, *child;

    assert(np != np->t_parent);
    assert(np != np->t_left);
    assert(np != np->t_right);
    if (np->t_parent == NULL) {
	/* don't remove root */
	printf("t_remtree: try to remove root!\n");
	return;
    }

    if (np->t_left == NULL || np->t_right == NULL)
	victim = np;
    else {
	/* the node has two children.  we have to find its successor */
	victim = np->t_right;
	while (victim->t_left != NULL)
	    victim = victim->t_left;
	assert(COMP_ID(np->t_id, victim->t_id) < 0);
    }

    /* victim has at most one child. just make a new link between
       its parent and child. */
    if (victim->t_left != NULL) {
	child = victim->t_left;
	assert(victim->t_right == NULL);
    }
    else
	child = victim->t_right;
    if (child != NULL)
	child->t_parent = victim->t_parent;
    if (victim == victim->t_parent->t_left)
	victim->t_parent->t_left = child;
    else {
	assert(victim == victim->t_parent->t_right);
	victim->t_parent->t_right = child;
    }

    if (victim != np) {
	/* replace node with its successor */
	victim->t_parent = np->t_parent;
	if (np == np->t_parent->t_left)
	    np->t_parent->t_left = victim;
	else {
	    assert(np == np->t_parent->t_right);
	    np->t_parent->t_right = victim;
	}

	if ((victim->t_left = np->t_left) != NULL)
	    np->t_left->t_parent = victim;
	if ((victim->t_right = np->t_right) != NULL)
	    np->t_right->t_parent = victim;
    }
    np->t_parent = np->t_left = np->t_right = NULL;
#ifdef NODE_DEBUG
    --node_in_use;
#endif
}

/* make sure that the node at the tail of the size 0 bucket
   is not in the tree. */
static void t_makefree(int tab_no)
{
    struct t_node *head;
    int n;
    
    head = &size_tab[tab_no][0];
    if (head->t_bigger == head) {
	static int too_few_nodes;
	/* the size 0 bucket is empty */
	n = b_collectgarbage(tab_no);
	if (n == 1) {
	    /* we are running out of free nodes */
	    too_few_nodes++;
	    if (too_few_nodes > 30 &&
		nodes_allocated[tab_no] < ttt_max_nodes) {
		/* too few nodes available */
		b_alloc_nodes(tab_no, 50);
#ifdef NODE_DEBUG
		printf("[debug] too few nodes. allocated another 50 nodes\n");
		printf("\ttotal nodes=%d for %s tab\n",
		       nodes_allocated[tab_no], (tab_no?"proto":"host"));
		if (nodes_allocated[tab_no] >= ttt_max_nodes) {
		    printf("!total nodes[%d] for %s tab hit the limit[%d]!\n",
			   nodes_allocated[tab_no],(tab_no?"proto":"host"),
			   ttt_max_nodes);
		}
#endif
	    }
	}
	else
	    too_few_nodes = 0;
    }
    assert (head->t_bigger != head);
    if (head->t_bigger->t_parent != NULL)
	t_remtree(head->t_bigger);
}

static struct t_node *t_newnode(struct t_node *parent, long type, long *id)
{
    struct t_node *np;

    np = b_getfree(TYPE2TAB(type));

    assert(np->t_parent == NULL && np->t_left == NULL && np->t_right == NULL);
    np->t_parent = parent;
    np->t_type = type;
    np->t_id[0] = id[0];
#ifdef IPV6
    np->t_id[1] = id[1];
    np->t_id[2] = id[2];
    np->t_id[3] = id[3];
#endif
#ifdef NODE_DEBUG
    node_in_use++;
#endif
    return np;
}

static void t_deletenode(struct t_node *np)
{
     /* first remove from the size table.  then, if it's on the tree,
	remove it from the binary tree */
    int tab_no = NODE2TAB(np);
	
    b_remq(np);
    if (np->t_parent != NULL)
	t_remtree(np);
    free(np);
    --nodes_allocated[tab_no];
}

/* look up the node by id in the binary tree.
   if a node doesn't exist, create one.  */
static struct t_node *t_findnode(struct t_node *root, long type, long *id)
{
    struct t_node *np = root;

    /* make sure we have at least one free node before we start
       tree-search.*/
    t_makefree(TYPE2TAB(type));
    
    while (!ISSAME_ID(np->t_id, id)) {
	if (COMP_ID(np->t_id, id) > 0) {
	    if (np->t_left == NULL) {
		np->t_left = t_newnode(np, type, id);
		return np->t_left;
	    }
	    np = np->t_left;
	}
	else {
	    if (np->t_right == NULL) {
		np->t_right = t_newnode(np, type, id);
		return np->t_right;
	    }
	    np = np->t_right;
	}
    }
    /* found */
    if (np == root) {
	/* special case for root.  we don't use the root node since removing
	   the root node is trickier than this.  */
	if (root->t_left == NULL) {
	    root->t_left = t_newnode(np, type, id);
	    return root->t_left;
	}
	else if (ISSAME_ID(root->t_left->t_id, id)) {
	    /* this avoids recursive root match */
	    return root->t_left;
	}
	else
	    return t_findnode(root->t_left, type, id);
    }
    return np;
}

/*

size bucket implementation:

the size bucket keeps all the items by size order.
each bucket head "size_tab[i][n]" holds items whose log2(size) is "n-1".

	bucket_head[0] -- 0 -- 0 -- free -- free
	bucket_head[1]
		|
	bucket_head[7] -- 124 -- 98
	bucket_head[8] -- 255 -- 190 -- 154
		|
	bucket_head[20] -- (1M-n)(byte)
		|
	bucket_head[31]

*/
#define B_INSFREEQ(tab_no, np)	b_insq((&size_tab[tab_no][0]), np)

static int b_alloc_nodes(int tab_no, int n)
{
    struct t_node *np;
    int i;
    
    for (i=0; i<n; i++) {
	if ((np = malloc(sizeof(struct t_node))) == NULL)
	    fatal_error("b_allocate: can't get memory");
	memset(np, 0, sizeof(struct t_node));
	np->t_type = (tab_no == 0) ? TTTTYPE_PROTO : TTTTYPE_HOST;
	B_INSFREEQ(tab_no, np);
    }
    nodes_allocated[tab_no] += n;
    return 0;
}

#define T_INIT_NODES 100

static void b_init_tab(void)
{
    struct t_node *np;
    int tab_no, i;
    long type;
    
    /* init size tables */
    for (tab_no=0; tab_no<2; tab_no++) {
	type = (tab_no == 0) ? TTTTYPE_PROTO : TTTTYPE_HOST;
	for (i=0; i<SIZETAB_SIZE; i++) {
	    np = &size_tab[tab_no][i];
	    np->t_bigger = np->t_smaller = np;
	    np->t_size = -1;
	    np->t_type = type;
	}

	/* allocate nodes */
	b_alloc_nodes(tab_no, T_INIT_NODES);
    }
}

static void b_resettime(struct t_node *np)
{
    np->t_time = current_time;
    if (np->t_size != 0) {
	b_remq(np);
	np->t_size = 0;
	B_INSFREEQ(NODE2TAB(np), np);
    }
}

static int b_addsize(struct t_node *np, int delta)
{
    b_remq(np);
    if (np->t_time != current_time) {
	/* size is obsolete, clear the size */
	np->t_size = 0;
	np->t_time = current_time;
    }
    np->t_size += delta;
    assert(np->t_size >= 0);
    b_insbucket(np);
    return np->t_size;
}

static void b_insbucket(struct t_node *np)
{
    struct t_node *head, *prev;

    head = &size_tab[NODE2TAB(np)][fls(np->t_size)];
    for (prev = head; prev->t_smaller != head; prev = prev->t_smaller)
	if (prev->t_smaller->t_size <= np->t_size)
	    break;
    b_insq(prev, np);
}

static void b_insq(struct t_node *prev, struct t_node *np)
{
    np->t_bigger = prev;
    np->t_smaller = prev->t_smaller;
    prev->t_smaller = np;
    np->t_smaller->t_bigger = np;
}

static struct t_node *b_remq(struct t_node *np)
{
    assert(np->t_size >= 0);
    np->t_bigger->t_smaller = np->t_smaller;
    np->t_smaller->t_bigger = np->t_bigger;
    return np;
}

struct t_node *b_getbiggest(int tab_no)
{
    return b_getnext(&size_tab[tab_no][SIZETAB_SIZE-1]);
}

struct t_node *b_getnext(struct t_node *np)
{
    while (1) {
	while (np->t_smaller->t_size == -1) {
	    /* smaller node must be a bucket head.
	       go down to the smaller size.  */
	    np = np->t_smaller - 1;
	    if (np == &size_tab[NODE2TAB(np)][0]) {
		/* we came down all the way to the bucket size 0. */
		return NULL;
	    }
	    assert(np >= &size_tab[NODE2TAB(np)][0] &&
		   np <= &size_tab[NODE2TAB(np)][31]);
	}
	if (np->t_smaller->t_time != current_time) {
	    /* this entry is obsolete.  reset its time and size.
	       since b_resettime removes the node from the bucket,
	       we have to check t_smaller again.  */
	    b_resettime(np->t_smaller);
	    continue;
	}
	return np->t_smaller;
    }
}

static int b_collectgarbage(int tab_no)
{
    struct t_node *head, *np;
    int i, n, limit;

    n = 0;
    limit = current_time - 20;  /* 20 sec */
    for (i=1; i<SIZETAB_SIZE; i++) {
	head = np = &size_tab[tab_no][i];
	while (np->t_bigger != head) {
	    if (np->t_bigger->t_time < limit) {
		b_resettime(np->t_bigger);
		n++;
		continue;
	    }
	    np = np->t_bigger;
	}
    }
    if (n == 0) {
	/* no node expired.  we should guarantee at least one node
	   is free.  */
	np = b_getfree(tab_no);
	n++;
    }
    return n;
}

/* return the count of free nodes */
static int b_countfree(int tab_no)
{
    struct t_node *head, *np;
    int n = 0;

    head = &size_tab[tab_no][0];
    for (np = head->t_bigger; np != head; np = np->t_bigger)
	n++;
    return n;
}

/* reallocate the smallest node as a free node */
static struct t_node *b_getfree(int tab_no)
{
    struct t_node *np;

    np = &size_tab[tab_no][0];
    if (np->t_bigger != np)
	return np->t_bigger;

    /* size 0 bucket is empty.  get the smallest node and put it on the
       size 0 bucket.  */
    while (np->t_bigger == np) {
	if (np == &size_tab[tab_no][31]) {
#ifdef NODE_DEBUG
	    printf("size table[%d]: empty! total nodes=%d\n",
		   tab_no, nodes_allocated[tab_no]);
#endif	    
	    return NULL;
	}
	np = np + 1;
	assert(np >= &size_tab[tab_no][1]
	       && np <= &size_tab[tab_no][31]);
    }
    np = np->t_bigger;
    assert(np->t_size >= 0);
    b_resettime(np);
    assert(size_tab[tab_no][0].t_bigger == np);
    return np;
}

/* fls - find last set bit  --- reverse function of vax ffs */
static int fls(int i)
{
    int index;

    assert(i >= 0);

    if (i == 0)
	return 0;
    index = 32;
    while ((i & 0xff000000) == 0) {
	index -= 8;
	i <<= 8;
    }

    do {
	if (i & 0x80000000) {
	    assert(index < 32);
	    return index;
	}
	i <<= 1;
    } while (--index);
    assert(0);
    return 0;
}

static int node_comp_id(long *a, long *b)
{
#ifdef IPV6
    if (a[0] == b[0]) {
	if (a[1] == b[1]) {
	    if (a[2] == b[2]) {
		if (a[3] == b[3])
		    return 0;
		else if (a[3] < b[3])
		    return (-1);
		else
		    return (1);
	    }
	    else if (a[2] < b[2])
		return (-1);
	    else
		return (1);
	}
	else if (a[1] < b[1])
	    return (-1);
	else
	    return (1);
    }
    else if (a[0] < b[0])
	return (-1);
    else
	return (1);
#else
    if (a < b)
	return (-1);
    if (a == b)
	return 0;
    return (1);
#endif
}

#ifdef NODE_DEBUG

static void dumptree(struct t_node *root)
{
    struct t_node *np = root;
    struct t_node *last = NULL;
    int n = 0, up = 0;
    
    while (1) {
	printf("node[%d][0x%x] type[%d] id[%6d] left[%x] right[%x] p[%x]\n",
	       n, np, np->t_type, np->t_id[0], 
	       np->t_left, np->t_right, np->t_parent);

	if (np->t_left != NULL && up == 0) {
	    last = np;
	    np = np->t_left;
	}
	else if (np->t_right != NULL && np->t_right != last) {
	    last = np;
	    np = np->t_right;
	    up = 0;
	}
	else {
	    last = np;
	    np = np->t_parent;
	    up = 1;
	    if (np->t_parent == NULL) {
		printf("dump abnormal end\n");
		break;
	    }
	}

	n++;
	if (np == root && (np->t_right == NULL || np->t_right == last)) {
	    printf("dump end\n");
	    break;
	}
    }
}
#endif /* NODE_DEBUG */
