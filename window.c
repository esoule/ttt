/* $Id: window.c,v 0.3 2003/10/16 10:38:32 kjc Exp kjc $ */
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
   window graph module:
	keep track of the top ranking protocols or hosts within the
	time window.
				kjc@csl.sony.co.jp
				96/06/11
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <netdb.h>
#include <ctype.h>
#include <assert.h>

#include "ttt.h"
#include "ttt_node.h"
#include "ttt_account.h"
#include "ttt_window.h"

#define WG_MAX_ENTRIES	30	/* max list size */

#define WG_LIST(type)	\
	(((type) < TTTTYPE_HOST) ? &wg_proto_list : &wg_host_list)

static struct wg_entry wg_proto_list, wg_host_list;
static int wg_proto_entries, wg_host_entries;
static int wg_cur_time;

static struct wg_entry *wg_create(long type, long *id);
static void wg_delete(struct wg_entry *wgp);
static void wg_qinit(struct wg_entry *wgp);
static void wg_insq(struct wg_entry *prev, struct wg_entry *wgp);
static struct wg_entry *wg_remq(struct wg_entry *wgp);
static void wg_setrank(struct wg_entry *wgp);

static void w_insq(struct w_ent *prev, struct w_ent *ep);
static struct w_ent *w_remq(struct w_ent *ep);
static void w_insert(struct w_ent *head, struct w_ent *entry);
static void w_alloc_entries(int n);
static void w_init(void);
static void w_qinit(struct w_ent *head);
static void w_removesublist(struct w_ent *head, struct w_ent *list);
static int w_getmaxsize(struct w_ent *head);
static struct w_ent *w_getent(void);
static int w_countfree(void);
static void w_collectgarbage(void);
static void w_cleanup(void);

/* get the top n protocols or hosts during this interval. */
void stat_record(long type, int n)
{
    struct t_node *np;
    struct wg_entry *wgp;
    int i;
    
    for (i=0, np = node_getbiggest(type);
	 i<n && np != NULL; i++, np = node_getnext(np)) {
	if ((wgp = wg_lookup(np->t_type, np->t_id)) == NULL)
	    break;
	wg_record(wgp, np->t_size);
    }
}

int stat_ranking(long type, struct wg_entry **rank_list, int n)
{
    struct wg_entry *wgp;
    int i, rval;

#ifdef PRINT_RANKING
    printf("%s ranking at time %d\n",
	   (type < TTTTYPE_HOST) ? "proto" : "host", wg_cur_time);
#endif
    if (n > WG_MAX_ENTRIES)
	n = WG_MAX_ENTRIES;
    for (i=0, wgp = wg_getbiggest(type); i<n && wgp != NULL;
	 i++, wgp = wg_getnext(wgp)) {
	rank_list[i] = wgp;
#ifdef PRINT_RANKING
	printf("rank[%d]: [%16s] %.2fMbps\n",
	       i, wgp->wg_name,
	       (double)wg_getmaxsize(wgp)/(1000.0*1000.0));
#endif
    }
#ifdef PRINT_RANKING
    printf("\n");
#endif
    rval = i;
    for (; i<n; i++)
	rank_list[i] = NULL;
    return rval;
}

/* dynamically assigned colors */
static char *default_colors[] = {
    "red", "green", "blue", "cyan", "magenta", "yellow",
};
static char **color_list = default_colors;
static int color_list_size = sizeof(default_colors) / sizeof(char *);
static int color_index = 0;

#define MAX_COLORS 64

int stat_set_colors(const char *string)
{
    char *cp;
    int i, done = 0;
    static char *colors[MAX_COLORS], *buf = NULL;;

    if (buf)
	free(buf);
    buf = malloc(strlen(string)+1);
    strcpy(buf, string);
    cp = buf;
    for (i=0; i < MAX_COLORS && !done && *cp; i++) {
	while (isspace(*cp))
	    cp++;
	if (!(*cp))
	    break;
	colors[i] = cp;
	while (isalnum(*cp))
	    cp++;
	if (!(*cp))
	    done = 1;
	*cp++ = '\0';
    }
    color_list = colors;
    color_list_size = i;
    color_index = 0;
    return color_list_size;
}

int stat_update(struct wg_entry **ranking, struct wg_entry **old_ranking,
		int *update_list, int n)
{
    int i, j, count = 0;
    int colors[32];
    
    for (i=0; i<32; i++)
	colors[i] = 0;
    
    for (i=0; i<n; i++) {
	if (ranking[i] == NULL) {
	    update_list[i] = 0;
	    continue;
	}
	if (ranking[i] == old_ranking[i]) {
	    /* no change */
	    update_list[i] = 0;
	    colors[ranking[i]->wg_colorindex] = 1;
	}
	else {
	    for (j=0; j<n; j++)
		if (ranking[i] == old_ranking[j]) {
		    /* this entry is also in the old ranking but its rank
		       changed.  we have to update the label but keep the
		       same color. */
		    update_list[i] = 1;
		    colors[ranking[i]->wg_colorindex] = 1;
		    count++;
		    break;
		}
	    if (j == n) {
		/* this is a new entry, assign a new color and update label */
		update_list[i] = 2;
		count++;
	    }
	}
    }

    /* assign unused colors to newly rank-in entries */
    if (count > 0) {
	for (i=0; i<n; i++)
	    if (update_list[i] == 2) {
		int start_index = color_index;
		/* get a unsed color */
		while (colors[color_index]) {
		    color_index = (color_index + 1) % color_list_size;
		    if (color_index == start_index)
			break;
		}
		ranking[i]->wg_color = color_list[color_index];
		ranking[i]->wg_colorindex = color_index;
		color_index = (color_index + 1) % color_list_size;
	    }
    }
    return count;
}

int wg_copybuf(struct wg_entry *wgp, double *vec, double interval, int n)
{
    int i, index;

    /* get the start index to the ring buf */
    index = (wg_cur_time - n + 1) % WG_WIN_SIZE;

    for (i=0; i<n; i++) {
	int bits = wgp->wg_ringbuf[index] * 8;
	vec[i] = (double)bits / interval / ttt_yscale;
	if (++index == WG_WIN_SIZE)
	    index = 0;
    }
    return i;
}
    
void wg_init(void)
{
    w_init();

    wg_qinit(&wg_proto_list);
    w_qinit(&wg_proto_list.wg_list);
    wg_proto_list.wg_type = TTTTYPE_PROTO;

    wg_qinit(&wg_host_list);
    w_qinit(&wg_host_list.wg_list);
    wg_host_list.wg_type = TTTTYPE_HOST;
}

void wg_cleanup(void)
{
    struct wg_entry *head;

    head = WG_LIST(TTTTYPE_PROTO);
    while (head->wg_prev != head)
	wg_delete(head->wg_prev);

    head = WG_LIST(TTTTYPE_HOST);
    while (head->wg_prev != head)
	wg_delete(head->wg_prev);

    w_cleanup();
}

int wg_gettime(void)
{
    return wg_cur_time;
}

void wg_bumptime(void)
{
    struct wg_entry *wgp;
    
    wg_cur_time++;

    /* clear ringbuf slot */
    for (wgp = wg_proto_list.wg_next; wgp != &wg_proto_list;
	 wgp = wgp->wg_next)
	wgp->wg_ringbuf[wg_cur_time%WG_WIN_SIZE] = 0;
    for (wgp = wg_host_list.wg_next; wgp != &wg_host_list;
	 wgp = wgp->wg_next)
	wgp->wg_ringbuf[wg_cur_time%WG_WIN_SIZE] = 0;

    /* do garbage collection every 7 minutes */
    if ((wg_cur_time % 420) == 0)
	w_collectgarbage();
}

static struct wg_entry *wg_create(long type, long *id)
{
    struct wg_entry *wgp;

    wgp = malloc(sizeof(struct wg_entry));
    if (wgp == NULL)
	fatal_error("wg_create: no memory!");

    wgp->wg_ringbuf = malloc(WG_WIN_SIZE*sizeof(int));
    if (wgp->wg_ringbuf == NULL)
	fatal_error("wg_create: no memory!");

    memset(wgp->wg_ringbuf, 0, WG_WIN_SIZE*sizeof(int));

    wgp->wg_type = type;
    wgp->wg_id[0] = id[0];
#ifdef IPV6
    wgp->wg_id[1] = id[1];
    wgp->wg_id[2] = id[2];
    wgp->wg_id[3] = id[3];
#endif
    w_qinit(&wgp->wg_list);
    wgp->wg_name = net_getname(type, id);

    /* put this at the tail of the rank list */
    if (type < TTTTYPE_HOST) {
	wg_insq(wg_proto_list.wg_prev, wgp);
	wg_proto_entries++;
    }
    else {
	wg_insq(wg_host_list.wg_prev, wgp);
	wg_host_entries++;
    }

    return wgp;
}

static void wg_delete(struct wg_entry *wgp)
{
    wg_remq(wgp);

    if (wgp->wg_type < TTTTYPE_HOST)
	--wg_proto_entries;
    else
	--wg_host_entries;
	
    /* if the history list is not empty, discard the list. */
    if (wgp->wg_list.w_next != &wgp->wg_list)
	w_removesublist(&wgp->wg_list, wgp->wg_list.w_next);
    free(wgp->wg_name);
    free(wgp->wg_ringbuf);
    free(wgp);
}

struct wg_entry *wg_lookup(long type, long *id)
{
    struct wg_entry *head, *wgp;

    head = WG_LIST(type);
    for (wgp = head->wg_next; wgp != head; wgp = wgp->wg_next)
	if (wgp->wg_type == type && ISSAME_ID(wgp->wg_id, id))
	    return wgp;

    /* if we already have too many entries, delete one. */
    if ((type < TTTTYPE_HOST && wg_proto_entries >= WG_MAX_ENTRIES) ||
	(type >= TTTTYPE_HOST && wg_host_entries >= WG_MAX_ENTRIES))
	wg_delete(head->wg_prev);
    
    wgp = wg_create(type, id);
    return wgp;
}

int wg_getmaxsize(struct wg_entry *wgp)

{
    return w_getmaxsize(&wgp->wg_list);
}


static void wg_qinit(struct wg_entry *wgp)
{
    wgp->wg_next = wgp->wg_prev = wgp;
}

static void wg_insq(struct wg_entry *prev, struct wg_entry *wgp)
{
    wgp->wg_next = prev->wg_next;
    wgp->wg_prev = prev;
    prev->wg_next = wgp;
    wgp->wg_next->wg_prev = wgp;
}

static struct wg_entry *wg_remq(struct wg_entry *wgp)
{
    wgp->wg_prev->wg_next = wgp->wg_next;
    wgp->wg_next->wg_prev = wgp->wg_prev;
    return wgp;
}

struct wg_entry *wg_getbiggest(long type)
{
    struct wg_entry *wgp;
    struct wg_entry *head;

    head = WG_LIST(type);
    /* recalculate all the ranks since the current entries may have
       obsolete entries.
       kludge: call wg_setrank from the bottom of the list to clear
       continuous size 0 entries in one sweep. */
    for (wgp = head->wg_prev; wgp != head; wgp = wgp->wg_prev)
	wg_setrank(wgp);

    return wg_getnext(head);
}

struct wg_entry *wg_getnext(struct wg_entry *wgp)
{
    struct wg_entry *head;
    
    head = WG_LIST(wgp->wg_type);
    if (wgp->wg_next == head)
	return NULL;
    return wgp->wg_next;
}

void wg_record(struct wg_entry *wgp, int size)
{
    struct w_ent *ep;
    
    ep = w_getent();
    ep->w_size = size;
    ep->w_time = wg_cur_time;
    w_insert(&wgp->wg_list, ep);

    wgp->wg_ringbuf[wg_cur_time % WG_WIN_SIZE] = size;

    wg_setrank(wgp);
}

static void wg_setrank(struct wg_entry *wgp) 
{
    struct wg_entry *head;
    int size;
    
    head = WG_LIST(wgp->wg_type);
    /* move the rank if necessary */
    /* note that swapping with a neighbor doesn't set the corrent rank
       but it eventually converges.  it is enough for us, isn't it?  */
    size = w_getmaxsize(&wgp->wg_list);
    while (wgp->wg_prev != head &&
	   size > w_getmaxsize(&wgp->wg_prev->wg_list)) {
	wg_insq(wgp, wg_remq(wgp->wg_prev));
    }
    while (wgp->wg_next != head &&
	   size < w_getmaxsize(&wgp->wg_next->wg_list)) {
	wg_insq(wgp->wg_prev, wg_remq(wgp->wg_next));
    }
}
/*
entry list:

entries are sorted by time and size like this:

	list_head -- 1st -- 2nd -- 3rd -- 4th
	  timestamp    3      8     25     89
	  size      8200   6500   5032    120

     this list has properties:
        (1) the timestamp fields are monotonically growing from the top.
	(2) the size fields are monotonically shrinking from the top.

when adding a new entry, check the entries from the top of the list
and discard
	(1) smaller entries than the new entry.
	(2) entries with time-stamp which became out of the time window.

by doing this, the biggest size is always kept on the top of the list.
*/
static struct w_ent free_list;
static int w_ent_allocated;

static void w_insq(struct w_ent *prev, struct w_ent *ep)
{
    ep->w_next = prev->w_next;
    ep->w_prev = prev;
    prev->w_next = ep;
    ep->w_next->w_prev = ep;
}

static struct w_ent *w_remq(struct w_ent *ep)
{
    ep->w_prev->w_next = ep->w_next;
    ep->w_next->w_prev = ep->w_prev;
    return ep;
}

static void w_insert(struct w_ent *head, struct w_ent *entry)
{
    struct w_ent *ep;

    /* if the list has a sublist whose max size is smaller than entry,
       remove the sublist.  */
#ifdef WG_DEBUG
    int tmp_size;
    tmp_size = 0x0fffffff;	/* big enough */
#endif
    ep = head;
    while (ep->w_next != head) { 
#ifdef WG_DEBUG
	assert(ep->w_next->w_size < tmp_size);
#endif
	if (ep->w_next->w_size <= entry->w_size) {
	    w_removesublist(head, ep->w_next);
	    break;
	}
#ifdef WG_DEBUG
	tmp_size = ep->w_next->w_size;
#endif
	if (ep->w_next->w_time <= entry->w_time - WG_WIN_SIZE) {
	    w_insq(free_list.w_prev, w_remq(ep->w_next));
	    continue;
	}
	ep = ep->w_next;
    }

    /* insert this entry at the tail */
    w_insq(head->w_prev, entry);
}

static void w_alloc_entries(int n)
{
    struct w_ent *ep;
    int i;
    
    for (i=0; i<n; i++) {
	if ((ep = malloc(sizeof(struct w_ent))) == NULL)
	    fatal_error("w_alloc_entries: can't get memory");
	memset(ep, 0, sizeof(struct w_ent));
	w_insq(&free_list, ep);
    }
    w_ent_allocated += n;
}

static void w_init(void)
{
    w_qinit(&free_list);

    w_alloc_entries(100);
}

static void w_qinit(struct w_ent *head)
{
    head->w_next = head->w_prev = head;
}

static void w_removesublist(struct w_ent *head, struct w_ent *list)
{
    struct w_ent *top, *tail;  /* top and tail of the sublist */
    
    top = list;
    tail = head->w_prev;

    /* remove the sublist from the original list */
    head->w_prev = top->w_prev;
    top->w_prev->w_next = head;

    /* add this sublist to the free list */
    top->w_prev = free_list.w_prev;
    top->w_prev->w_next = top;
    free_list.w_prev = tail;
    tail->w_next = &free_list;
}

static int w_getmaxsize(struct w_ent *head)
{
    struct w_ent *ep;

    /* expire old entries */
    ep = head;
    while (ep->w_next != head) { 
	if (ep->w_next->w_time <= wg_cur_time - WG_WIN_SIZE) {
	    w_insq(free_list.w_prev, w_remq(ep->w_next));
	    continue;
	}
	ep = ep->w_next;
    }
    if (head->w_next == head)
	return 0;
    return head->w_next->w_size;
}

static struct w_ent *w_getent(void)
{
    struct w_ent *ep = free_list.w_next;
    
    if (ep == &free_list) {
	/* free list is empty */
	w_alloc_entries(50);
#ifdef WG_DEBUG
	printf("[debug] allocated another 50 entries\n");
	printf("\ttotal entries=%d\n", w_ent_allocated);
#endif
	ep = free_list.w_next;
    }

    return w_remq(ep);
}

static int w_countfree(void)
{
    struct w_ent *ep;
    int n = 0;
    
    for (ep = free_list.w_next; ep != &free_list; ep = ep->w_next)
	n++;
    return n;
}

static void w_collectgarbage(void)
{
    int n;

    /* if there are more than 100 free entries, keep 50 and
       discard the rest. */
    n = w_countfree();
    if (n > 100) {
	n = n - 50;
#ifdef WG_DEBUG
	printf("[debug] too much entries. discard %d out of %d\n",
	       n, w_ent_allocated);
#endif
	while (n-- > 0) {
	    free(w_remq(free_list.w_next));
	    w_ent_allocated--;
	}
#ifdef WG_DEBUG
	printf("\ttotal entries=%d\n", w_ent_allocated);
#endif
    }
}

/* delete all the entries on the free list */
static void w_cleanup(void)
{
#ifdef WG_DEBUG
    printf("w_cleanup:\n");
#endif
    while (free_list.w_next != &free_list) {
	free(w_remq(free_list.w_next));
	w_ent_allocated--;
    }
#ifdef WG_DEBUG
    printf("total entries=%d\n", w_ent_allocated);
#endif
}
