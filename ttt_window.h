/* $Id: ttt_window.h,v 0.1 1996/06/30 12:52:32 kjc Exp $ */
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
/* ttt_window.h -- a module header to keep ranking by peak size within
   a time-window. */
#ifndef _TTT_WINDOW_H_
#define _TTT_WINDOW_H_

#define WG_WIN_SIZE	60

/* structure to keep track of the peak traffic in a time window */
struct w_ent {
    struct w_ent *w_next, *w_prev;
    int w_time;		/* time stamp */
    int w_size;		/* size in bytes */
};

/* structure to hold ranking info in a time window */
struct wg_entry {
    struct wg_entry *wg_next, *wg_prev;
    long wg_type;
#ifdef IPV6
    long wg_id[4];
#else
    long wg_id[1];
#endif
    struct w_ent wg_list;
    char *wg_name;		/* name string (e.g. host name) */
    char *wg_color;		/* color name */
    int wg_colorindex;		/* color index used for color allocation */
    int *wg_ringbuf;		/* ring data buffer to keep traffic size
				   in the time-window. */
};

void stat_record(long type, int n);
int stat_ranking(long type, struct wg_entry **rank_list, int n);
int stat_update(struct wg_entry **ranking, struct wg_entry **old_ranking,
		int *update_list, int n);
int stat_set_colors(char *string);

void wg_init(void);
void wg_cleanup(void);
struct wg_entry *wg_lookup(long type, long *id);
struct wg_entry *wg_getbiggest(long type);
struct wg_entry *wg_getnext(struct wg_entry *wgp);
void wg_record(struct wg_entry *wgp, int size);
int wg_getmaxsize(struct wg_entry *wgp);
int wg_gettime(void);
void wg_bumptime(void);
int wg_copybuf(struct wg_entry *wgp, double *vec, double interval, int n);

#endif /* _TTT_WINDOW_H_ */
