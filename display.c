/* $Id: display.c,v 0.4 2000/12/20 14:29:45 kjc Exp kjc $ */
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
/* display.c -- drawing graphs */
#include <stdio.h>
#include <sys/time.h>
#include <assert.h>

#include "ttt.h"
#include "ttt_tk.h"
#include "ttt_node.h"
#include "ttt_account.h"
#include "ttt_window.h"

/* get NUM_RANKS entries at each interval and show NUM_GRAPHS entries */
#define NUM_GRAPHS	6
#define NUM_RANKS	10

/*
 * tcl variables:  we assume the following tcl variables are defined
 *		   in ttt.tcl.
 *
 *	vector X, P0-P5, H0-H5: floating arrays to keep graph values.
 *	.graph, .graph2: graph objects
 *	p0-p5, h0-h5: graph elements for .graph and .graph2
 */

#if (BLT_MAJOR_VERSION == 2) && (BLT_MINOR_VERSION == 1)
static Blt_Vector X, Protos[NUM_GRAPHS], Hosts[NUM_GRAPHS];
#else /* blt2.3 */
static Blt_Vector *X, *Protos[NUM_GRAPHS], *Hosts[NUM_GRAPHS];
static double Xarr[WG_WIN_SIZE];
static double Parr[NUM_GRAPHS][WG_WIN_SIZE], Harr[NUM_GRAPHS][WG_WIN_SIZE];
#endif /* blt2.3 */

static struct wg_entry *proto_ranking[NUM_RANKS], *proto_oldranking[NUM_RANKS];
static struct wg_entry *host_ranking[NUM_RANKS], *host_oldranking[NUM_RANKS];

void display_init(void)
{
    int i;
    char buf[16];
    
#if (BLT_MAJOR_VERSION == 2) && (BLT_MINOR_VERSION == 1)
    /* allocate space for the vectors */
    X.arraySize = WG_WIN_SIZE;
    X.valueArr = (double *)malloc(sizeof(double) * WG_WIN_SIZE);
    for (i=0; i<NUM_GRAPHS; i++) {
	Protos[i].arraySize = WG_WIN_SIZE;
	Protos[i].valueArr = (double *)malloc(sizeof(double) * WG_WIN_SIZE);
    }
    for (i=0; i<NUM_GRAPHS; i++) {
	Hosts[i].arraySize = WG_WIN_SIZE;
	Hosts[i].valueArr = (double *)malloc(sizeof(double) * WG_WIN_SIZE);
    }
#else /* blt2.3 */
    if (Blt_VectorExists(ttt_interp, "X")) {
	if (Blt_GetVector(ttt_interp, "X", &X) != TCL_OK)
	    fatal_error("can't get vector X!");
    }
    else {
	if (Blt_CreateVector(ttt_interp, "X", WG_WIN_SIZE, &X) != TCL_OK)
	    fatal_error("can't create vector X!");
    }

    for (i=0; i<NUM_GRAPHS; i++) {
	sprintf(buf, "H%d", i);
	if (Blt_VectorExists(ttt_interp, buf)) {
	    if (Blt_GetVector(ttt_interp, buf, &Hosts[i]) != TCL_OK)
		fatal_error("can't get vector %s!", buf);
	}
	else {
	    if (Blt_CreateVector(ttt_interp, buf, WG_WIN_SIZE, &Hosts[i]) != TCL_OK)
		fatal_error("can't create vector Hosts!");
	}
    }
    for (i=0; i<NUM_GRAPHS; i++) {
	sprintf(buf, "P%d", i);
	if (Blt_VectorExists(ttt_interp, buf)) {
	    if (Blt_GetVector(ttt_interp, buf, &Protos[i]) != TCL_OK)
		fatal_error("can't get vector %s!", buf);
	}
	else {
	    if (Blt_CreateVector(ttt_interp, buf, WG_WIN_SIZE, &Protos[i]) != TCL_OK)
		fatal_error("can't create vector Protos!");
	}
    }
#endif /* blt2.3 */
}

void ttt_display(int time_tick)
{
    struct wg_entry *wgp;
    int i, n, protos, hosts, update_list[NUM_GRAPHS];
    char buf[128];
    double cur_time, interval;
    u_long recvpkts, droppkts, lostpkts;
    static double last_time;
    
    /* for start up.  until the sampling reaches the window size. */
    if (time_tick >= WG_WIN_SIZE) {
        for (i=0; i < WG_WIN_SIZE-1; i++)
#if (BLT_MAJOR_VERSION == 2) && (BLT_MINOR_VERSION == 1)
	    X.valueArr[i] = X.valueArr[i+1];
#else
	    Xarr[i] = Xarr[i+1];
#endif
	n = WG_WIN_SIZE - 1;
    }
    else
	n = time_tick;

    /* get the top 10 traffic of this interval.  */
    stat_record(TTTTYPE_PROTO, NUM_RANKS);
    stat_record(TTTTYPE_HOST, NUM_RANKS);

    /* next, get the top 10 traffic of the time window.  */
    protos = stat_ranking(TTTTYPE_IP, proto_ranking, NUM_GRAPHS);
    hosts = stat_ranking(TTTTYPE_HOST, host_ranking, NUM_GRAPHS);

    cur_time = get_timeindouble();

#if (BLT_MAJOR_VERSION == 2) && (BLT_MINOR_VERSION == 1)
    X.numValues = n;
    X.valueArr[n] = cur_time;
    if (Blt_ResetVector(ttt_interp, "X", &X, TCL_DYNAMIC) != TCL_OK) {
	printf("ResetVector: error\n");
    }
#else /* blt2.3 */
    Xarr[n] = cur_time;
    if (Blt_ResetVector(X, Xarr, n, WG_WIN_SIZE, TCL_STATIC) != TCL_OK) {
	printf("ResetVector: error\n");
    }
#endif /* blt2.3 */

    /* draw each graph.  data values are stored in the ring buffer of
       wg_entries. */
    interval = cur_time - last_time;
    for (i=0; i<protos; i++) {
	if ((wgp = proto_ranking[i]) == NULL)
	    break;
#if (BLT_MAJOR_VERSION == 2) && (BLT_MINOR_VERSION == 1)
	wg_copybuf(wgp, Protos[i].valueArr, interval, n);

	Protos[i].numValues = n;
	sprintf(buf, "P%d", i);
	if (Blt_ResetVector(ttt_interp, buf, &Protos[i], TCL_DYNAMIC)
	    != TCL_OK) {
	    printf("ResetVector: error\n");
	}
#else
	wg_copybuf(wgp, Parr[i], interval, n);

	if (Blt_ResetVector(Protos[i], Parr[i], n, WG_WIN_SIZE, TCL_STATIC)
	    != TCL_OK) {
	    printf("ResetVector: error\n");
	}
#endif
    }

    for (i=0; i<hosts; i++) {
	if ((wgp = host_ranking[i]) == NULL)
	    break;
#if (BLT_MAJOR_VERSION == 2) && (BLT_MINOR_VERSION == 1)
	wg_copybuf(wgp, Hosts[i].valueArr, interval, n);

	Hosts[i].numValues = n;
	sprintf(buf, "H%d", i);
	if (Blt_ResetVector(ttt_interp, buf, &Hosts[i], TCL_DYNAMIC)
	    != TCL_OK) {
	    printf("ResetVector: error\n");
	}
#else
	wg_copybuf(wgp, Harr[i], interval, n);

	if (Blt_ResetVector(Hosts[i], Harr[i], n, WG_WIN_SIZE, TCL_STATIC)
	    != TCL_OK) {
	    printf("ResetVector: error\n");
	}
#endif
    }

    /* check if we have to update the labels */
    stat_update(proto_ranking, proto_oldranking, update_list, protos);
    for (i=0; i<protos; i++)
	if (update_list[i]) {
	    if ((wgp = proto_ranking[i]) == NULL)
		break;
	    sprintf(buf, ".graph element configure p%d -label %s -color %s",
		    i, wgp->wg_name, wgp->wg_color);
	    if (Tcl_GlobalEval(ttt_interp, buf) != TCL_OK)
		printf("display: %s\n", ttt_interp->result);
	}

    stat_update(host_ranking, host_oldranking, update_list, hosts);
    for (i=0; i<hosts; i++)
	if (update_list[i]) {
	    if ((wgp = host_ranking[i]) == NULL)
		break;
	    sprintf(buf, ".graph2 element configure h%d -label %s -color %s",
		    i, wgp->wg_name, wgp->wg_color);
	    if (Tcl_GlobalEval(ttt_interp, buf) != TCL_OK)
		printf("display: %s\n", ttt_interp->result);
	}
    

    /* get pcap stats */
    if (get_pcapstat(&recvpkts, &droppkts, &lostpkts) == 0)
	ttt_showstat(recvpkts, droppkts, lostpkts);

    for (i=0; i<NUM_RANKS; i++) {
	proto_oldranking[i] = proto_ranking[i];
	host_oldranking[i] = host_ranking[i];
    }

    node_bumptime();
    wg_bumptime();
    last_time = cur_time;	/* save time to measure the interval */
}

