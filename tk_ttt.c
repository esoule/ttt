/* $Id: tk_ttt.c,v 0.6 1998/09/22 06:22:28 kjc Exp kjc $ */
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
/* tk_ttt.c -- tcl/tk related module. this module is shared by ttt and
   tttview but TTT_VIEW flag is set for tttview.*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
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

#include "ttt.h"
#include "ttt_tk.h"

Tcl_Interp *ttt_interp;		/* Interpreter for application. */
static int sockfd;
#ifndef TTT_VIEW    
static Tk_TimerToken timer_token;
static Tk_TimerProc call_display;
static Tk_TimerProc call_dumpread;
#endif

void TttCleanup(void);
static int TttCmd(ClientData clientData, Tcl_Interp *interp,
		  int argc, char *argv[]);
static int Ttt_Init(Tcl_Interp *interp);

static int Ttt_Init(Tcl_Interp *interp)
{
    char *ttt_dir, *colors;
#ifdef TTT_VIEW
    char *port_no;
#else    
    char *interval;
#endif
    char buf[128];

    ttt_interp = interp;

    Tcl_CreateCommand(interp, "ttt", TttCmd,
		      (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

    /* read ttt.tcl file: first try the current dir, then, install dir. */
    ttt_dir = getenv("TTT_LIBRARY");
    if (ttt_dir == NULL) {
	ttt_dir = TTT_LIBRARY;
    }
    if (Tcl_EvalFile(interp, "./ttt.tcl") != TCL_OK) {
	if (errno == ENOENT) {
	    sprintf(buf, "%s/ttt.tcl", ttt_dir);
	    if (Tcl_EvalFile(interp, buf) != TCL_OK) {
		printf("error in %s/ttt.tcl: %s\n",
		       ttt_dir, ttt_interp->result);
		printf("perhaps you need to install TTT\nor set your TTT_LIBRARY environment variable.\n");
		exit(1);
	    }
	}
	else {
	    printf("error in ./ttt.tcl: %s\n",ttt_interp->result);
	    exit(1);
	}
    }

    /* get ttt variables */
    if (colors = Tcl_GetVar(interp, "ttt_colors", TCL_LEAVE_ERR_MSG))
	stat_set_colors(colors);

    if (Tcl_GetVar(interp, "ttt_nohostname", TCL_LEAVE_ERR_MSG) != NULL)
	ttt_nohostname = 1;

#ifdef TTT_VIEW
    if (port_no = Tcl_GetVar(interp, "ttt_portno", TCL_LEAVE_ERR_MSG))
	ttt_portno = atoi(port_no);
    if (ttt_viewname == NULL)
	ttt_viewname = Tcl_GetVar(interp, "ttt_viewname", TCL_LEAVE_ERR_MSG);

    display_init();
    wg_init();
    sockfd = view_opensock();

    Tk_CreateFileHandler(sockfd, TK_READABLE, view_sockread, (ClientData)sockfd);

#else /* TTT */
    if (ttt_interface == NULL)
	ttt_interface = Tcl_GetVar(interp, "ttt_interface", TCL_LEAVE_ERR_MSG);
    if (interval = Tcl_GetVar(interp, "ttt_interval", TCL_LEAVE_ERR_MSG))
	ttt_interval = atoi(interval);

    display_init();
    netacc_init();
    wg_init();

    if (ttt_dumpfile == NULL) {
	sockfd = open_pf(ttt_interface);

	Tk_CreateFileHandler(sockfd, TK_READABLE, net_read,
			     (ClientData)sockfd);

	timer_token = Tk_CreateTimerHandler(2000, call_display, 0);
    }
    else {
	/* replay tcpdump file */
	sockfd = open_dump(ttt_dumpfile, ttt_interface);

	timer_token = Tk_CreateTimerHandler(2000, call_dumpread, 0);
    }
#endif /* !TTT_VIEW */
    /*
     * Specify a user-specific startup file to invoke if the application
     * is run interactively.  Typically the startup file is "~/.apprc"
     * where "app" is the name of the application.  If this line is deleted
     * then no user-specific startup file will be run under any conditions.
     */

#if (TCL_MAJOR_VERSION >= 8) || ((TCL_MAJOR_VERSION == 7) && (TCL_MINOR_VERSION >= 5))
    Tcl_SetVar(interp, "tcl_rcFileName", "~/.wishrc", TCL_GLOBAL_ONLY);
#else
    tcl_RcFileName = "~/.wishrc";
#endif
    return TCL_OK;
}

void TttCleanup(void)
{
#ifdef TTT_VIEW
    Tk_DeleteFileHandler(sockfd);
    view_closesock(sockfd);
    wg_cleanup();
#else /* !TTT_VIEW */
    Tk_DeleteTimerHandler(timer_token);
    Tk_DeleteFileHandler(sockfd);
    close_pf();
    wg_cleanup();
    netacc_cleanup();
#endif /* !TTT_VIEW */    
}

#ifndef TTT_VIEW    
/* wrapper to call display routine */    
void call_display(ClientData client_data)
{
    int time_tick = (int)client_data;
    
    ttt_display(time_tick);
    timer_token = Tk_CreateTimerHandler(ttt_interval, call_display,
				       (ClientData)(time_tick+1));
}

void call_dumpread(ClientData client_data)
{
    int time_tick = (int)client_data;
    int interval, rval;

    rval = dumpfile_read();
    ttt_display(time_tick);
    if (rval > 0) {
	if (ttt_speed == 0)
	    interval = 0;
	else
	    interval = ttt_interval / ttt_speed;
	timer_token = Tk_CreateTimerHandler(interval, call_dumpread,
					    (ClientData)(time_tick+1));
    }
}
#endif /* !TTT_VIEW */

static int TttCmd(ClientData clientData, Tcl_Interp *interp,
	   int argc, char *argv[])
{
    if (argc == 1)
	return TCL_OK;

    if (strcmp(argv[1], "cleanup") == 0) {
	    TttCleanup();
	    interp->result = "ttt cleanup";
	    return TCL_OK;
    }
    else if (strcmp(argv[1], "set") == 0) {
	if (strcmp(argv[2], "interval") == 0) {
	    ttt_interval = atoi(argv[3]);
	    interp->result = argv[3];
	    return TCL_OK;
	}
	else if (strcmp(argv[2], "nohostname") == 0) {
	    ttt_nohostname = atoi(argv[3]);
	    interp->result = argv[3];
	    return TCL_OK;
	}
    }
    else if (strcmp(argv[1], "get") == 0) {
	char buf[128];
    
	if (strcmp(argv[2], "interval") == 0) {
	    sprintf(buf, "%d", ttt_interval);
	    interp->result = buf;
	    return TCL_OK;
	}
	else if (strcmp(argv[2], "nohostname") == 0) {
	    sprintf(buf, "%d", ttt_nohostname);
	    interp->result = buf;
	    return TCL_OK;
	}
    }
    else if (strcmp(argv[1], "filter") == 0) {
	if (strcmp(argv[2], "src") == 0) {
	    ttt_filter |= TTTFILTER_SRCHOST;
	    interp->result = "src hosts filtered out";
	    return TCL_OK;
	}
	else if (strcmp(argv[2], "dst") == 0) {
	    ttt_filter |= TTTFILTER_DSTHOST;
	    interp->result = "dst hosts filtered out";
	    return TCL_OK;
	}
    }
    else if (strcmp(argv[1], "unfilter") == 0) {
	if (strcmp(argv[2], "src") == 0) {
	    ttt_filter &= ~TTTFILTER_SRCHOST;
	    interp->result = "unfilter src hosts";
	    return TCL_OK;
	}
	else if (strcmp(argv[2], "dst") == 0) {
	    ttt_filter &= ~TTTFILTER_DSTHOST;
	    interp->result = "unfilter dst hosts";
	    return TCL_OK;
	}
    }

    interp->result = "ttt # bad args";
    return TCL_ERROR;
}

/* show string at the bottom of the graph widget */
int ttt_showmessage(char *string)
{
    char buf[128];
    
    sprintf(buf, "set ttt_message {%s}", string);
    if (Tcl_GlobalEval(ttt_interp, buf) != TCL_OK) {
	printf("showmessage: %s\n", ttt_interp->result);
	return (-1);
    }
    return 0;
}

/* show stat info */
int ttt_showstat(u_long recvpkts, u_long droppkts, u_long report_drop)
{
    char buf[128];
    static recved, dropped, report_dropped;

    if (recvpkts != recved) {
	sprintf(buf, "set ttt_packets %d", recvpkts);
	if (Tcl_GlobalEval(ttt_interp, buf) != TCL_OK) {
	    printf("showstat: %s\n", ttt_interp->result);
	    return (-1);
	}
	recved = recvpkts;
    }
    if (droppkts != dropped) {
	sprintf(buf, "set ttt_drops %d", droppkts);
	if (Tcl_GlobalEval(ttt_interp, buf) != TCL_OK) {
	    printf("showstat: %s\n", ttt_interp->result);
	    return (-1);
	}
	dropped = droppkts;
    }
    if (report_drop != report_dropped) {
	sprintf(buf, "set ttt_reportdrops %d", report_drop);
	if (Tcl_GlobalEval(ttt_interp, buf) != TCL_OK) {
	    printf("showstat: %s\n", ttt_interp->result);
	    return (-1);
	}
	report_dropped = report_drop;
    }
    return 0;
}


#include "tk.h"
#include "blt.h"
#if !defined(TTT_VERSION)	/* not required for ttt */
#include "src/bltConfig.h"
#endif
#if (TK_MAJOR_VERSION > 3) 
#if HAVE_ITCL_H
#include "itcl.h"
#endif
#if HAVE_ITK_H
#include "itk.h"
#endif
#endif

#if (TK_MAJOR_VERSION > 3)
/*
 * The following variable is a special hack that is needed in order for
 * Sun shared libraries to be used for Tcl.
 */

#ifdef NEED_MATHERR
extern int matherr();
int *tclDummyMathPtr = (int *) matherr;
#endif


/*
 *----------------------------------------------------------------------
 *
 * main --
 *
 *	This is the main program for the application.
 *
 * Results:
 *	None: Tk_Main never returns here, so this procedure never
 *	returns either.
 *
 * Side effects:
 *	Whatever the application does.
 *
 *----------------------------------------------------------------------
 */
extern int Blt_Init _ANSI_ARGS_((Tcl_Interp *interp));
extern int Blt_SafeInit _ANSI_ARGS_((Tcl_Interp *interp));
extern int Tcl_AppInit _ANSI_ARGS_((Tcl_Interp *interp));

int
main(argc, argv)
    int argc;			/* Number of command-line arguments. */
    char **argv;		/* Vector of command-line arguments. */
{
#if defined(TTT_VERSION)  /* process ttt options */
#ifndef TTT_VIEW
    ttt_parseargs(argc, argv);
#else /* !TTT_VIEW */
    view_parseargs(argc, argv);
#endif /* !TTT_VIEW */
#endif

    Tk_Main(argc, argv, Tcl_AppInit);
    return 0;			/* Needed only to prevent compiler warning. */
}

#else

/*
 * The following variable is a special hack that allows applications
 * to be linked using the procedure "main" from the Tk library.  The
 * variable generates a reference to "main", which causes main to
 * be brought in from the library (and all of Tk and Tcl with it).
 */

extern int main();
int *tclDummyMainPtr = (int *) main;

#endif /* TK_MAJOR_VERSION >= 4 */

/*
 *----------------------------------------------------------------------
 *
 * Tcl_AppInit --
 *
 *	This procedure performs application-specific initialization.
 *	Most applications, especially those that incorporate additional
 *	packages, will have their own version of this procedure.
 *
 * Results:
 *	Returns a standard Tcl completion code, and leaves an error
 *	message in interp->result if an error occurs.
 *
 * Side effects:
 *	Depends on the startup script.
 *
 *----------------------------------------------------------------------
 */

int
Tcl_AppInit(interp)
    Tcl_Interp *interp;		/* Interpreter for application. */
{
    if (Tcl_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    if (Tk_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    /*
     * Call the init procedures for included packages.  Each call should
     * look like this:
     *
     * if (Mod_Init(interp) == TCL_ERROR) {
     *     return TCL_ERROR;
     * }
     *
     * where "Mod" is the name of the module.
     */

#if defined(ITCL_MAJOR_VERSION) && (ITCL_MAJOR_VERSION == 2)
    if (Itcl_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    if (Itk_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
#endif
    if (Blt_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
#if (BLT_MAJOR_VERSION == 2) && (BLT_MINOR_VERSION == 1)
    /* no Blt_SafeInit */
#else
    Tcl_StaticPackage(interp, "BLT", Blt_Init, Blt_SafeInit);
#endif

    if (Ttt_Init(interp) == TCL_ERROR) {
	return TCL_ERROR;
    }
    /*
     * Call Tcl_CreateCommand for application-specific commands, if
     * they weren't already created by the init procedures called above.
     */

    /*
     * Specify a user-specific startup file to invoke if the application
     * is run interactively.  Typically the startup file is "~/.apprc"
     * where "app" is the name of the application.  If this line is deleted
     * then no user-specific startup file will be run under any conditions.
     */

#if (TCL_MAJOR_VERSION >= 8) || ((TCL_MAJOR_VERSION == 7) && (TCL_MINOR_VERSION >= 5))
    Tcl_SetVar(interp, "tcl_rcFileName", "~/.wishrc", TCL_GLOBAL_ONLY);
#else
    tcl_RcFileName = "~/.wishrc";
#endif
    return TCL_OK;
}
