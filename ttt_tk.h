/* $Id: ttt_tk.h,v 0.1 1996/06/30 12:52:32 kjc Exp $ */
/* ttt_tk.h -- tk-related header */
#ifndef _TTT_TK_H_
#define _TTT_TK_H_

#include "tk.h"
#include "blt.h"

extern Tcl_Interp *ttt_interp;		/* Interpreter for application. */
extern Tk_FileProc net_read;		/* read proc for pcap */

extern Tk_FileProc view_sockread;	/* read proc for ttt packet */

extern int ttt_showmessage(char *string);
extern int ttt_showstat(u_long recvpkts, u_long droppkts, u_long report_drop);


#endif /* _TTT_TK_H_ */
