/* $Id: ttt_tk.h,v 0.2 2003/10/16 10:38:32 kjc Exp kjc $ */
/* ttt_tk.h -- tk-related header */
#ifndef _TTT_TK_H_
#define _TTT_TK_H_

#include "tk.h"
#include "blt.h"

/* const directive for tcl84 */
#ifndef CONST84
#define CONST84
#endif

extern Tcl_Interp *ttt_interp;		/* Interpreter for application. */
extern Tk_FileProc net_read;		/* read proc for pcap */

extern Tk_FileProc view_sockread;	/* read proc for ttt packet */

extern int ttt_showmessage(char *string);
extern int ttt_showstat(u_long recvpkts, u_long droppkts, u_long report_drop);


#endif /* _TTT_TK_H_ */
