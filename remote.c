/* $Id: remote.c,v 0.4 2003/10/16 10:38:32 kjc Exp $ */
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
/* remote.c -- a module common for remote-monitoring */
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ttt.h"
#include "ttt_remote.h"

/* convert a string name to struct sockaddr_in */
int name2sockaddrin(char *name, int port, struct sockaddr_in *addrp)
{
    unsigned long inaddr;
    struct hostent *hep;

    memset(addrp, 0, sizeof(struct sockaddr_in));
    addrp->sin_family = PF_INET;
    if (name != NULL) {
	if ((inaddr = inet_addr(name)) != -1)
	    memcpy(&addrp->sin_addr, &inaddr, sizeof(inaddr));
	else if ((hep = gethostbyname(name)) != NULL)
	    memcpy(&addrp->sin_addr, hep->h_addr, hep->h_length);
	else
	    return (-1);
    }
    else
	addrp->sin_addr.s_addr = htonl(INADDR_ANY);
    addrp->sin_port = htons(port);
    return 0;
}
