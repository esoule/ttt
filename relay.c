/* $Id: relay.c,v 0.2 1998/04/03 09:18:59 kjc Exp $ */
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

/* a standalone tool to relay ttt packets */

#include <stdio.h>
#include <signal.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#define TTT_PORT		7288		/* receiver port */
#define BUFFER_SIZE	4096	/* big enough */
static char buffer[BUFFER_SIZE];

int name2sockaddrin(name, port, addrp)
    char *name;
    int port;
    struct sockaddr_in *addrp;
{
    unsigned long inaddr;
    struct hostent *hep;

    bzero(addrp, sizeof(struct sockaddr_in));
    addrp->sin_family = PF_INET;
    if (name != NULL) {
	if ((inaddr = inet_addr(name)) != -1)
	    bcopy(&inaddr, &addrp->sin_addr, sizeof(inaddr));
	else if ((hep = gethostbyname(name)) != NULL)
	    bcopy(hep->h_addr, &addrp->sin_addr, hep->h_length);
	else
	    return (-1);
    }
    else
	addrp->sin_addr.s_addr = htonl(INADDR_ANY);
    addrp->sin_port = htons(port);
    return 0;
}

int usage()
{
    printf("usage: tttrelay [options] dest\n");
    printf(" options:\n");
    printf("    [-addr addr]\n");
    printf("    [-mcastifaddr addr]\n");
    printf("    [-port recv_port]\n");
    printf("    [-dport dest_port]\n");
    printf("    [-probe addr]\n");
    exit(1);
}

int main(argc, argv)
    int argc;
    char **argv;
{
    struct sockaddr_in my_addr, probe_addr, view_addr;
    int in_fd, out_fd;
    int in_port = TTT_PORT;		/* my port number */
    int dest_port = TTT_PORT;		/* receiver's port number */
    char *my_name = NULL;
    char *mcastif_name = NULL;
    char *view_name = NULL;
    char *probe_name = NULL;
    int shared_port = 1;
    u_char ttl = 1;
    u_char mloop = 0;
    int packets = 0;
    
    while (--argc > 0) {
	if (strncmp(*++argv, "-port", 4) == 0 && --argc > 0)
	    in_port = atoi(*++argv);
	else if (strncmp(*argv, "-addr", 4) == 0 && --argc > 0)
	    my_name = *++argv;
	else if (strncmp(*argv, "-mcastifaddr", 4) == 0 && --argc > 0)
	    mcastif_name = *++argv;
	else if (strncmp(*argv, "-probe", 4) == 0 && --argc > 0)
	    probe_name = *++argv;
	else if (strncmp(*argv, "-ttl", 4) == 0 && --argc > 0)
	    ttl = atoi(*++argv);
	else if (strncmp(*argv, "-dport", 4) == 0 && --argc > 0)
	    dest_port = atoi(*++argv);
	else if (view_name == NULL)
	    view_name = *argv;
	else
	    usage();
    }

    if (view_name == NULL) {
	printf("no destination specified!\n");
	usage();
    }

    /* set up input socket */
    if (name2sockaddrin(my_name, in_port, &my_addr) < 0)
	fatal_error("can't get my address!");
    if ((in_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	fatal_error("can't open socket");
#ifdef IP_ADD_MEMBERSHIP
    if (IN_MULTICAST(ntohl(my_addr.sin_addr.s_addr))) {
	struct ip_mreq mreq;
	struct sockaddr_in ifaddr;

	mreq.imr_multiaddr.s_addr = my_addr.sin_addr.s_addr;
	if (mcastif_name == NULL) {
	    mreq.imr_interface.s_addr = htonl(INADDR_ANY); /* use default if */
	}
	else {
	    if (name2sockaddrin(mcastif_name, in_port, &ifaddr) < 0)
		fatal_error("can't get mcast if address!");
	    mreq.imr_interface.s_addr = ifaddr.sin_addr.s_addr;
	}
	
	if (setsockopt(in_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		       (char *)&mreq, sizeof(mreq)) < 0)
	    fatal_error("can't join group");
	
	printf("joined multicast group: %s\n", my_name);
    }
#endif /* IP_ADD_MEMBERSHIP */
    if (shared_port) {
	int one = 1;
	if (setsockopt(in_fd, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&one, sizeof(one)) < 0)
	    fatal_error("can't share the port");
	printf("port %d is shared.\n", in_port);
    }
    if (bind(in_fd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0)
	fatal_error("can't bind");
    
    /* set up output socket */
    if (name2sockaddrin(view_name, dest_port, &view_addr) < 0)
	fatal_error("can't get viewer's address!");

    if (name2sockaddrin(NULL, 0, &my_addr) < 0)
	fatal_error("can't get my address!");
    if ((out_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	fatal_error("can't open socket");
#ifdef IP_MULTICAST_TTL
    if (IN_MULTICAST(ntohl(view_addr.sin_addr.s_addr)) && ttl != 1)
	if (setsockopt(out_fd, IPPROTO_IP, IP_MULTICAST_TTL,
		       &ttl, sizeof(ttl)) < 0)
	    fatal_error("can't set ttl");
#endif
#ifdef IP_MULTICAST_LOOP
    if (setsockopt(out_fd, IPPROTO_IP, IP_MULTICAST_LOOP,
		   &mloop, sizeof(mloop)) < 0)
	fatal_error("can't disable mcast loop");
#endif
    if (bind(out_fd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0)
	fatal_error("can't bind");
    
    printf("relay started. sending to %s:%d ....\n",
	   inet_ntoa(view_addr.sin_addr), dest_port);

    if (probe_name != NULL) {
	if (name2sockaddrin(probe_name, 0, &probe_addr) < 0)
	    fatal_error("can't get probe address!");
	printf("reading from [%s] ....\n", probe_name);
    }
    else
	bzero(&probe_addr, sizeof(probe_addr));
	
    while (1) {
	int nbytes, fromlen;
	struct sockaddr_in from_addr;

	fromlen = sizeof(from_addr);
	if ((nbytes = recvfrom(in_fd, buffer, BUFFER_SIZE, 0,
		      (struct sockaddr *)&from_addr, &fromlen)) == -1) {
	    perror("recvfrom");
	    continue;
	}

	if (probe_addr.sin_addr.s_addr == 0) {
	    probe_addr = from_addr;
	    printf("reading from [%s] ....\n", inet_ntoa(from_addr.sin_addr));
	}

	/* is this the probe we are reading from? */
	if (from_addr.sin_addr.s_addr != probe_addr.sin_addr.s_addr) {
	    static int warned = 0;
	    if (!warned) {
		printf("[warning] there are multiple inputs.\n");
		printf("\tignoring %s\n", inet_ntoa(from_addr.sin_addr));
		warned = 1;
	    }
	    continue;
	}
	
	if ((nbytes = sendto(out_fd, buffer, nbytes, 0,
		      (struct sockaddr *)&view_addr, sizeof(view_addr))) < 0)
	    perror("sendto");
	packets++;
#if 1
	printf("*"); fflush(stdout);
	if ((packets % 60) == 0)
	    printf("\n");
#endif
    }
}

#include <errno.h>
#include <varargs.h>

fatal_error(va_alist)
    va_dcl
{
    va_list ap;
    char *fmt;

    if (errno != 0)
	perror("fatal_error");
    else
	fprintf(stderr, "fatal_error: ");
    va_start(ap);
    fmt = va_arg(ap, char *);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

