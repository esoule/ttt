/* $Id: relay.c,v 0.4 2000/12/20 14:29:45 kjc Exp kjc $ */
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

/* a standalone tool to relay ttt packets */

#include <stdio.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/* for address family independent socket address structure */
union sockunion {
	struct sockinet {
		u_char si_len;
		u_char si_family;
		u_short si_port;
	} su_si;
	struct sockaddr_in  su_sin;
#ifdef INET6
	struct sockaddr_in6 su_sin6;
#endif
};
#define su_len		su_si.si_len
#define su_family	su_si.si_family
#define su_port		su_si.si_port

#define TTT_PORT		7288		/* receiver port */
#define BUFFER_SIZE	4096	/* big enough */
static char buffer[BUFFER_SIZE];

int name2sockaddr(char *name, int port, union sockunion *addrp, int family)
{
    unsigned long inaddr;
    struct hostent *hep;

    bzero(addrp, sizeof(union sockunion));
#ifdef INET6
    {
	struct addrinfo hints, *res;
	char portstr[64];
	int error;

	sprintf(portstr, "%d", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	if (name == NULL)
	    hints.ai_flags = AI_PASSIVE;

	if ((error = getaddrinfo(name, portstr, &hints, &res)) != 0) {
	    fprintf(stderr, "can't get addrinfo for %s: %s\n",
		    name, gai_strerror(error));
	    return (-1);
	}

	*addrp = *(union sockunion *)res->ai_addr;

	freeaddrinfo(res);
    }
#else /* INET6 */    
    addrp->su_sin.sin_family = AF_INET;
    addrp->su_sin.sin_len = sizeof(struct sockaddr_in);
    if (name != NULL) {
	if ((inaddr = inet_addr(name)) != -1)
	    bcopy(&inaddr, &addrp->su_sin.sin_addr, sizeof(inaddr));
	else if ((hep = gethostbyname(name)) != NULL)
	    bcopy(hep->h_addr, &addrp->su_sin.sin_addr, hep->h_length);
	else
	    return (-1);
    }
    else
	addrp->su_sin.sin_addr.s_addr = htonl(INADDR_ANY);
    addrp->su_sin.sin_port = htons(port);
#endif /* INET6 */    
    return 0;
}

int usage()
{
    printf("usage: tttrelay [options] dest\n");
    printf(" options:\n");
    printf("    [-addr addr]\n");
    printf("    [-mcastifaddr addr]\n");
    printf("    [-out addr]\n");
    printf("    [-port recv_port]\n");
    printf("    [-dport dest_port]\n");
    printf("    [-probe addr]\n");
    printf("    [-mloop {0|1}]\n");
    exit(1);
}

int main(argc, argv)
    int argc;
    char **argv;
{
    union sockunion my_addr, probe_addr, view_addr;
    int in_fd, out_fd;
    int in_port = TTT_PORT;		/* my port number */
    int dest_port = TTT_PORT;		/* receiver's port number */
    char *my_name = NULL;
    char *out_name = NULL;
    char *mcastif_name = NULL;
    char *view_name = NULL;
    char *probe_name = NULL;
    int shared_port = 1;
    u_char ttl = 1;
    u_char mloop = 0;
    int in_family = AF_UNSPEC;
    int out_family = AF_UNSPEC;
    int packets = 0;
    const char *ptr;
#ifdef INET6
    char str[INET6_ADDRSTRLEN];
#else
    char str[16];
#endif
    
    while (--argc > 0) {
	if (strncmp(*++argv, "-port", 4) == 0 && --argc > 0)
	    in_port = atoi(*++argv);
	else if (strncmp(*argv, "-addr", 4) == 0 && --argc > 0)
	    my_name = *++argv;
	else if (strncmp(*argv, "-out", 4) == 0 && --argc > 0)
	    out_name = *++argv;
	else if (strncmp(*argv, "-mcastifaddr", 4) == 0 && --argc > 0)
	    mcastif_name = *++argv;
	else if (strncmp(*argv, "-probe", 4) == 0 && --argc > 0)
	    probe_name = *++argv;
	else if (strncmp(*argv, "-ttl", 4) == 0 && --argc > 0)
	    ttl = atoi(*++argv);
	else if (strncmp(*argv, "-dport", 4) == 0 && --argc > 0)
	    dest_port = atoi(*++argv);
	else if (strncmp(*argv, "-mloop", 4) == 0 && --argc > 0)
	    mloop = atoi(*++argv);
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
    if (name2sockaddr(my_name, in_port, &my_addr, in_family) < 0)
	fatal_error("can't get my address!");
    if ((in_fd = socket(my_addr.su_family, SOCK_DGRAM, 0)) < 0)
	fatal_error("can't open socket");
#ifdef IP_ADD_MEMBERSHIP
    if (my_addr.su_family == AF_INET &&
	IN_MULTICAST(ntohl(my_addr.su_sin.sin_addr.s_addr))) {
	struct ip_mreq mreq;
	union sockunion ifaddr;

	mreq.imr_multiaddr.s_addr = my_addr.su_sin.sin_addr.s_addr;
	if (mcastif_name == NULL) {
	    mreq.imr_interface.s_addr = htonl(INADDR_ANY); /* use default if */
	}
	else {
	    if (name2sockaddr(mcastif_name, in_port, &ifaddr, AF_INET) < 0)
		fatal_error("can't get local address!");
	    mreq.imr_interface.s_addr = ifaddr.su_sin.sin_addr.s_addr;
	}
	
	if (setsockopt(in_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		       (char *)&mreq, sizeof(mreq)) < 0)
	    fatal_error("can't join group");
	
	printf("joined multicast group: %s\n", my_name);
    }
#endif /* IP_ADD_MEMBERSHIP */
#ifdef INET6
    else if (my_addr.su_family == AF_INET6 &&
	     IN6_IS_ADDR_MULTICAST(&my_addr.su_sin6.sin6_addr)) {
	struct ipv6_mreq mreq6;
	union sockunion ifaddr;

	mreq6.ipv6mr_multiaddr = my_addr.su_sin6.sin6_addr;
	if (mcastif_name == NULL) {
	    mreq6.ipv6mr_interface = 0; /* use default if */
	}
	else {
	    if (name2sockaddr(mcastif_name, in_port, &ifaddr, AF_INET6) < 0)
		fatal_error("can't get local address!");
	    mreq6.ipv6mr_interface = ifaddr.su_sin6.sin6_ifindex;
	}

	if (setsockopt(in_fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
		       (char *)&mreq6, sizeof(mreq6)) < 0)
	    fatal_error("can't join group");
	
	printf("joined multicast group: %s\n", view_name);
    }
#endif /* INET6 */
    if (shared_port) {
	int one = 1;
	if (setsockopt(in_fd, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&one, sizeof(one)) < 0)
	    fatal_error("can't share the port");
	printf("port %d is shared.\n", in_port);
    }
    if (bind(in_fd, (struct sockaddr *)&my_addr, my_addr.su_len) < 0)
	fatal_error("can't bind");
    
    /* set up output socket */
    if (name2sockaddr(view_name, dest_port, &view_addr, out_family) < 0)
	fatal_error("can't get viewer's address!");

    if (name2sockaddr(out_name, 0, &my_addr, view_addr.su_family) < 0)
	fatal_error("can't get my address!");
    if ((out_fd = socket(my_addr.su_family, SOCK_DGRAM, 0)) < 0)
	fatal_error("can't open socket");

#ifdef IP_MULTICAST_TTL
    if (view_addr.su_family == AF_INET &&
	IN_MULTICAST(ntohl(view_addr.su_sin.sin_addr.s_addr))) {
	if (ttl != 1) {
	    if (setsockopt(out_fd, IPPROTO_IP, IP_MULTICAST_TTL,
			   &ttl, sizeof(ttl)) < 0)
		fatal_error("can't set ttl");
	}
#ifdef IP_MULTICAST_LOOP
	if (setsockopt(out_fd, IPPROTO_IP, IP_MULTICAST_LOOP,
		       &mloop, sizeof(mloop)) < 0)
	    fatal_error("can't disable mcast loop");
#endif
    }
#endif
#ifdef INET6
    else if (view_addr.su_family == AF_INET6 &&
	IN6_IS_ADDR_MULTICAST(&view_addr.su_sin6.sin6_addr)) {
	int hops = ttl;
	u_int loop = mloop;
	
	if (hops != 1) {
	    if (setsockopt(out_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			   &hops, sizeof(hops)) < 0)
		fatal_error("can't set ttl");
	}
	if (setsockopt(out_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		       &loop, sizeof(loop)) < 0)
	    fatal_error("can't disable mcast loop");
    }
#endif /* INET6 */

    if (bind(out_fd, (struct sockaddr *)&my_addr, my_addr.su_len) < 0)
	fatal_error("can't bind");
    
    switch (view_addr.su_family) {
    case AF_INET:
	ptr = inet_ntop(AF_INET, &view_addr.su_sin.sin_addr,
			str, sizeof(str));
	break;
#ifdef INET6
    case AF_INET6:
	ptr = inet_ntop(AF_INET6, &view_addr.su_sin6.sin6_addr,
			str, sizeof(str));
	break;
#endif
    }
    printf("relay started. sending to %s:%d ....\n", ptr, dest_port);

    if (probe_name != NULL) {
	if (name2sockaddr(probe_name, 0, &probe_addr, my_addr.su_family) < 0)
	    fatal_error("can't get probe address!");
	printf("reading from [%s] ....\n", probe_name);
    }
    else
	bzero(&probe_addr, sizeof(probe_addr));
	
    while (1) {
	int nbytes, fromlen;
	union sockunion from_addr;

	fromlen = sizeof(from_addr);
	if ((nbytes = recvfrom(in_fd, buffer, BUFFER_SIZE, 0,
		      (struct sockaddr *)&from_addr, &fromlen)) == -1) {
	    perror("recvfrom");
	    continue;
	}

	if (probe_addr.su_family == 0) {
	    probe_addr = from_addr;
	    switch (from_addr.su_family) {
	    case AF_INET:
		ptr = inet_ntop(AF_INET, &from_addr.su_sin.sin_addr,
				str, sizeof(str));
		break;
#ifdef INET6
	    case AF_INET6:
		ptr = inet_ntop(AF_INET6, &from_addr.su_sin6.sin6_addr,
				str, sizeof(str));
		break;
#endif
	    }
	    printf("reading from probe [%s] ....\n", ptr);
	}

	/* is this the probe we are reading from? */
	if (from_addr.su_family != probe_addr.su_family ||
	    (from_addr.su_family == AF_INET &&
	     from_addr.su_sin.sin_addr.s_addr !=
	     probe_addr.su_sin.sin_addr.s_addr)
#ifdef INET6
	    ||
	    (from_addr.su_family == AF_INET6 &&
	     (from_addr.su_sin6.sin6_addr.s6_addr32[0] !=
	      probe_addr.su_sin6.sin6_addr.s6_addr32[0] ||
	      from_addr.su_sin6.sin6_addr.s6_addr32[1] !=
	      probe_addr.su_sin6.sin6_addr.s6_addr32[1] || 
	      from_addr.su_sin6.sin6_addr.s6_addr32[2] !=
	      probe_addr.su_sin6.sin6_addr.s6_addr32[2] || 
	      from_addr.su_sin6.sin6_addr.s6_addr32[3] !=
	      probe_addr.su_sin6.sin6_addr.s6_addr32[3]))
#endif
	    ) {
	    static int warned = 0;
	    if (!warned) {
		printf("[warning] there are multiple probes.\n");
		switch (from_addr.su_family) {
		case AF_INET:
		    ptr = inet_ntop(AF_INET, &from_addr.su_sin.sin_addr,
				    str, sizeof(str));
		    break;
#ifdef INET6
		case AF_INET6:
		    ptr = inet_ntop(AF_INET6, &from_addr.su_sin6.sin6_addr,
				    str, sizeof(str));
		    break;
#endif
		}
		printf("\tignoring probe: %s\n", ptr);
		warned = 1;
	    }
	    continue;
	}
	
	if ((nbytes = sendto(out_fd, buffer, nbytes, 0,
		      (struct sockaddr *)&view_addr, view_addr.su_len)) < 0)
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

