/* $Id: ttt_ipv6.h,v 0.2 2000/12/20 14:29:45 kjc Exp $ */
/* ttt_ipv6.h -- minimum defines and data structures to understand
   ipv6 packets */

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6		0x86dd
#endif

#ifndef IPPROTO_IPV6

#define	IPPROTO_IPV6		41		/* IPv6 encapsulated in IP */
#define	IPPROTO_ICMPV6		58		/* ICMP for IPv6 */

#endif /* !IPPROTO_IPV6 */

#ifndef INET6_ADDRSTRLEN
/*
 * IPv6 address data structures.
 */

struct in6_addr {
	u_char	s6_addr[16];	/* IPv6 address */
};
#endif /* !INET6_ADDRSTRLEN */

#ifndef IPV6_NH_HOP

#define IPV6_NH_HOP		0	/* Hop-by-hop option header */
#define IPV6_NH_RT		43	/* Routing header */
#define IPV6_NH_FRAG		44	/* Fragment header */
#define IPV6_NH_ESP		50	/* Encapsulated Security Payload */
#define IPV6_NH_AUTH		51	/* Authentication header */
#define IPV6_NH_NONH		59	/* No next header */
#define IPV6_NH_DST		60	/* Destination option header */

#endif /* IPV6_NH_HOP */

#if !defined(IPV6VERSION) && (IPVERSION != 6)
/* 
 * IPv6 code by keiiti-s@is.aist-nara.ac.jp
 * 	$Id: ttt_ipv6.h,v 0.2 2000/12/20 14:29:45 kjc Exp $
 */

#define	IPV6VERSION	6

struct ipv6 {
	union {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u_long	i6vpf_v:4,	/* version */
	                i6vpf_pri:4,	/* priority */
			i6vpf_flbl:24;	/* flowlabel */
#endif
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
		u_long	i6vpf_flbl:24,	/* flowlabel */
			i6vpf_v:4,	/* version */
			i6vpf_pri:4;	/* priority */
#endif
		u_long	i6vpf_head;	/* version, priority and flowlabel */
	} ipv6_vpf;
	u_short	ipv6_len;		/* payload length */
	u_char	ipv6_nh;		/* next header */
	u_char	ipv6_hlim;		/* hop limit */
	struct	in6_addr ipv6_src;	/* source address */
	struct	in6_addr ipv6_dst;	/* destination address */
};
#define ipv6_v		ipv6_vpf.i6vpf_v
#define ipv6_pri	ipv6_vpf.i6vpf_pri
#define ipv6_flbl	ipv6_vpf.i6vpf_flbl
#define ipv6_head	ipv6_vpf.i6vpf_head

struct	ipv6_ext {
	u_char	i6ext_nh;
	u_char	i6ext_len;
};

#endif /* !defined(IPV6VERSION) && (IPVERSION != 6) */

