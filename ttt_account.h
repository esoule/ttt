/* $Id: ttt_account.h,v 0.1 1996/06/30 12:52:32 kjc Exp $ */
#ifndef _TTT_ACCOUNT_H_
#define _TTT_ACCOUNT_H_

void netacc_init(void);
void netacc_cleanup(void);

int eth_addsize(int etype, int pkt_len);
int ip_addsize(int proto, int pkt_len);
int udp_addsize(int port, int pkt_len);
int tcp_addsize(int port, int pkt_len);
int host_addsize(u_long addr, int pkt_len);
#ifdef IPV6
int ipv6_addsize(int proto, int pkt_len);
int udpv6_addsize(int port, int pkt_len);
int tcpv6_addsize(int port, int pkt_len);
int hostv6_addsize(u_long *addr, int pkt_len);
#endif

#endif /* _TTT_ACCOUNT_H_ */
