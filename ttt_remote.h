/* $Id: ttt_remote.h,v 0.1 1996/06/30 12:52:32 kjc Exp $ */
/* ttt_remote.h -- ttt report protocol packet format. */
#ifndef _TTT_REMOTE_H_
#define _TTT_REMOTE_H_

#define TTT_MAGIC	0x3845

struct ttt_hdr {
    u_short th_magic;	/* magic number */
    u_short th_version;	/* version no */
    u_long th_network;	/* network address probed */
    u_long th_recvpkts;	/* recieved packets of pcap stats */
    u_long th_droppkts;	/* dropped packets of pcap stats */
    long th_seqno;	/* sequence number */
    long th_nrecords;	/* number of records */
    long th_tvsec;	/* time-stamp (sec) */
    long th_tvusec;	/* time-stamp (usec) */
    /* follows ttt_record array */
};

struct ttt_record {
    long tr_type;
    long tr_size;
    long tr_id[1];
};

/* for ipv6 host type */
struct ttt_record6 {
    long tr_type;
    long tr_size;
    long tr_id[4];
};

extern int name2sockaddrin(char *name, int port, struct sockaddr_in *addrp);
extern void view_parseargs(int argc, char **argv);

#endif /* _TTT_REMOTE_H_ */
