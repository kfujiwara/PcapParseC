/*
	$Id: pcapparse.h,v 1.123 2025/05/30 08:19:43 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

/*
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
*/

#ifdef __sun
#define	u_int32_t	uint32_t
#define	u_int16_t	uint16_t
#endif

#define	PcapParse_DNAMELEN	1280
#define	PcapParse_LABELS		32
#define	PcapParse_nSubstring		5
#define	PcapParse_Naddr		16

#define	PcapParse_tld	label[0]

struct case_stats
{
	int uppercase;
	int lowercase;
	int nocase;
};

struct DNSdata
{
  int version;
  int af;
  int alen;
  u_char *p_src;
  u_char *p_dst;
  u_short p_sport;
  u_short p_dport;
  u_char portaddr[54]; // srcport, srcaddr, dstport, dstaddr, srport, srcaddr // portaddrlen*3
  u_char portaddrlen;  // 2+alen
  u_char *_ip;
  u_char *protoheader;
  int protolen;
  int datatype;
  u_char *dns;
  u_char *endp;
  int dnslen;
  u_char partial;
  u_char proto;
  u_char _transport_type; /* T_UDP, T_UDP_FRAG, T_TCP, T_TCP_FRAG */
  u_char tcp_fastopen; // FastOpen
  unsigned int checksum0;
  int64_t tcp_delay; // Round Trip Time from TCP  ... data - SYN (must > 0)
  int64_t tcp_syn_ack_delay; // ACK - SYN (must >= 0)
  int tcp_mss;         // MSS valuedata
  int tcp_dnscount;    // Number of queries in one TCP
  int len;
  int iplen;
  int ip_df;
  int dns_offset;
  int pointer;
  int error;
  u_int32_t tv_sec;
  u_int32_t tv_usec;
  int64_t ts;
  char qname[PcapParse_DNAMELEN];
  int qnamelen;
  struct case_stats case_stats;
  char qnamebuf[PcapParse_DNAMELEN];
  char *label[PcapParse_LABELS];
  u_char labellen[PcapParse_LABELS];
  char *substring[PcapParse_nSubstring];
  int substringlen[PcapParse_nSubstring];
  int nlabel;
  int nsubstring;
  int qtype;
  int qclass;
  u_int16_t edns0udpsize;
  u_int16_t _fragSize;
  u_short _edns0;
  u_short _ednsver;
  u_short _edns_rdlen;
  u_short _edns_cookie_len;
  u_short _edns_numopts;
  u_short _do;
  u_short _edns_nsid;
  u_char _edns_nsid_buff[257];
  u_short _edns_nsid_bufflen;
  u_char _edns_reserved;
  u_char _edns_llq;
  u_char _edns_ul;
  u_char _edns_dau;
  u_char _edns_dhu;
  u_char _edns_n3u;
  u_char _edns_ecs; // 1 ... v4, 2...v6
  u_char _edns_expire;
  u_char _edns_cookie;
  u_char _edns_cookiesit;
  u_char _edns_keepalive;
  u_char _edns_padding;
  u_char _edns_chain;
  u_char _edns_keytag;
  u_char _edns_keytag_4a5c;
  u_char _edns_keytag_4f66;
  u_char _edns_keytag_9728;
  u_char _edns_keytag_other;
  u_char _edns_unassigned;
  u_char _edns_future;
  u_char _edns_experimental;
  u_char _ecs_mask;
  u_char _ecs_addr[32];
  int _id;
  u_char _aa;
  u_char _cd;
  u_char _ad;
  u_char _rd;
  u_char _ra;
  u_char _tc;
  u_char _flag1;
  u_char _flag2;
  u_char _qr;
  u_char IPaddrUpdated;
  int _qdcount;
  int _ancount;
  int _nscount;
  int _arcount;
  int _opcode;
  int _rcode;
  char *str_rcode;
  int additional_dnssec_rr;
  int _auth_ns;
  int _auth_soa;
  int _auth_ds;
  int _auth_rrsig;
  int _auth_other;
  int _glue_a;
  int _glue_aaaa;
  int _answertype;
  u_char _udpsumoff;
	/* Valid if debug & FLAG_MODE_PARSE_ANSWER */
  int soa_ttl;
  u_char soa_dom[PcapParse_DNAMELEN];
  int cname_ttl;
  int answer_ttl;  /* Valid if debug & FLAG_MODE_PARSE_ANSWER
      -1 ... _rcode == 1 or _rcode == 2 or ancount == 0 or another error */
  u_char ans_v4[PcapParse_Naddr][4];
  int n_ans_v4;
  u_char ans_v6[PcapParse_Naddr][16];
  int n_ans_v6;
  u_char cnamelist[4096];
};

#define _ANSWER_REF 1			/* AUTH REF */
#define _ANSWER_NXDOMAIN 2		/* AUTH NXD */
#define _ANSWER_ANSWER 3		/* AUTH ANS */
#define _ANSWER_RECURSION 0
#define _ANSWER_UNKNOWN -1

struct PcapStatistics 
{
	int64_t first_ts;
	int64_t last_ts;
	int _pcap;
	int _ipv4;
	int _ipv6;
	int _version_unknown;
	int _portmismatch;
	int _udp4;
	int _tcp4;
	int _udp6;
	int _tcp6;
	int _tcp4_frag;
	int _tcp4_frag_next;
	int _udp4_frag_first;
	int _udp4_frag_next;
	int _tcp6_frag;
	int _udp6_frag_first;
	int _udp6_frag_next;
	int _tcp_query;
	int _udp_query;
	int _tcpbuff_syn;
	int _tcpbuff_fin;
	int _tcpbuff_merged;
	int _tcpbuff_unused;
	int _tcpbuff_zerofin;
	int _ipv6_unknownfragment;
	int _proto_mismatch;
	int _ipv4_headerchecksumerror;
	int _ipv4_protochecksumerror;
	int _ipv6_protochecksumerror;
	int _udp_checksumerror;
	int _before_checking_dnsheader;
	int _dns_query;
	int _dns_response;
	int _parsed_dnsquery;
	int _IPlenMissmatch;
	int _unknown_ipaddress;
	int _edns_error;
	int _rd;
	int _numfiles;
	int error[10];
};

struct node_hash {
	char *node;
	int index;
	UT_hash_handle hh;
};

struct DNSdataControl {
  int (*callback)(struct DNSdataControl*, int);
  int (*otherdata)(FILE *fp, struct DNSdataControl*d, int pass);
  struct node_hash *node_hash;
  struct node_hash **node_name;
  int num_node_name;
  int max_node_name;
  int input_type;
  char *filename;
  long long open_time;
  size_t file_size;
  char letter;
  char node[9];
  int current_nodeid;
  char *current_nodename;
  struct PcapStatistics ParsePcapCounter;
  struct DNSdata dns;
  int enable_tcp_state;
  int enable_tcpsyn_callback;
  int getdname_options;
  int do_scanonly;
  int mode;
  int debug;
  int tz_read_offset;
  int linktype;
  int caplen;
  int lineno;
  int print_answer_options;
#ifdef IPV6_PREFIX_HASH  
  struct ipv6_prefix_hash *v6hash;
#else
  void *v6hash;  // for dummy
#endif
  u_char *raw;
  int rawlen;
  u_char *l2;
};

int parse_file(char *file, struct DNSdataControl*d, int pass);
int _parse_file(FILE *fp, struct DNSdataControl* d, int pass);
int add_node_name(struct DNSdataControl *d, char *node);
char *get_node_name(struct DNSdataControl *d, int nodeid);
char *parse_file_error(int errorcode);
void print_dns_answer(struct DNSdataControl *);
void dump_tcpbuf();
void tcpbuff_statistics();
extern char *PcapParseC_datatype[];

void hexdump(char *msg, u_char *data, int len);
void Print_PcapStatistics(struct DNSdataControl *d);

#define	GET_DNAME_NO_COMP 1
#define GET_DNAME_NO_SAVE 2
#define	GET_DNAME_SEPARATE 4
#define	GET_DNAME_IgnoreErrorChar 0x100
#define GET_DNAME_LOWERCASE 0x200

#define INPUT_TYPE_NONE 0
#define INPUT_TYPE_PCAP 1
#define INPUT_TYPE_QUERYLOG 2
#define INPUT_TYPE_TEST 3
#define INPUT_TYPE_OTHERDATA 4

#define MODE_PARSE_QUERY	1
#define MODE_PARSE_ANSWER	2
#define	MODE_ANSWER_TTL_CNAME_PARSE	4
#define	MODE_IGNOREERROR	8
#define	MODE_IGNORE_CHECKSUM_ERROR	16
#define	MODE_FIX_IPV4ADDR	32

#define FLAG_DUMP 1
#define FLAG_INFO 2
#define FLAG_DEBUG_TCP 4
#define FLAG_DEBUG_UNKNOWNPROTOCOL	8
#define FLAG_DEBUG_JSON			16
#define FLAG_DEBUG_256			0x100
#define FLAG_DEBUG_512			0x200
#define FLAG_SCANONLY			0x400

// Control->print_answer_options
#define _PRINT_EDNSSIZE		0x1
#define _PRINT_FLAG			0x2
#define _PRINT_DNSLEN		0x4
#define _PRINTANS_ALLRR		0x10000
#define _PRINTANS_REFNS		0x20000
#define _PRINTANS_REFDS		0x40000
#define _PRINTANS_REFGLUE		0x80000
#define _PRINTANS_AUTHSOA		0x100000
#define _PRINTANS_ANSWER_PTR	0x200000
#define _PRINTANS_ANSWER_A		0x400000
#define _PRINTANS_ANSWER_AAAA	0x800000
#define _PRINTANS_ANSWER_NS		0x1000000
#define _PRINTANS_ANSWER_DS		0x2000000
#define _PRINTANS_ANSWER_CNAME	0x4000000

#define	CALLBACK_PARSED		1
#define	CALLBACK_TCPSYN		2

enum {
	ParsePcap_NoError = 0,
	ParsePcap_ERROR_Empty = -1,
	ParsePcap_ERROR_BogusSavefile = -2,
	ParsePcap_ERROR_ShortRead = -3,
	ParsePcap_ERROR_FILE_OPEN = -4,
	ParsePcap_ERROR_UnknownLinkType = -5,
	ParsePcap_ERROR_COMMAND = -6,
	ParsePcap_ERROR_OutofPeriod = -7,
	ParsePcap_ERROR_EmptyMerge = -8,
	ParsePcap_ERROR_Memory = -9,
	ParsePcap_EOF = -10,
	ParsePcap_ForceClose = -11,

	ParsePcap_IPv4ChecksumError = 1,
	ParsePcap_UDPchecksumError = 2,
	ParsePcap_TCPError = 4,
	ParsePcap_IPv6LengthError = 8,
	ParsePcap_EDNSError = 16,
	ParsePcap_DNSError = 32,
	ParsePcap_AnswerAnalysisError = 64,
	ParsePcap_CnameError = 128
};

enum {
T_UDP = 1, T_UDP_FRAG = 2, T_TCP = 3, T_TCP_FRAG = 4, T_TCP_PARTIAL = 5,
};

enum { DATATYPE_DNS = 0, DATATYPE_TCPSYN = 1 };

#define	TransportTypeStr { "Unknown", "UDP", "UDP_FRAG", "TCP", "TCP_FRAG", "TCP_Partial" }

#define	TESTDATA_HEAD "#TESTDATA"

extern int tcpbuff_max;
extern char *PcapParseC_datatype[];

void print_rusage(void);

void inc_ipv_proto_counter(struct DNSdataControl *c);
void fixup_portaddr(struct DNSdataControl *c);
void prepare_dns_labels(struct DNSdataControl *c);
void prepare_dns_substring(struct DNSdataControl *c);
