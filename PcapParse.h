/*
	$Id: PcapParse.h,v 1.57 2019/02/20 11:56:25 fujiwara Exp $

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

#define	PcapParse_tld	label[0]

struct DNSdata
{
  int version;
  int af;
  int alen;
  u_char *p_src;
  u_char *p_dst;
  u_short p_sport;
  u_short p_dport;
  u_char *req_src;
  u_char *req_dst;
  u_short req_sport;
  u_short req_dport;
  u_char *_ip;
  u_char *protoheader;
  int protolen;
  u_char *dns;
  u_char *endp;
  int dnslen;
  u_char proto;
  u_char _transport_type; /* T_UDP, T_UDP_FRAG, T_TCP, T_TCP_FRAG */
  int len;
  int iplen;
  int dns_offset;
  int pointer;
  int error;
  u_int32_t tv_sec;
  u_int32_t tv_usec;
  u_char s_src[INET6_ADDRSTRLEN];
  u_char s_dst[INET6_ADDRSTRLEN];
  u_char qname[PcapParse_DNAMELEN];
  u_char qnamebuf[PcapParse_DNAMELEN];
  u_char *label[PcapParse_LABELS];
  int nlabel;
  int qtype;
  int qclass;
  u_int16_t edns0udpsize;
  u_int16_t _fragSize;
  u_char _edns0;
  u_char _ednsver;
  u_short _edns_rdlen;
  u_short _edns_cookie_len;
  u_char _edns_numopts;
  u_char _do;
  u_char _edns_nsid;
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
  u_char _edns_unassigned;
  u_char _edns_future;
  u_char _edns_experimental;
  u_char _ecs_mask;
  u_char _ecs_addr[32];
  int _id;
  u_char _cd;
  u_char _rd;
  u_char _tc;
  int _flag;
  u_char _qr;
  int _opcode;
  int _rcode;
  u_char _udpsumoff;
	/* Valid if debug & FLAG_MODE_PARSE_ANSWER */
  int cname_ttl;
  int answer_ttl;  /* Valid if debug & FLAG_MODE_PARSE_ANSWER
                      -1 ... _rcode == 1 or _rcode == 2 or ancount == 0 or another error */
  u_char ans_v4[16][4];
  int n_ans_v4;
  u_char ans_v6[16][32];
  int n_ans_v6;
  u_char cnamelist[4096];
};

struct PcapStatistics 
{
	u_int32_t first_sec;
	u_int32_t first_usec;
	u_int32_t last_sec;
	u_int32_t last_usec;
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
	int _udp4_frag_first;
	int _udp4_frag_next;
	int _tcp6_frag;
	int _udp6_frag_first;
	int _udp6_frag_next;
	int _tcp_query;
	int _udp_query;
	int _tcpbuff_merged;
	int _tcpbuff_unused;
	int _tcpbuff_zerofin;
	int _ipv6_unknownfragment;
	int _proto_mismatch;
	int _ipv4_headerchecksumerror;
	int _udp_checksumerror;
	int _before_checking_dnsheader;
	int _dns_query;
	int _dns_response;
	int _parsed_dnsquery;
	int _IPlenMissmatch;
	int _unknown_ipaddress;
	int _edns_error;
	int _rd;
	int error[10];
};

struct DNSdataControl {
  int (*callback)(struct DNSdataControl*, int);
  int (*otherdata)(FILE *fp, struct DNSdataControl*);
  char *filename;
  char letter;
  struct PcapStatistics ParsePcapCounter;
  struct DNSdata dns;
  int debug;
  int tz_read_offset;
  int linktype;
  int caplen;
  u_char raw[65536];
  u_char *l2;
};

int parse_pcap(char *file, struct DNSdataControl*);
int _parse_pcap(FILE *fp, struct DNSdataControl* c);
char *parse_pcap_error(int errorcode);
void print_dns_answer(struct DNSdataControl *);

unsigned int get_uint16(struct DNSdata *d);
unsigned long long int get_uint32(struct DNSdata *d);
int get_dname(struct DNSdata *d, u_char *o, int o_len, int mode, int bind9logmode);
void hexdump(char *msg, u_char *data, int len);
void Print_PcapStatistics(struct DNSdataControl *d);

#define GET_DNAME_NO_COMP 1
#define GET_DNAME_NO_SAVE 2

#define FLAG_DUMP 1
#define FLAG_INFO 2
#define FLAG_DEBUG_TCP 4
#define	FLAG_DEBUG_UNKNOWNPROTOCOL	8
#define	FLAG_IGNOREERROR	16
#define	FLAG_BIND9LOG	32
#define FLAG_MODE_PARSE_QUERY	64
#define FLAG_MODE_PARSE_ANSWER	128
#define	FLAG_ANSWER_TTL_CNAME_PARSE	256
#define	FLAG_DO_ADDRESS_CHECK		512
#define	FLAG_DEBUG_1024			1024
#define	FLAG_DEBUG_2048			2048
#define	FLAG_DEBUG_4096			4096
#define	FLAG_DEBUG_8192			8192
#define	FLAG_NO_INETNTOP		16384
#define	FLAG_SCANONLY			32768

#define	CALLBACK_PARSED		1
#define	CALLBACK_ADDRESSCHECK	2

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

#define	TransportTypeStr { "Unknown", "UDP", "UDP_FRAG", "TCP", "TCP_FRAG", "TCP_Partial" }
