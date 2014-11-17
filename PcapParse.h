/*
	$Id: PcapParse.h,v 1.19 2012/06/12 06:58:46 fujiwara Exp $

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
#endif

#define	DNAMELEN	1025

struct DNSdata
{
  int version;
  int af;
  u_char *p_src;
  u_char *p_dst;
  u_short p_sport;
  u_short p_dport;
  u_char *req_src;
  u_char *req_dst;
  u_short req_sport;
  u_short req_dport;
  u_char *raw;
  u_char *protoheader;
  int protolen;
  u_char *dns;
  u_char *endp;
  int dnslen;
  u_char proto;
  int len;
  int dns_offset;
  int pointer;

  int error;
  u_int32_t tv_sec;
  u_int32_t tv_usec;
  u_char s_src[INET6_ADDRSTRLEN];
  u_char s_dst[INET6_ADDRSTRLEN];
  u_char qname[DNAMELEN];
  int qtype;
  int qclass;
  u_char _edns0;
  u_char _do;
  u_char _cd;
  u_char _rd;
  u_short _flag;
  int _opcode;
  int _rcode;
  int debug;
  u_char cname_target[DNAMELEN]; /* Valid if debug & FLAG_MODE_PARSE_ANSWER */
  int answer_ttl;  /* Valid if debug & FLAG_MODE_PARSE_ANSWER
                      -1 ... _rcode == 1 or _rcode == 2 or ancount == 0 or another error */
};

struct PcapStatistics 
{
	int _pcap;
	int _ipv4;
	int _ipv6;
	int _version_unknown;
	int _portmismatch;
	int _udp;
	int _tcp;
	int _proto_mismatch;
	int _ipv4_headerchecksumerror;
	int _udp_checksumerror;
	int _dns;
	int _parsed_dnsquery;
	int _IPlenMissmatch;
	int _rd;
};

int parse_pcap(char *file, int callback(struct DNSdata*, int), int debug);
char *parse_pcap_error(int errorcode);
void print_dns_answer(struct DNSdata *);
extern struct PcapStatistics ParsePcapCounter;

#define FLAG_DUMP 1
#define FLAG_INFO 2
#define FLAG_DEBUG_TCP 4
#define	FLAG_DEBUG_UNKNOWNPROTOCOL	8
#define	FLAG_IGNOREERROR	16
#define	FLAG_BIND9LOG	32
#define FLAG_MODE_PARSE_ANSWER	64
#define	FLAG_ANSWER_TTL_CNAME_PARSE	128
#define	FLAG_DO_ADDRESS_CHECK		256
#define	FLAG_DEBUG_1024			1024
#define	FLAG_DEBUG_2048			2048
#define	FLAG_DEBUG_4096			4096
#define	FLAG_DEBUG_8192			8192

#define	CALLBACK_PARSED		1
#define	CALLBACK_ADDRESSCHECK	2

enum {
	ParsePcap_NoError = 0,
	ParsePcap_ERROR_Empty = -1,
	ParsePcap_ERROR_BogusSavefile = -2,
	ParsePcap_ERROR_ShortRead = -3,
	ParsePcap_ERROR_FILE_OPEN = -4,

	ParsePcap_IPv4ChecksumError = 1,
	ParsePcap_UDPchecksumError = 2,
	ParsePcap_IPv6LengthError = 4,
	ParsePcap_EDNS0Error = 8,
	ParsePcap_DNSError = 16
};
