/*
	$Id: pcapgetquery.c,v 1.37 2012/06/12 06:58:46 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#include "PcapParse.h"

#define MODE_CSV	0
#define	MODE_BIND9LOG	1
#define MODE_COUNTONLY 2

int mode = MODE_BIND9LOG;

struct counter {
	int32_t prev;
	int32_t interval;
	u_long counter;
};

u_int32_t server_ipv4 = 0;
u_char server_ipv6[16] = { 255 };

struct filter_addr_mask4 {
	u_int32_t addr;
	u_int32_t mask;
};

int check_v4 = 0;
int check_v6 = 0;

int nv4mask = 0;
struct filter_addr_mask4 v4mask[10];

int nexclude4 = 0;
u_int32_t exclude4[10];

int repeat_threshold = -1;
int repeated_detection_by_ttl = 0;
int report_repeated_queries = 0;
int print_queries_bind9 = 0;
int print_queries_csv = 0;
int print_query_counter = 0;
int show_repeated_queries = 0;
int report_repeated_statistics = 0;
int print_repeated_list = 0;
int entries = 0;
int parsed_queries = 0;

u_int32_t t_start = 0;
u_int32_t t_end = 0;
#define TZ_UNSPEC	-9999999
int tz_offset = TZ_UNSPEC;

struct counter counter;

u_char *typestr[] = {
/*	0*/	NULL, "A", "NS", "MD", "MF", "CNAME", "SOA", "MB",
/*	8*/	"MG", "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX",
/* 16*/	"TXT", "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP-PTR",
/* 24*/	"SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID",
/* 32*/	"NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME",
/* 40*/	"SINK", "OPT", "APL", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC",
/* 48*/	"DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM", NULL, NULL, NULL, "HIP",
/* 56*/	"NINFO", "RKEY", "TALINK", "CDS", NULL, NULL, NULL, NULL,
/* 64*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 72*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 80*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 88*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 96*/	NULL, NULL, NULL, "SPF", "UINFO", "UID", "GID", "UNSPEC", 
/*104*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*112*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*120*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*128*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*136*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*144*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*152*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*160*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*168*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*176*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*184*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*192*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*200*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*208*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*216*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*224*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*232*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*240*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*248*/	NULL, "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY", 
/*256*/	"URI", "CAA", NULL, NULL, NULL, NULL, NULL, NULL, 
};
u_char *type2str(u_short _type)
{
	static u_char buff[30];

	if (_type == 32768) { return "TA"; }
	if (_type == 32769) { return "DLV"; }
	if (_type < 258 && typestr[_type] != NULL) {
		return typestr[_type];
	}
	sprintf(buff, "TYPE%d", _type);
	return buff;
}

u_char *class2str(u_short _class)
{
	static u_char buff[30];

	if (_class == 1) { return "IN"; };
	if (_class == 3) { return "CH"; };
	if (_class == 4) { return "HS"; };
	if (_class == 254) { return "NONE"; };
	if (_class == 255) { return "ANY"; };
	sprintf(buff, "CLASS%d", _class);
	return buff;
}

static u_char *monthlabel[] = {
	"Jun", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
	"Oct", "Nov", "Dec",
};


void print_counter()
{
	if (counter.counter != 0) {
		printf("%d,%d,%ld,%f\n", counter.prev, counter.interval, counter.counter, (double)counter.counter / (double)counter.interval);
		counter.counter = 0;
	}
}

int callback(struct DNSdata *d, int mode)
{
	int found, i, c;
	struct tm *t;
	time_t ttt;

	if (mode == CALLBACK_ADDRESSCHECK) {
		/* Dest addr != server_ipc4 */
		if (d->version == 4) {
			if (check_v4 == 0) return 1;
			if (server_ipv4 != 0 && server_ipv4 != *(u_int32_t *)(d->req_dst)) return 0;
			if (d->req_dport != 53) return 0;
			if (nv4mask != 0) {
				for (found = 0, c = 0; c < nv4mask; c++) {
					if (((*(u_int32_t *)d->req_src) & v4mask[c].mask) == v4mask[c].addr) {
						found = 1;
						break;
					}
				}
				if (found == 0)
					return 0;
			}
			for (i = 0; i < nexclude4; i++) {
				if (exclude4[i] == (*(u_int32_t *)d->req_src))
					return 0;
			}
		} else if (d->version == 6) {
			if (check_v6 == 0) return 1;
			if (server_ipv6[0] != 255 && memcmp(server_ipv6, d->req_dst, 16) != 0)
				return 0;
			if (d->req_dport != 53) return 0;
		}
		return 1;
	}
	if (t_start == 0 || t_start > d->tv_sec) { t_start = d->tv_sec; }
	if (t_end == 0 || t_end < d->tv_sec) { t_end = d->tv_sec; }
	parsed_queries++;

	if (print_query_counter) {
		int32_t now = d->tv_sec - (d->tv_sec % counter.interval);
		if (now != counter.prev) {
			print_counter();
			counter.prev = now;
		} else {
			counter.counter += 1;
		}
	}
	if (print_queries_csv) {
		printf("%d.%06d,%s,%d,%s,%d,%d,%d,%d,%d,%s\n", d->tv_sec, d->tv_usec, d->s_src, d->req_sport, d->qname, d->qclass, d->qtype, d->_edns0,d->error, d->answer_ttl, d->cname_target);
	}
	if (print_queries_bind9) {
		if (tz_offset == TZ_UNSPEC) {
			ttt = d->tv_sec;
			t = localtime(&ttt);
		} else {
			ttt = d->tv_sec + tz_offset;
			t = gmtime(&ttt);
		}
		printf("%02d-%s-%04d %02d:%02d:%02d.%03d queries: info: client %s#%d: query: %s %s %s %s%s%s%s%s (%s)\n",
	 	t->tm_mday, monthlabel[t->tm_mon], t->tm_year+1900,
	 	t->tm_hour, t->tm_min, t->tm_sec,
	 	d->tv_usec/1000,
	 	d->s_src, d->req_sport,
	 	d->qname, class2str(d->qclass), type2str(d->qtype),
	 	d->_rd ? "+" : "-", d->_edns0?"E":"",
 	 	d->proto==6?"T":"",
	 	d->_do?"D":"", d->_cd ? "C":"",
	 	d->s_dst);
/*
		if (d->error) {
			printf("%s%s%s%ss\n",
				(d->error & ParsePcap_IPv4ChecksumError)?"4":"",
				(d->error & ParsePcap_UDPchecksumError)?"u":"",
				(d->error & ParsePcap_IPv6LengthError)?"6":"",
				(d->error & ParsePcap_EDNS0Error)?"E":"",
				(d->error & ParsePcap_DNSError)?"D":"");
		}
*/
	}
}

usage(int c)
{
	if (c == -1) {
		printf("pcapgetquery version %s, compiled at %s %s\n"
		,VERSION, __DATE__, __TIME__);
		exit(0);
	}
	fprintf(stderr,
"pcapgetquery version %s, compiled at %s %s\n"
"\n"
"Usage: pcapgetquery [options] pcap files...\n"
"\n"
"	-A	Parse response packets\n"
"\n"
"	-L	Print queries in BIND 9 querylog format\n"
"	-C	Print queries in CSV format\n"
"	-c NN	Print query counter in each NN second\n"
"\n"
"	-D num	Debug flag\n"
"	-t num  Specify timezone offset (in second)\n"
"	-4 v4	Specify DNS server's IPv4 address\n"
"	-e v4	Specify IPv4 address of excluded client\n"
"	-m v4	Specify netmask for -a option\n"
"	-a v4	Specify allowed client address prefix\n"
"\n"
"	-s	Print statistics\n"
,VERSION, __DATE__, __TIME__);
	exit(1);
}

void err_exit(int err, char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	printf("\n");
	va_end(ap);
	exit(err);
}

void Print_PcapStatistics()
{
	printf("#PcapStatistics._pcap,%d\n", ParsePcapCounter._pcap);
	printf("#PcapStatistics._ipv4,%d\n", ParsePcapCounter._ipv4);
	printf("#PcapStatistics._ipv6,%d\n", ParsePcapCounter._ipv6);
	printf("#PcapStatistics._version_unknown,%d\n", ParsePcapCounter._version_unknown);
	printf("#PcapStatistics._portmismatch,%d\n", ParsePcapCounter._portmismatch);
	printf("#PcapStatistics._udp,%d\n", ParsePcapCounter._udp);
	printf("#PcapStatistics._tcp,%d\n", ParsePcapCounter._tcp);
	printf("#PcapStatistics._proto_mismatch,%d\n", ParsePcapCounter._proto_mismatch);
	printf("#PcapStatistics._ipv4_headerchecksumerror,%d\n", ParsePcapCounter._ipv4_headerchecksumerror);
	printf("#PcapStatistics._udp_checksumerror,%d\n", ParsePcapCounter._udp_checksumerror);
	printf("#PcapStatistics._dns,%d\n", ParsePcapCounter._dns);
	printf("#PcapStatistics._parsed_dnsquery,%d\n", ParsePcapCounter._parsed_dnsquery);
	printf("#PcapStatistics._IPlenMissmatch,%d\n", ParsePcapCounter._IPlenMissmatch);
};

main(int argc, char *argv[])
{
	int bflag, ch;
	char *p;
	int len;
	int ret;
	char buff[256];
	u_int32_t mask4, addr4;
	int debug = 0;
	int print_statistics = 0;
	int addresscheck = 0;

	bflag = 0;
	while ((ch = getopt(argc, argv, "t:4:6:e:m:a:c:CD:ALsr:SRTv")) != -1) {
	switch (ch) {
	case '4':
		if (inet_aton(optarg, (struct in_addr *)&server_ipv4) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		check_v4 = 1;
		break;
#if defined(AF_INET6) && defined(HAVE_INET_PTON)
	case '6':
		if (inet_pton(AF_INET6, optarg, server_ipv6) != 1)
			err_exit(1, "bad IPv6 address: %s", optarg);
		check_v6 = 1;
		addresscheck = 1;
		break;
#endif
	case 'e':
		if (inet_aton(optarg, (struct in_addr *)&exclude4[nexclude4]) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		nexclude4++;
		check_v4 = 1;
		break;
	case 'm':
		if (inet_aton(optarg, (struct in_addr *)&mask4) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		break;
	case 'a':
		if (inet_aton(optarg, (struct in_addr *)&addr4) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		v4mask[nv4mask].mask = mask4;
		v4mask[nv4mask].addr = addr4;
		nv4mask++;
		check_v4 = 1;
		break;
	case 'C':
		print_queries_csv = 1;
		break;
	case 'L':
		print_queries_bind9 = 1;
		debug |= FLAG_BIND9LOG;
		break;
	case 'c':
		counter.interval = atoi(optarg);
		counter.counter = 0;
		counter.prev = 0;
		print_query_counter = 1;
		break;
	case 'D':
		debug = atoi(optarg);
		break;
	case 't':
		tz_offset = atoi(optarg);
		break;
	case 'A':
		debug |= FLAG_MODE_PARSE_ANSWER;
		break;
	case 's':
		print_statistics = 1;
		break;
	case 'v':
		usage(-1);
	case '?':
	default:
		usage(ch);
	}}
	argc -= optind;
	argv += optind;
	if (check_v4 != 0 || check_v6 != 0) {
		debug |= FLAG_DO_ADDRESS_CHECK;
	}
	if (print_query_counter == 0 && print_queries_csv == 0 && print_queries_bind9 == 0) {
		print_queries_bind9 = 1;
		debug |= FLAG_BIND9LOG;
	}
	if (argc > 0) {
		while (*argv != NULL) {
			p = *argv++;
			if (strcmp(p, "-") == 0) p = NULL;
			ret = parse_pcap(p, callback, debug);
			if (ret != ParsePcap_NoError) {
				printf("#Error:%s:%s:errno=%d\n", parse_pcap_error(ret), *argv, errno);
				exit(1);
			}
		}
	} else {
		usage(0);
	}
}
