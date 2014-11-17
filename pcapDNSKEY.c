/*
	$Id: pcapDNSKEY.c,v 1.26 2012/06/08 09:51:07 fujiwara Exp $

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

#include <apr_hash.h>
#include "PcapParse.h"

int debug = 0;

struct eachcounter
{
	int jp_key;
	int jp_ds;
	int jp_total;
	int arpa_key;
	int arpa_ds;
	int arpa_total;	
	int bind;
	int server;
	int unknown;
};

u_int32_t t_start = 0;
u_int32_t t_end = 0;
unsigned long long num_jp_key = 0;
unsigned long long num_jp_ds = 0;
unsigned long long num_jp_total = 0;
unsigned long long num_arpa_key = 0;
unsigned long long num_arpa_ds = 0;
unsigned long long num_arpa_total = 0;
unsigned long long num_bind = 0;
unsigned long long num_server = 0;
unsigned long long num_unknown = 0;
unsigned long long num_total = 0;

apr_status_t status = APR_SUCCESS;
apr_pool_t *pool = NULL;
apr_hash_t *hash = NULL;

int check_v4 = 0;
int check_v6 = 0;
u_int32_t server_ipv4 = 0;
u_char server_ipv6[16] = { 255 };

int callback(struct DNSdata *d, int mode)
{
	int category = -1;
	int len = strlen(d->qname);
	struct eachcounter *e;
	int index;

	if (mode == CALLBACK_ADDRESSCHECK) {
		/* Dest addr != server_ipc4 */
		if (d->version == 4) {
			if (check_v4 == 0) return 1;
			if (server_ipv4 != 0 && server_ipv4 != *(u_int32_t *)(d->req_dst)) return 0;
			if (d->req_dport != 53) return 0;
		} else if (d->version == 6) {
			if (check_v6 == 0) return 1;
			if (server_ipv6[0] != 255 && memcmp(server_ipv6, d->req_dst, 16) != 0)
				return 0;
			if (d->req_dport != 53) return 0;
		}
		return 1;
	}
	if (d->_rd) {
		ParsePcapCounter._rd++;
		if ((d->debug & FLAG_DEBUG_2048) == 0) {
			return 0;
		}
	}
	if (t_start == 0 || t_start > d->tv_sec) { t_start = d->tv_sec; }
	if (t_end == 0 || t_end < d->tv_sec) { t_end = d->tv_sec; }

	if (d->debug & FLAG_DEBUG_1024) {
		printf("source=%s name=%s type=%d\n", d->s_src, d->qname, d->qtype);
	}
	e = (struct eachcounter *)apr_hash_get(hash, d->s_src, APR_HASH_KEY_STRING);
	if (e == NULL) {
		e = malloc(sizeof(struct eachcounter));
		memset(e, 0, sizeof(struct eachcounter));
		apr_hash_set(hash, strdup(d->s_src), APR_HASH_KEY_STRING, e);
	}
	num_total++;
	if (!strcasecmp(d->qname, "jp")) {
		e->jp_total++;
		num_jp_total++;
		if (d->qtype == 48 && d->_do && d->_cd) {
			e->jp_key++;
			num_jp_key++;
		}
	} else if (len > 3 && !strcasecmp(d->qname + len - 3, ".jp")) {
		e->jp_total++;
		num_jp_total++;
		if (d->qtype == 43 && d->_do && d->_cd) {
			e->jp_ds++;
			num_jp_ds++;
		}
	} else if (len > 13 && !strcasecmp(d->qname + len - 13, ".in-addr.arpa")) {
		e->arpa_total++;
		num_arpa_total++;
		if (d->qtype == 48) {
			e->arpa_key++;
			num_arpa_key++;
		} else
		if (d->qtype == 43) {
			e->arpa_ds++;
			num_arpa_ds++;
		}
	} else if (len > 5 && !strcasecmp(d->qname + len - 5, ".bind")) {
		e->bind++;
		num_bind++;
	} else if (len > 7 && !strcasecmp(d->qname + len - 7, ".server")) {
		e->server++;
		num_server++;
	} else {
		e->unknown++;
		num_unknown++;
#if 0
		printf("Unknown: %s %s %d %d\n", d->s_src, d->qname, d->qtype, d->qclass);
#endif
	}
	return 0;
}

void print_hash()
{
	apr_hash_index_t *hash_index = NULL;
	struct eachcounter *e;
	void *key = NULL;
	int *klen = NULL;
	void *val = NULL;
	char *s;
	int i_jp_total = 0, i_jp_ds = 0, i_jp_key = 0;
	int i_arpa_total = 0, i_arpa_ds = 0, i_arpa_key = 0;
	int i_unknown = 0, i_bind = 0, i_server = 0;

	printf("#start,end=%d,%d\n", t_start, t_end);
	printf("#number_of_ip_addresses=%d\n", apr_hash_count(hash));

	hash_index = apr_hash_first(pool, hash);
	while (hash_index) {
		apr_hash_this(hash_index, &key, &klen, &val);
		e = val;
		s = key;
		if (e->jp_total != 0) { i_jp_total++; };
		if (e->jp_ds != 0) { i_jp_ds++; };
		if (e->jp_key != 0) { i_jp_key++; };
		if (e->arpa_total != 0) { i_arpa_total++; };
		if (e->arpa_ds != 0) { i_arpa_ds++; };
		if (e->arpa_key != 0) { i_arpa_key++; };
		if (e->unknown != 0) { i_unknown++; };
		if (e->server != 0) { i_server++; };
		if (e->bind != 0) { i_bind++; };
		printf("%s,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", s, e->jp_total, e->jp_key, e->jp_ds, e->arpa_total, e->arpa_key, e->arpa_ds, e->bind, e->server, e->unknown);
		hash_index = apr_hash_next(hash_index);
	}

	printf("#jp_total,%d,%llu\n",i_jp_total, num_jp_total);
	printf("#jp_ds,%d,%llu\n",i_jp_ds, num_jp_ds);
	printf("#jp_dnskey,%d,%llu\n",i_jp_key, num_jp_key);
	printf("#arpa_total,%d,%llu\n",i_arpa_total, num_arpa_total);
	printf("#arpa_ds,%d,%llu\n",i_arpa_ds, num_arpa_ds);
	printf("#arpa_dnskey,%d,%llu\n",i_arpa_key, num_arpa_key);
	printf("#bind,%d,%llu\n",i_bind, num_bind);
	printf("#server,%d,%llu\n",i_server, num_server);
	printf("#unknown,%d,%llu\n",i_unknown, num_unknown);
	printf("#total,%d,%llu\n", apr_hash_count(hash), num_total);
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
	printf("#PcapStatistics._rd,%d\n", ParsePcapCounter._rd);
}

void usage(u_char c)
{
	if (c == -1) {
		printf("pcapDNSKEY version %s, compiled at %s %s\n"
		,VERSION, __DATE__, __TIME__);
		exit(0);
	}
	fprintf(stderr, 
"pcapDNSKEY version %s, compiled at %s %s\n"
"\n"
"Usage: pcapgetquery [options] pcap files...\n"
"\n"
"	-4 v4	Specify DNS server's IPv4 address\n"
"	-6 v6	Specify DNS server's IPv6 address\n"
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

main(int argc, char *argv[])
{
	FILE *fp;
	char *p;
	int len;
	char buff[256];
	int ret;
	int ch;

	while ((ch = getopt(argc, argv, "4:6:D:v")) != -1) {
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
		break;
#endif
	case 'v':
		usage(-1);
		break;
	case 'D':
		debug = atoi(optarg);
		break;
	case '?':
	default:
		usage(ch);
	}}
	argc -= optind;
	argv += optind;
	if (check_v4 != 0 || check_v6 != 0) {
		debug |= FLAG_DO_ADDRESS_CHECK; }
	apr_initialize();
	status = apr_pool_create(&pool, NULL);
	if (status != APR_SUCCESS) {
		printf("#Error:could not create apr_pool");
		exit(0);
	}
	hash = apr_hash_make(pool);

	if (argc > 0) {
		while (*argv != NULL) {
			ret = parse_pcap(*argv, callback, debug);
			if (ret != ParsePcap_NoError) {
				printf("#Error:%s:%s\n", parse_pcap_error(ret), *argv);
			}
			argv++;
		}
	} else {
		ret = parse_pcap(NULL, callback, debug);
		if (ret != ParsePcap_NoError) {
			printf("#Error:%s:stdin\n", parse_pcap_error(ret));
		}
	}
	print_hash();
	apr_terminate();
	exit(0);
}
