/*
	$Id: pcapV6addr.c,v 1.10 2025/05/30 08:19:43 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2013 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <assert.h>

#include "ext/uthash.h"

#include "config.h"
#include "pcapparse.h"
#include "mytool.h"
#include "load_ipv6list.h"

int debug = 0;
int mode = MODE_PARSE_QUERY;

struct ipv6addr_hash
{
	UT_hash_handle hh;
	uint8_t addr[16];
	int number_of_addrs; // !=0, then addr is /64 prefix
	long count;
	long error;
};

struct server_hash {
	char letter;
	u_char alen;
	u_char addr[16];
	UT_hash_handle hh;
};

static const char ipv6addr_tag[] = "ipv6addr,";
static int ipv6addr_tag_len = sizeof(ipv6addr_tag)-1;

static u_int32_t accept_start = 0;
static u_int32_t accept_length = 3600;
static u_int32_t accept_end = 0;
static u_int32_t t_start = 0;
static u_int32_t t_end = 0;
static u_int32_t data_start = 0;
static u_int32_t data_end = 0;
static struct ipv6addr_hash *ipv6addr_hash = NULL;

static int verbose = 0;
static int flag_answer = 0;
struct server_hash *server_hash = NULL;

int callback(struct DNSdataControl *c, int mode)
{
	int j;
	char *u;
	struct ipv6addr_hash *e, *e6;
	struct server_hash *server;
	int delay;
	u_char *addr, *serveraddr;
	int portno, serverport;
	int tcp = 0;

	if (c->dns._qr) {
		addr = c->dns.p_dst;
		portno = c->dns.p_dport;
		serveraddr = c->dns.p_src;
		serverport = c->dns.p_sport;
	} else {
		addr = c->dns.p_src;
		portno = c->dns.p_sport;
		serveraddr = c->dns.p_dst;
		serverport = c->dns.p_dport;
	}
	server = NULL;
	if (server_hash != NULL) {
		HASH_FIND(hh, server_hash, serveraddr, c->dns.alen, server);
		if (server == NULL) return 0;
	}
	if (serverport != 53) return 0;
	if (mode != CALLBACK_PARSED) return 0;

	if (accept_start != 0 && accept_start > c->dns.tv_sec) return 0;
	if (accept_end != 0 && accept_end < c->dns.tv_sec) return 0;
	if (c->dns.version == 4) return 0;
	if (addr[0] < 0x20 || addr[0] > 0x3f) return 0;

	if (t_start == 0 || t_start > c->dns.tv_sec) { t_start = c->dns.tv_sec; }
	if (t_end == 0 || t_end < c->dns.tv_sec) { t_end = c->dns.tv_sec; }

	HASH_FIND(hh, ipv6addr_hash, addr, 8, e);
	HASH_FIND(hh, ipv6addr_hash, addr, 16, e6);
	if (e != NULL) {
		e->count++;
	} else {
		e = (struct ipv6addr_hash *)
			my_malloc(sizeof(struct ipv6addr_hash));
		memcpy(e->addr, addr, 8);
		e->count = 1;
		HASH_ADD(hh, ipv6addr_hash, addr, 8, e);
	}
	if (e6 != NULL) {
		e6->count++;
	} else {
		e6 = (struct ipv6addr_hash *)
			my_malloc(sizeof(struct ipv6addr_hash));
		memcpy(e6->addr, addr, 16);
		e6->count = 1;
		HASH_ADD(hh, ipv6addr_hash, addr, 16, e6);
		e->number_of_addrs++;
	}
	if ((c->dns.error & ParsePcap_UDPchecksumError) != 0) {
		e->error++;
		e6->error++;
	}
	return 0;
}

void load_server_list(char *filename)
{
	struct server_hash *ee, e;
	FILE *fp;
	char *p;
	char buff[1024];

	if ((fp = fopen(filename, "r")) == NULL) {
		err(1, "cannot open %s", filename);
	}
	while(fgets(buff, sizeof buff, fp) != NULL) {
		p = strchr(buff, '\n');
		if (p < buff+sizeof(buff)) {
			*p = 0;
		}
		if (!isalpha(buff[0]) || buff[1] != ',') {
			goto error;
		}
		if (inet_pton(AF_INET6, buff+2, &e.addr) == 1) {
			e.alen = 16;
		} else
		if (inet_pton(AF_INET, buff+2, &e.addr) == 1) {
			e.alen = 4;
		} else {
			goto error;
		}
		ee = my_malloc(sizeof(*ee));
		memcpy(ee, &e, sizeof(e));
		ee->letter = buff[0];
		HASH_ADD(hh, server_hash, addr, ee->alen, ee);
	}
	fclose(fp);
	return;
error:
	err(1, "load_rootlist:Broken line: %s, %s", buff, filename);
}

int load_prev_line(struct DNSdataControl *c)
{
	struct ipv6addr_hash *ep, *e6;
	char *p, *q;
	char s1[512], s2[512];
	long v1, v2, v3;
	uint8_t addr[16];

	p = (char *)c->raw;
	if (p[0] == '#') return 0;
	if (strncmp(p, ipv6addr_tag, ipv6addr_tag_len) != 0) return -1;
	p += ipv6addr_tag_len;
	q = strchr(p, ',');
	if (q == NULL || q == p || q - p > sizeof(s1)) return -1;
	memcpy(s1, p, q-p);
	s1[q-p] = 0;
	if (inet_pton(AF_INET6, s1, addr) == 0)
		return -1;
	p = q + 1;
	if (sscanf(p, "%ld,%ld,%ld", &v1, &v2, &v3) != 3)
		return -1;
	if (v1 != 0) return 0; // ignore
	HASH_FIND(hh, ipv6addr_hash, addr, 8, ep);
	if (ep == NULL) {
		ep = (struct ipv6addr_hash *)
		my_malloc(sizeof(struct ipv6addr_hash));
		memcpy(ep->addr, addr, 8);
		memset(ep->addr+8, 0, 8);
		ep->number_of_addrs = 0;
		ep->count = v2;
		ep->error = v3;
		HASH_ADD(hh, ipv6addr_hash, addr, 8, ep);
	} else {
		ep->count += v2;
		ep->error += v3;
	}
	HASH_FIND(hh, ipv6addr_hash, addr, 16, e6);
	if (e6 != NULL) {
		e6->count += v2;
		e6->error += v3;
	} else {
		e6 = (struct ipv6addr_hash *)
		my_malloc(sizeof(struct ipv6addr_hash));
		memcpy(e6->addr, addr, 16);
		e6->number_of_addrs = 0;
		e6->count = v2;
		e6->error = v3;
		HASH_ADD(hh, ipv6addr_hash, addr, 16, e6);
		ep->number_of_addrs++;
	}
	return 0;
}

int load_prev(FILE *fp, struct DNSdataControl *c, int pass)
{
	char *p, *q;
	int i, j;
	struct ipv6addr_hash *ep, *e6;
	long long tt, line1 = 0, size1 = 0;
	double d1, d2, d3, d4;
	int n;
	int index;
	int error = 0;

	do {
		error = 0;
		n = strlen((char *)c->raw);
		p = (char *)c->raw;
		line1++;
		size1 += n;
		if (p[n-1] == '\n') p[n-1] = 0;
		if (load_prev_line(c) != 0)
			err(1, "FormatError: %s, line %lld, file %s", p, line1, c->filename);
	} while(fgets((char *)c->raw, c->rawlen, fp) != NULL);

	tt = now() - c->open_time;
	if (tt == 0) tt = 1;
	d1 = tt / 1000000.0;
	d2 = line1 / d1;
	d3 = size1 / d1/1024.0/1024.0;
	d4 = c->file_size / d1/1024.0/1024.0;

	fprintf(stderr, "Loaded %lld lines from %s, %.2f secc, %.1f lines/sec, %.1f (%.1f) MB/s\n", line1, c->filename, d1, d2, d3, d4);
	fflush(stderr);
	if (feof(fp)) return 0;
	err(1, "cannot parse: errorcode=%d field=%s/%s file=%s", error, c->raw, p, c->filename);
}

int ipv6addr_hash_sort(const void *aa, const void *bb)
{
	struct ipv6addr_hash **a = (struct ipv6addr_hash **)aa;
	struct ipv6addr_hash **b = (struct ipv6addr_hash **)bb;
	int v;

	if ((*a)->number_of_addrs == 0) {
		if ((*b)->number_of_addrs == 0) {
			return memcmp((*a)->addr, (*b)->addr, 16);
		} else return 1;
	} else {
		if ((*b)->number_of_addrs != 0) {
			v = (*b)->number_of_addrs - (*a)->number_of_addrs;
			if (v == 0) return memcmp((*a)->addr, (*b)->addr, 8);
			return v;
		} else return -1;
	}
	return memcmp((*a)->addr, (*b)->addr, 16);
}

void print_ipv6addr_hash()
{
	struct ipv6addr_hash *e, *tmp, **sp;
	int len, len2, i;
	u_char addr[16];
	char str[100];

	len = HASH_CNT(hh, ipv6addr_hash);
	sp = (struct ipv6addr_hash **)my_malloc(sizeof(struct ipv6addr_hash *) * len);
	len2 = 0;
	HASH_ITER(hh, ipv6addr_hash, e, tmp) {
		sp[len2++] = e;
	}
	qsort(sp, len2, sizeof(struct ipv6addr_hash *), ipv6addr_hash_sort);
	for (i = 0; i < len2; i++) {
		e = sp[i];
		inet_ntop(AF_INET6, e->addr, str, sizeof(str));
		printf("%s%s,%d,%ld,%ld\n", ipv6addr_tag, str, e->number_of_addrs, e->count, e->error);
	}
}

void usage(u_char c)
{
	fprintf(stderr, 
"pcapRoot version %s, compiled at %s %s\n"
"\n"
"Usage: pcapRoot [options] pcap files...\n"
"\n"
"	-v		Verbose++\n"
"	-D num  	Set debug flag\n"
"	-s start_time	\n"
"	-l length	\n"
"   -S root_addr_file\n"
"	-6 file		Load IPv6 addrlist\n"
		,VERSION, __DATE__, __TIME__);
	exit (0);
}

void call_parse_file(char *path, struct DNSdataControl *d)
{
	char *p;
	int ret;

	p = strchr(path, ',');
	d->letter = 0;
	d->node[0] = 0;
	d->current_nodeid = 0;
	if (p != NULL && *p == ',') {
		*p++ = 0;
		if (isalpha(*p)) {
			d->letter = *p;
			strncpy(d->node, p, sizeof(d->node));
			d->current_nodeid = add_node_name(d, d->node);
			d->current_nodename = get_node_name(d, d->current_nodeid);
		}
	}
	fprintf(stderr, "Loading: %s node=%s\n", path, d->node);
	fflush(stderr);
	ret = parse_file(path, d, 0);
	if (ret != ParsePcap_NoError && ret != ParsePcap_ERROR_OutofPeriod && ret != ParsePcap_ERROR_EmptyMerge) {
		printf("#Error:%d:%s:%s:errno=%d\n", ret, parse_file_error(ret), path, errno);
	}
}

int main(int argc, char *argv[])
{
	char *p;
	int len;
	int ch;
	struct DNSdataControl c;
	int flag_ignoreerror = 0;
	char buff2[1024];
	char serverlist_file[1024] = {0};
	char tldlist_file[1024] = {0};
	int flag_print_label = 0;

	memset(&c, 0, sizeof(c));

	while ((ch = getopt(argc, argv, "FmavIMD:s:l:pxr:z:iS:N:T:6:")) != -1) {
	switch (ch) {
	case 'a':
		flag_answer = 1;
		mode |= MODE_PARSE_ANSWER | MODE_IGNORE_CHECKSUM_ERROR;
		break;
	case 'v':
		verbose++;
		break;
	case 'D':
		debug = atoi(optarg);
		break;
	case 's':
		accept_start = atoi(optarg);
		break;
	case 'l':
		accept_length = atoi(optarg);
		break;
	case 'i':
		flag_ignoreerror++;
		break;
	case 'S':
		strncpy(serverlist_file, optarg, sizeof(serverlist_file));
		break;
	case 'm': break; // ignore
	case '6': c.v6hash = load_ipv6_prefix_list(optarg); break;
	case '?':
	default:
		usage(ch);
	}}
	argc -= optind;
	argv += optind;

	if (serverlist_file[0] != 0) { load_server_list(serverlist_file); }
	c.callback = callback;
	c.otherdata = load_prev;
	c.getdname_options = GET_DNAME_LOWERCASE | GET_DNAME_IgnoreErrorChar;
	c.enable_tcp_state = 0;
	c.mode = mode;
	c.rawlen = 65536;
	c.raw = my_malloc(c.rawlen);
	if (accept_start != 0) accept_end = accept_start + accept_length;

	if (argc == 0 && isatty(fileno(stdin))) usage(0);

	if (argc > 0) {
		while (*argv != NULL) {
			p = *argv++;
			call_parse_file(p, &c);
		}
	} else {
		while (fgets(buff2, sizeof buff2, stdin) != NULL) {
			len = strlen(buff2);
			if (len > 0 && buff2[len-1] == '\n') {
				buff2[len-1] = 0;
			}
			call_parse_file(buff2, &c);
		}
	}
	print_ipv6addr_hash();
	return 0;
}
