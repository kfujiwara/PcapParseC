/*
	$Id: pcapNULL.c,v 1.5 2025/05/29 09:30:30 fujiwara Exp $

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
#include "dns_string.h"
#include "load_ipv6list.h"
#include "pcapparse.h"
#include "mytool.h"
#include "bit.h"
#include "geoiplookup.h"

int debug = 0;
int mode = MODE_PARSE_QUERY;
int mask_low_address_anonymize = 0;

static u_int32_t accept_start = 0;
static u_int32_t accept_length = 3600;
static u_int32_t accept_end = 0;
static u_int32_t t_start = 0;
static u_int32_t t_end = 0;
static u_int32_t data_start = 0;
static u_int32_t data_end = 0;
static struct ipaddr_hash *ipaddr_hash = NULL;
struct server_hash *server_hash = NULL;
static struct pcapstat_hash *pcapstat_hash = NULL;

static int accept_private = 0;
static int minimize_output = 0;
static int summary_output = 0;
static int verbose = 0;
static int flag_answer = 0;
static int jp_analysis = 0;

int callback(struct DNSdataControl *c, int mode)
{
	int j;
	char *u;
	u_char *addr;
	int portno;
	char node0[2];
	char s_src[INET6_ADDRSTRLEN];
	char s_dst[INET6_ADDRSTRLEN];

	if (flag_answer) {
		addr = c->dns.p_dst;
		portno = c->dns.p_dport;
	} else {
		addr = c->dns.p_src;
		portno = c->dns.p_sport;
	}
	if (mode != CALLBACK_PARSED) return 0;

	if (accept_start != 0 && accept_start > c->dns.tv_sec) {
		return 0;
	}
	if (accept_end != 0 && accept_end < c->dns.tv_sec) {
		return 0;
	}
	return 1;
	// Do nothing
}

void call_parse_file(char *path, struct DNSdataControl *d, int pass)
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
	fprintf(stderr, "Loading: %s node=%s, pass=%d\n", path, d->node, pass);
	fflush(stderr);
	ret = parse_file(path, d, pass);
	if (ret != ParsePcap_NoError && ret != ParsePcap_ERROR_OutofPeriod && ret != ParsePcap_ERROR_EmptyMerge) {
		printf("#Error:%d:%s:%s:errno=%d\n", ret, parse_file_error(ret), path, errno);
	}
}

int main(int argc, char *argv[])
{
	char *p;
	int len, i;
	int ch;
	struct DNSdataControl c;
	int flag_ignoreerror = 0;
	int flag_print_label = 0;
	char buff2[1024];

	memset(&c, 0, sizeof(c));

	while ((ch = getopt(argc, argv, "a")) != -1) {
	switch (ch) {
	case 'a':
		flag_answer = 1;
		mode |= MODE_PARSE_ANSWER | MODE_IGNORE_CHECKSUM_ERROR;
		break;
	}}
	argc -= optind;
	argv += optind;

	add_node_name(&c, "none");

	c.callback = callback;
	c.otherdata = NULL;
	c.debug = debug;
	c.enable_tcp_state = 1;
	c.mode = mode;
	c.rawlen = 1024*1024;
	c.raw = my_malloc(c.rawlen);

	if (mask_low_address_anonymize) {
		c.mode |= MODE_IGNORE_CHECKSUM_ERROR | MODE_IGNOREERROR;
	}
	if (accept_start != 0) accept_end = accept_start + accept_length;

	if (argc == 0 && isatty(fileno(stdin))) exit(0);

	if (argc > 0) {
		for (i = 0; argv[i] != NULL; i++) {
			p = argv[i];
			call_parse_file(p, &c, 0);
		}
		for (i = 0; argv[i] != NULL; i++) {
			p = argv[i];
			call_parse_file(p, &c, 1);
		}
	} else {
		while (fgets(buff2, sizeof buff2, stdin) != NULL) {
			len = strlen(buff2);
			if (len > 0 && buff2[len-1] == '\n') {
				buff2[len-1] = 0;
			}
			call_parse_file(buff2, &c, 0);
		}
	}
	print_rusage();
	return 0;
}
