/*
	$Id: PcapSelectDNS.c,v 1.11 2021/04/15 11:49:20 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2013 Japan Registry Servcies Co., Ltd.

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_MATH_H
#include <math.h>
#endif
#ifdef HAVE_ERR_H
#include <err.h>
#endif

#include "ext/uthash.h"
#include "PcapParse.h"

/*****************************************************************************
	 Warning
			Little endian only
			Supported Linktype: 0==PPP	1==Ether
 *****************************************************************************
 */

struct pcap_file_header {
	u_int32_t magic;
	u_short version_major;
	u_short version_minor;
	int32_t thiszone;	/* gmt to local correction */
	u_int32_t sigfigs;	/* accuracy of timestamps */
	u_int32_t snaplen;	/* max length saved portion of each pkt */
	u_int32_t linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_header {
	struct pcap_timeval {
		u_int32_t tv_sec;	/* seconds */
		u_int32_t tv_usec;	/* microseconds */
	} ts;				/* time stamp */
	int32_t caplen;	/* length of portion present */
	int32_t len;	/* length this packet (off wire) */
};
#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define	DLT_IP		101	/* IP packet directly */
#define DLT_LINUX_SLL	113	/* Linux cocked */
#define DLT_RAW		12	/* _ip IP */

int debug = 0;
int flag_exact_match = 0;
static u_int32_t client_ipv4 = 0;
static u_char client_ipv6[16] = { 255 };
int check_v4 = 0;
int check_v6 = 0;

FILE *wfp = NULL;

struct dom_hash_ {
	UT_hash_handle hh;
	int count;
	char *dom;
} *dom_hash = NULL;

int callback(struct DNSdataControl *c, int mode)
{
	char *p;
	int found = 0;
	struct pcap_header ph;
	struct dom_hash_ *e;

	if (mode == CALLBACK_ADDRESSCHECK) {
		return 1;
	}
	p = (char *)c->dns.qname;
	e = NULL;
	while(*p != 0) {
		HASH_FIND_STR(dom_hash, p, e);
		if (e != NULL) break;
		p = strchr(p, '.');
		if (p == NULL) break;
		p++;
	}
	if (e != NULL) {
		e->count++;
		found = 1;
	}
	if (found == 0) { return 0; }
	ph.ts.tv_sec = c->dns.tv_sec;
	ph.ts.tv_usec = c->dns.tv_usec;
	ph.caplen = c->dns.len;
	ph.len = c->dns.len;
	printf("writing: %d.%06d %d bytes\n", c->dns.tv_sec, c->dns.tv_usec, c->dns.len);
	fwrite(&ph, sizeof(ph), 1, wfp);
	fwrite(c->dns._ip, c->dns.len, 1, wfp);

	return 0;
}

void usage()
{
	fprintf(stderr, 
"pcapDNSKEY version %s, compiled at %s %s\n"
"\n"
"Usage: pcapChoose [options] pcap files...\n"
"\n"
"	-l	Label\n"
		,VERSION, __DATE__, __TIME__);
	exit(1);
}

int main(int argc, char *argv[])
{
	char *p;
	char *outputfile = NULL;
	int len;
	int ret;
	int ch;
	int mode = 0;
	struct dom_hash_ *dom;
	struct pcap_file_header pfw;
	struct DNSdataControl c;
	memset((void *)&c, 0, sizeof(&c));

	while ((ch = getopt(argc, argv, "Ao:el:4:6:")) != -1) {
	switch (ch) {
	case 'A':
		mode |= MODE_PARSE_ANSWER;
		break;
	case 'e':
		flag_exact_match = 1;
		break;
	case 'o':
		outputfile = strdup(optarg);
		break;
	case 'l':
		len = strlen(optarg);
		p = malloc(len+1+sizeof(struct dom_hash_));
		dom = (struct dom_hash_ *) (p + len + 1);
		dom->dom = p;
		dom->count = 0;
		memcpy(p, optarg, len);
		p[len] = 0;
		HASH_ADD_STR(dom_hash, dom, dom);
		break;
	case '4':
		if (inet_aton(optarg, (struct in_addr *)&client_ipv4) == 0)
			err(1, "bad IPv4 address: %s", optarg);
		check_v4 = 1;
		break;
#if defined(AF_INET6) && defined(HAVE_INET_PTON)
	case '6':
		if (inet_pton(AF_INET6, optarg, client_ipv6) != 1)
			err(1, "bad IPv6 address: %s", optarg);
		check_v6 = 1;
		break;
#endif
	case '?':
	default:
		usage();
	}}
	argc -= optind;
	argv += optind;

	c.callback = callback;
	c.otherdata = NULL;
	c.mode = MODE_IGNOREERROR | MODE_PARSE_QUERY;
	c.debug = debug;

	if (outputfile == NULL) { printf("#Error:No outputfilename\n"); exit(1); };
	if ((wfp = fopen(outputfile, "w")) == NULL) {
		printf("#Werror:Cannot write %s", outputfile);
		exit(1);
	}
	argv++;
	argc--;

	pfw.magic = 0xa1b2c3d4;
	pfw.version_major = 2;
	pfw.version_minor = 4;
	pfw.thiszone = 0;
	pfw.sigfigs = 0;
	pfw.snaplen = 1500;
	pfw.linktype = DLT_IP;
	fwrite(&pfw, sizeof(pfw), 1, wfp);

	while (*argv != NULL) {
		if (argc > 1) fprintf(stderr, "Loading %s\n", *argv);
		// fflush(stderr);
		ret = parse_pcap(*argv, &c);
		if (ret != ParsePcap_NoError) {
			printf("#Error:%s:%s\n", parse_pcap_error(ret), *argv);
		}
		argv++;
	}
	fclose(wfp);
	return 0;
}
