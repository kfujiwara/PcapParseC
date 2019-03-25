/*
	$Id: PcapSelectDNS.c,v 1.7 2018/08/03 05:17:46 fujiwara Exp $

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
#ifdef HAVE_APR_HASH_H
#include <apr_hash.h>
#endif

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

struct {
	char *dom;
	int len;
} doms[100];
int ndoms = 0;

FILE *wfp = NULL;

#ifdef HAVE_APR_HASH_H
typedef struct ipaddr_list {
	int count;
	u_int alen;
	u_char addr[16];
};

static apr_pool_t *pool = NULL;
static apr_hash_t *ipaddr_hash = NULL;
#endif

int callback(struct DNSdataControl *c, int mode)
{
	int len = strlen((char *)c->dns.qname);
	u_char *u;
	int found = 0;
	int i;
	struct pcap_header ph;
#ifdef HAVE_APR_HASH_H
	struct ipaddr_list *e;
#endif
	if (mode == CALLBACK_ADDRESSCHECK) {
		return 1;
	}
#ifdef HAVE_APR_HASH_H
	if (ipaddr_hash != NULL) {
		e = (struct ipaddr_list *)apr_hash_get(ipaddr_hash, c->dns.req_src, c->dns.alen);
		if (e == NULL) return 0;
		e->count++;
		found = 1;
	}
#endif
	if (found == 0) {
	  for (i = 0, found = 0; i < ndoms; i++) {
	    if (len == doms[i].len && strcasecmp((char *)c->dns.qname, doms[i].dom) == 0) {
	      found = 1;
	      break;
	    }
	    else if (flag_exact_match == 0 && len > doms[i].len && strcasecmp((char *)c->dns.qname + len - doms[i].len, doms[i].dom) == 0 && c->dns.qname[len-doms[i].len-1] == '.') {
	      found = 1;
	      break;
	    }
	  }
	}
	//printf("compare:qname=%s:doms=%s:ndoms=%d:found=%d\n", (char *)c->dns.qname, doms[0].dom, ndoms, found);
#if 0
	if (found == 0) {
		if (c->dns.version == 4 && check_v4 != 0) {
			if (client_ipv4 == *(u_int32_t *)(c->dns.req_src))
				found = 1;
		} else
		if (c->dns.version == 6 && check_v6 != 0) {
			if (memcmp(client_ipv6, c->dns.req_src, 16) == 0)
				found = 1;
		}
	}
#endif
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
	FILE *fp;
	char *p;
	char *outputfile = NULL;
	int len;
	char buff[256];
	int ret;
	int ch;
	struct pcap_file_header pfw;
	struct DNSdataControl c;

	memset((void *)&c, 0, sizeof(&c));

	while ((ch = getopt(argc, argv, "Ao:el:4:6:")) != -1) {
	switch (ch) {
	case 'A':
		debug |= FLAG_MODE_PARSE_ANSWER;
		break;
	case 'e':
		flag_exact_match = 1;
		break;
	case 'o':
		outputfile = strdup(optarg);
		break;
	case 'l':
		doms[ndoms].dom = strdup(optarg);
		doms[ndoms].len = strlen(optarg);
		ndoms++;
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
	c.debug = FLAG_IGNOREERROR | FLAG_MODE_PARSE_QUERY;

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
