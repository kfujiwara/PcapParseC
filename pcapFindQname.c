/*
	$Id: pcapFindQname.c,v 1.22 2025/06/04 09:47:34 fujiwara Exp $

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
#include <ctype.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ext/uthash.h"
#include "config.h"
#include "pcapparse.h"
#include "name_match.h"

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
int opt_v = 0;
int ignore_shortread = 0;

long long begin = -1;
long long end = -1;
long long length = 60;

FILE *wfp = NULL;
struct name_list name_list = { NULL, 0};

int callback(struct DNSdataControl *c, int mode)
{
	char *p = NULL;
	int found = 0;
	struct pcap_header ph;
	struct name_hash *e;
	int j;

	p = (char *)c->dns.qname;
	e = match_name(&name_list, c);
	//printf("match: qname=%s e=%lp\n", p, e);
	if (begin >= 0 && c->dns.ts < begin) return 0;
	if (end >= 0 && c->dns.ts >= end) return 0;
	if (e == NULL) { return 0; }
	ph.ts.tv_sec = c->dns.tv_sec;
	ph.ts.tv_usec = c->dns.tv_usec;
	ph.caplen = c->dns.len;
	ph.len = c->dns.len;
	if (opt_v) printf("writing: %d.%06d %d bytes\n", c->dns.tv_sec, c->dns.tv_usec, c->dns.len);
	fwrite(&ph, sizeof(ph), 1, stdout);
	j = fwrite(c->dns._ip, c->dns.len, 1, stdout);
	if (opt_v) printf("fwrite returned %d errno=%d\n", j, errno);
	fflush(stdout);

	return 0;
}

void usage()
{
	fprintf(stderr, 
"pcapSelectQname version %s, compiled at %s %s\n"
"\n"
"Usage: pcapSelectQname [options] pcap files...\n"
"\n"
"	-a name,name,..	domainname\n"
"	-I file         Load name list file\n"
		,VERSION, __DATE__, __TIME__);
	exit(1);
}

int main(int argc, char *argv[])
{
	char *p;
	char *outputfile = NULL;
	int len, ret, i, ch;
	int mode = 0;
	struct dom_hash_ *dom;
	struct pcap_file_header pfw;
	struct DNSdataControl c;
	char buff[1024];

	memset((void *)&c, 0, sizeof(&c));

	while ((ch = getopt(argc, argv, "s:l:o:a:I:vimAo:el:4:6:")) != -1) {
	switch (ch) {
	case 's': begin = (long long)(atof(optarg) * 1000000.0); break;
	case 'l': length = (long long)(atof(optarg) * 1000000.0); break;
	case 'a': register_name_list(optarg, &name_list, opt_v); break;
	case 'i': ignore_shortread = 1; break;
	case 'v': opt_v++; break;
	case 'I': load_name_list(optarg, &name_list); break;
	case 'A': mode |= MODE_PARSE_ANSWER; break;
	case 'o': outputfile = strdup(optarg); 	break;
	case 'm': break; // ignore
	case '?':
	default:
		usage();
	}}
	argc -= optind;
	argv += optind;

	memset(&c, 0, sizeof(c));
	c.rawlen = 65536;
	c.raw = malloc(c.rawlen);
	c.callback = callback;
	c.otherdata = NULL;
	c.mode = MODE_IGNOREERROR | MODE_PARSE_QUERY;
	c.debug = debug;
	if (opt_v) print_name_list(&name_list);
	if (begin > 0) end = begin + length;
	if (argc == 0 && isatty(fileno(stdin))) { usage(); }
	if (outputfile != NULL) {
		if ((wfp = fopen(outputfile, "w")) == NULL) {
			fprintf(stderr, "#Wrror:Cannot write %s : errno=%d\n", outputfile, errno);
			exit(1);
		}
	} else {
		wfp = stdout;
	}
	pfw.magic = 0xa1b2c3d4;
	pfw.version_major = 2;
	pfw.version_minor = 4;
	pfw.thiszone = 0;
	pfw.sigfigs = 0;
	pfw.snaplen = 1500;
	pfw.linktype = DLT_IP;
	fwrite(&pfw, sizeof(pfw), 1, wfp);
	if (argc > 0) {
		for (i = 0; i < argc; i++) {
			strcpy(buff, argv[i]);
			p = strchr(buff, ',');
			if (p != NULL && *p == ',') *p = 0;
			ret = parse_file(buff, &c, 0);
			if (ret != ParsePcap_NoError) {
				fprintf(stderr, "#Error:%s:%s\n", parse_file_error(ret), *argv);
			}
			if (ignore_shortread != 0 && ret == ParsePcap_ERROR_ShortRead) {
				exit(0);
			}
			if (ret != ParsePcap_NoError) {
				fprintf(stderr, "#Error:%s:errno=%d\n", parse_file_error(ret), errno);
				exit(1);
			}
		}
	} else {
		while (fgets(buff, sizeof buff, stdin) != NULL) {
			len = strlen(buff);
			if (len > 0 && buff[len-1] == '\n') {
				buff[len-1] = 0;
			}
			p = strchr(buff, ',');
			if (p != NULL && *p == ',') *p = 0;
			ret = parse_file(buff, &c, 0);
			if (ignore_shortread != 0 && ret == ParsePcap_ERROR_ShortRead) {
				exit(0);
			}
			if (ret != ParsePcap_NoError) {
				fprintf(stderr, "#Error:%s:errno=%d\n", parse_file_error(ret), errno);
				exit(1);
			}
		}
	}
	if (outputfile != NULL) fclose(wfp);
	return 0;
}
