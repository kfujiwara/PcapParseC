/*
		nexact++;
	$Id: PcapSelectL3.c,v 1.14 2019/03/19 08:05:26 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDLIB_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
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
#ifdef HAVE_SYS_TYPES_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "PcapParse.h"

int begin = -1;
int end = -1;
int time_offset = 0;
int accept_v4 = 0;
int accept_v6 = 0;
int accept_frag = 0;
double exact[100];
int nexact = 0;
int opt_v = 0;
u_char src4[4] = { 255 };
u_char src6[16] = { 255 };
u_char dest4[4] = { 255 };
u_char dest6[16] = { 255 };

/* Ignore UDP fragment */
/* parse query packet only */

/*
 hexdump for debug
 */

void hexdump(char *msg, u_char *data, int len)
{
	int addr = 0;
	if (msg != NULL)
		printf("%s : \n", msg);
	while(len-- > 0) {
		if ((addr % 16) == 0) {
			printf("%s%04x ", (addr!=0)?"\n":"", addr);
		}
		printf("%02x ", *data++);
		addr++;
	}
	printf("\n");
}

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

static u_short swap16(u_short x)
{
	return ((x & 0xff) << 8) | (x >> 8);
}

static u_long swap32(u_int32_t x)
{
	return ((x & 0xff) << 24)
		| ((x & 0xff00) << 8)
		| ((x & 0xff000) >> 8)
		| ((x & 0xff000000) >> 24);
}

int _pcap_cleanup(FILE *fp, FILE *wfp)
{
	struct pcap_header ph;
	struct pcap_file_header pf;
	int needswap = 0;
	int len;
	int l2header = 0;
	long long offset = 0;
	long long offset2;
	int i;
	int match_time = 0;
	int match_addr = 0;
	int match_frag = 0;
	int ignore;
	double d;
	u_char buff[2000], *_ip;

	len = fread(&pf, 1, sizeof(pf), fp);
	offset += len;

 	if (len == 0) {
		if (len == 0) return 0; /* Ignore */
	}
	if (len != sizeof(pf)) {
		return ParsePcap_ERROR_BogusSavefile;
	}
	if (pf.magic == 0xa1b2c3d4) { /* OK */
	} else
	if (pf.magic == 0xd4c3b2a1) {
		needswap = 1;
		pf.version_major = swap16(pf.version_major);
		pf.version_minor = swap16(pf.version_minor);
		pf.thiszone = swap32(pf.thiszone);
		pf.sigfigs = swap32(pf.sigfigs);
		pf.snaplen = swap32(pf.snaplen);
		pf.linktype = swap32(pf.linktype);
	} else
		return ParsePcap_ERROR_BogusSavefile;

	while((len = fread(&ph, 1, sizeof(ph), fp)) == sizeof(ph)) {
		match_time = 0;
		match_addr = 0;
		match_frag = 0;
		ignore = 0;
		offset += len;
		if (ph.len == 0 || ph.caplen == 0) {
			ph.ts.tv_usec = ph.caplen;
			len = fread(&ph.caplen, 1, 8, fp);
			offset += len;
			if (len != 8) { break; }
		}
		if (needswap) {
			ph.caplen = swap32(ph.caplen);
			ph.len = swap32(ph.len);
			ph.ts.tv_sec = swap32(ph.ts.tv_sec);
			ph.ts.tv_usec = swap32(ph.ts.tv_usec);
		}
		if (ph.caplen > 65535 || ph.len > 65535 || ph.caplen < 0) {
			return 0;
		}
		if ((len = fread(buff, 1, ph.caplen, fp)) != ph.caplen) {
			return ParsePcap_ERROR_ShortRead;
		}
		offset += len;
		if (pf.linktype == DLT_NULL) {
			l2header = 4;
		} else
		if (pf.linktype == DLT_EN10MB) {
			if (buff[12] == 0x81 && buff[13] == 0) { /* VLAN */
				l2header = 18;
			} else {
				l2header = 14;
			}
		} else
		if (pf.linktype == DLT_LINUX_SLL) {
			l2header = 16;
		} else
		if (pf.linktype == DLT_IP) {
			l2header = 0;
		} else {
			printf("#Error:unknownLinkType:%d", pf.linktype);
			return ParsePcap_ERROR_UnknownLinkType;
		}
		_ip = buff + l2header;
		len = len - l2header;
		d = (double)ph.ts.tv_sec + (double)ph.ts.tv_usec/1000000;
		if (begin >= 0 || end >= 0) {
			if (begin >= 0 && ph.ts.tv_sec >= begin) continue;
			if (end >= 0 && ph.ts.tv_sec >= end) continue;
			match_time = 1;
		} else
		if (nexact > 0) {
			for (i = 0; i < nexact; i++)
				if (exact[i] == d) {
					match_time = 1;
					break;
				}
			if (i >= nexact)
				continue;
		} else {
			match_time = 1;
		}
		if (accept_frag) {
			// Test Fragment
			if (_ip[0] >> 4 == 4 && (((_ip[6]<<8)|_ip[7]) & 0x3fff) != 0) {
				match_frag = 1;
			} else
			if (_ip[0] >> 6 && _ip[6] == 44) {
				match_frag = 1;
			}
		} else {
			match_frag = 1;
		}
		if ((*src4 & *src6 & *dest4 & *dest6) == 255) {
		   	match_addr = 1;
		} else {
			if ((_ip[0]>>4) == 4) {
				if ((*src4 & *dest4) == 255)
					ignore++;
				if (src4[0]!=255 && memcmp(src4,_ip+12,4) != 0)
					ignore++;
				if (dest4[0]!=255 && memcmp(dest4,_ip+16,4)!=0)
				   	ignore++;
			}
			else
			if ((_ip[0]>>4) == 6) {
				if ((*src6 & *dest6) == 255)
					ignore++;
				if (src6[0] != 255 && memcmp(src6, _ip+8, 16) != 0)
					ignore++;
				if (dest6[0] != 255 && memcmp(dest6, _ip+24, 16) != 0)
					ignore++;
			}
			match_addr = (ignore == 0) ? 1 : 0;
		}
		if (!match_time || !match_frag || !match_addr) continue;
		if (opt_v) printf("writing: %d.%06d %d bytes\n", ph.ts.tv_sec, ph.ts.tv_usec, len);
		ph.ts.tv_sec += time_offset;
		ph.caplen = len;
		ph.len = len;
		fwrite(&ph, sizeof(ph), 1, wfp);
		fwrite(_ip, len, 1, wfp);
	}
	if (len == 0)
		return 0;
	return ParsePcap_ERROR_ShortRead;
}

int pcap_cleanup(char *file, FILE *wfp)
{
	int ret;
	FILE *fp;
	int len;
	char buff[256];

	if (file == NULL)
		return _pcap_cleanup(stdin, wfp);
	len = strlen(file);
	if (len > 3 && strcmp(file+len-4, ".xz") == 0) {
		snprintf(buff, sizeof buff, "xz -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcap_cleanup(fp, wfp);
		pclose(fp);
	} else
	if (len > 4 && strcmp(file+len-4, ".bz2") == 0) {
		snprintf(buff, sizeof buff, "bzip2 -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcap_cleanup(fp, wfp);
		pclose(fp);
	} else
	if (len > 3 && strcmp(file+len-3, ".gz") == 0) {
		snprintf(buff, sizeof buff, "gzip -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcap_cleanup(fp, wfp);
		pclose(fp);
	} else {
		if ((fp = fopen(file, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcap_cleanup(fp, wfp);
		fclose(fp);
	}
	return ret;
}

char *pcap_cleanup_error(int errorcode)
{
	switch(errorcode) {
	case ParsePcap_NoError:
		return "NoError";
	case ParsePcap_ERROR_Empty:
		return "Empty";
	case ParsePcap_ERROR_BogusSavefile:
		return "BogusSavefile";
	case ParsePcap_ERROR_ShortRead:
		return "ShortRead";
	case ParsePcap_ERROR_FILE_OPEN:
		return "Cannot Open File";
	case ParsePcap_ERROR_UnknownLinkType:
		return "Unknown Link Type";
	default:
		return "Unknown";
	}
}

void usage(int c)
{
	printf("PcapSelectL3 [-T timezone offset] options OutputFile InputFiles....\n"
"time options: if specified, only matched packet will be written.\n"
"  -b begin\n"
"  -e end\n"
"  -E exact_match_time (multiple, max 10)\n"
"address options: if specified, only matched packet will be written.\n"
"                 source & dest\n"
"  -s IPv4_source\n"
"  -d IPv4_destination\n"
"  -S IPv6_source\n"
"  -D IPv6_destination\n"
"fragment\n"
"  -f\n");

	exit(0);
}

int main(int argc, char *argv[])
{
	int bflag, ch;
	double d;
	int len;
	int ret;
	char *p, *q;
	FILE *wfp;
	struct pcap_file_header pfw;

	bflag = 0;
	while ((ch = getopt(argc, argv, "vb:e:T:E:46fs:S:d:D:")) != -1) {
	switch (ch) {
	case 'f':
		accept_frag = 1;
		break;
	case '4':
		accept_v4 = 1;
		break;
	case '6':
		accept_v6 = 1;
		break;
	case 'e':
		end = atoi(optarg);
		break;
	case 'b':
		begin = atoi(optarg);
		break;
	case 'T':
		time_offset = atoi(optarg);
		break;
	case 'E':
		exact[nexact++] = atof(optarg);
		/*printf("-E %s is parsed as tv_sec=%d tv_usec=%d\n", optarg, exact_time_sec, exact_time_usec);*/
		break;
	case 's':
		if (inet_aton(optarg, (struct in_addr *)&src4) == 0)
			err(1, "bad IPv4 address: %s", optarg);
		break;
	case 'S':
		if (inet_pton(AF_INET6, optarg, src6) != 1)
			err(1, "bad IPv6 address: %s", optarg);
		break;
	case 'd':
		if (inet_aton(optarg, (struct in_addr *)&dest4) == 0)
			err(1, "bad IPv4 address: %s", optarg);
		break;
	case 'D':
		if (inet_pton(AF_INET6, optarg, dest6) != 1)
			err(1, "bad IPv6 address: %s", optarg);
		break;
	case 'v':
		opt_v = 1;
		break;
	case '?':
	default:
		usage(-1);
	}}
	argc -= optind;
	argv += optind;
	if (accept_v4 == 0 && accept_v6 == 0) {
	  accept_v4 = 1; accept_v6 = 1;
	}
	if (argc < 1) { usage(-1); }
	if ((wfp = fopen(*argv, "w")) == NULL) {
		printf("#Wrror:Cannot write %s", *argv); exit(1);
	}
	pfw.magic = 0xa1b2c3d4;
	pfw.version_major = 2;
	pfw.version_minor = 4;
	pfw.thiszone = 0;
	pfw.sigfigs = 0;
	pfw.snaplen = 1500;
	pfw.linktype = DLT_IP;
	fwrite(&pfw, sizeof(pfw), 1, wfp);
	argv++;
	argc--;
	if (argc > 0) {
		while (*argv != NULL) {
			p = *argv++;
			if (strcmp(p, "-") == 0) p = NULL;
			ret = pcap_cleanup(p, wfp);
			if (ret != ParsePcap_NoError) {
				printf("#Error:%s:%s:errno=%d\n", pcap_cleanup_error(ret), p, errno);
				exit(1);
			}
		}
	} else {
		usage(0);
	}
	return 0;
}
