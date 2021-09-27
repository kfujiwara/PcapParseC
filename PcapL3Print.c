/*
		nexact++;
	$Id: PcapL3Print.c,v 1.9 2021/04/15 11:49:20 fujiwara Exp $

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
#ifdef HAVE_ERR_H
#include <err.h>
#endif

#include "ext/uthash.h"
#include "PcapParse.h"

int start = -1;
int end = -1;
int time_offset = 0;
int accept_v4 = 0;
int accept_v6 = 0;
u_char src4[4] = { 255 };
u_char src6[16] = { 255 };
u_char dest4[4] = { 255 };
u_char dest6[16] = { 255 };
int accept_frag = 0;
double exact[100];
int nexact = 0;
int opt_v = 0;
int opt_qr = -1; /* -1 no check / 0 query / 1 response */

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

int _pcapL3print(FILE *fp)
{
	struct pcap_header ph;
	struct pcap_file_header pf;
	int needswap = 0;
	int len;
	int l2header = 0;
	long long offset = 0;
	int frag;
	int srcp;
	int dstp;
	int iplen;
	int af;
	int udpsize;
	int proto;
	int ignore;
	u_char buff[2000], *_ip;
	char src[100], dst[100];

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
		ignore = 0;
		if ((_ip[0]>>4) == 4) {
			af = AF_INET;
			if (src4[0] != 255 && memcmp(src4, _ip+12, 4) != 0)
				ignore++;
			if (dest4[0] != 255 && memcmp(dest4, _ip+16, 4) != 0)
				ignore++;
			inet_ntop(AF_INET, _ip+12, src, sizeof(src));
			inet_ntop(AF_INET, _ip+16, dst, sizeof(dst));
			frag = ((_ip[6]<<8) | _ip[7]) & 0x3fff;
			iplen = (_ip[2]<<8) | _ip[3];
			proto = _ip[9];
			if ((frag & 0x1fff) == 0) {
				srcp = (_ip[20]<<8) | _ip[21];
				dstp = (_ip[22]<<8) | _ip[23];
				udpsize = (proto == 17) ? (_ip[24]<<8) | _ip[25] : -1;
			} else {
				srcp = dstp = udpsize = -1;
			}
		} else
		if ((_ip[0]>>4) == 6) {
			af = AF_INET6;
			if (src6[0] != 255 && memcmp(src6, _ip+8, 16) != 0)
				ignore++;
			if (dest6[0] != 255 && memcmp(dest6, _ip+24, 16) != 0)
				ignore++;
			inet_ntop(AF_INET6, _ip+8, src, sizeof(src));
			inet_ntop(AF_INET6, _ip+24, dst, sizeof(dst));
			proto = _ip[6];
			iplen = ((_ip[4]<<8) | _ip[5]) + 40;
			if (proto != 44) { // not fragment
				srcp = (_ip[40]<<8) | _ip[41];
				dstp = (_ip[42]<<8) | _ip[43];
				udpsize = (proto == 17) ? (_ip[44]<<8) | _ip[45] : -1;
				frag = 0x8000;
			} else {
				proto = _ip[40];
				frag = (_ip[42]<<8)|_ip[43];
				if ((frag & 0xfff8) == 0) {
					srcp = (_ip[48]<<8) | _ip[49];
					dstp = (_ip[50]<<8) | _ip[51];
					udpsize = (proto==17)?(_ip[52]<<8) | _ip[53]: -1;
				} else {
					srcp = dstp = udpsize = -1;
				}
			}
		} else continue;
		// timestamp,source,sport,dest,dport,caplen,frag,proto
		if (!ignore)
			printf("%d.%06d,%s,%d,%s,%d,%d,%d,%d,%d\n", 
			ph.ts.tv_sec, ph.ts.tv_usec,
			       src, srcp, dst, dstp,
			       iplen, frag, proto, udpsize);
	}
	if (len == 0)
		return 0;
	return ParsePcap_ERROR_ShortRead;
}

int pcapL3print(char *file)
{
	int ret;
	FILE *fp;
	int len;
	char buff[256];

	if (file == NULL)
		return _pcapL3print(stdin);
	len = strlen(file);
	if (len > 3 && strcmp(file+len-4, ".xz") == 0) {
		snprintf(buff, sizeof buff, "xz -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcapL3print(fp);
		pclose(fp);
	} else
	if (len > 4 && strcmp(file+len-4, ".bz2") == 0) {
		snprintf(buff, sizeof buff, "bzip2 -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcapL3print(fp);
		pclose(fp);
	} else
	if (len > 3 && strcmp(file+len-3, ".gz") == 0) {
		snprintf(buff, sizeof buff, "gzip -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcapL3print(fp);
		pclose(fp);
	} else {
		if ((fp = fopen(file, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _pcapL3print(fp);
		fclose(fp);
	}
	return ret;
}

char *pcapL3print_error(int errorcode)
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
	printf("PcapL3print InputFiles....\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int ret;
	char *p;
	int ch;

	while ((ch = getopt(argc, argv, "s:S:d:D:")) != -1) {
	switch (ch) {
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
	}}
	argc -= optind;
	argv += optind;
	if (argc > 0) {
		//argv++;
		while (*argv != NULL) {
			p = *argv++;
			if (strcmp(p, "-") == 0) p = NULL;
			ret = pcapL3print(p);
			if (ret != ParsePcap_NoError) {
				printf("#Error:%s:%s:errno=%d\n", pcapL3print_error(ret), p, errno);
				exit(1);
			}
		}
	} else {
		usage(0);
	}
	return 0;
}
