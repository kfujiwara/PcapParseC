/*
	$Id: pcapinfo.c,v 1.10 2021/04/15 11:49:20 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2017 Japan Registry Servcies Co., Ltd.

	int parse_pcap(char *file) reads
	pcap files and returns two timevals.

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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
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
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

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

#define parse_decimal2(x) ((x[0]<'0'||x[0]>'9'||x[1]<'0'||x[1]>'9')?-1:(x[0]-'0')*10+x[1]-'0')
#define parse_decimal3(x) ((x[0]<'0'||x[0]>'9'||x[1]<'0'||x[1]>'9'||x[2]<'0'||x[2]>'9')?-1:(x[0]-'0')*100+(x[1]-'0')*10+x[2]-'0')
#define parse_decimal4(x) ((x[0]<'0'||x[0]>'9'||x[1]<'0'||x[1]>'9'||x[2]<'0'||x[2]>'9'||x[3]<'0'||x[3]>'9')?-1:(x[0]-'0')*1000+(x[1]-'0')*100+(x[2]-'0')*10+x[3]-'0')

long long parse_line(u_char *input)
{
	u_char *p;
	int msec;
	struct tm tm;

	p = input;
	memset(&tm, 0, sizeof(tm));
	tm.tm_mday = parse_decimal2(p);
	if (tm.tm_mday < 0 || tm.tm_mday > 31 || p[2] != '-') return -1;
	p += 3;
	if (p[0] == 0 || p[1] == 0 || p[2] == 0 || p[3] != '-') return -1;
	switch (*p) {
	case 'J': /* Jan, Jun, Jul */
		if (p[1] == 'a') { tm.tm_mon = 1; }
		else { tm.tm_mon = (p[2] == 'n') ? 6 : 7; }
		break;
	case 'F': /* Feb */ tm.tm_mon = 2;	break;
	case 'M': /* Mar, May */ tm.tm_mon = (p[2] == 'r') ? 3 : 5;	break;
	case 'A': /* Apr, Aug */ tm.tm_mon = (p[1] == 'p') ? 4 : 8; break;
	case 'S': /* Sep */ tm.tm_mon = 9;  break;
	case 'O': /* Oct */ tm.tm_mon = 10; break;
	case 'N': /* Nov */ tm.tm_mon = 11; break;
	case 'D': /* Dec */ tm.tm_mon = 12; break;
	default:	    return 0;
	}
	tm.tm_mon--;
	p += 4;
	tm.tm_year = parse_decimal4(p) - 1900;
	if (tm.tm_year < 0 || p[4] != ' ') return 0;
	p += 5;
	tm.tm_hour = parse_decimal2(p);
	if (tm.tm_hour < 0 || tm.tm_hour > 23 || p[2] != ':') return 0;
	p += 3;
	tm.tm_min = parse_decimal2(p);
	if (tm.tm_min < 0 || tm.tm_min > 60 || p[2] != ':') return 0;
	p += 3;
	tm.tm_sec = parse_decimal2(p);
	if (tm.tm_sec < 0 || tm.tm_sec >= 60 || p[2] != '.') return 0;
	p += 3;
	msec = parse_decimal3(p);
	if (msec < 0 || p[3] != ' ') return -1;

	return mktime(&tm) * 1000000 + msec * 1000;
}

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
#define	LINKTYPE_OPENBSD_LOOP	108

u_short swap16(u_short x)
{
	return ((x & 0xff) << 8) | (x >> 8);
}

u_long swap32(u_int32_t x)
{
	return ((x & 0xff) << 24)
	       | ((x & 0xff00) << 8)
	       | ((x & 0xff000) >> 8)
	       | ((x & 0xff000000) >> 24);
}

typedef struct pcap_result {
	long long start;
	long long end;
	long long count;
	long long size;
	long long readsize;
} pcap_result;

void _parse_file(FILE *fp, pcap_result *result)
{
	struct pcap_header ph;
	struct pcap_file_header pf;
	int needswap = 0;
	int len;
	long long offset = 0;
	long long date;
	u_char raw[65536];

	len = fread(&pf, 1, sizeof(pf), fp);
	result->readsize = len;

 	if (len == 0) {
		if (len == 0) return;
	}
	if (len != sizeof(pf)) {
		return;
	}
	if (pf.magic == 0xa1b2c3d4) { /* OK */
		needswap = 0;
	} else
	if (pf.magic == 0xd4c3b2a1) {
		needswap = 1;
	} else { /* Query Log mode */
		memcpy(raw, &pf, len);
		if (fgets((char *)(raw + len), sizeof(raw)-len, fp) == NULL) {
			return;
		}
		if (!isdigit(raw[0]))
			return;
		if ((result->start = parse_line(raw)) <= 0)
			return;
		while(fgets((char *)raw, sizeof(raw), fp) != NULL) {
			if ((date = parse_line(raw)) > 0) {
				result->end = date;
			}
		}
		return;
	}
	if (needswap) {
		pf.version_major = swap16(pf.version_major);
		pf.version_minor = swap16(pf.version_minor);
		pf.thiszone = swap32(pf.thiszone);
		pf.sigfigs = swap32(pf.sigfigs);
		pf.snaplen = swap32(pf.snaplen);
		pf.linktype = swap32(pf.linktype);
	}
	result->start = 0;
	while((len = fread(&ph, 1, sizeof(ph), fp)) == sizeof(ph)) {
		result->readsize += len;
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
		//printf("pakcet:%lld.%06ld %d %d\n", ph.ts.tv_sec, ph.ts.tv_usec, ph.caplen, ph.len);
		if (ph.caplen > 2000 || ph.len > 2000 || ph.caplen < 0 || ph.len < 0) {
			break;
		}
		if ((len = fread(raw, 1, ph.caplen, fp)) != ph.caplen) {
			break;
		}
		result->readsize += len;
		result->end = ph.ts.tv_sec * 1000000LL + ph.ts.tv_usec;
		if (result->start == 0) { result->start = result->end; }
		result->count++;
	}
}

void parse_file(char *file, pcap_result *result)
{
	FILE *fp;
	int len;
	int close_status = 0;
	struct stat sb;
	char buff[1024];

	if (stat(file, &sb) == 0) {
		result->size = sb.st_size;
	}
	len = strlen(file);
	if (len > 4 && strcmp(file+len-4, ".bz2") == 0) {
		snprintf(buff, sizeof buff, "bzip2 -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return;
		_parse_file(fp, result);
		close_status = pclose(fp);
	} else
	if (len > 3 && strcmp(file+len-3, ".gz") == 0) {
		snprintf(buff, sizeof buff, "gzip -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return;
		_parse_file(fp, result);
		close_status = pclose(fp);
	} else
	if (len > 3 && strcmp(file+len-3, ".xz") == 0) {
		snprintf(buff, sizeof buff, "xz -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return;
		_parse_file(fp, result);
		close_status = pclose(fp);
	} else {
		if ((fp = fopen(file, "r")) == NULL)
			return;
		_parse_file(fp, result);
		close_status = fclose(fp);
	}
}

int main(int argc, char *argv[])
{
	pcap_result t;
	int i;

	// printf("#filename,#start,#end,#filesize,#readsize\n");
	for (i = 1; i < argc; i++) {
		memset(&t, 0, sizeof(t));
		parse_file(argv[i], &t);
		if (t.start <= 0 || t.end <= 0) { t.start = -1; t.end = -1; }
		printf("%s,%lld,%lld,%lld,%lld,%lld\n", argv[i], t.start, t.end, t.count, t.size, t.readsize);
		fflush(stdout);
	}
	return 0;
}

