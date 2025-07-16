/*
	$Id: pcapinfo2.c,v 1.1 2025/07/15 10:32:35 fujiwara Exp $

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
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <errno.h>

#include "config.h"
#include "pcap_data.h"
#include "dns_string.h"
#include "mytool.h"

/*****************************************************************************
	 Warning
			Little endian only
			Supported Linktype: 0==PPP	1==Ether
 *****************************************************************************
 */

#define parse_decimal2(x) ((x[0]<'0'||x[0]>'9'||x[1]<'0'||x[1]>'9')?-1:(x[0]-'0')*10+x[1]-'0')
#define parse_decimal3(x) ((x[0]<'0'||x[0]>'9'||x[1]<'0'||x[1]>'9'||x[2]<'0'||x[2]>'9')?-1:(x[0]-'0')*100+(x[1]-'0')*10+x[2]-'0')
#define parse_decimal4(x) ((x[0]<'0'||x[0]>'9'||x[1]<'0'||x[1]>'9'||x[2]<'0'||x[2]>'9'||x[3]<'0'||x[3]>'9')?-1:(x[0]-'0')*1000+(x[1]-'0')*100+(x[2]-'0')*10+x[3]-'0')

long long parse_line(char *input)
{
	char *p, *q, *r;
	int msec;
	double d;
	struct tm tm;

	if (input[0] == '{') {
		p = input;
		while (p != NULL && (p = strchr(p, '"')) != NULL) {
			if (strncmp(p+1, "timestamp-rfc3339ns\":\"", 22) == 0) {
				return str2unixlltime(p + 23);
			}
			p = strchr(p, ',');
		}
		return 0;
	}
	p = input;
	memset(&tm, 0, sizeof(tm));
	tm.tm_mday = parse_decimal2(p);
	if (tm.tm_mday < 0 || tm.tm_mday > 31 || p[2] != '-') return 0;
	p += 3;
	if (p[0] == 0 || p[1] == 0 || p[2] == 0 || p[3] != '-') return 0;
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
	if (msec < 0 || p[3] != ' ') return 0;

	return mktime(&tm) * 1000000 + msec * 1000;
}

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
	long long mtime;
	char *type;
	long long start;
	long long end;
	long long count;
	long long size;
	long long readsize;
	char hash[512];
} pcap_result;

int read_pcap(FILE *fp, pcap_result *result, int needswap)
{
	struct pcap_header ph;
	int len;
	u_char buff[65536];

	result->start = 0;
	while((len = fread(&ph, 1, sizeof(ph), fp)) == sizeof(ph)) {
		result->readsize += len;
		if (ph.len == 0 || ph.caplen == 0) {
			ph.ts.tv_usec = ph.caplen;
			len = fread(&ph.caplen, 1, 8, fp);
			if (len != 8) { break; }
			result->readsize += len;
		}
		if (needswap) {
			ph.caplen = swap32(ph.caplen);
			ph.len = swap32(ph.len);
			ph.ts.tv_sec = swap32(ph.ts.tv_sec);
			ph.ts.tv_usec = swap32(ph.ts.tv_usec);
		}
		//printf("pakcet:%lld.%06ld %d %d\n", ph.ts.tv_sec, ph.ts.tv_usec, ph.caplen, ph.len);
		if (ph.caplen > 2000 || ph.len > 2000 || ph.caplen < 0 || ph.len < 0) {
			return -1;
		}
		if ((len = fread(buff, 1, ph.caplen, fp)) != ph.caplen) {
			return -1;
		}
		result->readsize += len;
		result->end = ph.ts.tv_sec * 1000000LL + ph.ts.tv_usec;
		if (result->start == 0) { result->start = result->end; }
		result->count++;
	}
	return 0;
}

int read_pcapng(FILE *fp, struct pcap_file_header *pf, pcap_result *result)
{
	struct pcapng_section_header3 *png3p =
	       (struct pcapng_section_header3 *)(pf);
	struct pcapng_section_header2 png2;
	struct pcapng_type6 *png6p;
	int len;
	int rest;
	int type;
	int needswap;
	time_t tt;
	long long t64;
	u_char buff[65536];

	result->start = 0;
	//printf("magic=%lx length=%lx\n", png3p->magic, png3p->length);
	if (png3p->magic == 0x1a2b3c4d) {
		needswap = 0;
	} else {
		needswap = 1;
	}
	rest = needswap ? swap32(png3p->length) : png3p->length;
	rest -= len;
	//printf("needswap=%d rest=%d\n", needswap, rest);
	if (fread(buff, 1, rest, fp) != rest) {
		return -1;
	}
	while((len = fread(&png2, 1, sizeof(png2), fp)) == sizeof(png2)) {
		rest = needswap ? swap32(png2.length) : png2.length;
		rest -= sizeof(png2);
		type = needswap ? swap32(png2.block_type) : png2.block_type;
		len = fread(buff, 1, rest, fp);
		if (len != rest) return -1;
		//printf("type=%d len=%d\n", type, len);
		//hexdump("data", c->raw, rest);
		if (type == 6) {
			png6p = (struct pcapng_type6 *)&buff;
			t64 = ((unsigned long long)(needswap?swap32(png6p->tv_h):png6p->tv_h) << 32) + (needswap?swap32(png6p->tv_l):png6p->tv_l);
			result->readsize += len;
			result->end = t64;
			if (result->start == 0) { result->start=result->end; }
			result->count++;
		}
	}
	return 0;
}

#define	NBUFF 10
#define	BSIZE 65536

int _parse_file(FILE *fp, pcap_result *result)
{
	struct pcap_file_header pf;
	int needswap = 0;
	int len;
	int rest;
	long long tt;
	int max = 0;
	int i;
	char *raw[NBUFF];

	for (i = 0; i < NBUFF; i++)
		if ((raw[i] = malloc(BSIZE)) == NULL) return -1;
	len = fread(&pf, 1, sizeof(pf), fp);
	result->readsize = len;

 	if (len == 0) {
		if (len == 0) return -1;
	}
	if (len != sizeof(pf)) {
		return -1;
	}
	needswap = 0;
	switch(pf.magic) {
	case 0xd4c3b2a1:
		needswap = 1;
	case 0xa1b2c3d4:
		result->type = "pcap";
		return read_pcap(fp, result, needswap);
		break;
	case 0x0a0d0d0a: // pcapng mode
		result->type = "pcapng";
		return read_pcapng(fp, &pf, result);
		break;
	}
	/* Text mode */
	memcpy(raw[0], &pf, len);
	if (fgets((char *)(raw[0] + len), BSIZE-len, fp) == NULL) return -1;
	result->readsize = strlen(raw[0]);
	result->count++;
	if (isdigit(raw[0][0]) || raw[0][0] == '{') { // query log or json mode
		if ((result->start = parse_line(raw[0])) <= 0)
			return -1;
		result->type = (raw[0][0] == '{')? "dnstap":"querylog";
		i = NBUFF-1;
		while(i-- > 0 && fgets(raw[0], BSIZE, fp) != NULL) {
			result->readsize += strlen(raw[0]);
			result->count++;
			if ((tt = parse_line(raw[0])) <= 0) return -1;
			if (result->start > tt) result->start = tt;
			if (result->end < tt) result->end = tt;
		}
		max = 0;
		i = 0;
		while(fgets(raw[i], BSIZE, fp) != NULL) {
			result->readsize += strlen(raw[i]);
			result->count++;
			i = (i + 1) % NBUFF;
			if (max < i) max = i;
		}
		for (i = 0; i < max; i++) {
			if ((tt = parse_line(raw[i])) > 0) {
				if (result->end < tt) result->end = tt;
			}
		}
		return -1;
	}
	return -1;
}

static struct compressed_files
{ char *extention;char *extractcmd; } compressed_files[] = {
	{ ".gz", "gzip -cd %s" },
	{ ".zst", "zstd -cd %s" },
	{ ".xz", "xz -cd %s" },
	{ ".bz2", "bzip2 -cd %s" },
	{ NULL, NULL }
};

int parse_file(char *file, pcap_result *result)
{
	FILE *fp;
	int len, extlen, ret;
	int close_status = 0;
	struct compressed_files *cp = compressed_files;
	char *p;
	struct stat sb;
	char buff[1024];

	if (stat(file, &sb) == 0) {
		result->size = sb.st_size;
		result->mtime = sb.st_mtim.tv_sec * 1000000 + sb.st_mtim.tv_nsec / 1000;
	}
	len = strlen(file);
	while (cp->extention != NULL) {
		extlen = strlen(cp->extention);
		if (len>extlen && strcmp(file+len-extlen, cp->extention) == 0) {
			snprintf(buff, sizeof buff, cp->extractcmd, file);
			if ((fp = popen(buff, "r")) == NULL)
				ret = -1;
			else {
				ret = _parse_file(fp, result);
				close_status = pclose(fp);
			}
			break;
		}
		cp++;
	}
	if (cp->extention == NULL) {
		if ((fp = fopen(file, "r")) == NULL)
			ret = -1;
		else {
			ret = _parse_file(fp, result);
			close_status = fclose(fp);
		}
	}
	if (ret == 0 && close_status > 0)
		fprintf(stderr, "fclose_returned:%d/%d:%s errno=%d\n", close_status, ret, file, errno);
	snprintf(buff, sizeof buff, "openssl sha256 -r %s", file);
	result->hash[0] = 0;
	if ((fp = popen(buff, "r")) == NULL)
		ret = -1;
	else {
		if (fgets(buff, sizeof buff, fp) != NULL) {
			p = strchr(buff, ' ');
			if (p != NULL) {
				*p = 0;
				strncpy(result->hash, buff, sizeof(result->hash));
			}
		}
		close_status = pclose(fp);
	}
	return ret;
}

int main(int argc, char *argv[])
{
	pcap_result t;
	int i;
	int r;
	double v1, v2, v3, v4;
	long long tt1, tt2;

	// printf("#filename,#start,#end,#filesize,#readsize\n");
	for (i = 1; i < argc; i++) {
		memset(&t, 0, sizeof(t));
		t.type = "";
		tt1 = now();
		r = parse_file(argv[i], &t);
		tt2 = now() - tt1;
		if (tt2 == 0) tt2 = 1;
		printf("%s,%s,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%s\n", argv[i], t.type, t.start, t.end, t.count, t.size, t.readsize, tt2, t.mtime, t.hash);
		v1 = tt2 / 1000000.0;
		v2 = t.count / v1;
		v3 = t.readsize / v1 / 1024 / 1024;
		v4 = t.size / v1 / 1024 / 1024;
		fprintf(stderr, "Loaded %lld data from %s, %.2f sec, %.1f data/sec, %.1f (%.1f) MB/sec\n", t.count, argv[i], v1, v2, v3, v4);
		fflush(stdout);
	}
	return 0;
}

