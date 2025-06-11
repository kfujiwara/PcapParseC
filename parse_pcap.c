/*
	$Id: parse_pcap.c,v 1.9 2025/05/29 09:30:52 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "config.h"
#include "mytool.h"
#include "ext/uthash.h"
#include "pcapparse.h"
#include "pcap_data.h"
#include "parse_L3.h"

u_short swap16(u_short x)
{
	return ((x & 0xff) << 8) | (x >> 8);
}

u_long swap32(u_int32_t x)
{
	return ((x & 0xff) << 24)
	       | ((x & 0xff00) << 8)
	       | ((x & 0xff0000) >> 8)
	       | ((x & 0xff000000) >> 24);
}

int parse_pcap(FILE *fp, struct DNSdataControl *c, u_char *pcap_first_read, int needswap)
{
	u_char *p;
	int plen, len, count, error;
	long long tt1, tt2, tt3, offset;
	long long npackets = 0;
	struct pcap_header ph;
	struct pcap_file_header pf;
	double v1, v2, v3, v4;

	tt1 = now();
	count = 0;
	p = (u_char *)&pf;
	memcpy(p, pcap_first_read, PCAP_FIRST_READ);
	p += PCAP_FIRST_READ;
	plen = sizeof(pf) - PCAP_FIRST_READ;
	len = fread(p, 1, plen, fp);
	offset += len;
	if (len != plen) return 0; /* Ignore */
	if (needswap) {
		pf.version_major = swap16(pf.version_major);
		pf.version_minor = swap16(pf.version_minor);
		pf.thiszone = swap32(pf.thiszone);
		pf.sigfigs = swap32(pf.sigfigs);
		pf.snaplen = swap32(pf.snaplen);
		pf.linktype = swap32(pf.linktype);
	}
	c->linktype = pf.linktype;
	if (c->debug & FLAG_DUMP) {
		hexdump("pcap_file_header", (u_char *)&pf, sizeof(pf));
		printf("magic = %08x  version=%d.%d  thiszone=%d  sigflag=%d\n",
			pf.magic, pf.version_major, pf.version_minor,
			pf.thiszone, pf.sigfigs);
		printf("snaplen=%d  linktype=%d  needswap=%d\n", pf.snaplen, pf.linktype, needswap);
	}
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
		if (c->debug & FLAG_DUMP) {
			printf("time=%u.%06u  caplen=%d  len=%d\n", ph.ts.tv_sec, ph.ts.tv_usec, ph.caplen, ph.len);
			hexdump("pcap_header", (u_char *)&ph, len);
		}
		if (ph.caplen > 65535 || ph.len > 65535 || ph.caplen < 0) {
			printf("#Error:bogus savefile header:short read or broken ph.caplen=%d, ph.len=%d, offset=%lld\n", ph.caplen, ph.len, offset);
			return 0;
		}
		if ((len = fread(c->raw, 1, ph.caplen, fp)) != ph.caplen) {
			if (c->debug & FLAG_INFO) printf("#Error:Short read buffer: %d != %d\n", len, ph.caplen);
			return ParsePcap_ERROR_ShortRead;
		}
		offset += len;
		c->caplen = len;
		c->l2 = c->raw;
		npackets++;
		//hexdump("fread", c->raw, c->caplen);
		error = parse_L2(&ph, c);
#if 0
		if ((npackets % 1000000) == 0) {
			tt2 = now() - tt1;
			if (tt2 == 0) tt2 = 1;
			v1 = tt2 / 1000000.0;
			v2 = npackets / v1;
			fprintf(stderr, "Loaded %lld packets from %s, %.2f sec, %.1f packets/sec\n", npackets, c->filename, v1, v2);
			fflush(stderr);
		}
#endif
		if (error != 0) return error;
	}
			tt2 = now() - tt1;
			if (tt2 == 0) tt2 = 1;
			v1 = tt2 / 1000000.0;
			v2 = npackets / v1;
			v3 = offset / v1 / 1024.0/1024.0;
			v4 = c->file_size / v1 / 1024.0/1024.0;
			fprintf(stderr, "Loaded %lld packets from %s, %.1f sec, %.1f packets/sec, %.1f (%.1f) MB/s\n",
				npackets, c->filename, v1, v2, v3, v4);
			fflush(stderr);
	if (len == 0) return 0;
	if (c->debug & FLAG_INFO) {
		printf("#Error:short read: %s\n",
			(len == sizeof ph) ? "Packet data":"Pcap header");
	}
	return ParsePcap_ERROR_ShortRead;
}

int parse_pcapng(FILE *fp, struct DNSdataControl *c, u_char *pcap_first_read)
{
	int needswap, rest, len, type,error;
	unsigned long long t64;
	long long offset;
	struct pcapng_section_header2 png2;
	struct pcapng_section_header3 *png3p;
	struct pcapng_type6 *png6p;
	struct pcapng_type1 *png1p;
	struct pcap_header ph;

	png3p = (struct pcapng_section_header3 *)pcap_first_read;
	//printf("magic=%lx length=%lx\n", png3p->magic, png3p->length);
	if (png3p->magic == 0x1a2b3c4d) {
		needswap = 0;
	} else {
		needswap = 1;
	}
	rest = needswap ? swap32(png3p->length) : png3p->length;
	rest -= len;
	//printf("needswap=%d rest=%d\n", needswap, rest);
	if (fread(&c->raw, 1, rest, fp) != rest) {
		return ParsePcap_ERROR_BogusSavefile;
	}
	while((len = fread(&png2, 1, sizeof(png2), fp)) == sizeof(png2)) {
		offset += len;
		rest = needswap ? swap32(png2.length) : png2.length;
		rest -= sizeof(png2);
		type = needswap ? swap32(png2.block_type) : png2.block_type;
		len = fread(c->raw, 1, rest, fp);
		if (len != rest) return ParsePcap_ERROR_BogusSavefile;
		//printf("type=%d len=%d\n", type, len);
		//hexdump("data", c->raw, rest);
		if (type == 6) {
			png6p = (struct pcapng_type6 *)c->raw;
			ph.caplen = needswap?swap32(png6p->caplen):png6p->caplen;
			ph.len = needswap?swap32(png6p->len):png6p->len;
			t64 = ((unsigned long long)(needswap?swap32(png6p->tv_h):png6p->tv_h) << 32) + (needswap?swap32(png6p->tv_l):png6p->tv_l);
			ph.ts.tv_sec = t64 / 1000000;
			ph.ts.tv_usec = t64 % 1000000;
			//printf("t64=%lld tv_sec=%d:%06d len=%d caplen=%d\n", t64, ph.ts.tv_sec, ph.ts.tv_usec, png6p->len, png6p->caplen);
			c->l2 = c->raw + 20;
			c->caplen = ph.caplen;
			if (ph.caplen > 65535 || ph.len > 65535 || ph.caplen < 0) {
				printf("#Error:bogus savefile header:short read or broken ph.caplen=%d, ph.len=%d, offset=%lld\n", ph.caplen, ph.len, offset);
				return 0;
			}
			c->ParsePcapCounter._pcap++;
			error = parse_L2(&ph, c);
			if (error != 0) return error;
		} else if (type == 1) {
			png1p = (struct pcapng_type1 *)c->raw;
			c->linktype = needswap?swap16(png1p->linktype):png1p->linktype;
			fprintf(stderr, "linktype=%d\n", c->linktype);
		}
	}
	return 0;
}
