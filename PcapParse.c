/*
	$Id: PcapParse.c,v 1.234 2024/05/09 15:15:28 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

	int parse_pcap(char *file, struct DNSdataControl* c) reads
	pcap files or BIND 9 log files (with/without gzip/bzip2/xz) and
	calls callback function.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.

        How to use: write a code and link with PcapParse.c.

	Example code:

	    #include "PcapParse.h"

	    int counter = 0;

	    int callback(struct DNSdataControl *c, int mode)
	    {
		c->dns contains DNS query information. see PcapParse.h
		if (c->dns._rd) counter++;
	    }
	    void print_result()
	    {
		printf("Num of RD1 = %d\n", counter);
	    }
	    main(int argc, char **argv) {
		struct DNSdataControl c;
		c.callback = callback;
		c.otherdata = NULL; // other data loader function
		c.debug = 0; // Flags
		while(*argv) {
		    int ret = parse_pcap(*argv, &c);
		    argv++;
		}
		print_result();
	    }

*/


#include "config.h"

#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "ext/uthash.h"
#include "mytool.h"
#include "PcapParse.h"
#include "pcap_data.h"
#include "parse_L3.h"
#include "parse_int.h"
#include "parse_testdata.h"

/* Ignore UDP fragment */
/* parse query packet only */

/*****************************************************************************
	 Warning
			Little endian only
			Supported Linktype: 0==PPP	1==Ether
 *****************************************************************************
 */

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

static char testdatahead[] = TESTDATA_HEAD;

int _parse_pcap(FILE *fp, struct DNSdataControl* c, int pass)
{
	struct pcap_header ph;
	struct pcap_file_header pf;
	struct pcapng_section_header2 png2;
	struct pcapng_section_header3 *png3p;
	struct pcapng_type6 *png6p;
	struct pcapng_type1 *png1p;
	u_char *p;
	int plen;
	int error;
	int rest;
	int needswap = 0;
	int len;
	int type;
	long long offset = 0;
	unsigned long long t64;

	c->ParsePcapCounter._numfiles++;
	len = fread(&pf, 1, PCAP_FIRST_READ, fp);
	offset = len;

 	if (len == 0) {
		if (len == 0) return 0; /* Ignore */
#if 0
		if (c->debug & FLAG_INFO) printf("#Empty:Empty");
		return ParsePcap_ERROR_Empty;
#endif
	}
	if (len != PCAP_FIRST_READ) {
		if (c->debug & FLAG_INFO) printf("#Empty:ERROR: short read: pcap_file_header");
		return ParsePcap_ERROR_BogusSavefile;
	}
	//hexdump("head", &pf, 12);
	needswap = 0;
	switch(pf.magic) {
	case 0xd4c3b2a1: // pcap mode big endian
		needswap = 1;
	case 0xa1b2c3d4: // pcap mode
		if (pass != 0) return ParsePcap_ForceClose;
		c->input_type = INPUT_TYPE_PCAP;
		p = (u_char *)&pf;
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
				if (c->debug & FLAG_INFO) printf("#Error:Short read buffer: %d != %d", len, ph.caplen);
				return ParsePcap_ERROR_ShortRead;
			}
			offset += len;
			c->caplen = len;
			c->l2 = c->raw;
			//hexdump("fread", c->raw, c->caplen);
			error = parse_L2(&ph, c);
			if (error != 0) return error;
		}
		if (len == 0) return 0;
		if (c->debug & FLAG_INFO)
			printf("#Error:short read: %s\n",
				(len == sizeof ph) ? "Packet data":"Pcap header");
		return ParsePcap_ERROR_ShortRead;
	case 0x0a0d0d0a: // pcapng mode
		if (pass != 0) return ParsePcap_ForceClose;
		c->input_type = INPUT_TYPE_PCAP;
		png3p = (struct pcapng_section_header3 *)(&pf);
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
				error = parse_L2(&ph, c);
				if (error != 0) return error;
			} else if (type == 1) {
				png1p = (struct pcapng_type1 *)c->raw;
				c->linktype = needswap?swap16(png1p->linktype):png1p->linktype;
				fprintf(stderr, "linktype=%d\n", c->linktype);
			}
		}
		return 0;
	default: // Query Log mode
		c->input_type = INPUT_TYPE_QUERYLOG;
		memcpy(c->raw, &pf.magic, len);
		if (fgets((char *)(c->raw + len), c->rawlen - len, fp) == NULL) {
			return ParsePcap_ERROR_BogusSavefile;
		}
		if (memcmp(c->raw, testdatahead, sizeof(testdatahead)-1) == 0) {
			if (pass == 0) _parse_testdata(fp, c);
		} else if (isdigit(c->raw[0]))
			_parse_bind9log(fp, c);
		else
		if (c->otherdata != NULL) {
			c->input_type = INPUT_TYPE_OTHERDATA;
			return c->otherdata(fp, c, pass);
		}
		return 0;
	}
}

int parse_pcap(char *file, struct DNSdataControl* c, int pass)
{
	int ret;
	FILE *fp;
	int len;
	int close_status = 0;
	char buff[256];

	c->input_type = INPUT_TYPE_NONE;
	if (file == NULL)
		return _parse_pcap(stdin, c, pass);
	c->filename = file;
	c->lineno = 0;
	len = strlen(file);
	if (len > 3 && strcmp(file+len-3, ".gz") == 0) {
		snprintf(buff, sizeof buff, "gzip -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c, pass);
		close_status = pclose(fp);
		if (ret == ParsePcap_ForceClose && close_status > 0) return 0;
	} else
	if (len > 3 && strcmp(file+len-3, ".xz") == 0) {
		snprintf(buff, sizeof buff, "xz -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c, pass);
		close_status = pclose(fp);
		if (ret == ParsePcap_ForceClose && close_status > 0) return 0;
	} else if (len > 4 && strcmp(file+len-4, ".zst") == 0) {
		snprintf(buff, sizeof buff, "zstd -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c, pass);
		close_status = pclose(fp);
		if (ret == ParsePcap_ForceClose && close_status > 0) return 0;
	} else if (len > 4 && strcmp(file+len-4, ".bz2") == 0) {
		snprintf(buff, sizeof buff, "bzip2 -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c, pass);
		close_status = pclose(fp);
		if (ret == ParsePcap_ForceClose && close_status > 0) return 0;
	} else {
		if ((fp = fopen(file, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c, pass);
		close_status = fclose(fp);
	}
	if (ret == 0 && close_status > 0) {
		fprintf(stderr, "fclose_returned:%d/%d:%s errno=%d\n", close_status, ret, file, errno);
		return ParsePcap_ERROR_COMMAND;
	}
	return ret;
}

