/*
	$Id: parse_file.c,v 1.246 2025/05/08 05:02:07 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

	int parse_files(char *file, struct DNSdataControl* c) reads
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
		    int ret = parse_files(*argv, &c);
		    argv++;
		}
		print_result();
	    }

*/



#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#include "ext/uthash.h"

#include "config.h"
#include "mytool.h"
#include "pcapparse.h"
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

static char testdatahead[] = TESTDATA_HEAD;

int _parse_files(FILE *fp, struct DNSdataControl* c, int pass)
{
	struct pcap_header ph;
	struct pcap_file_header pf;
	u_char *p;
	int plen;
	int error;
	int rest;
	int needswap = 0;
	int len;
	long long offset = 0;

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
		return parse_pcap(fp, c, (u_char *)&pf, needswap);
	case 0x0a0d0d0a: // pcapng mode
		if (pass != 0) return ParsePcap_ForceClose;
		c->input_type = INPUT_TYPE_PCAP;
		return parse_pcapng(fp, c, (u_char *)&pf);
	default: // Query Log mode
		c->input_type = INPUT_TYPE_QUERYLOG;
		memcpy(c->raw, &pf.magic, len);
		if (fgets((char *)(c->raw + len), c->rawlen - len, fp) == NULL) {
			return ParsePcap_ERROR_BogusSavefile;
		}
		if (memcmp(c->raw, testdatahead, sizeof(testdatahead)-1) == 0) {
			if (pass == 0) _parse_testdata(fp, c);
		} else if (c->raw[0] == '{') {
			if (pass == 0) _parse_dnsjson(fp, c);
		} else if (isdigit(c->raw[0])) {
			if (pass == 0) _parse_bind9log(fp, c);
		} else
		if (c->otherdata != NULL) {
			c->input_type = INPUT_TYPE_OTHERDATA;
			return c->otherdata(fp, c, pass);
		}
		return 0;
	}
}

static struct compressed_files
{ char *extention;char *extractcmd; } compressed_files[] = {
	{ ".gz", "gzip -cd %s" },
	{ ".zst", "zstd -cd %s" },
	{ ".xz", "xz -cd %s" },
	{ ".bz2", "bzip2 -cd %s" },
	{ NULL, NULL }
};

int parse_file(char *file, struct DNSdataControl* c, int pass)
{
	FILE *fp;
	int len, extlen, ret;
	int close_status = 0;
	char buff[1024];
	struct compressed_files *cp = compressed_files;
	struct stat sb;

	c->input_type = INPUT_TYPE_NONE;
	c->file_size = 0;
	c->open_time = now();
	if (file == NULL)
		return _parse_files(stdin, c, pass);
	c->filename = file;
	c->lineno = 0;
	if (stat(file, &sb) == 0) {
		c->file_size = sb.st_size;
	}
	buff[0] = 0;
	len = strlen(file);
	while (cp->extention != NULL) {
		extlen = strlen(cp->extention);
		if (len>extlen && strcmp(file+len-extlen, cp->extention) == 0) {
			snprintf(buff, sizeof buff, cp->extractcmd, file);
			if ((fp = popen(buff, "r")) == NULL)
				return ParsePcap_ERROR_FILE_OPEN;
			ret = _parse_files(fp, c, pass);
			close_status = pclose(fp);
			break;
		}
		cp++;
	}
	if (cp->extention == NULL) {
		if ((fp = fopen(file, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_files(fp, c, pass);
		close_status = fclose(fp);
	}
	if (ret == 0 && close_status > 0) {
		fprintf(stderr, "pclose_returned=%d cmd=%s errno=%d\n", close_status, buff[0]==0?file:buff, errno);
		return ParsePcap_ERROR_COMMAND;
	}
	return ret;
}
