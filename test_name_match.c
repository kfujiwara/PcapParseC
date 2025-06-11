/*
	$Id: test_name_match.c,v 1.4 2025/06/04 09:47:34 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

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
#include "pcapparse.h"
#include "name_match.h"

static struct name_list list = { NULL, 0};

void usage(int c)
{
	printf("test_name_match -a names -I names_file\n"
"  -a names,names,..   set name list\n"
"  -I file      Load name list file into list1\n");

	exit(0);
}

int main(int argc, char *argv[])
{
	int len;
	int ret;
	char *p;
	int port;
	int i, ch;
	struct name_hash *e;
	char *buff;
	struct DNSdataControl c;

	while ((ch = getopt(argc, argv, "vB:E:O:E:46a:b:f:t:FI:SsHL:TUn:QRe:")) != -1) {
	switch (ch) {
	case 'a':
		register_name_list(optarg, &list, 1);
		break;
	case 'I': load_name_list(optarg, &list); break;
	default:
		usage(ch);
	}}
	argc -= optind;
	argv += optind;

	//register_name_list("example", &list, 1);
	//register_name_list("resolver.arpa", &list, 1);

	print_name_list(&list);

	buff = c.dns.qname;
	while (fgets(buff, PcapParse_DNAMELEN, stdin) != NULL) {
		len = strlen(buff);
		if (len > 0 && buff[len-1] == '\n') {
			buff[len-1] = 0;
		}
		prepare_dns_substring(&c);
		e = match_name(&list, &c);
		if (e == NULL) { printf("NotMatch\n"); }
		else {
			printf("Match: name=%s\n", e->name);
		}
	}
	exit(0);
}
