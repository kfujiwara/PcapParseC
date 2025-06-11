/*
	$Id: test_addrport_match.c,v 1.2 2025/05/30 08:02:34 fujiwara Exp $

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

#include "addrport_match.h"

#define ENVNAME "PCAPGETQUERY_ENV"

static struct ipaddr_port_list list = { NULL, 0};

void usage(int c)
{
	printf("test_addrport_match -a ipaddr_port_mask -I ipaddr_port_mask_file\n"
"  -a ipaddr[#port],ipaddr/mask...   set ipaddress match list client side\n"
"  -I file      Load IPaddrlist into list1\n");

	exit(0);
}

int main(int argc, char *argv[])
{
	int len;
	int ret;
	char *p;
	int port;
	int i, ch;
	struct ipaddr_hash *e;
	u_char addr[18];
	char buff2[1000];

	while ((ch = getopt(argc, argv, "vB:E:O:E:46a:b:f:t:FI:SsHL:TUn:QRe:")) != -1) {
	switch (ch) {
	case 'a':
		register_ipaddr_port_hash(optarg, &list, 1);
		break;
	case 'I': load_ipaddrlist(optarg, &list); break;
	default:
		usage(ch);
	}}
	argc -= optind;
	argv += optind;

	register_ipaddr_port_hash("2001:db8:1111::/48", &list, 1);
	register_ipaddr_port_hash("2001:db8::1#53", &list, 1);
	register_ipaddr_port_hash("10.0.0.0/8", &list, 1);
	register_ipaddr_port_hash("192.0.2.1#53", &list, 1);

	print_ipaddrlist_hash(&list);

	while (fgets(buff2, sizeof buff2, stdin) != NULL) {
		len = strlen(buff2);
		if (len > 0 && buff2[len-1] == '\n') {
			buff2[len-1] = 0;
		}
		p = strchr(buff2, '#');
		port = 53;
		if (p != NULL && *p =='#') {
			port = atoi(p+1);
			*p = 0;
		}
		addr[0] = port >> 8;
		addr[1] = port & 0xff;
		p = strchr(buff2, ':');
		if (inet_pton(p==NULL?AF_INET:AF_INET6, buff2, addr+2) == 0)
			printf("Error: %s is not ip addr, port=%d\n", buff2, port);
		else {
			e = match_ipaddr_port(&list, addr, p==NULL?4:16);
			if (e == NULL) { printf("NotMatch\n"); }
			else {
				printf("Match: klen=%d [ ", e->klen);
				for (i = 0; i < e->klen; i++) printf("%02x ", e->addr[i]);
				printf("]\n");
			}
		}
	}
	exit(0);
}
