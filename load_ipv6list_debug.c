/*
	$Id: load_ipv6list_debug.c,v 1.2 2024/10/07 03:36:18 fujiwara Exp $

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
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <assert.h>
#include <arpa/inet.h>

#include "ext/uthash.h"
#include "load_ipv6list.h"
#include "mytool.h"

char *hex64str(char *buff, int len, u_char *addr)
{
	snprintf(buff, len, "%02x%02x:%02x%02x:%02x%02x:%02x%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
	return buff;
}

void print_ipv6_prefix_hash(struct ipv6_prefix_hash *hash)
{
	int i;
	struct ipv6_prefix_hash *e,*f;
	int printed = 0;
	u_char addr1[16];
	u_char addr2[16];

	char str1[INET6_ADDRSTRLEN+1];
	char str2[INET6_ADDRSTRLEN+1];
	
	HASH_ITER(hh, hash, e, f) {
		for (i = 0; i < e->used; i++) {
			printf("%s::,%d,::%s,%d\n",
				hex64str(str1, sizeof str1, (u_char *)&e->prefix),
				i,
				hex64str(str2, sizeof str2, (u_char *)&e->suffix[i]),
				e->sump[i]);
		}
	}
}

int main(int argc, char *argv[])
{
	struct ipv6_prefix_hash *h;

	h = load_ipv6_prefix_list(argv[1]);
	print_ipv6_prefix_hash(h);
}
