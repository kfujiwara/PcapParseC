/*
	$Id: load_ipv6list.h,v 1.4 2024/10/07 03:36:18 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2013 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

struct ipv6_prefix_hash
{
	uint64_t prefix;
	int count;
	int used;
	unsigned int *sump;
	uint64_t *suffix;
	u_char *endp;
	UT_hash_handle hh;
};

struct ipv6_prefix_hash *load_ipv6_prefix_list(char *filename);
void print_ipv6_prefix_hash(struct ipv6_prefix_hash *h);

#define IPV6_PREFIX_HASH
