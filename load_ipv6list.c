/*
	$Id: load_ipv6list.c,v 1.4 2024/10/07 03:36:18 fujiwara Exp $

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
#include <sys/types.h>

#include "ext/uthash.h"
#include "load_ipv6list.h"
#include "mytool.h"

struct ipv6_prefix_hash *load_ipv6_prefix_list(char *filename)
{
	struct ipv6_prefix_hash *hash = NULL, *e, *f;
	FILE *fp;
	int lineno, index, num, size1, size2, size3;
	char *p, *q;
	u_char *u;
	unsigned int suffixsum;
	u_char prefix[16];
	u_char addr[16];
	char buff[256];

	if ((fp = fopen(filename, "r")) == NULL) {
		err(1, "cannot open %s", filename);
	}
	lineno = 0;
	while(fgets(buff, sizeof buff, fp) != NULL) {
		lineno++;
		p = strchr(buff, '\n');
		if (p == NULL) { printf("break:%s\n", buff); break; }
		if (p < buff+sizeof(buff)) {
			*p = 0;
		} else goto error;
		p = strtok(buff, ",");
		if (inet_pton(AF_INET6, p, prefix) != 1)
			goto error;
		p = strtok(NULL, ",");
		if (p == NULL) goto error;
		num = atoi(p);
		if (num < 1 || num > 1000000) goto error;
		p = strtok(NULL, ",");
		if (p == NULL || inet_pton(AF_INET6, p, addr) != 1)
			goto error;
		p = strtok(NULL, ",");
		if (p == NULL) goto error;
		suffixsum = atoi(p);
		HASH_FIND(hh, hash, prefix, 8, f);
		if (f == NULL) {
			size1 = sizeof(struct ipv6_prefix_hash);
			size2 = sizeof(unsigned int) * num;
			size3 = sizeof(uint64_t) * num;
			//printf("count=%d size=%d/%d/%d %d\n", num, size1, size2, size3, size1+size2+size3);
			u = my_malloc(size1+size2+size3);
			memset(u, 0, size1+size2+size3);
			f = (struct ipv6_prefix_hash *)u;
			f->count = num;
			f->used = 0;
			f->sump = (unsigned int *)(u + size1);
			f->suffix = (uint64_t *)(u + size1 + size2);
			f->endp = u + size1 + size2 + size3;
			memcpy(&f->prefix, prefix, 8);
			HASH_ADD(hh, hash, prefix, 8, f);
		}
		index = f->used;
		if (index >= f->count) { printf("#index>count:%s:%d:%d\n", buff, f->count, index); exit(1); }
		memcpy(&(f->suffix[index]), addr+8, 8);
		f->sump[index] = suffixsum;
		f->used++;
		//if (f->used == f->count) { printf("f=%lp ", f); hexdump("", (uchar *)f, f->endp - (uchar *)f); }
	}
	fclose(fp);
	//printf("lineno=%d, hash size = %d\n", lineno, HASH_CNT(hh, hash));

	return hash;
error:
	err(1, "load_ipv6_prefix_list: Broken line: %s, lineno %d", filename, lineno);
}
