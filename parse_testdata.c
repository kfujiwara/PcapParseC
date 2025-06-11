/*
	$Id: parse_testdata.c,v 1.6 2025/04/17 06:55:26 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <err.h>

#include "ext/uthash.h"

#include "config.h"
#include "mytool.h"
#include "pcapparse.h"
#include "parse_DNS.h"

/*
 * testdata format
 * 1 query 1 line   (No answer support)
 *   keyword=value space keyword=value ...
 *   node=NodeName
 *   tt=tv_sec.tv_usec
 *   src=IPaddr#port
 *   dst=IPaddr#port
 *   query=qname/qtype/qclass     example.com/43/1
 *   error=
 *   ednssize=
 *   edns=
 *   do=
 *   cd=
 *   transport=   1=UDP 2=UDP_FRAG 3=TCP 4=TCP_FRAG 5=TCP_PARTIAL
 *   tcp_mss=
 *   tcp_dnscount=
 *   tcp_delay=
 */

int parse_testdata_addr(char *str, u_char *addr)
{
	char *p;
	int port;
	int alen = -1;

	p = strchr(str, '#');
	if (p != NULL) {
		*p++ = 0;
		port = atoi(p);
	} else {
		port = 53;
	}
	if (inet_pton(AF_INET6, str, addr+2) == 1) {
		alen = 16;
	} else
	if (inet_pton(AF_INET, str, addr+2) == 1) {
		alen = 4;
	}
	if (alen > 0) {
		addr[0] = (port >> 8) & 0xff;
		addr[1] = port & 0xff;
	}
	return alen;
}

int parse_testdata(struct DNSdataControl* c)
{
	char *p, *q, *r, *s;
	double tt;
	int i, j, alen = 0, qclass;

	c->input_type = INPUT_TYPE_TEST;
	p = (char *)c->raw;
	memset(&c->dns, 0, sizeof(c->dns));

	//printf("Input=%s\n", p);
	while (*p == ' ') p++;
	while (*p == '#') {
		q = strchr(p, '\n');
		if (q == NULL) return 0;
		*q++ = 0;
		if (*q == 0) return 0;
		p = q;
		c->lineno++;
	}
	while(*p != 0) {
		q = strchr(p, '=');
		if (q == NULL || q == p)
			err(1, "#BadTestData:line=%d:brokenInput:p=%s q=%s", c->lineno, p, q);
		*q++ = 0;	// p = key , q = value
		r = q;
		while(*r > ' ') r++;
		if (*r != 0) { *r++ = 0; }
		//printf("key=%s value=%s rest=%s\n", p, q, r);
		if (strcmp(p, "tt") == 0) {
			tt = atof((char *)q);
			c->dns.tv_sec = (int)tt;
			tt = (tt - c->dns.tv_sec) * 1000000;
			c->dns.tv_usec = tt;
		} else if (strcmp(p, "src") == 0) {
			alen = parse_testdata_addr(q, c->dns.portaddr);
			if (alen <= 0)
				err(1, "#BadTestData:line=%d:BadAddr=%s", c->lineno, q);
			if (c->dns.alen != 0 && c->dns.alen != alen)
				err(1, "#BadTestData:line=%d:src/dst IPaddr mismatch:src=%d:prev=%d", c->lineno, alen, c->dns.alen);
			c->dns.alen = alen;
			c->dns.portaddrlen = alen+2;
			c->dns.af = (alen == 4) ? AF_INET : AF_INET6;
		} else if (strcmp((char *)p, "dst") == 0) {
			alen = parse_testdata_addr(q, c->dns.portaddr+18);
			if (alen <= 0)
				err(1, "#BadTestData:line=%d:BadAddr=%s", c->lineno, q);
			if (c->dns.alen != 0 && c->dns.alen != alen)
				err(1, "#BadTestData:line=%d:src/dst IPaddr mismatch:src=%d:prev=%d", c->lineno, alen, c->dns.alen);
			if (alen == 4)
				memcpy(c->dns.portaddr+6, c->dns.portaddr+18, 6);
			c->dns.alen = alen;
			c->dns.portaddrlen = alen+2;
			c->dns.af = (alen==4)?AF_INET:AF_INET6;
		} else if (strcmp((char *)p, "query") == 0) {
			p = strchr(q, '/');
			if (p == NULL) {
				c->dns.qtype = 1;
				c->dns.qclass = 1;
			} else {
				*p++ = 0;
				s = strchr(p, '/');
				if (s == NULL) {
					qclass = 1;
				} else {
					*s++ = 0;
					c->dns.qclass = atoi(s);
				}
				c->dns.qtype = atoi(p);
			}
			strncpy((char *)c->dns.qname, q, sizeof(c->dns.qname));
			strncpy((char *)c->dns.qnamebuf, q, sizeof(c->dns.qnamebuf));
			// separate qname at q into labels (label[])
			p = (char *)c->dns.qnamebuf;
			i = 0;
			while (p != NULL && i < PcapParse_LABELS) {
				c->dns.label[i] = p;
				q = strchr(p, '.');
				if (q != NULL) {
					*q = 0;
					p = q+1;
					if (*p == 0) { p = NULL; };
				} else {
					p = NULL;
				}
				i++;
			}
			c->dns.nlabel = i;
			/* swap order */
			for (i = 0, j = c->dns.nlabel - 1; i < j; i++, j--) {
				p = c->dns.label[i];
				c->dns.label[i] = c->dns.label[j];
				c->dns.label[j] = p;
			}
		} else if (strcmp((char *)p, "node") == 0) {
			c->current_nodeid = add_node_name(c, q);
		} else if (strcmp(p, "error") == 0) {
			c->dns.error = atoi(q);
		} else if (strcmp(p, "ednssize") == 0) {
			c->dns.edns0udpsize = atoi(q);
		} else if (strcmp(p, "edns") == 0) {
			c->dns._edns0 = atoi(q);
		} else if (strcmp(p, "id") == 0) {
			c->dns._id = atoi(q);
		} else if (strcmp(p, "rd") == 0) {
			c->dns._rd = atoi(q);
		} else if (strcmp(p, "do") == 0) {
			c->dns._do = atoi(q);
		} else if (strcmp(p, "cd") == 0) {
			c->dns._cd = atoi(q);
		} else if (strcmp(p, "transport") == 0) {
			c->dns._transport_type = atoi(q);
		} else if (strcmp(p, "tcp_mss") == 0) {
			c->dns.tcp_mss = atoi(q);
		} else if (strcmp(p, "tcp_dnscount") == 0) {
			c->dns.tcp_dnscount = atoi(q);
		} else if (strcmp(p, "tcp_delay") == 0) {
			c->dns.tcp_delay = atoi(q);
		}
		p = r;
		while (*p == ' ') p++;
	}
	c->dns.ts = c->dns.tv_sec * 1000000LL + c->dns.tv_usec;
	c->dns._fragSize = 0;
	c->dns.p_src = c->dns.portaddr+2;
	c->dns.p_dst = c->dns.portaddr+c->dns.portaddrlen+2;
	c->dns.p_sport = c->dns.portaddr[0]*256+c->dns.portaddr[1];
	c->dns.p_dport = c->dns.portaddr[alen+2]*256+c->dns.portaddr[alen+3];
	c->dns.datatype = DATATYPE_DNS;
	(void)(c->callback)(c, CALLBACK_PARSED);
	return 0;
}

int _parse_testdata(FILE *fp, struct DNSdataControl *c)
{
	int line1 = 0;
	int ret;

	do {
		c->lineno++;
		line1++;
		memset(&c->dns, 0, sizeof(c->dns));
		ret = parse_testdata(c);
		if (ret > 0 && ret < 10) {
			c->ParsePcapCounter.error[ret]++;
			fprintf(stderr, "error%02d: %s", ret, c->raw);
		}
	} while(fgets((char *)c->raw, c->rawlen, fp) != NULL);
	fprintf(stderr, "Loaded %d/%d lines from %s\n", line1, c->lineno, c->filename);
	fflush(stderr);
	return 0;
}

