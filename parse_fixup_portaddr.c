/*
	$Id: parse_fixup_portaddr.c,v 1.6 2025/06/04 04:12:03 fujiwara Exp $

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
#include <netinet/in.h>

#include "ext/uthash.h"

#include "config.h"
#include "mytool.h"
#include "pcapparse.h"

void inc_ipv_proto_counter(struct DNSdataControl *c)
{
	if (c->dns.af == AF_INET) {
		c->ParsePcapCounter._ipv4++;
		if (c->dns._transport_type == T_TCP) {
			c->ParsePcapCounter._tcp4++;
		} else {
			c->ParsePcapCounter._udp4++;
		};
	}
	if (c->dns.af == AF_INET6) {
		c->dns.version = 6;
		c->ParsePcapCounter._ipv6++;
		if (c->dns._transport_type == T_TCP) {
			c->ParsePcapCounter._tcp6++;
		} else {
			c->ParsePcapCounter._udp6++;
		}
	}
}

void fixup_portaddr(struct DNSdataControl *c)
{
	if (c->dns.af == AF_INET) {
		c->dns.version = 4;
		c->dns.alen = 4;
		c->dns.portaddrlen = 2+4;
		c->dns.portaddr[0] = c->dns.p_sport >> 8;
		c->dns.portaddr[1] = c->dns.p_sport & 0xff;
		memcpy(c->dns.portaddr+2, c->dns.p_src, 4);
		c->dns.portaddr[6] = 0;
		c->dns.portaddr[7] = 53;
		if (c->dns.p_dst != NULL) {
			memcpy(c->dns.portaddr+8, c->dns.p_dst, 4);
		} else {
			memset(c->dns.portaddr+8, 0, 4);
		}
	} else
	if (c->dns.af == AF_INET6) {
		c->dns.version = 6;
		c->dns.alen = 16;
		c->dns.portaddrlen = 2+16;
		c->dns.portaddr[0] = c->dns.p_sport >> 8;
		c->dns.portaddr[1] = c->dns.p_sport & 0xff;
		memcpy(c->dns.portaddr+2, c->dns.p_src, 16);
		c->dns.portaddr[18] = 0;
		c->dns.portaddr[19] = 53;
		if (c->dns.p_dst != NULL) {
			memcpy(c->dns.portaddr+20, c->dns.p_dst, 16);
		} else {
			memset(c->dns.portaddr+20, 0, 16);
		}
	}
}

void prepare_dns_labels(struct DNSdataControl *c)
{
	char *p, *q;
	int i, j, k;

	strcpy((char *)c->dns.qnamebuf, (char *)c->dns.qname);
	p = c->dns.qnamebuf;
	i = 0;
	while (p != NULL && *p != 0 && i < PcapParse_LABELS) {
		c->dns.label[i] = p;
		q = p + 1;
		while(*q != '.' && *q != 0) q++;
		c->dns.labellen[i] = q - p;
		if (p == q) break;
		if (*q == '.') { *q = 0; p = q+1; } else { p = q; }
		i++;
	}
	c->dns.nlabel = i;
	/* swap order */
	for (i = 0, j = c->dns.nlabel - 1; i < j; i++, j--) {
		//printf("swap %d %d: %s %s %d %d\n", i, j, c->dns.label[i], c->dns.label[j], c->dns.labellen[i], c->dns.labellen[j]);
		p = c->dns.label[i];
		c->dns.label[i] = c->dns.label[j];
		c->dns.label[j] = p;
		k = c->dns.labellen[i];
		c->dns.labellen[i] = c->dns.labellen[j];
		c->dns.labellen[j] = k;
	}
	c->ParsePcapCounter._before_checking_dnsheader++;
	c->ParsePcapCounter._parsed_dnsquery++;
	c->dns.datatype = DATATYPE_DNS;
	//printf("nlabels=%d\n", c->dns.nlabel);
}

void prepare_dns_substring(struct DNSdataControl *c)
{
	char *p, *endp, *qname;
	int i, j;

	qname = c->dns.qname;
	c->dns.qnamelen = strlen(qname);
	if (c->dns.qnamelen == 1 && c->dns.qname[0] == '.') {
		c->dns.substring[0] = c->dns.qname;
		c->dns.substringlen[0] = c->dns.qnamelen;
		c->dns.nsubstring = 0;
		return;
	}
	endp = c->dns.qname + c->dns.qnamelen - 1;
	if (c->dns.qnamelen>0 && *endp=='.') {*endp=0; endp--; c->dns.qnamelen--;}
		// ignore tailing "."
	p = endp;
	i = 0;
	while(p > qname && i < PcapParse_nSubstring) {
		if (*p == '.') {
			c->dns.substring[i] = p+1;
			c->dns.substringlen[i] = endp - p;
			i++;
		}
		p--;
	}
	if (i < PcapParse_nSubstring) {
		c->dns.substring[i] = p;
		c->dns.substringlen[i] = c->dns.qnamelen;
		i++;
	}
	c->dns.nsubstring = i;
}
