/*
	$Id: print_dns_answer.c,v 1.5 2025/04/17 06:55:26 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>

#include "config.h"

#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ext/uthash.h"

#include "mytool.h"
#include "pcapparse.h"
#include "parse_int.h"
#include "parse_DNS.h"

#define ANSSEC 1
#define AUTHSEC 2
#define ADDSEC 3
#define NONESEC 0
static char *sections[] = { "NONE", "Ans", "Auth", "Add" };

/* rdlength = 0 -> rdata is string */
void printans_rr(int section, struct DNSdataControl *d, char *name, int rtype, int rclass, int ttl, int rdlen, void *rdata)
{
	char *s;
	u_char *u;
	int i, j, k;
	int do_print = 0;
	char dname[257];
	char s_src[INET6_ADDRSTRLEN];
	char s_addr[INET6_ADDRSTRLEN];

	int print_refns = d->print_answer_options & _PRINTANS_REFNS;
	int print_refds = d->print_answer_options & _PRINTANS_REFDS;
	int print_refglue = d->print_answer_options & _PRINTANS_REFGLUE;
	int print_ans_a = d->print_answer_options & _PRINTANS_ANSWER_A;
	int print_ans_aaaa = d->print_answer_options & _PRINTANS_ANSWER_AAAA;
	int print_ans_ns = d->print_answer_options & _PRINTANS_ANSWER_NS;
	int print_ans_ds = d->print_answer_options & _PRINTANS_ANSWER_DS;
	int print_ans_cname = d->print_answer_options & _PRINTANS_ANSWER_CNAME;
	int print_ans_ptr = d->print_answer_options & _PRINTANS_ANSWER_PTR;
	int print_soa = d->print_answer_options & _PRINTANS_AUTHSOA;
	int print_allrr = d->print_answer_options & _PRINTANS_ALLRR;

	do_print = print_allrr;
	if (d->dns._answertype == _ANSWER_REF && 
		(   (print_refns && rtype == 2 && section == AUTHSEC)
		 || (print_refglue && (rtype == 1 || rtype == 28) && section == ADDSEC)
		 || (print_refds && rtype == 43 && section == AUTHSEC) ) ) {
		do_print = 1;
	} else
	if (d->dns._answertype == _ANSWER_ANSWER && section == ANSSEC) {
		if ((print_ans_ns && rtype == 2)
		 || (print_ans_a && rtype == 1)
		 || (print_ans_aaaa && rtype == 28)
		 || (print_ans_cname && rtype == 5)
		 || (print_ans_ds && rtype == 43)
		 || (print_ans_ptr && rtype == 12))
		do_print = 1;
	}
	if (do_print == 0) return;

	inet_ntop(d->dns.af, d->dns.p_src, s_src, sizeof(s_src));

	// "_,From,AnsType,Section,Name,Type,Class,TTL,RDLEN,RDATA
	printf("_,%s,%d,%s,%s,%d,%d,%d,%d,", s_src, d->dns._answertype, sections[section], name, rtype, rclass, ttl, rdlen);
	switch(rtype) {
	case 1: // A
		inet_ntop(AF_INET, rdata, s_addr, sizeof(s_addr));
		printf("A %s", s_addr);
		break;
	case 28: // AAAA
		inet_ntop(AF_INET6, rdata, s_addr, sizeof(s_addr));
		printf("AAAA %s", s_addr);
		break;
	case 43: // DS
		u = rdata;
		i = u[0] * 256 + u[1];
		j = u[2];
		k = u[3];
		printf("DS %d %d %d ", i, j, k);
		u += 4;
		rdlen -= 4;
		while (rdlen-- > 0) {
			printf("%02x", *u++);
		}
		break;
	case 2: // NS
		i = get_dname(&d->dns, dname, sizeof(dname), d->getdname_options, NULL);
		printf("NS %s", dname);
		break;
	case 5: // CNAME
		i = get_dname(&d->dns, dname, sizeof(dname), d->getdname_options, NULL);
		printf("CNAME %s", dname);
		break;
	case 12: // PTR
		i = get_dname(&d->dns, dname, sizeof(dname), d->getdname_options, NULL);
		printf("PTR %s", dname);
		break;
	default: // others
		u = rdata;
		while (rdlen-- > 0) {
			printf("%02x ", *u++);
		}
	}
	printf("\n");
}

void print_dns_answer(struct DNSdataControl *d)
{
	u_char *p, *rdata;
	u_short *r;
	char rr_name[257], rr_rdata_name[257];
	int i;
	int rr_type, rr_class, rr_ttl, rdlen;
	int next_pointer;
	int anssec, authsec, additional;
	int section;

	//if (d->dns._qr == 0 && d->dns._opcode == 5) { update_flag = 1; }
	d->dns.pointer = 12;
	i = get_dname(&d->dns, rr_name, sizeof(rr_name), GET_DNAME_NO_COMP | d->getdname_options, &d->dns.case_stats);
	rr_type = get_uint16(&d->dns);
	rr_class = get_uint16(&d->dns);
	anssec = d->dns.dns[7];
	authsec = d->dns.dns[9];
	additional = d->dns.dns[11];
	while (anssec + authsec + additional > 0) {
		if (anssec > 0) { section = ANSSEC; }
		else if (authsec > 0) { section = AUTHSEC; }
		else { section = ADDSEC; }
		i = get_dname(&d->dns, rr_name, sizeof(rr_name), d->getdname_options, NULL);
		if (i < 0) break;
		rr_type = get_uint16(&d->dns);
		rr_class = get_uint16(&d->dns);
		rr_ttl = get_uint32(&d->dns);
		rdlen = get_uint16(&d->dns);
		rdata = d->dns.dns + d->dns.pointer;
		next_pointer = d->dns.pointer + rdlen;
		printans_rr(section, d, rr_name, rr_type, rr_class, rr_ttl, rdlen, rdata);
		d->dns.pointer = next_pointer;
		if (anssec > 0) {
			anssec--;
		} else if (authsec > 0) {
			authsec--;
		} else if (additional > 0) {
			additional--;
		} else {
			anssec = 0; authsec = 0; additional = 0;
		}
	}
}

