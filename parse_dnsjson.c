/*
	$Id: parse_dnsjson.c,v 1.15 2025/05/01 10:06:07 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "ext/uthash.h"

#include "config.h"
#include "mytool.h"
#include "pcapparse.h"
#include "parse_int.h"
#include "parse_DNS.h"
#include "dns_string.h"

enum _dnsjson { json_null = 0, json_hash, json_int, json_ipaddr,
	json_bool, json_timestamp, json_string,
	json_family, json_protocol,
	json_query_ip, json_query_port, json_response_ip, json_response_port,
	json_dns_length, json_dns_id, json_dns_opcode, json_dns_rcode,
	json_dns_qname, json_dns_qclass, json_dns_qtype,
	json_dns_flags_qr, json_dns_flags_tc, json_dns_flags_aa, json_dns_flags_ra,
	json_dns_flags_ad, json_dns_flags_rd, json_dns_flags_cd,
	json_edns_udp_size, json_edns_version, json_edns_dnssec_ok,
	json_dnstap_identity, json_dnstap_timestamp };

struct json_struct {
	char *key;
	int json_type;
	int common_proc;
	UT_hash_handle hh;
};

struct json_struct *dnsjson_hash = NULL;

struct json_struct dnsjson[] = {
	{ "network/family", json_family, json_string },
	{ "network/protocol", json_protocol, json_string },
	{ "network/query-ip", json_query_ip, json_ipaddr },
	{ "network/query-port", json_query_port, json_int },
	{ "network/response-ip", json_response_ip, json_ipaddr },
	{ "network/response-port", json_response_port, json_int },
	{ "dns/length", json_dns_length, json_int },
	{ "dns/id", json_dns_id, json_int },
	{ "dns/opcode", json_dns_opcode, json_int },
	{ "dns/rcode", json_dns_rcode, json_string },
	{ "dns/qname", json_dns_qname, json_string },
	{ "dns/qclass", json_dns_qclass, json_string },
	{ "dns/qtype", json_dns_qtype, json_string },
	{ "dns/flags/qr", json_dns_flags_qr, json_bool },
	{ "dns/flags/tc", json_dns_flags_tc, json_bool },
	{ "dns/flags/aa", json_dns_flags_aa, json_bool },
	{ "dns/flags/ra", json_dns_flags_ra, json_bool },
	{ "dns/flags/ad", json_dns_flags_ad, json_bool },
	{ "dns/flags/rd", json_dns_flags_rd, json_bool },
	{ "dns/flags/cd", json_dns_flags_cd, json_bool },
	{ "edns/udp-size", json_edns_udp_size, json_int },
	{ "edns/version", json_edns_version, json_int },
	{ "edns/dnssec-ok", json_edns_dnssec_ok, json_int },
	{ "dnstap/identity", json_dnstap_identity, json_string },
	{ "dnstap/timestamp-rfc3339ns", json_dnstap_timestamp, json_string },
	{ NULL, json_null, json_null },
};

char *skipspace(char *str)
{
	char *result = str;
	if (str == NULL) return NULL;
	while(*result ==' ' || *result == '\t' || *result == '\n') result++;
	return result;
}

char *skipvalue(char *str)
{
	char *result = str;
	if (str == NULL) return NULL;
	if (*result == '"') {
		result++;
		while(*result != '"' && *result != 0) {
			if (*result == '\\' && result[1] != 0) result++;
			result++;
		}
		if (*result != 0) result++;
	} else {
		while(*result != 0 && *result != ',' && *result != '}') result++;
	}
	return result;
}

char *skip_parensis(char *str, char Copen)
{
	char Cclose = ']';
	char *p = str;
	int cc;
	int depth = 1;

	switch(Copen) {
		case '[': Cclose = ']'; break;
		case '(': Cclose = ')'; break;
		case '{': Cclose = '}'; break;
		case '"': Cclose = '"'; break;
		default: Cclose = 0; break;
	}
	while((cc = *p++) != 0) {
		if (cc == '\\') {
			if (*p == 0) return NULL; // error: escape \0
			p++;
		} else
		if (cc == Cclose) {
			depth--;
			if (depth == 0) return p;
		} else
		if (cc == Copen) { depth++; }
	}
	return NULL; // no close
}

#define KEYVARLEN 512

char *do_dnsjson_entry(char **keys, int depth, char *p, struct DNSdataControl* c)
{
	int i, l, len;
	int value;
	char *q, *r;
	int found;
	struct json_struct *h;
	long long tt;
	int debug = c->debug & FLAG_DEBUG_JSON;
	char key[KEYVARLEN];
	char val[KEYVARLEN];

	if (dnsjson_hash == NULL) {
		for (i = 0; dnsjson[i].key != NULL; i++) {
			h = &dnsjson[i];
			HASH_ADD_STR(dnsjson_hash, key, h);
		}
	}

	if (keys[depth] == NULL) return NULL;
	len = KEYVARLEN;
	q = key;
	for (i = 0; i <= depth; i++) {
		if (keys[i] != NULL) {
			if (i != 0) { *q++ = '/'; len--; *q = 0; }
			l = strlen(keys[i]);
			len -= l;
			if (len < 2) {
				if (debug) printf("do_dnsjson_entry: TooLongKey: %s + %s\n", key, keys[i]);
				return NULL;
			}
			strcpy(q, keys[i]);
			q += l;
		}
	}

	q =  skipvalue(p);
	if (q-p >= sizeof(val)) {
		if (debug) printf("do_dnsjson_entry: TooLongValue: %s\n", p);
		return NULL;
	}
	if (*p == '"' && q[-1] == '"') {
		memcpy(val, p+1, q-p-2);
		val[q-p-2] = 0;
	} else {
		memcpy(val, p, q-p);
		val[q-p] = 0;
	}
	p = q;

	HASH_FIND_STR(dnsjson_hash, key, h);
	/*
	for (i = 0, found = -1; dnsjson[i].key != NULL; i++) {
		if (strcmp(dnsjson[i].key, key) == 0) { found = i; break; }
	}
	*/
	if (debug) {
		r = (h == NULL)?"NotFound":h->key;
		printf("key=%s value=%s hash=%s\n", key, val, r);
	}
	if (h == NULL) return p;

	switch(h->common_proc) {
	case json_bool:
		if (strcmp(val, "false") == 0) { value = 0; }
		else if (strcmp(val, "true") == 0) { value = 1; }
		else return NULL;
		switch(h->json_type) {
		case json_dns_flags_qr: c->dns._qr = value; break;
		case json_dns_flags_tc: c->dns._tc = value; break;
		case json_dns_flags_aa: c->dns._aa = value; break;
		case json_dns_flags_ra: c->dns._ra = value; break;
		case json_dns_flags_ad: c->dns._ad = value; break;
		case json_dns_flags_rd: c->dns._rd = value; break;
		case json_dns_flags_cd: c->dns._cd = value; break;
		default:
			if (debug) printf("Unknown key %s %d\n", h->key, h->json_type);
			return NULL;
		}
		break;
	case json_int:
		value = atoi(val);
		switch(h->json_type) {
		case json_query_port: c->dns.p_sport = value; break;
		case json_response_port: c->dns.p_dport = value; break;
		case json_dns_length: c->dns.dnslen = value; break;
		case json_dns_id: c->dns._id = value; break;
		case json_dns_opcode: c->dns._opcode = value; break;
		case json_edns_version: c->dns._ednsver = value; c->dns._edns0=1; break;
		case json_edns_udp_size: c->dns.edns0udpsize = value; c->dns._edns0=1; break;
		case json_edns_dnssec_ok: c->dns._do = value; c->dns._edns0=1; break;
		default:
			if (debug) printf("Unknown key %s %d\n", h->key, h->json_type);
			return NULL;
		}
		break;
	case json_string:
		switch(h->json_type) {
		case json_family:
			if (strcmp(val,"IPv4") == 0) {c->dns.af=AF_INET;c->dns.alen=4; }
			else
			if (strcmp(val,"IPv6") == 0) {c->dns.af=AF_INET6;c->dns.alen=6; }
			break;
		case json_protocol:
			if (strcmp(val,"UDP") == 0) c->dns._transport_type = T_UDP;
			else if (strcmp(val,"TCP") == 0) c->dns._transport_type = T_TCP;
			break;
		case json_dns_rcode: c->dns._rcode = str2rcode(val); break;
		case json_dns_qname: strncpy(c->dns.qname, val, PcapParse_DNAMELEN);
			break;
		case json_dns_qclass: c->dns.qclass = str2class(val); break;
		case json_dns_qtype: c->dns.qtype = str2type(val); break;
		case json_dnstap_identity: break; // ignore
		case json_dnstap_timestamp:
			tt = str2unixlltime(val);
			if (tt > 0) {
				c->dns.ts = tt;
				c->dns.tv_sec = tt / 1000000LL;
				c->dns.tv_usec = tt % 1000000LL;
			} else return NULL;
			break;
		default:
			if (debug) printf("Unknown key %s %d\n", h->key, h->json_type);
			return NULL;
		}
		break;
	case json_ipaddr:
		r = strchr(val, ':');
		i = (r == NULL) ? AF_INET : AF_INET6;
		switch(h->json_type) {
		case json_query_ip:
			inet_pton(i, val, c->dns.p_src); break;
		case json_response_ip:
			inet_pton(i, val, c->dns.p_dst); break;
		}
		break;
	default:
		if (debug) printf("Unknown key %s %d\n", h->key, h->common_proc);
		return NULL;
	}

	return p;
}

int parse_dnsjson(struct DNSdataControl* c)
{
	char *p, *q, *next;
	int debug = c->debug & FLAG_DEBUG_JSON;
	int _typelen = 0, _classlen = 0;
	int msec;
	int len, i, j, k, cc;
	int depth;
	char *keys[10];
	depth = 0;
	p = (char *)c->raw;
	p = skipspace(p);
	if (*p++ != '{') return -1;
	keys[0] = NULL;
	while (depth >= 0 && (p = skipspace(p)) != NULL && (cc = *p++) != 0) {
		switch(cc) {
		case '{':
			depth++;
			if (depth >= 10) { p = NULL; break; } // depth over
			keys[depth] = NULL;
			p = skipspace(p);
			break;
		case '}':
			depth--;
			if (depth < 0) { goto exitloop; }
			p = skipspace(p);
			break;
		case ',': keys[depth] = NULL; break;
		case '"':
			q = skip_parensis(p, '"');
			if (q == NULL) {
				if (debug) printf("StorangeParensis: %c p=%s\n", cc, p);
				p = NULL;
				break;
			}
			next = skipspace(q);
			if (*next == ':') { keys[depth] = p; q[-1] = 0; p = next+1; break; }
			if (*next == ',' || *next == '}') {
				if ((p = do_dnsjson_entry(keys,depth,p-1,c)) == NULL) break;
				keys[depth] = NULL;
				p = q + 1;
			} else {
				if (debug) printf("next=%c p=%s\n", *next, p);
				p = NULL;
			}
			break;
		case '[':
			p = skip_parensis(p, cc);
			break;
		default:
			if (isalnum(cc)) {
				p = do_dnsjson_entry(keys,depth,p-1,c);
				break;
			}
			if (debug) printf("Unknown_character: %c p=%s\n", cc, p);
			p = NULL;
		}
	}
exitloop:
	//printf("parse_dnsjson returns %lp\n", p);
	if (p == NULL) return -1;
	inc_ipv_proto_counter(c);
	fixup_portaddr(c);
	c->dns.p_dport = 53;
	c->ParsePcapCounter._dns_query++;

	prepare_dns_labels(c);
	prepare_dns_substring(c);
	(void)(c->callback)(c, CALLBACK_PARSED);
	return 0;
};

int _parse_dnsjson(FILE *fp, struct DNSdataControl *c)
{
	int line1 = 0;
	size_t size1 = 0;
	int ret;
	long long tt;
	double v1, v2, v3, v4;
	u_char ip_src[16], ip_dst[16];
#ifdef DEBUG_LOGmode
	char buff[1024];
#endif

	do {
		c->lineno++;
		line1++;
		size1 += strlen((char *)c->raw);
		memset(&c->dns, 0, sizeof(c->dns));
		memset(&ip_src, 0, sizeof(ip_src));
		memset(&ip_dst, 0, sizeof(ip_dst));
		c->dns.p_src = ip_src;
		c->dns.p_dst = ip_dst;
#ifdef DEBUG_LOGmode
		strncpy(buff, c->raw, sizeof(buff));
#endif
		ret = parse_dnsjson(c);
		if (ret < 0) {
			c->ParsePcapCounter.error[0]++;
#ifdef DEBUG_LOGmode
			fprintf(stderr, "error%02d:%s: %s", ret, parse_line_error[ret], buff);
#endif
		}
#if 0
		if ((c->lineno % 1000000) == 0) {
			tt = now() - c->open_time;
			if (tt == 0) tt = 1;
			v1 = tt / 1000000.0;
			v2 = line1 / v1;
			v3 = size1 / 1024.0/1024.0;
			v4 = v3 / v1;
			fprintf(stderr, "Loaded %d lines from %s, %.1f secc, %.1f lines/sec, %.1f MB, %.1f MB/s\n", line1, c->filename, v1, v2, v3, v4);
		}
#endif
	} while(fgets((char *)c->raw, c->rawlen, fp) != NULL);
	tt = now() - c->open_time;
	if (tt == 0) tt = 1;
	v1 = tt / 1000000.0;
	v2 = line1 / v1;
	v3 = size1 / v1/1024.0/1024.0;
	v4 = c->file_size / v1/1024.0/1024.0;
	fprintf(stderr, "Loaded %d lines from %s, %.2f secc, %.1f lines/sec, %.1f (%.1f) MB/s\n", line1, c->filename, v1, v2, v3, v4);
	fflush(stderr);
	return 0;
}

