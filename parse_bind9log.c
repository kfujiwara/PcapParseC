/*
	$Id: parse_bind9log.c,v 1.16 2025/05/01 10:06:07 fujiwara Exp $

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
#include "dns_string.h"
#include "pcapparse.h"
#include "parse_int.h"
#include "parse_DNS.h"

/* ------------------------------------------------------------------
   BIND 9 Log file parser 
   ------------------------------------------------------------------
*/

enum _state { err_date = 1, err_addr = 2, err_port = 3, err_qname = 4, err_class = 5, err_type = 6, err_flag = 7, err_server = 8, err_ignored = 9 };
char *parse_bind9log_error[] = {
"NoERROR", "ErrDate", "ErrAddr", "ErrPort", "ErrQname", "ErrClass",
"ErrType", "ErrFlag", "ErrServer", "ErrIgnored" };

#if 0
int parse_uint16(u_char *str, int len)
{
	int num = 0;

	while(len > 0) {
		if (isdigit(*str)) {
			num = num * 10 + *str - '0';
		} else
			return -1;
		str++;
		len--;
	}
	return num;
}
#endif

int parse_decimal2(char *x)
{
	if (x[0]<'0' || x[0]>'9' || x[1]<'0' || x[1]>'9') {
		return -1;
	}
	return (x[0]-'0')*10+x[1]-'0';
}

int parse_decimal3(char *x)
{
	if (x[0]<'0' || x[0]>'9' || x[1]<'0' || x[1]>'9' || x[2]<'0' || x[2]>'9') {
		return -1;
	}
	return (x[0]-'0')*100+(x[1]-'0')*10+x[2]-'0';
}

int parse_decimal4(char *x)
{
	if (x[0]<'0' || x[0]>'9' || x[1]<'0' || x[1]>'9' || x[2]<'0' || x[2]>'9' || x[3]<'0' || x[3]>'9') {
		return -1;
	}
	return (x[0]-'0')*1000+(x[1]-'0')*100+(x[2]-'0')*10+x[3]-'0';
}

int parse_bind9log(struct DNSdataControl* c)
{
	char *p, *q, *r;
	char *_type = NULL, *_class = NULL;
	int _typelen = 0, _classlen = 0;
	int msec;
	struct tm tm;
	int len, i, j, k;
	struct dns_types *tt;
	char *str;
	u_char ip_src[16];
	u_char ip_dst[16];
	char s_src[INET6_ADDRSTRLEN];
	char s_dst[INET6_ADDRSTRLEN];

	p = (char *)c->raw;
	memset(&tm, 0, sizeof(tm));
	tm.tm_mday = parse_decimal2(p);
	if (tm.tm_mday < 0 || tm.tm_mday > 31 || p[2] != '-') return err_date;
	p += 3;
	if (p[0] == 0 || p[1] == 0 || p[2] == 0 || p[3] != '-') return err_date;
	switch (*p) {
	case 'J': /* Jan, Jun, Jul */
		if (p[1] == 'a') { tm.tm_mon = 1; }
		else { tm.tm_mon = (p[2] == 'n') ? 6 : 7; }
		break;
	case 'F': /* Feb */ tm.tm_mon = 2;	break;
	case 'M': /* Mar, May */ tm.tm_mon = (p[2] == 'r') ? 3 : 5;	break;
	case 'A': /* Apr, Aug */ tm.tm_mon = (p[1] == 'p') ? 4 : 8; break;
	case 'S': /* Sep */ tm.tm_mon = 9;  break;
	case 'O': /* Oct */ tm.tm_mon = 10; break;
	case 'N': /* Nov */ tm.tm_mon = 11; break;
	case 'D': /* Dec */ tm.tm_mon = 12; break;
	default:	    return err_date;
	}
	tm.tm_mon--;
	p += 4;
	tm.tm_year = parse_decimal4(p) - 1900;
	if (tm.tm_year < 0 || p[4] != ' ') return err_date;
	p += 5;
	tm.tm_hour = parse_decimal2(p);
	if (tm.tm_hour < 0 || tm.tm_hour > 23 || p[2] != ':') return err_date;
	p += 3;
	tm.tm_min = parse_decimal2(p);
	if (tm.tm_min < 0 || tm.tm_min > 60 || p[2] != ':') return err_date;
	p += 3;
	tm.tm_sec = parse_decimal2(p);
	if (tm.tm_sec < 0 || tm.tm_sec >= 60 || p[2] != '.') return err_date;
	p += 3;
	msec = parse_decimal3(p);
	if (msec < 0 || p[3] != ' ') return err_date;

	c->dns.tv_sec = mktime(&tm)+c->tz_read_offset;
	c->dns.tv_usec = msec * 1000;
	c->dns.ts = c->dns.tv_sec * 1000000LL + c->dns.tv_usec;
	p += 4;
	c->dns._fragSize = 0;

	if (c->do_scanonly) {
		if (c->ParsePcapCounter.first_ts == 0) {
			c->ParsePcapCounter.first_ts = c->dns.ts;
		}
		c->ParsePcapCounter.last_ts = c->dns.ts;
		return 0;
	}
	// Test BIND 8 style ?
	// 27-Jan-2004 00:00:00.000 queries: info: XX /192.168.1.5/mx1.example.co.jp/A/IN
	q = strchr(p, 'X');
	if (q != NULL && q[0] == 'X' && q[1] == 'X' && q[2] != 0 && q[3] == '/') {
		// BIND 8 mode
		c->dns._rd = (q[2] == '+') ? 1 : 0;
		p = q + 4;
		q = strchr(p, '/');
		if (q == NULL) return err_addr;
		if (q-p-1 >= sizeof(s_src)) return err_addr;
		memcpy(s_src, p, q - p);
		s_src[q-p] = 0;
		if (inet_pton(AF_INET, s_src, ip_src) == 1) {
			c->dns.af = AF_INET;
			c->dns.alen = 4;
		} else
		if (inet_pton(AF_INET6, s_src, ip_src) == 1) {
			c->dns.af = AF_INET6;
			c->dns.alen = 16;
		} else
			return err_addr;
		c->dns.p_src = ip_src;
		c->dns.p_sport = 0;
		p = q + 1;
		/* find lastest / / */
		q = p + strlen((char *)p);
		while((*q == 0 || *q == '\n') && q > p)
			q--;
		if (q <= p) return err_qname;
		r = q + 1;
		while(*q != '/' && q > p)
			q--;
		if (q > p && *q == '/') {
			_class = q+1;
			_classlen = r - _class;
		} else
			return err_class;
		r = q;
		q--;
		while(*q != '/' && q > p)
			q--;
		if (q > p && *q == '/') {
			_type = q+1;
			_typelen = r - _type;
		} else
			return err_type;
		r = q;
		if (c->getdname_options & GET_DNAME_LOWERCASE) {
			for (i = 0; i < q-p; i++) {
				c->dns.qname[i] = tolower(p[i]);
			}
		} else {
			memcpy(c->dns.qname, p, q-p);
		}
		c->dns.qname[q-p] = 0;
		_type[_typelen] = 0;
		k = str2type(_type);
		if (k == -1) {
			if (strncasecmp((char *)_type, "BADTYPE", _typelen) == 0) {
				k = 0;
			} else
			if (strncasecmp((char *)_type, "TYPE", 4) == 0)
				k = strtol((char *)_type + 4, NULL, 10);
		}
		if (k < 0 || k > 65535) return err_type;
		c->dns.qtype = k;
		_class[_classlen] = 0;
		c->dns.qclass = str2class(_class);
		if (c->dns.qclass < 0) return err_class;

		c->dns._transport_type = T_UDP;
		c->dns._qr = 0;
	} else {
	// BIND 9 mode
		q = strchr(p, '#');
		if (q == NULL) return err_addr;
		for (r = q - 1; r >= p && *r != ' ' && *r != 0; r--);
		if (*r != ' ') return err_addr;
		p = r + 1;
		if (q-p-1 >= sizeof(s_src)) return err_addr;
		memcpy(s_src, p, q - p);
		s_src[q-p] = 0;
		r = strchr(s_src, '%');
		if (r != NULL) *r = 0;
		if (inet_pton(AF_INET, s_src, ip_src) == 1) {
			c->dns.af = AF_INET;
			c->dns.alen = 4;
		} else
		if (inet_pton(AF_INET6, s_src, ip_src) == 1) {
			c->dns.af = AF_INET6;
			c->dns.alen = 16;
		} else
			return err_addr;
		c->dns.p_src = ip_src;
		p = q + 1;
		k = strtol(p, &q, 10);
		if (k < 0 || k > 65535 || q == NULL || (*q != ':' && *q != ' ')) return err_port;
		c->dns.p_sport = k;
		p = q;
		while (*p == ' ') p++;
/*
30-Jan-2011 00:00:01.852 queries: info: client 10.10.10.11#2582: query: ns.dns.jp IN A -EDC (203.119.1.1)
01-Jul-2013 00:00:01.395 queries: info: client 10.11.21.21#2210 (google.co.jp): query: google.co.jp IN DS -EDC (203.119.1.1)
02-Nov-2020 17:50:06.220 queries: info: client @0x7ff2bd0a81a0 10.22.33.2#51012 (2001:db8:111:2:12:): view view-jp: query: 2001:db8:111:2:12: IN AAAA +E(0)T (203.119.1.1)
02-Nov-2020 17:50:06.211 queries: info: client @0x7ff2bd0a81a0 10.22.33.2#51012 (2001:db8:111:3:122:): view view-jp: query: 2001:db8:111:3:122: IN A +E(0)T (203.119.1.1)
*/
		c->dns.qname[0] = 0;
		len = 0;
		if (*p == '(') {
			p++;
			str = "): ";
#define USE_STRSTR 1
#ifdef USE_STRSTR
			q = strstr(p, str);
#else
			q = p;
			while (q != NULL) {
				q = strchr(q, str[0]);
				if (q == NULL) break;
				if (strncmp(q+1, str+1, 2) == 0) break;
				q++;
			}
#endif
			if (q == NULL) return err_qname;
			len = q-p;
			if (c->getdname_options & GET_DNAME_LOWERCASE) {
				for (i = 0; i < len; i++) {
					c->dns.qname[i] = tolower(p[i]);
				}
			} else {
				memcpy(c->dns.qname, p, len);
			}
			c->dns.qname[len] = 0;
			p = q + 3;
		}
		str = "query: ";
#ifdef USE_STRSTR
		q = strstr(p, str);
#else
		q = p;
		while (q != NULL) {
			q = strchr(q, str[0]);
			if (q == NULL) break;
			if (strncmp(q+1, str+1, 6) == 0) break;
			q++;
		}
#endif
		if (q != NULL) { p = q + 7; }

		if (len != 0) {
			if (strncasecmp((char *)p, (char *)c->dns.qname, len) != 0 || p[len] != ' ')
				return err_qname;
			p += len + 1;
		} else {
			q = strchr(p, ' ');
			if (q == NULL) return err_qname;
			len = q - p;
			memcpy(c->dns.qname, p, len);
			c->dns.qname[len] = 0;
			p += len + 1;
		}
		q = strchr(p, ' ');
		*q = 0;
		c->dns.qclass = str2class(p);
		if (c->dns.qclass < 0) return err_class;
	
		p = q + 1;
		q = strchr(p, ' ');
		if (q == NULL) return err_type;
		*q = 0;
		k = str2type(p);
		if (k < 0 || k > 65535) return err_type;
		c->dns.qtype = k;
	
		p = q + 1;
		q = strchr(p, ' ');
		if (q == NULL) {
			len = strlen(p);
			if (len == 0 || len > 4)
				return err_flag;
			q = p + len;
		}
	
		c->dns._transport_type = T_UDP;
		c->dns._qr = 0;
		for (r = p; r < q; r++) {
			switch(*r) {
			case '-': c->dns._rd = 0; break;
			case '+': c->dns._rd = 1; break;
			case 'E': c->dns._edns0 = 1; break;
			case 'D': c->dns._do = 1; break;
			case 'C': c->dns._cd = 1; break;
			case 'T': c->dns._transport_type = T_TCP; break;
			}
		}
	
		p = q;
		if (*p == ' ') p++;
	
		if (*p == '(') {
			p++;
			q = strchr(p, ')');
			if (q != NULL) {
				if (q-p-1 >= sizeof(s_src)) return err_server;
				memcpy(s_dst, p, q - p);
				s_dst[q-p] = 0;
				if (inet_pton(c->dns.af, s_dst, ip_dst) != 1) {
					fprintf(stderr, "Unparseable [%s] af=%d\n", s_dst, c->dns.af);
					return err_server;
				}
				c->dns.p_dst = ip_dst;
			}
		}
	} // End of both BIND 8 and BIND 9

	inc_ipv_proto_counter(c);
	fixup_portaddr(c);
	c->dns.p_dport = 53;
	c->ParsePcapCounter._dns_query++;

	prepare_dns_labels(c);
	prepare_dns_substring(c);
	(void)(c->callback)(c, CALLBACK_PARSED);
	return 0;
}

int _parse_bind9log(FILE *fp, struct DNSdataControl *c)
{
	long line1 = 0;
	long long size1 = 0;
	int ret;
	time_t tt;
	double v1, v2, v3, v4;
#ifdef DEBUG_LOGmode
	char buff[1024];
#endif
	do {
		c->lineno++;
		line1++;
		size1 += strlen((char *)c->raw);
		memset(&c->dns, 0, sizeof(c->dns));
#ifdef DEBUG_LOGmode
		strncpy(buff, c->raw, sizeof(buff));
#endif
		ret = parse_bind9log(c);
		if (ret > 0 && ret < 10) {
			c->ParsePcapCounter.error[ret]++;
#ifdef DEBUG_LOGmode
			fprintf(stderr, "error%02d:%s: %s", ret, parse_bind9log_error[ret], buff);
#endif
		}
	} while(fgets((char *)c->raw, c->rawlen, fp) != NULL);
	tt = now() - c->open_time;
	if (tt == 0) tt = 1;
	v1 = tt / 1000000.0;
	v2 = line1 / v1;
	v3 = size1 / v1 / 1024.0/1024.0;
	v4 = c->file_size / v1 / 1024.0/1024.0;
	fprintf(stderr, "size: %lld %ld\n", size1, c->file_size);
	fprintf(stderr, "Loaded %ld lines from %s, %.1f sec, %.1f lines/sec, %.1f (%.1f) MB/s\n",
		line1, c->filename, v1, v2, v3, v4);
	fflush(stderr);
	return 0;
}

