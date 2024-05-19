/*
	$Id: parse_bind9log.c,v 1.4 2024/05/13 07:09:55 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "ext/uthash.h"
#include "mytool.h"
#include "PcapParse.h"
#include "parse_int.h"
#include "parse_DNS.h"

/* ------------------------------------------------------------------
   BIND 9 Log file parser 
   ------------------------------------------------------------------
*/

struct types { char *name; int code; } types[] = {
{ "A", 1, },
{ "AAAA", 28, },
{ "PTR", 12, },
{ "MX", 15, },
{ "TXT", 16, },
{ "NS", 2, },
{ "DS", 43, },
{ "SRV", 33, },
{ "CNAME", 5, },
{ "SOA", 6, },
{ "DNSKEY", 48, },
{ "ANY", 255, },
{ "AXFR", 252, },
{ "TLSA", 52, },
{ "HINFO", 13, },
{ "A6", 38, },
{ "SPF", 99, },
{ "ATMA", 34, },
{ "NAPTR", 35, },
{ "KX", 36, },
{ "CERT", 37, },
{ "DNAME", 39, },
{ "SINK", 40, },
{ "OPT", 41, },
{ "APL", 42, },
{ "SSHFP", 44, },
{ "IPSECKEY", 45, },
{ "RRSIG", 46, },
{ "NSEC", 47, },
{ "DHCID", 49, },
{ "NSEC3", 50, },
{ "NSEC3PARAM", 51, },
{ "SMIMEA", 53, },
{ "HIP", 55, },
{ "NINFO", 56, },
{ "RKEY", 57, },
{ "TALINK", 58, },
{ "CDS", 59, },
{ "CDNSKEY", 60 },
{ "OPENPGPKEY", 61 },
{ "CSYNC", 62 },
{ "ZONEMD", 63 },
{ "SVCB", 64 },
{ "HTTPS", 65 },
{ "SPF", 99, },
{ "UINFO", 100, },
{ "UID", 101, },
{ "GID", 102, },
{ "UNSPEC", 103, },
{ "NID", 104 },
{ "L32", 105 },
{ "L64", 106 },
{ "LP", 107 },
{ "EUI48", 108 },
{ "EUI64", 109 },
{ "TKEY", 249, },
{ "TSIG", 250, },
{ "IXFR", 251, },
{ "MAILB", 253, },
{ "MAILA", 254, },
{ "*", 255, },
{ "URI", 256, },
{ "CAA", 257, },
{ "AVC", 258, },
{ "DOA", 259, },
{ "AMTRELAY", 260, },
{ "TA", 32768, },
{ "DLV", 32769, },
{ "RESERVED0", 0, },
{ "MD", 3, },
{ "MF", 4, },
{ "MB", 7, },
{ "MG", 8, },
{ "MR", 9, },
{ "NULL", 10, },
{ "WKS", 11, },
{ "MINFO", 14, },
{ "RP", 17, },
{ "AFSDB", 18, },
{ "X25", 19, },
{ "ISDN", 20, },
{ "RT", 21, },
{ "NSAP", 22, },
{ "NSAP-PTR", 23, },
{ "SIG", 24, },
{ "KEY", 25, },
{ "PX", 26, },
{ "GPOS", 27, },
{ "LOC", 29, },
{ "NXT", 30, },
{ "EID", 31, },
{ "NIMLOC", 32, },
{ NULL, -1 },
};

enum _state { err_date = 1, err_addr = 2, err_port = 3, err_qname = 4, err_class = 5, err_type = 6, err_flag = 7, err_server = 8, err_ignored = 9 };
char *parse_line_error[] = {
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

int parse_line(struct DNSdataControl* c)
{
	char *p, *q, *r;
	char *_type = NULL, *_class = NULL;
	int _typelen = 0, _classlen = 0;
	int msec;
	struct tm tm;
	int len, i, j, k;
	struct types *tt;
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
	q = strchr(p, 'X');
	if (q != NULL && q[0] == 'X' && q[1] == 'X' && q[2] != 0 && q[3] == '/') {
		// BIND 8 mode
		c->dns._rd = (q[2] == '+') ? 1 : 0;
		p = q + 4;
		q = strchr(p, '/');
		if (q == NULL) return err_addr;
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
		k = -1;
		for (tt = types; tt->name != NULL; tt++) {
			if (strncasecmp((char *)_type, tt->name, _typelen) == 0) {
				k = tt->code;
				break;
			}
		}
		if (k == -1) {
			if (strncasecmp((char *)_type, "BADTYPE", _typelen) == 0) {
				k = 0;
			} else
			if (strncasecmp((char *)_type, "TYPE", 4) == 0)
				k = strtol((char *)_type + 4, NULL, 10);
		}
		if (k < 0 || k > 65535) return err_type;
		c->dns.qtype = k;

		if (strncasecmp((char *)_class, "IN", _classlen) == 0) {
			c->dns.qclass = 1;
		} else
		if (strncasecmp((char *)_class, "CHAOS", _classlen) == 0) {
			c->dns.qclass = 3;
		} else
		if (strncasecmp((char *)_class, "HS", _classlen) == 0) {
			c->dns.qclass = 4;
		} else
		if (strncasecmp((char *)_class, "BADCLASS", _classlen) == 0) {
			c->dns.qclass = 0;
		} else
		if (strncasecmp((char *)_class, "ANY", _classlen) == 0) {
			c->dns.qclass = 255;
		} else
		if (strncasecmp((char *)_class, "CLASS", 5) == 0) {
			k = strtol((char *)_class + 5, NULL, 10);
			if (k < 0 || k > 65535) return err_class;
			c->dns.qclass = k;
		} else
			return err_class;

		c->dns._transport_type = T_UDP;
		c->dns._qr = 0;
	} else {
	// BIND 9 mode
		q = strchr(p, '#');
		if (q == NULL) return err_addr;
		for (r = q - 1; r >= p && *r != ' ' && *r != 0; r--);
		if (*r != ' ') return err_addr;
		p = r + 1;
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
		if (q == NULL) return err_class;
		len = q-p;
		if (strncasecmp(p, "IN", len) == 0) {
			c->dns.qclass = 1;
		} else
		if (strncasecmp(p, "CH", len) == 0) {
			c->dns.qclass = 3;
		} else
		if (strncasecmp(p, "HS", len) == 0) {
			c->dns.qclass = 4;
		} else
		if (strncasecmp(p, "ANY", len) == 0) {
			c->dns.qclass = 255;
		} else
		if (strncasecmp(p, "CLASS", 5) == 0) {
			k = strtol(p + 5, NULL, 10);
			if (k < 0 || k > 65535) return err_class;
			c->dns.qclass = k;
		} else
			return err_class;
	
		p = q + 1;
		q = strchr(p, ' ');
		if (q == NULL) return err_type;
		len = q-p;
		k = -1;
		for (tt = types; tt->name != NULL; tt++) {
			if (strncasecmp(p, tt->name, len) == 0) {
				k = tt->code;
				break;
			}
		}
		if (k == -1) {
			if (strncasecmp(p, "TYPE", 4) == 0)
				k = strtol(p + 4, NULL, 10);
		}
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

	if (c->dns.af == AF_INET) {
		c->dns.version = 4;
		c->ParsePcapCounter._ipv4++;

		if (c->dns._transport_type == T_TCP) {
			c->ParsePcapCounter._tcp4++;
		} else {
			c->ParsePcapCounter._udp4++;
		};
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
		c->ParsePcapCounter._ipv6++;
		if (c->dns._transport_type == T_TCP) {
			c->ParsePcapCounter._tcp6++;
		} else {
			c->ParsePcapCounter._udp6++;
		}
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

	c->dns.p_dport = 53;
	c->ParsePcapCounter._dns_query++;

	if (c->do_address_check)
		if (c->callback(c, CALLBACK_ADDRESSCHECK) == 0) {
			c->ParsePcapCounter._unknown_ipaddress++;
			return err_ignored;
		}

	if (c->dns.version == 6 && (c->dns.p_src[0] & 0xfc) == 0xfc) {
		return 1;
	}

	c->ParsePcapCounter._before_checking_dnsheader++;

	strcpy((char *)c->dns.qnamebuf, (char *)c->dns.qname);
	p = c->dns.qnamebuf;
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
	c->ParsePcapCounter._parsed_dnsquery++;
	c->dns.datatype = DATATYPE_DNS;
	(void)(c->callback)(c, CALLBACK_PARSED);
	return 0;
}

int _parse_bind9log(FILE *fp, struct DNSdataControl *c)
{
	int line1 = 0;
	int ret;
	time_t tt1, tt2;
#ifdef DEBUG_LOGmode
	char buff[1024];
#endif

	tt1 = time(NULL);
	do {
		c->lineno++;
		line1++;
		memset(&c->dns, 0, sizeof(c->dns));
#ifdef DEBUG_LOGmode
		strncpy(buff, c->raw, sizeof(buff));
#endif
		ret = parse_line(c);
		if (ret > 0 && ret < 10) {
			c->ParsePcapCounter.error[ret]++;
#ifdef DEBUG_LOGmode
			fprintf(stderr, "error%02d:%s: %s", ret, parse_line_error[ret], buff);
#endif
		}
	} while(fgets((char *)c->raw, c->rawlen, fp) != NULL);
	tt2 = time(NULL) - tt1;
	if (tt2 == 0) tt2 = 1;
	fprintf(stderr, "Loaded %d/%d lines from %s, %ld sec, %ld lines/sec\n", line1, c->lineno, c->filename, tt2, line1/tt2);
	fflush(stderr);
	return 0;
}

