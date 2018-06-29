/*
	$Id: pcapgetquery.c,v 1.73 2017/01/13 04:03:44 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_APR_HASH_H
#include <apr_hash.h>
#endif
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#include "PcapParse.h"

#define MODE_CSV	0
#define	MODE_BIND9LOG	1
#define MODE_COUNTONLY 2

int mode = MODE_BIND9LOG;

struct counter {
	int32_t prev;
	int32_t interval;
	u_long counter;
};

u_int32_t server_ipv4 = 0;
u_char server_ipv6[16] = { 255 };

struct filter_addr_mask4 {
	u_int32_t addr;
	u_int32_t mask;
};

#ifdef HAVE_APR_HASH_H
struct ipaddr_list {
	int count;
	u_int alen;
	u_char addr[16];
};

static apr_pool_t *pool = NULL;
static apr_hash_t *ipaddr_hash = NULL;
#endif

int check_v4 = 0;
int check_v6 = 0;
static int select_rd = -1;

int nv4mask = 0;
struct filter_addr_mask4 v4mask[10];

int nexclude4 = 0;
u_int32_t exclude4[10];

int repeat_threshold = -1;
int repeated_detection_by_ttl = 0;
int report_repeated_queries = 0;
int print_queries_bind9 = 0;
int print_queries_csv = 0;
int print_query_counter = 0;
int print_response_detail = 0;
int show_repeated_queries = 0;
int report_repeated_statistics = 0;
int print_repeated_list = 0;
int entries = 0;
int parsed_queries = 0;
int do_print_dns_answer = 0;
int ignore_udp = 0;
int ignore_tcp = 0;
int print_filename = 0;
u_int32_t t_start = 0;
u_int32_t t_end = 0;
int tz_offset = 0;
int flag_filter_ednsopt = 0;
int flag_print_ednsopt = 0;
int flag_checksumerror_only = 0;
int flag_print_error = 0;
int flag_wide_cloud = 0;
u_char wide_cloud_prefix[] = { 0x20, 0x01, 0x02, 0x00, 0x0d, 0x00, 0x01, 0x00, 0,0,0,0 };

u_int32_t data_start = 0;
u_int32_t data_end = 0;
u_int32_t data_time_length = 0;

struct counter counter;

char *typestr[] = {
/*	0*/	"RESERVED0", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB",
/*	8*/	"MG", "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX",
/* 16*/	"TXT", "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP-PTR",
/* 24*/	"SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID",
/* 32*/	"NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME",
/* 40*/	"SINK", "OPT", "APL", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC",
/* 48*/	"DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM", NULL, NULL, NULL, "HIP",
/* 56*/	"NINFO", "RKEY", "TALINK", "CDS", NULL, NULL, NULL, NULL,
/* 64*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 72*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 80*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 88*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 96*/	NULL, NULL, NULL, "SPF", "UINFO", "UID", "GID", "UNSPEC", 
/*104*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*112*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*120*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*128*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*136*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*144*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*152*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*160*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*168*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*176*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*184*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*192*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*200*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*208*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*216*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*224*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*232*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*240*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/*248*/	NULL, "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY", 
/*256*/	"URI", "CAA", NULL, NULL, NULL, NULL, NULL, NULL, 
};
char *type2str(u_short _type)
{
	if (_type == 32768) { return "TA"; }
	if (_type == 32769) { return "DLV"; }
	if (_type < 258)
		return typestr[_type];
	return NULL;
}

char *class2str(u_short _class)
{
	if (_class == 1) { return "IN"; };
	if (_class == 3) { return "CH"; };
	if (_class == 4) { return "HS"; };
	if (_class == 254) { return "NONE"; };
	if (_class == 255) { return "ANY"; };
	return NULL;
}

static char *monthlabel[] = {
	"Jun", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
	"Oct", "Nov", "Dec",
};


void print_counter()
{
	if (counter.counter != 0) {
		printf("%d,%d,%ld,%f\n", counter.prev, counter.interval, counter.counter, (double)counter.counter / (double)counter.interval);
		counter.counter = 0;
	}
}

int print_ednsoptions(struct DNSdataControl *d, char *buff, int len)
{
	char *p = buff;
	u_char *q;
	int l, m;
	int rest = len;

	// if (d->dns._edns0 == 0 || d->dns._edns_numopts == 0) return 0;
	if (d->dns._edns_reserved != 0) {
		l = snprintf(p, rest, " E_Reserved");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_ul != 0) {
		l = snprintf(p, rest, " E_UL");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_llq != 0) {
		l = snprintf(p, rest, " E_LLQ");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_nsid != 0) {
		l = snprintf(p, rest, " E_NSID:%d:", d->dns._edns_nsid_bufflen);
		q = d->dns._edns_nsid_buff;
		m = d->dns._edns_nsid_bufflen;
		if (m > 32) m = 32;
		rest -= l;
		p += l;
		while (rest > 0 && m > 0) {
			l = snprintf(p, rest, "%02x", *q++);
			m--;
			rest -= l;
			p += l;
		}
	}
	if (d->dns._edns_ecs != 0) {
		l = snprintf(p, rest, " E_ECS:%d:", d->dns._edns_ecs);
		rest -= l;
		p += l;
		q = d->dns._ecs_addr;
		m = (d->dns._ecs_mask + 7) / 8;;
		while (rest > 0 && m > 0) {
			l = snprintf(p, rest, "%02x", *q++);
			m--;
			rest -= l;
			p += l;
		}
		l = snprintf(p, rest, "/%d", d->dns._ecs_mask);
		rest -= l;
		p += l;
	}
	if (d->dns._edns_dau != 0) {
		l = snprintf(p, rest, " E_DAU");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_dhu != 0) {
		l = snprintf(p, rest, " E_DHU");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_n3u != 0) {
		l = snprintf(p, rest, " E_N3U");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_expire != 0) {
		l = snprintf(p, rest, " E_Expire");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_cookie != 0) {
		l = snprintf(p, rest, " E_Cookie:%d", d->dns._edns_cookie_len);
		rest -= l;
		p += l;
	}
	if (d->dns._edns_cookiesit != 0) {
		l = snprintf(p, rest, " E_SIT:%d", d->dns._edns_cookie_len);
		rest -= l;
		p += l;
	}
	if (d->dns._edns_keepalive != 0) {
		l = snprintf(p, rest, " E_Keepalive");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_padding != 0) {
		l = snprintf(p, rest, " E_Padding");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_chain != 0) {
		l = snprintf(p, rest, " E_Chain");
		rest -= l;
		p += l;
	}
	if (d->dns._edns_unassigned != 0) {
		l = snprintf(p, rest, " E_Unassigned:%d", d->dns._edns_unassigned);
		rest -= l;
		p += l;
	}
	if (d->dns._edns_experimental != 0) {
		l = snprintf(p, rest, " E_Experimental:%d", d->dns._edns_experimental);
		rest -= l;
		p += l;
	}
	if (d->dns._edns_future != 0) {
		l = snprintf(p, rest, " E_Future%d", d->dns._edns_future);
		rest -= l;
		p += l;
	}
	return len - rest;
}

static char *transport_type_str[] = TransportTypeStr;

int callback(struct DNSdataControl *d, int mode)
{
	int found, i, c, l;
	struct tm *t;
	char *typestr, typestrbuff[30];
	char *classstr, classstrbuff[30];
	char addrstr[INET6_ADDRSTRLEN];
	time_t ttt;
	char *p;
	int len;
#ifdef HAVE_APR_HASH_H
	struct ipaddr_list *e;
#endif
	char additional[40] = "";
	char additional2[4096] = "";

	if (mode == CALLBACK_ADDRESSCHECK) {
		/* Dest addr != server_ipc4 */
		if (d->dns.version == 4) {
			if (check_v4 == 0) return 1;
			if (server_ipv4 != 0 && server_ipv4 != *(u_int32_t *)(d->dns.req_dst)) return 0;
			if (d->dns.req_dport != 53) return 0;
			if (nv4mask != 0) {
				for (found = 0, c = 0; c < nv4mask; c++) {
					if (((*(u_int32_t *)d->dns.req_src) & v4mask[c].mask) == v4mask[c].addr) {
						found = 1;
						break;
					}
				}
				if (found == 0)
					return 0;
			}
			for (i = 0; i < nexclude4; i++) {
				if (exclude4[i] == (*(u_int32_t *)d->dns.req_src))
					return 0;
			}
		} else if (d->dns.version == 6) {
			if (check_v6 == 0) return 1;
			if (server_ipv6[0] != 255 && memcmp(server_ipv6, d->dns.req_dst, 16) != 0)
				return 0;
			if (d->dns.req_dport != 53) return 0;
		}
		return 1;
	}
	if (data_start != 0 && d->dns.tv_sec < data_start) {
		return 0;
	}
	if (data_end != 0 && d->dns.tv_sec >= data_end) {
		return 0;
	}
	if ((select_rd == 1 && d->dns._rd == 0)
	    || (select_rd == 0 && d->dns._rd == 1)) {
		return 0;
	}
	if (flag_checksumerror_only) {
		if ((d->dns.error & (ParsePcap_IPv4ChecksumError
					| ParsePcap_UDPchecksumError
					| ParsePcap_IPv6LengthError)) == 0) {
			if (flag_checksumerror_only == 1) return 0;
		} else {
			if (flag_checksumerror_only == 2) return 0;
		}
	}
#ifdef HAVE_APR_HASH_H
	if (ipaddr_hash != NULL) {
		e = (struct ipaddr_list *)apr_hash_get(ipaddr_hash, d->dns.req_src, d->dns.alen);
		if (e == NULL) return 0;
		e->count++;
	}
#endif
	if (t_start == 0 || t_start > d->dns.tv_sec) { t_start = d->dns.tv_sec; }
	if (t_end == 0 || t_end < d->dns.tv_sec) { t_end = d->dns.tv_sec; }
	if (d->dns._opcode != 0) { return 0; };
	parsed_queries++;

	if (print_query_counter) {
		int32_t now = d->dns.tv_sec - (d->dns.tv_sec % counter.interval);
		if (now != counter.prev) {
			print_counter();
			counter.prev = now;
		} else {
			counter.counter += 1;
		}
	}

	if (ignore_udp && d->dns._transport_type == T_UDP) return 0;
	if (ignore_tcp && d->dns._transport_type == T_TCP) return 0;

	if (flag_filter_ednsopt != 0 && d->dns._edns_rdlen == 0)
		return 0;
	if (print_response_detail) {
		sprintf(additional, ",%d,%s,%s,%d", d->dns._rcode, d->dns._tc?"tc":"", transport_type_str[d->dns._transport_type], d->dns.dnslen);
	}
	p = additional2;
	len = sizeof(additional2);
	if (flag_print_ednsopt != 0 && d->dns._edns0 != 0 && d->dns._edns_rdlen != 0) {
		l = print_ednsoptions(d, p, len);
		p += l;
		len -= l;
	}
	if (d->dns.error && flag_print_error) {
		l = snprintf(p, len, " Error:%s%s%s%s",
			(d->dns.error & ParsePcap_IPv4ChecksumError)?"4":"",
			(d->dns.error & ParsePcap_UDPchecksumError)?"u":"",
			(d->dns.error & ParsePcap_IPv6LengthError)?"6":"",
			(d->dns.error & ParsePcap_DNSError)?"D":"");
		p += l;
		len -= l;
	}
	if (flag_wide_cloud) {
		if (d->dns.af == AF_INET6 && memcmp(d->dns.req_src, wide_cloud_prefix, 12) == 0) {
			inet_ntop(AF_INET, d->dns.req_src+12, (char *)d->dns.s_src, sizeof(d->dns.s_src));
		}
	}
	if (print_filename) {
		snprintf(p, len, "filename=%s", d->filename);
	}
	if (print_queries_csv) {
		printf("%d.%06d,"
			"%s,%d,"
			"%s,%d,%d,"
			"%d,%d,%d,"
			"%d,%d,%d,"
			"%d,%d,%s,",
			d->dns.tv_sec, d->dns.tv_usec,
			d->dns.s_src, d->dns.req_sport,
			d->dns.qname, d->dns.qclass, d->dns.qtype,
			d->dns._id, d->dns._qr, d->dns._rd,
			d->dns._edns0, d->dns.error, d->dns._rcode,
			d->dns.answer_ttl, d->dns.cname_ttl, d->dns.cnamelist);
		for (i = 0; i < d->dns.n_ans_v4; i++) {
			inet_ntop(AF_INET, d->dns.ans_v4[i], addrstr, sizeof(addrstr));
			printf("%s/", addrstr);
		}
		for (i = 0; i < d->dns.n_ans_v6; i++) {
			inet_ntop(AF_INET6, d->dns.ans_v6[i], addrstr, sizeof(addrstr));
			printf("%s/", addrstr);
		}
		printf("\n");
	}
	if (print_queries_bind9) {
		ttt = d->dns.tv_sec + tz_offset;
		t = gmtime(&ttt);
	 	typestr = type2str(d->dns.qtype);
	 	classstr = class2str(d->dns.qclass);
		if (typestr == NULL) sprintf(typestr = typestrbuff, "TYPE%d", d->dns.qtype);
		if (classstr == NULL) sprintf(classstr = classstrbuff, "CLASS%d", d->dns.qclass);
		if (print_queries_bind9 == 2) {
			printf("%02d-%s-%04d %02d:%02d:%02d.%06d queries: info: client %s#%d: query: %s %s %s %s%s%s%s%s%s%s%s%s%s\n",
	 		t->tm_mday, monthlabel[t->tm_mon], t->tm_year+1900,
	 		t->tm_hour, t->tm_min, t->tm_sec,
	 		d->dns.tv_usec,
	 		d->dns.s_src, d->dns.req_sport,
	 		d->dns.qname, class2str(d->dns.qclass), type2str(d->dns.qtype),
	 		d->dns._rd ? "+" : "-", d->dns._edns0?"E":"",
 	 		d->dns.proto==6?"T":"",
	 		d->dns._do?"D":"", d->dns._cd ? "C":"",
	 		*d->dns.s_dst==0?"":"(",
			d->dns.s_dst,
	 		*d->dns.s_dst==0?"":")",
			additional, additional2);
		} else {
			printf("%02d-%s-%04d %02d:%02d:%02d.%03d queries: info: client %s#%d (%s): query: %s %s %s %s%s%s%s%s %s%s%s%s%s\n",
	 		t->tm_mday, monthlabel[t->tm_mon], t->tm_year+1900,
	 		t->tm_hour, t->tm_min, t->tm_sec,
	 		d->dns.tv_usec/1000,
	 		d->dns.s_src, d->dns.req_sport,
			d->dns.qname,
	 		d->dns.qname, classstr, typestr,
	 		d->dns._rd ? "+" : "-", d->dns._edns0?"E":"",
 	 		d->dns._transport_type==T_TCP?"T":"",
	 		d->dns._do?"D":"", d->dns._cd ? "C":"",
	 		*d->dns.s_dst==0?"":"(",
			d->dns.s_dst,
	 		*d->dns.s_dst==0?"":")",
			additional, additional2);
		}
		if (do_print_dns_answer > 1 && (d->debug & FLAG_MODE_PARSE_ANSWER)) {
			print_dns_answer(d);
		}
	} 
	return 0;
}

void print_ipaddrhash()
{
	apr_hash_index_t *hash_index = NULL;
	struct ipaddr_list *e;
	const void *key;
	apr_ssize_t klen;
	void *val = NULL;
	char s[256];

	hash_index = apr_hash_first(pool, ipaddr_hash);
	while (hash_index) {
		apr_hash_this(hash_index, &key, &klen, &val);
		e = val;
		if (e->count > 0) {
			inet_ntop(klen==4?AF_INET:AF_INET6, key, s, sizeof(s));
			printf("I,%s,%d\n", s, e->count);
		}
		hash_index = apr_hash_next(hash_index);
	}
}

void load_ipaddrlist(char *filename)
{
#ifdef HAVE_APR_HASH_H
	static apr_status_t status = APR_SUCCESS;
	apr_initialize();
	char buff[512];
	u_char addr[16];
	int alen;
	int l;
	FILE *fp;
	struct ipaddr_list *e;

	status = apr_pool_create(&pool, NULL);
	if (status != APR_SUCCESS) {
		printf("#Error:could not create apr_pool");
		exit(0);
	}
	ipaddr_hash = apr_hash_make(pool);
	
	if ((fp = fopen(filename, "r")) == NULL)
		err(1, "cannot open %s", filename);
	while(fgets(buff, sizeof buff, fp) != NULL) {
		if (buff[0] == '#') continue;
		l = strlen(buff);
		if (l > 0 && !isprint(buff[l-1])) buff[l-1] = 0;
		if (strchr(buff, ':') != NULL) {
			if (inet_pton(AF_INET6, buff, addr) == 0)
				err(1, "cannot parse %s", buff);
			alen = 16;
		} else {
			if (inet_pton(AF_INET, buff, addr) == 0)
				err(1, "cannot parse %s", buff);
			alen = 4;
		}
		e = malloc(sizeof(struct ipaddr_list));
		e->alen = alen;
		memcpy(e->addr, addr, alen);
		e->count = 0;
		apr_hash_set(ipaddr_hash, e->addr, e->alen, e);
	}
	fclose(fp);
#endif
}

void usage(int c)
{
	if (c == -1) {
		printf("pcapgetquery version %s, compiled at %s %s\n"
		,VERSION, __DATE__, __TIME__);
		exit(0);
	}
	fprintf(stderr,
"pcapgetquery version %s, compiled at %s %s\n"
"\n"
"Usage: pcapgetquery [options] pcap files...\n"
"\n"
"	-X	Scan and print first and last timestamp\n"
"	-A	Parse response packets\n"
"	-A -A	Print DNS answer\n"
"\n"
"	-L	Print queries in BIND 9 querylog format\n"
"	-C	Print queries in CSV format\n"
"	-q NN	Print query counter in each NN second\n"
"\n"
"	-D num	Debug flag\n"
"	-t num  Specify timezone offset (in second)\n"
"	-4 v4	Specify DNS server's IPv4 address\n"
"	-e v4	Specify IPv4 address of excluded client\n"
"	-m v4	Specify netmask for -a option\n"
"	-a v4	Specify allowed client address prefix\n"
"	-R      Print response detail\n"
"	-o off	Timezone read offset\n"
"	-S	print statistics\n"
"	-f	print filename\n"
"	-R	print response detail\n"
"	-U	ignore udp\n"
"	-T	ignore TCP\n"
"	-E	Print packets with EDNS0 option only\n"
"	-O	Print EDNS0 option\n"
"	-g	Print Checksum Error\n"
"	-c	Print packets with checksum error only\n"
"	-s time	Dsta start time\n"
"	-l len	Data length\n"
"	-I file Load IPaddrlist and print packets whose source address matches\n"
"\n"
"	-s	Print statistics\n"
"	-W	decode WIDE cloud address\n"
"	-r RD	specify RD=0 or RD=1 or -1:any\n"
,VERSION, __DATE__, __TIME__);
	exit(1);
}

void err_exit(int err, char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	printf("\n");
	va_end(ap);
	exit(err);
}

int main(int argc, char *argv[])
{
	int bflag, ch;
	char *p;
	int len;
	int ret;
	char buff[256];
	u_int32_t mask4, addr4;
	int debug = FLAG_IGNOREERROR;
	int print_statistics = 0;
	int addresscheck = 0;
	struct DNSdataControl c;
	int load_bind9log = 0;
	int flag_v = 0;

	memset(&c, 0, sizeof(c));

	bflag = 0;
	while ((ch = getopt(argc, argv, "t:4:6:e:m:a:q:CD:AQLo:SRThvUfs:l:EOcgI:Wr:X")) != -1) {
	switch (ch) {
	case '4':
		if (inet_aton(optarg, (struct in_addr *)&server_ipv4) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		check_v4 = 1;
		break;
#if defined(AF_INET6) && defined(HAVE_INET_PTON)
	case '6':
		if (inet_pton(AF_INET6, optarg, server_ipv6) != 1)
			err_exit(1, "bad IPv6 address: %s", optarg);
		check_v6 = 1;
		addresscheck = 1;
		break;
#endif
	case 'e':
		if (inet_aton(optarg, (struct in_addr *)&exclude4[nexclude4]) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		nexclude4++;
		check_v4 = 1;
		break;
	case 'm':
		if (inet_aton(optarg, (struct in_addr *)&mask4) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		break;
	case 'a':
		if (inet_aton(optarg, (struct in_addr *)&addr4) == 0)
			err_exit(1, "bad IPv4 address: %s", optarg);
		v4mask[nv4mask].mask = mask4;
		v4mask[nv4mask].addr = addr4;
		nv4mask++;
		check_v4 = 1;
		break;
	case 'C':
		print_queries_csv = 1;
		break;
	case 'L':
		print_queries_bind9++;
		debug |= FLAG_BIND9LOG;
		break;
	case 'q':
		counter.interval = atoi(optarg);
		counter.counter = 0;
		counter.prev = 0;
		print_query_counter = 1;
		break;
	case 'D':
		debug = atoi(optarg);
		break;
	case 't':
		tz_offset = atoi(optarg);
		break;
	case 'o':
		c.tz_read_offset = atoi(optarg);
		break;
	case 'Q':
		debug |= FLAG_MODE_PARSE_QUERY;
		break;
	case 'A':
		debug |= FLAG_MODE_PARSE_ANSWER | FLAG_ANSWER_TTL_CNAME_PARSE;
		do_print_dns_answer++;
		break;
	case 'S':
		print_statistics = 1;
		break;
	case 'f':
		print_filename = 1;
		break;
	case 'R':
		print_response_detail = 1;
		break;
	case 'U':
		ignore_udp = 1;
		break;
	case 'T':
		ignore_tcp = 1;
		break;
	case 'h':
		usage(-1);
		break;
	case 'v':
		flag_v = 1;
		break;
	case 'E':
		flag_filter_ednsopt = 1;
		flag_print_ednsopt = 1;
		break;
	case 'O':
		flag_print_ednsopt = 1;
		break;
	case 'g':
		flag_print_error = 1;
		break;
	case 'c':
		flag_checksumerror_only++;
		break;
	case 's':
		data_start = atoi(optarg);
		break;
	case 'l':
		data_time_length = atoi(optarg);
		break;
	case 'I':
		load_ipaddrlist(optarg);
		break;
	case 'W':
		flag_wide_cloud = 1;
		break;
	case 'r':
		select_rd = atoi(optarg);
		if (select_rd < -1 || select_rd > 1 || 
			(select_rd == 0 && *optarg != '0'))
			usage(ch);
		break;
	case 'X':
		debug = FLAG_SCANONLY;
		break;
	case '?':
	default:
		usage(ch);
	}}
	argc -= optind;
	argv += optind;
	if ((debug & (FLAG_MODE_PARSE_QUERY|FLAG_MODE_PARSE_ANSWER)) == 0)
		debug |= FLAG_MODE_PARSE_QUERY;
	if (check_v4 != 0 || check_v6 != 0) {
		debug |= FLAG_DO_ADDRESS_CHECK;
	}
	if (print_query_counter == 0 && print_queries_csv == 0 && print_queries_bind9 == 0) {
		print_queries_bind9 = 1;
		debug |= FLAG_BIND9LOG;
	}

	if (data_start != 0 && data_time_length != 0)
		data_end = data_start + data_time_length;

	c.callback = callback;
	c.debug = debug;
	if (argc > 0) {
		while (*argv != NULL) {
			p = *argv++;
			if (strcmp(p, "-") == 0) p = NULL;
			if (flag_v) {
				fprintf(stderr, "Loading %s.\n", p);
				fflush(stderr);
			}
			if (debug & FLAG_SCANONLY) {
				memset(&c.ParsePcapCounter, 0, sizeof(c.ParsePcapCounter));
				ret = parse_pcap(p, &c);
				printf("%s,%ld.%06d,%ld.%06d,%d\n", p, c.ParsePcapCounter.first_sec, c.ParsePcapCounter.first_usec, c.ParsePcapCounter.last_sec, c.ParsePcapCounter.last_usec, ret);
			} else {
				ret = parse_pcap(p, &c);
				if (ret != ParsePcap_NoError) {
					printf("#Error:%s:%s:errno=%d\n", parse_pcap_error(ret), p, errno);
					exit(1);
				}
			}
		}
	} else {
		usage(0);
	}
	if (print_statistics) {
		Print_PcapStatistics(&c);
	}
	return 0;
}
