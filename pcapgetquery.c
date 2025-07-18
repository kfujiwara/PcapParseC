/*
	$Id: pcapgetquery.c,v 1.191 2025/06/04 11:03:47 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include "config.h"

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <err.h>
#include <ctype.h>

#include "ext/uthash.h"
#include "mytool.h"
#include "load_ipv6list.h"
#include "pcapparse.h"
#include "addrport_match.h"
#include "name_match.h"

#define ENVNAME "PCAPGETQUERY_ENV"

struct counter {
	int32_t prev;
	int32_t interval;
	u_long counter;
};

static struct ipaddr_port_list src_list = { NULL, 0 };
static struct ipaddr_port_list dst_list = { NULL, 0 };
static struct name_list name_list = { NULL, 0 };

static int select_rd = -1;
int repeat_threshold = -1;
int repeated_detection_by_ttl = 0;
int report_repeated_queries = 0;
int print_queries_bind9 = 0;
int print_queries_csv = 0;
int print_queries_debug = 0;
int print_query_counter = 0;
int print_response_detail = 0;
int print_tcpsyn = 0;
int show_repeated_queries = 0;
int report_repeated_statistics = 0;
int print_repeated_list = 0;
int print_filename = 0;
int entries = 0;
int parsed_queries = 0;
int do_print_dns_answer = 0;
int do_print_hexdump = 0;
int both_direction = 0;
int print_limit = 0;

int ignore_EDNS = 0;
int ignore_noEDNS = 0;
int ignore_CD = 0;
int ignore_noCD = 0;
int ignore_DO = 0;
int ignore_noDO = 0;
int ignore_AD = 0;
int ignore_noAD = 0;
int ignore_TC = 0;
int ignore_noTC = 0;
int ignore_RD = 0;
int ignore_noRD = 0;
int ignore_v4 = 0;
int ignore_v6 = 0;
int ignore_TCP = 0;
int ignore_UDP = 0;
int ignore_OPCODE0 = 0;
int ignore_noOPCODE0 = 0;
int ignore_RCODE0 = 0;
int ignore_noRCODE0 = 0;
int ignore_ANCOUNT0 = 0;
int ignore_noANCOUNT0 = 0;
int ignore_REF = 0;
int ignore_noREF = 0;
int inverse_match_qname = 0;
int print_tcp_delay_longer_than = -1;
int print_tcp_delay_shorter_than = -1;

static struct ignore_options {
	char *name;
	int *variable;
} ignore_options[] = {
	{ "v4", &ignore_v4 },
	{ "v6", &ignore_v6 },
	{ "EDNS", &ignore_EDNS },
	{ "noEDNS", &ignore_noEDNS },
	{ "CD", &ignore_CD },
	{ "noCD", &ignore_noCD },
	{ "DO", &ignore_DO },
	{ "noDO", &ignore_noDO },
	{ "AD", &ignore_AD },
	{ "noAD", &ignore_noAD },
	{ "TC", &ignore_TC },
	{ "noTC", &ignore_noTC },
	{ "RD", &ignore_RD },
	{ "noRD", &ignore_noRD },
	{ "v4", &ignore_v4 },
	{ "v6", &ignore_v6 },
	{ "TCP", &ignore_TCP },
	{ "UDP", &ignore_UDP },
	{ "OPCODE0", &ignore_OPCODE0 },
	{ "noOPCODE0", &ignore_noOPCODE0 },
	{ "RCODE0", &ignore_RCODE0 },
	{ "noRCODE0", &ignore_noRCODE0 },
	{ "ANCOUNT0", &ignore_ANCOUNT0 },
	{ "noANCOUNT0", &ignore_noANCOUNT0 },
	{ "REF", &ignore_REF },
	{ "noREF", &ignore_noREF },
	{ "QNAME", &inverse_match_qname },
	{ NULL, NULL },
};

static struct print_answer_options {
	char *name;
	int bit;
} print_answer_options[] = {
	{ "RefNS", _PRINTANS_REFNS },
	{ "RefDS", _PRINTANS_REFDS },
	{ "RefGlue", _PRINTANS_REFGLUE },
	{ "AuthSOA", _PRINTANS_AUTHSOA },
	{ "AnsA", _PRINTANS_ANSWER_A },
	{ "AnsAAAA", _PRINTANS_ANSWER_AAAA },
	{ "AnsNS", _PRINTANS_ANSWER_NS },
	{ "AnsDS", _PRINTANS_ANSWER_DS },
	{ "AnsCNAME", _PRINTANS_ANSWER_CNAME },
	{ "AnsPTR", _PRINTANS_ANSWER_PTR },
	{ "ALLRR", _PRINTANS_ALLRR },
	{ "EDNSSIZE", _PRINT_EDNSSIZE },
	{ "FLAG", _PRINT_FLAG },
	{ "DNSLEN", _PRINT_DNSLEN },
	{ NULL, 0 },
};

u_int32_t t_start = 0;
u_int32_t t_end = 0;
int tz_offset = 0;
int flag_filter_ednsopt = 0;
int flag_print_ednsopt = 1;
int flag_error_only = 0;
int flag_print_error = 1;
int flag_print_labels = 0;
int flag_greater_than = -1;
int flag_smaller_than = -1;
int flag_ignore_error = 0;
int tzread_offset = 0;
int print_statistics = 0;
int flag_v = 0;
int count_printed = 0;
int count_notprinted = 0;
int flag_print_ipaddr_hash = 0;
char * serverlist_file = NULL;

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
/* 56*/	"NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY", "OPENPGPKEY", "CSYNC", "ZONEMD",
/* 64*/	"SVCB", "HTTPS", NULL, NULL, NULL, NULL, NULL, NULL, 
/* 72*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 80*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 88*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
/* 96*/	NULL, NULL, NULL, "SPF", "UINFO", "UID", "GID", "UNSPEC", 
/*104*/	"NID", "L32", "L64", "LP", "EUI48", "EUI64", NULL, NULL, 
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
/*256*/	"URI", "CAA", "AVC", "DOA", "AMTRELAY", NULL, NULL, NULL, 
};

char *type2str(u_short _type)
{
	if (_type == 32768) { return "TA"; }
	if (_type == 32769) { return "DLV"; }
	if (_type < 264)
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
	int added = 0;

	// if (d->dns._edns0 == 0 || d->dns._edns_numopts == 0) return 0;
	if (d->dns._edns_reserved != 0) {
		l = snprintf(p, rest, " E_Reserved");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_ul != 0) {
		l = snprintf(p, rest, " E_UL");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_llq != 0) {
		l = snprintf(p, rest, " E_LLQ");
		rest -= l;
		p += l;
		added++;
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
		added++;
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
		added++;
	}
	if (d->dns._edns_dau != 0) {
		l = snprintf(p, rest, " E_DAU");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_dhu != 0) {
		l = snprintf(p, rest, " E_DHU");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_n3u != 0) {
		l = snprintf(p, rest, " E_N3U");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_expire != 0) {
		l = snprintf(p, rest, " E_Expire");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_cookie != 0) {
		l = snprintf(p, rest, " E_Cookie:%d", d->dns._edns_cookie_len);
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_cookiesit != 0) {
		l = snprintf(p, rest, " E_SIT:%d", d->dns._edns_cookie_len);
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_keepalive != 0) {
		l = snprintf(p, rest, " E_Keepalive");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_padding != 0) {
		l = snprintf(p, rest, " E_Padding");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_chain != 0) {
		l = snprintf(p, rest, " E_Chain");
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_unassigned != 0) {
		l = snprintf(p, rest, " E_Unassigned:%d", d->dns._edns_unassigned);
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_experimental != 0) {
		l = snprintf(p, rest, " E_Experimental:%d", d->dns._edns_experimental);
		rest -= l;
		p += l;
		added++;
	}
	if (d->dns._edns_future != 0) {
		l = snprintf(p, rest, " E_Future%d", d->dns._edns_future);
		rest -= l;
		p += l;
		added++;
	}
	if (added) { *p++ = ' '; *p = 0; rest--; }
	return len - rest;
}

static char *transport_type_str[] = TransportTypeStr;

void print_bind9log(struct DNSdataControl *d)
{
	int l, len;
	char *p;
	int p_sport;
	int p_dport;
	char *qr;
	time_t ttt;
	struct tm *t;
	char s_src[INET6_ADDRSTRLEN];
	char s_dst[INET6_ADDRSTRLEN];
	char *typestr, typestrbuff[30];
	char *classstr, classstrbuff[30];
	char additional[40] = "";
	char additional2[4096] = "";

	if (print_response_detail) {
		sprintf(additional, ",%d,%s,%s,%d", d->dns._rcode, d->dns._tc?"tc":"", transport_type_str[d->dns._transport_type], d->dns.dnslen);
	}
	p = additional2;
	len = sizeof(additional2);
	if (d->dns._qr == 1) {
		l = sprintf(p, " rcode=%d", d->dns._rcode);
		p += l;
		len -= l;
	}
	if (flag_print_ednsopt != 0 && d->dns._edns0 != 0 && d->dns._edns_rdlen != 0) {
		l = print_ednsoptions(d, p, len);
		p += l;
		len -= l;
	}
	if (d->dns.tcp_delay > 0) {
		l = snprintf(p, len, "tcprtt=%f,", (double)d->dns.tcp_delay/1000000.0);
		p += l; len -= l; 
	}
	if (d->dns.tcp_syn_ack_delay > 0) {
		l = snprintf(p, len, "synack=%f,", (double)d->dns.tcp_syn_ack_delay/1000000.0);
		p += l; len -= l; 
	}
	if (d->dns.tcp_mss > 0) {
		l = snprintf(p, len, "mss=%d,", d->dns.tcp_mss);
		p += l; len -= l; 
	}
	if (d->dns.tcp_fastopen > 0) {
		l = snprintf(p, len, "fastopen=%d,", d->dns.tcp_fastopen);
		p += l; len -= l; 
	}
	if (d->dns.tcp_dnscount > 0) {
		l = snprintf(p, len, "tcpdnscount=%d,", d->dns.tcp_dnscount);
		p += l; len -= l; 
	}
	if ((d->dns.error!=0 || d->dns.IPaddrUpdated) && flag_print_error) {
		l = snprintf(p, len, " Error:%s%s%s%s%s%s%s%s%s",
			(d->dns.error & ParsePcap_IPv4ChecksumError)?"4":"",
			(d->dns.error & ParsePcap_UDPchecksumError)?"u":"",
			(d->dns.error & ParsePcap_TCPError)?"t":"",
			(d->dns.error & ParsePcap_IPv6LengthError)?"6":"",
			(d->dns.error & ParsePcap_EDNSError)?"E":"",
			(d->dns.error & ParsePcap_DNSError)?"D":"",
			(d->dns.error & ParsePcap_AnswerAnalysisError)?"a":"",
			(d->dns.error & ParsePcap_CnameError)?"c":"",
			d->dns.IPaddrUpdated ?"A":""
			);
		p += l;
		len -= l;
	}
	if ((d->print_answer_options & _PRINT_EDNSSIZE) != 0 && d->dns._edns0 != 0) {
		l = snprintf(p, len, " EDNSLEN=%d", d->dns.edns0udpsize);
		p += l;
		len -= l;
	}
	if ((d->print_answer_options & _PRINT_FLAG) != 0) {
		l = snprintf(p, len, " FLAG=%02x%02x", d->dns._flag1, d->dns._flag2);
		p += l;
		len -= l;
	}
	if ((d->print_answer_options & _PRINT_DNSLEN) != 0) {
		l = snprintf(p, len, " DNSLEN=%d", d->dns.dnslen);
		p += l;
		len -= l;
	}
	if (print_filename) { printf("%s,", d->filename); }

	if ((d->mode & MODE_PARSE_QUERY) != 0
	 && (d->mode & MODE_PARSE_ANSWER) != 0) {
		qr = (d->dns._qr) ? "R":"Q";
	} else {
		qr = "";
	}
	ttt = d->dns.tv_sec + tz_offset;
	t = gmtime(&ttt);
 	typestr = type2str(d->dns.qtype);
 	classstr = class2str(d->dns.qclass);
	if (typestr == NULL) sprintf(typestr = typestrbuff, "TYPE%u", d->dns.qtype);
	if (classstr == NULL) sprintf(classstr = classstrbuff, "CLASS%u", d->dns.qclass);
	if (d->dns._qr == 0) {
		inet_ntop(d->dns.af, d->dns.p_src, s_src, sizeof(s_src));
		inet_ntop(d->dns.af, d->dns.p_dst, s_dst, sizeof(s_dst));
		p_sport = d->dns.p_sport;
		p_dport = d->dns.p_dport;
	} else {
		inet_ntop(d->dns.af, d->dns.p_dst, s_src, sizeof(s_src));
		inet_ntop(d->dns.af, d->dns.p_src, s_dst, sizeof(s_dst));
		p_sport = d->dns.p_dport;
		p_dport = d->dns.p_sport;
	}
	if (print_queries_bind9 == 2) {
		printf("%s%02d-%s-%04d %02d:%02d:%02d.%03d %s %s %s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		qr,
 		t->tm_mday, monthlabel[t->tm_mon], t->tm_year+1900,
 		t->tm_hour, t->tm_min, t->tm_sec,
 		d->dns.tv_usec/1000,
 		(*d->dns.qname==0)?".":d->dns.qname, classstr, typestr,
 		d->dns._rd ? "+" : "-", d->dns._edns0?"E":"",
	 		d->dns._transport_type>=T_TCP?"T":"",
 		d->dns._do?"D":"", d->dns._cd ? "C":"",
		d->dns._tc?"/tc ":"",
		d->dns._aa?"/aa ":"",
		d->dns.ip_df?"/df ":"",
 		*s_dst==0?"":"(",
		s_dst,
		d->node[0] == 0 ? "": "/",
		d->node,
 		*s_dst==0?"":")",
		additional, additional2);
	} else {
		printf("%s%02d-%s-%04d %02d:%02d:%02d.%03d client %s#%d: query: %s %s %s %s%s%s%s%s%s%s%s%s%s%s%s%s %s%s%s\n",
		qr,
 		t->tm_mday, monthlabel[t->tm_mon], t->tm_year+1900,
 		t->tm_hour, t->tm_min, t->tm_sec,
 		d->dns.tv_usec/1000,
		s_src,
 		p_sport,
 		(*d->dns.qname==0)?".":d->dns.qname, classstr, typestr,
 		d->dns._rd ? "+" : "-", d->dns._edns0?"E":"",
 		d->dns._transport_type>=T_TCP?"T":"",
 		d->dns._do?"D":"", d->dns._cd ? "C":"",
		d->dns._tc?"/tc ":"",
		d->dns._aa?"/aa ":"",
		d->dns.ip_df?"/df ":"",
 		*s_dst==0?"":"(",
		s_dst,
		d->node[0] == 0 ? "": "/",
		d->node,
		*s_dst==0?"":")",
		d->dns.str_rcode == NULL ? "":d->dns.str_rcode,
		additional, additional2);
	}
}

int _comp4(const void *p1, const void *p2)
{
	return memcmp(p1, p2, 4);
}

int _comp6(const void *p1, const void *p2)
{
	return memcmp(p1, p2, 16);
}

void print_csv(struct DNSdataControl *d)
{
	int i, _do;
	char addrstr[INET6_ADDRSTRLEN];
	char s_src[INET6_ADDRSTRLEN];
	char s_dst[INET6_ADDRSTRLEN];

	inet_ntop(d->dns.af, d->dns.p_src, s_src, sizeof(s_src));
	inet_ntop(d->dns.af, d->dns.p_dst, s_dst, sizeof(s_dst));
	_do = d->dns._do;
	if (d->dns._do == 0 && d->dns.additional_dnssec_rr > 0) {
		_do = 1;
	}
	if (print_filename) { printf("%s,", d->filename); }
#define CSV_STR "timestamp,s_adr,s_port,d_adr,d_port,node,datatype,qname,qclass,qtype,id,qr,rd,edns0,edns0len,do,error,rcode,str_rcode,tc,aa,qdcount,ancount,nscount,arcount,additionaldnssecrrs,dnslen,transport,FragSize,ip_df,tcp_dnscount,tcp_fastopen,tcp_mss,tcp_delay,tcp_syn_ack_delay,soa_ttl,soa_dom,ans_ttl,cname_ttl,cname,a_aaaa"
	printf("%d.%06d,"       // timestamp
		"%s,%d,%s,%d,"	// source, dest
		"%s,"		// anycast node
		"%s,"		// datatype
		"%s,%d,%d,"	// qname qclass qtype
		"%d,%d,%d,"	// id qr rd
		"%d,%d,%d,"	// edns0 edns0len do
		"%d,%d,%s,%d,%d,"  // error rcode StrRcode tc aa
		"%d,%d,%d,%d,"	// qdcount,ancount,nscount,arcount
		"%d,"		//  additionaldnssecrrs
		"%d,%d,%d,"	// dnslen transport_type FragSize
		"%d,"           // ip_df
		"%d,%d,%d,%ld,%ld,"	// tcp_dnscount tcp_fastopen
				// tcp_mss tcp_delay tcp_syn_ack_delay
		"%d,%s,"        // soa_ttl soa_dom
		"%d,%d,"	// ans_ttl cname_ttl
		"%s,"           // cnamelist
		,
		d->dns.tv_sec, d->dns.tv_usec,
		s_src, d->dns.p_sport,
		s_dst, d->dns.p_dport,
		d->node,
		PcapParseC_datatype[d->dns.datatype],
 		(*d->dns.qname==0)?".":d->dns.qname, 
		d->dns.qclass, d->dns.qtype,
		d->dns._id, d->dns._qr?1:0, d->dns._rd?1:0,
		d->dns._edns0, d->dns._edns0 ? d->dns.edns0udpsize : 0, _do,
		d->dns.error, d->dns._rcode, d->dns.str_rcode==NULL?"":d->dns.str_rcode,
			d->dns._tc?1:0, d->dns._aa?1:0,
		d->dns._qdcount, d->dns._ancount, d->dns._nscount, d->dns._arcount,
		d->dns.additional_dnssec_rr,
		d->dns.dnslen, d->dns._transport_type, d->dns._fragSize,
		d->dns.ip_df,
		d->dns.tcp_dnscount, d->dns.tcp_fastopen,
		d->dns.tcp_mss,
		d->dns.tcp_delay,
		d->dns.tcp_syn_ack_delay,
		d->dns.soa_ttl,
		d->dns.soa_dom,
		d->dns.answer_ttl,
		d->dns.cname_ttl,
		d->dns.cnamelist);
	if (d->dns.n_ans_v4 > 1)
		qsort(d->dns.ans_v4, d->dns.n_ans_v4, 4, _comp4);
	if (d->dns.n_ans_v6 > 1)
	       	qsort(d->dns.ans_v6, d->dns.n_ans_v6, 16, _comp6);
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

void print_debug(struct DNSdataControl *c)
{
	int i;
	printf("  nlabel=%d  nsubstring=%d\n", c->dns.nlabel, c->dns.nsubstring);
	for (i = 0; i < c->dns.nlabel; i++) {
		printf("        %d len=%d %s\n", i, c->dns.labellen[i], c->dns.label[i]);
	}
	for (i = 0; i < c->dns.nsubstring; i++) {
		printf("        %d len=%d %s\n", i, c->dns.substringlen[i], c->dns.substring[i]);
	}
}

int pcapgetquery_callback(struct DNSdataControl *d, int mode)
{
	int i, l;
	char *p;
	int len;
	int match_src_hash = 0, match_dest_hash = 0;
#define _src_addr 1
#define _dest_addr 2
	struct ipaddr_hash *is1, *id1, *i1 = NULL, *is2, *id2, *i2 = NULL;
	struct qname_hash *qh;
	struct name_hash *e;

	if (both_direction) {
		if (src_list.hash != NULL) {
			is1 = match_ipaddr_port(&src_list, d->dns.portaddr, d->dns.alen);
			id1 = match_ipaddr_port(&src_list, d->dns.portaddr+d->dns.portaddrlen, d->dns.alen);
			match_src_hash = (is1!=NULL?_src_addr:0)|(id1!=NULL?_dest_addr:0);
			if (match_src_hash == 0) return 0;
			i1 = (is1 != NULL) ? is1 : id1;
		}
		if (dst_list.hash != NULL) {
			is2 = match_ipaddr_port(&dst_list, d->dns.portaddr, d->dns.alen);
			id2 = match_ipaddr_port(&dst_list, d->dns.portaddr+d->dns.portaddrlen, d->dns.alen);
			match_dest_hash = (is2!=NULL?_src_addr:0)|(id2!=NULL?_dest_addr:0);
			if (match_dest_hash == 0) return 0;
			i2 = (is2 != NULL) ? is2 : id2;
		}
		if (src_list.hash != NULL && dst_list.hash != NULL) {
			if (match_src_hash + match_dest_hash != _src_addr + _dest_addr)
				return 0;
		}
		if (i1 != NULL) i1->count++;
		if (i2 != NULL) i2->count++;
    } else {
		if (src_list.hash != NULL) {
			is1 = match_ipaddr_port(&src_list, d->dns.portaddr, d->dns.alen);
			if (is1 == NULL) return 0;
			is1->count++;
		}
		if (dst_list.hash != NULL) {
			id2 = match_ipaddr_port(&dst_list, d->dns.portaddr+d->dns.portaddrlen, d->dns.alen);
			if (id2 == NULL) return 0;
			id2->count++;
		}
	}
	if (data_start != 0 && d->dns.tv_sec < data_start) {
		return 0;
	}
	if (data_end != 0 && d->dns.tv_sec >= data_end) {
		return 0;
	}

	if (t_start == 0 || t_start > d->dns.tv_sec) { t_start = d->dns.tv_sec; }
	if (t_end == 0 || t_end < d->dns.tv_sec) { t_end = d->dns.tv_sec; }
	if (d->dns._opcode != 0) { return 0; };

	if (ignore_v4 && d->dns.alen == 4) return 0;
	if (ignore_v6 && d->dns.alen == 16) return 0;
	if (ignore_UDP && d->dns._transport_type < T_TCP) return 0;
	if (ignore_TCP && d->dns._transport_type >= T_TCP) return 0;

	if (mode == CALLBACK_TCPSYN) {
		if (print_queries_csv) print_csv(d);
		return 0;
	}
	// Require DNS
	if (mode != CALLBACK_PARSED) return 0;
	parsed_queries++;
	if ((select_rd == 1 && d->dns._rd == 0)
	    || (select_rd == 0 && d->dns._rd == 1)) {
		return 0;
	}
	if (print_query_counter) {
		int32_t now = d->dns.tv_sec - (d->dns.tv_sec % counter.interval);
		if (now != counter.prev) {
			print_counter();
			counter.prev = now;
		} else {
			counter.counter += 1;
		}
	}
	if (name_list.hash != NULL) {
		e = match_name(&name_list, d);
		if (e == NULL) return 0;
	}
	if (flag_error_only && d->dns.error == 0) return 0;
	if (ignore_EDNS && d->dns._edns0 != 0) return 0;
	if (ignore_noEDNS && d->dns._edns0 == 0) return 0;
	if (ignore_CD && d->dns._cd != 0) return 0;
	if (ignore_noCD && d->dns._cd == 0) return 0;
	if (ignore_DO && d->dns._do != 0) return 0;
	if (ignore_noDO && d->dns._do == 0) return 0;
	if (ignore_RD && d->dns._rd != 0) return 0;
	if (ignore_noRD && d->dns._rd == 0) return 0;
	if (ignore_OPCODE0 && d->dns._opcode == 0) return 0;
	if (ignore_noOPCODE0 && d->dns._opcode != 0) return 0;
	if (ignore_RCODE0 && d->dns._opcode == 0) return 0;
	if (ignore_noRCODE0 && d->dns._opcode != 0) return 0;
	if (ignore_REF && (d->dns._ancount == 0 && d->dns._rcode == 0 && d->dns._nscount != 0)) return 0;
	if (ignore_noREF && (d->dns._ancount != 0 || d->dns._rcode != 0 || d->dns._nscount == 0)) return 0;
	if (ignore_ANCOUNT0 && d->dns._ancount == 0) return 0;
	if (ignore_noANCOUNT0 && d->dns._ancount != 0) return 0;
	if (ignore_AD && d->dns._ad != 0) return 0;
	if (ignore_noAD && d->dns._ad == 0) return 0;
	if (ignore_TC && d->dns._tc != 0) return 0;
	if (ignore_noTC && d->dns._tc == 0) return 0;
	if (flag_greater_than > 0 && d->dns.dnslen < flag_greater_than) return 0;
	if (flag_smaller_than > 0 && d->dns.dnslen > flag_smaller_than) return 0;
	if (flag_filter_ednsopt != 0 && d->dns._edns_rdlen == 0)
		return 0;
	if (print_tcp_delay_longer_than >= 0) {
		if (d->dns.tcp_delay <= 0 ||
		    d->dns.tcp_delay < print_tcp_delay_longer_than)
			return 0;
	}
	if (print_tcp_delay_shorter_than >= 0) {
		if (d->dns.tcp_delay <= 0 ||
		    d->dns.tcp_delay > print_tcp_delay_shorter_than)
			return 0;
	}
	if (print_queries_csv) print_csv(d);
	if (print_queries_bind9) print_bind9log(d);
	if (do_print_dns_answer > 1 && (d->mode & MODE_PARSE_ANSWER)) {
		print_dns_answer(d);
	}
	if (do_print_hexdump)
		hexdump("", d->dns.dns, d->dns.dnslen);
	if (print_queries_debug) print_debug(d);
	count_printed++;
	if (print_limit > 0 && count_printed >= print_limit) exit(0);
	return 0;
}

void load_ipaddrlist_tld(char *tld)
{
	char buff[512];
	int l;
	FILE *fp;
	char *p, *q;

	if ((fp = fopen(serverlist_file, "r")) == NULL)
		err(1, "cannot open %s", serverlist_file);
	l = strlen(tld);
	while(fgets(buff, sizeof buff, fp) != NULL) {
		if (buff[0] == '#') continue;
		if (strncmp(buff, "T,", 2) == 0
		   && strncasecmp(buff+2, tld, l) == 0
		   && buff[2+l] == ',') {
			p = &buff[2+l+1];
			q = strchr(p, '\n');
			if (q != NULL) *q = 0;
			q = strchr(p, ',');
			if (q != NULL) { p = q+1; }
			do {
				q = strchr(p, '/');
				if (q != NULL) {
					*q = 0;
					q++;
				}
				register_ipaddr_port_hash(p, &dst_list, 0);
				p = q;
			} while (p != NULL);
		}
	}
	fclose(fp);
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
"-X      Print each DNS messages in hex\n"
"-A      Parse response packets\n"
"-A -A   Print DNS answer\n"
"\n"
"-9      Print queries in BIND 9 querylog format\n"
"-C      Print queries in CSV format\n"
"-U      Print more data for debug\n"
"-P      Erroneous qname characters are changed to '!' (otherwise, BIND 9 style\n"
"-i      Qname are changed as lowercase\n"
"-q NN   Print query counter in each NN second\n"
"\n"
"-D num  Debug flag\n"
"-B      ip addr/port match both query/response\n"
"-a ipaddr      print if the ipaddr matches source addr/port\n"
"-b ipaddr#port[,ipaddr#port,..]  specify destination IP addr/port\n"
"-f list specify destination TLD/root server IP address list file\n"
"-t TLD  Match specified TLD servers as destination (requires -f)\n"
"-I file Load IPaddrlist and print packets whose IP address matches\n"
"-J      print IPaddrlist\n"
"-N file Load qname list file and print packets whose qname matches\n"
"-n qname  Sepficy qname: print packets whose qname matches\n"
"-x XX,XX,XX : Exclude queries\n"
"   XX: v4,v6,TCP,UDP,OPCODE0,noOPCODE0,EDNS,noEDNS,DO,noDO,AD,noAD,RD,noRD,\n"
"       TC,noTC,RCODE0,noRCODE0,ANCOUNT0,noANCOUNT0,noREF,REF (response)\n"
"       QNAME (inverse -n/-N options)\n"
"-p XX,XX,XX : Print DNS answer options\n"
"       RefNS,RefGlue,RefDS,AuthSOA,AnsA,AnsAAAA,AnsNS,AnsDS,AnsCNAME,AnsPTR,ALLRR\n"
"       EDNSSIZE/FLAG/DNSLEN... print edns0udpsize,flag,dnslen on DNS query/answer\n"
"-G size: print if DNS size is greater or equal to 'size'\n"
"-L size: print if DNS size is smaller or equal to 'size'\n"
"-R      Print response detail\n"
"-o off  Timezone read offset\n"
"-M num  exit if num lines printed\n"
"-y      print filename\n"
"-O      Print EDNS0 option\n"
"-g      Print Checksum Error\n"
"-c      Print packets with error only\n"
"-s time Data start time\n"
"-l len  Data time length (second)\n"
"-T msec Print packets if RTT >= msec\n"
"-T -msec Print packets if RTT < msec\n"
"-S      Print TCP/SYN (CSV mode only)\n"
"-z      enable TCP State ... print TCP RTT\n"
"-6 file Load IPv6 addrlist and try to update IPv6 address\n"
"-F      update IPv4 address by header/udp checksum\n"
"\n"
"-Y      Print statistics\n"
"-Z      Print label\n"
"-r RD   specify RD=0 or RD=1 or -1:any\n"
"\n"
"Result: CSV mode (-C) ... see with -Z option\n"
"        BIND 9 mode ... added Error:  4=IPv4HeaderChecksum u=UDPchecksum\n"
"                                      t=TCPError 6=IPv6Length E=EDNS\n"
"                                      D=DNSerror a=AnswerAnalysis c=CNAME err\n"
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

int getopt_env_(char *str, char **envp)
{
	int ch = -1;
	char *p, *q;

	p = *envp;
	while(*p == ' ' || *p == '\t') p++;
	if (*p != '-' || p[1] == 0) return -1;
	ch = p[1];
	q = strchr(str, ch);
	if (q == NULL) return -1;
	if (q[1] == ':') {
		p += 2;
		while(*p == ' ' || *p == '\t') p++;
		optarg = p;
		while(*p != ' ' && *p != '\t' && *p != 0) p++;
		if (*p == 0) {
			*envp = p;
		} else {
			*p = 0;
			*envp = p+1;
		}
		return ch;
	} else {
		*envp = p+2;
		return p[1];
	}
}

int getopt_env(int argc, char **argv, char *str, char *env)
{
	static int envfinish = 0;
	static char *envp = NULL;
	int ch;

	if (envfinish == 0 && env != NULL) {
		if (envp == NULL) envp = env;
		ch = getopt_env_(str, &envp);
		if (ch > 0) return ch;
		envfinish = 1;
	 }
	return getopt(argc, argv, str);
}

int parse_exclude_option(char *str)
{
	struct ignore_options *x;
	char *p;
	static char sep[] = ",";

	while((p = strtok(str, sep)) != NULL) {
		str = NULL;
		for (x = ignore_options; x->name != NULL; x++) {
			if (strcasecmp(x->name, p) == 0) {
				//printf("Found: %s\n", p);
				*(x->variable) = 1;
				break;
			}
		}
		if (x->name == NULL) {
			fprintf(stderr, "NotFound: %s\n", p);
			return -1;
		}
	}
	return 0;
}

int parse_print_answer_options(char *str)
{
	struct print_answer_options *x;
	char *p;
	int bitmap = 0;
	static char sep[] = ",";

	while((p = strtok(str, sep)) != NULL) {
		str = NULL;
		for (x = print_answer_options; x->name != NULL; x++) {
			if (strcasecmp(x->name, p) == 0) {
				bitmap |= x->bit;
				//printf("Found: %s\n", p);
				break;
			}
		}
		if (x->name == NULL) {
			fprintf(stderr, "NotFound: %s\n", p);
			return -1;
		}
	}
	return bitmap;
}


void parse_args(int argc, char **argv, char *env, struct DNSdataControl *c)
{
	int ch;
	int print_answer_option = 0;
	double t;

	c->getdname_options = 0;

	while ((ch = getopt_env(argc, argv, "a:b:t:T:q:9BCUYD:AQL:o:hvf:l:O:cgI:Jr:XZG:x:BXp:q:n:N:s:yPRSizF6:M:", env)) != -1) {
	// printf("getopt: ch=%c optarg=%s\n", ch, optarg);
	switch (ch) {
	case 'P': c->getdname_options |= GET_DNAME_IgnoreErrorChar; break;
	case 'B': both_direction = 1; break;
	case 'n': register_name_list(optarg, &name_list, 0); break;
	case 'N': load_name_list(optarg, &name_list); break;
	case 'a': register_ipaddr_port_hash(optarg, &src_list, flag_v); break;
	case 'b': register_ipaddr_port_hash(optarg, &dst_list, flag_v); break;
	case 'C': print_queries_csv++; break;
	case '9': print_queries_bind9++; break;
	case 'U': print_queries_debug++; break;
	case 'q':
		counter.interval = strtol(optarg, NULL, 10);
		if (counter.interval == 0 && errno != 0) { usage('L'); }
		counter.counter = 0; counter.prev = 0; print_query_counter = 1; break;
	case 'D': c->debug = strtol(optarg, NULL, 10);
		  if (c->debug == 0 && errno != 0) { usage('D'); } break;
	case 'O': tz_offset = atoi(optarg); break;
	case 'o': tzread_offset = atoi(optarg); break;
	case 'Q': c->mode |= MODE_PARSE_QUERY; break;
	case 'A':
		c->mode |= MODE_PARSE_ANSWER | MODE_ANSWER_TTL_CNAME_PARSE;
		do_print_dns_answer++; break;
	case 'Y': print_statistics = 1; break;
	case 'y': print_filename = 1; break;
	case 'R': print_response_detail = 1; flag_print_ednsopt = 1; break;
	case 'v': flag_v = 1; break;
	case 'g': flag_print_error = !flag_print_error; break;
	case 'c': flag_error_only++; break;
	case 's': data_start = atoi(optarg); break;
	case 'l': data_time_length = atoi(optarg); break;
	case 'I': load_ipaddrlist(optarg, 0); break;
	case 'J': flag_print_ipaddr_hash = 1; break;
	case 'f': serverlist_file = optarg; break;
	case 't': if (serverlist_file != NULL) {
			load_ipaddrlist_tld(optarg);
			break;
		  }
		  err(1, "specify TLD server list\n");
		  break;
	case 'r':
		select_rd = atoi(optarg);
		if (select_rd<-1 || select_rd>1 || (select_rd==0 && *optarg != '0'))
			usage(ch);
		break;
	case 'Z': flag_print_labels++; break;
	case 'X': do_print_hexdump = 1; break;
 	case 'G': flag_greater_than = strtol(optarg, NULL, 10);
			if (flag_greater_than == 0 && errno != 0) { usage(ch); }; break;	
 	case 'L': flag_smaller_than = strtol(optarg, NULL, 10);
		  if (flag_smaller_than == 0 && errno != 0) { usage(ch); } break;
	case 'x': if (parse_exclude_option(optarg) != 0) usage(ch); break;
	case 'p': if ((c->print_answer_options = parse_print_answer_options(optarg)) == -1) usage(ch);
		c->debug |= print_answer_option; break;
	case 'e': flag_ignore_error = 1; break;
	case 'T': t = atof(optarg);
		if (t >= 0) { print_tcp_delay_longer_than = t * 1000; }
		else { print_tcp_delay_shorter_than = -t * 1000; }
		break;
	case 'i': c->getdname_options |= GET_DNAME_LOWERCASE; break;
	case 'S': print_tcpsyn = 1; break;
	case 'z': c->enable_tcp_state = 1; break;
	case 'F': c->mode |= MODE_FIX_IPV4ADDR; break;
	case 'M': print_limit = atoi(optarg); break;
#ifdef IPV6_PREFIX_HASH
	case '6': c->v6hash = load_ipv6_prefix_list(optarg); break;
#endif
	case '?':
	default: usage(ch);
	}}
}

int main(int argc, char *argv[])
{
	int ret, i;
	char *env, *p, *q;
	struct DNSdataControl c;
	char buff2[1024];
	char csv_str[] = CSV_STR;
	char *sep = ",";

	memset(&c, 0, sizeof(c));
	env = getenv(ENVNAME);
	c.mode = MODE_IGNOREERROR | MODE_IGNORE_CHECKSUM_ERROR;
	c.enable_tcp_state = 0;
	c.do_scanonly =0;
	c.debug = 0;
	parse_args(argc, argv, env, &c);
	argc -= optind;
	argv += optind;
	c.tz_read_offset = tzread_offset;
	if ((c.mode & (MODE_PARSE_QUERY|MODE_PARSE_ANSWER)) == 0)
		c.mode |= MODE_PARSE_QUERY;
	if (print_query_counter == 0 && print_queries_csv == 0 && print_queries_bind9 == 0) {
		print_queries_bind9 = 1;
	}
	if (flag_print_labels != 0 && print_queries_csv != 0) {
		printf("%s\n", csv_str);
		if (flag_print_labels > 1) {
			i = 1;
			p = strtok_r(csv_str, sep, &q);
			while (p != NULL) {
				printf("\t%d,%s\n", i++, p);
				p = strtok_r(NULL, sep, &q);
			}
		}
	}
	if (data_start != 0 && data_time_length != 0)
		data_end = data_start + data_time_length;

	c.callback = pcapgetquery_callback;
	c.rawlen = 65536;
	c.raw = my_malloc(c.rawlen);

	if (print_tcpsyn) { c.enable_tcpsyn_callback = 1; }

	if (flag_print_ipaddr_hash) {
		printf("src_list:\n");
		print_ipaddrlist_hash(&src_list);
		printf("dst_list:\n");
		print_ipaddrlist_hash(&dst_list);
		printf("name_list:\n");
		print_name_list(&name_list);
	}
	if (argc > 0) {
		while (*argv != NULL) {
			p = *argv++;
			if (strcmp(p, "-") == 0) p = NULL;
			if (flag_v) {
				fprintf(stderr, "Loading %s.\n", p);
				fflush(stderr);
			}
			if (c.do_scanonly) {
				memset(&c.ParsePcapCounter, 0, sizeof(c.ParsePcapCounter));
				ret = parse_file(p, &c, 0);
				printf("%s,%lu,%lu,%d\n", p, c.ParsePcapCounter.first_ts, c.ParsePcapCounter.last_ts, ret);
			} else {
				ret = parse_file(p, &c, 0);
				if (ret != ParsePcap_NoError) {
					printf("#Error:%s:%s:errno=%d\n", parse_file_error(ret), p, errno);
					if (flag_ignore_error == 0) {
						exit(1);
					}
				}
			}
		}
	} else
	if (isatty(fileno(stdin)) == 1) {
		if (!flag_print_labels) usage(0);
	} else {
		while (fgets(buff2, sizeof buff2, stdin) != NULL) {
			ret = strlen(buff2);
			if (ret > 0 && buff2[ret-1] == '\n') {
				buff2[ret-1] = 0;
			}
			p = strchr(buff2, ',');
			c.node[0] = 0;
			if (p != NULL) {
				*p++ = 0;
				if (isalpha(*p)) {
					c.letter = *p;
					strncpy(c.node, p, sizeof(c.node));
					c.node[sizeof(c.node)-1] = 0;
					c.current_nodeid = add_node_name(&c, c.node);
				}
			}
printf("Loading %s\n", buff2);
			ret = parse_file(buff2, &c, 0);
			if (ret != ParsePcap_NoError) {
				printf("#Error:%s:%s:errno=%d\n", parse_file_error(ret), buff2, errno);
				if (flag_ignore_error == 0) {
					exit(1);
				}
			}
		}
	}
	if (print_statistics) {
		if (print_queries_csv) {
			printf("#Number,print/notprint/total,%d,%d,%d\n",
				count_printed, count_notprinted, count_printed+count_notprinted);
		} else {
			Print_PcapStatistics(&c);
		}
	}
	//dump_tcpbuff();
	//tcpbuff_statistics();

	return 0;
}
