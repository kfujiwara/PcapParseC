/*
	$Id: PcapParse.c,v 1.134 2020/08/06 07:28:32 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

	int parse_pcap(char *file, struct DNSdataControl* c) reads
	pcap files or BIND 9 log files (with/without gzip/bzip2/xz) and
	calls callback function.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.

        How to use: write a code and link with PcapParse.c.

	Example code:

	    #include "PcapParse.h"

	    int counter = 0;

	    int callback(struct DNSdataControl *c, int mode)
	    {
		c->dns contains DNS query information. see PcapParse.h
		if (c->dns._rd) counter++;
	    }
	    void print_result()
	    {
		printf("Num of RD1 = %d\n", counter);
	    }
	    main(int argc, char **argv) {
		struct DNSdataControl c;
		c.callback = callback;
		c.otherdata = NULL; // other data loader function
		c.debug = 0; // Flags
		while(*argv) {
		    int ret = parse_pcap(*argv, &c);
		    argv++;
		}
		print_result();
	    }

*/

#include <stdio.h>

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDLIB_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "PcapParse.h"

/* Ignore UDP fragment */
/* parse query packet only */

/*
 hexdump for debug
 */

void hexdump(char *msg, u_char *data, int len)
{
	int addr = 0;
	if (msg != NULL)
		printf("%s : \n", msg);
	while(len-- > 0) {
		if ((addr % 16) == 0) {
			printf("%s%04x ", (addr!=0)?"\n":"", addr);
		}
		printf("%02x ", *data++);
		addr++;
	}
	printf("\n");
}

/*****************************************************************************
	 Warning
			Little endian only
			Supported Linktype: 0==PPP	1==Ether
 *****************************************************************************
 */

unsigned long long int get_uint32(struct DNSdata *d)
{
	u_char *p;

	p = (u_char *)(d->dns + d->pointer);
	if (p + 4 > d->endp)
		return -1;
	d->pointer += 4;
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

unsigned int get_uint16(struct DNSdata *d)
{
	u_char *p;

	p = (u_char *)(d->dns + d->pointer);
	if (p + 2 > d->endp)
		return -1;
	d->pointer += 2;
	return (p[0] << 8) | p[1];
}

void labelcopy(u_char *dest, u_char *src, int count)
{
	u_char c;

	while (count-- > 0) {
		c = *src;
		if (c < 0x21 || c == ',' || c == ':' || c >= 0x7f) {
			c = '!';
		} else {
			c = tolower(c);
		}
		*dest++ = c;
		src++;
	}
}

int labelcopy_bind9(u_char *dest, u_char *src, int count)
{
	u_char c;
	int n = 0;
	while (count-- > 0) {
		c = *src++;
		switch(c) {
		case '@': case '$': case '"': case '(': case ')': case '.':
		case ';': case '\\':
			*dest++ = '\\';
			*dest++ = c;
			n+=2;
			break;
		default:
			if (c > 0x20 && c < 0x7f) {
				*dest++ = c; n++;
			} else {
				*dest++ = '\\';
				*dest++ = '0' + ((c / 100) % 10);
				*dest++ = '0' + ((c / 10) % 10);
				*dest++ = '0' + (c % 10);
				n += 4;
			}
			break;
		}
	}
	return n;
}

#define	GET_DNAME_NO_COMP 1
#define GET_DNAME_NO_SAVE 2
#define	GET_DNAME_SEPARATE 4
int get_dname(struct DNSdata *d, u_char *o, int o_len, int mode, int bind9logmode)
{
	unsigned char *p;
	int olen = 0;
	int count;
	u_char *op = o;
	int newp = 0;
	int nlabel = 0;
	u_char *wp = d->qnamebuf;
	int i, j;
	int prev_compress = 65536;

	if (mode & GET_DNAME_SEPARATE) {
		d->nlabel = 0;
		d->label[0] = NULL;
		d->label[1] = NULL;
	}
	p = (unsigned char *)d->dns + d->pointer;

	while (p < d->endp) {
		if (*p == 0) {
			if (olen + 2 > o_len) return -1;
			if (op == o) {
				*op++ = '.';
				olen++;
			}
			*op = 0;
			if (newp == 0 && (mode & GET_DNAME_NO_SAVE) == 0) d->pointer = p + 1 - d->dns;
			if (mode & GET_DNAME_SEPARATE) {
				d->nlabel = nlabel;
				/* swap order */
				for (i = 0, j = nlabel - 1; i < j; i++, j--) {
					wp = d->label[i];
					d->label[i] = d->label[j];
					d->label[j] = wp;
				}
			}
			return olen;
		} else if ((*p & 192) == 192) {
			if (mode & GET_DNAME_NO_COMP) return -1;
			if (newp == 0 && (mode & GET_DNAME_NO_SAVE) == 0) d->pointer = p + 2 - d->dns;
			newp = (p[0] & 0x3f) * 256 + p[1];
			if (newp >= (p - d->dns) || newp == 0 || prev_compress <= newp)
				return -1;
			prev_compress = newp;
			p = d->dns + newp;
		} else if (*p > 63) {
			return -1;
		} else {
			if (p + *p + 1 >= d->endp) return -1;
			if (olen + *p + 1 > o_len) return -1;
			if (op != o) {
				*op++ = '.';
				olen++;
			}
			if (bind9logmode) {
				count = labelcopy_bind9(op, p+1, *p);
				olen += count;
				op += count;
			} else {
				labelcopy(op, p+1, *p);
				olen += *p;
				op += *p;
			}
			if (mode & GET_DNAME_SEPARATE) {
				if (nlabel >= PcapParse_LABELS)
					return -1;
				d->label[nlabel++] = wp;
				memcpy(wp, p+1, *p);
				wp[*p] = 0;
				wp += *p + 1;
			}
			p += *p + 1;
		}
	}
	return -1;
}

static u_char _count[] = { 0, 1, 0, 0, 0, 0, 0 };
static u_char _edns0[] = { 0, 0, 41 };

#define TCPBUF_BUFFLEN 4096
#define TCPBUF_HEADERLEN 128
#define TCPBUF_LEN 10

struct TCPbuff {
	int used;
	u_int32_t timestamp;
	u_char header[TCPBUF_HEADERLEN];
	int headerlen;
	u_char buff[TCPBUF_BUFFLEN];
	int datalen;
	int count;
};
static struct TCPbuff tcpbuff[TCPBUF_LEN];
static int tcpbuff_used = -1;
static int tcpbuff_max = 10;

int parse_edns(struct DNSdataControl *d)
{
	int c;
	int i;
	u_char *p;
	int rdlen, rdlen0;
	int optcode, optlen;
	int error = 0;
	u_short keytag;

	p = d->dns.dns + d->dns.pointer;

#if DEBUG
printf("parse_edns: p=%lx dns=%lx pointer=%d\n[", p, d->dns.dns, d->dns.pointer);
while (p < d->dns.endp) {
	printf(" %02x", *p++);
}
printf("\n");
	p = d->dns.dns + d->dns.pointer;
fflush(stdout);
#endif

	if (p + 11 > d->dns.endp
	   || p[0] != 0 || p[1] != 0 || p[2] != 41) {
		if (d->debug & FLAG_INFO)
			hexdump("#Error:BrokenEDNS0",
				d->dns._ip, d->dns.len);
		return ParsePcap_EDNSError;
	}
	d->dns._edns0 = 1;
	d->dns._do = (p[7] & 0x80) != 0 ? 1 : 0;
	d->dns._ednsver = p[8];
	d->dns.edns0udpsize = p[3] * 256 + p[4];
	d->dns._edns_numopts = 0;
	rdlen0 = rdlen = p[9] * 256 + p[10];
	d->dns._edns_rdlen = rdlen;
	p += 11;
	if (p + rdlen > d->dns.endp) {
		if (d->debug & FLAG_INFO)
			hexdump("#Error:BrokenEDNS0", d->dns._ip, d->dns.len);
		error = ParsePcap_EDNSError;
		rdlen = d->dns.endp - p;
	}
	while(rdlen >= 4) {
		optcode = p[0] * 256 + p[1];
		optlen = p[2] * 256 + p[3];
		rdlen -= 4;
		p += 4;
		switch (optcode) {
		case 0: // Reserved
			d->dns._edns_reserved = 1;	break;
		case 1: // LLQ
			d->dns._edns_llq = 1;	break;
		case 2: // UL
			d->dns._edns_ul = 1;	break;
		case 3: // NSID
			d->dns._edns_nsid = 1;
			d->dns._edns_nsid_bufflen = optlen;
			if (optlen > 0)
				memcpy(d->dns._edns_nsid_buff, p, optlen > 256? 256:optlen);
			break;
		case 5: // DAU
			d->dns._edns_dau = 1;	break;
		case 6: // DHU
			d->dns._edns_dhu = 1;	break;
		case 7: // N3U
			d->dns._edns_n3u = 1;	break;
		case 8: // ECS
			d->dns._edns_ecs = 1;
			if (rdlen < optlen) {
				error |= ParsePcap_EDNSError;
				break;
			}
			d->dns._edns_ecs = p[0] * 256 + p[1];
			d->dns._ecs_mask = p[2];
			for (i = 4; i < optlen; i++) {
				d->dns._ecs_addr[i-4] = p[i];
			}
			break;
		case 9: // Expire
			d->dns._edns_expire = 1;
			break;
		case 10: // COOKIE
			d->dns._edns_cookie = 1;
			d->dns._edns_cookie_len = optlen;
			break;
		case 11: // keepalive
			d->dns._edns_keepalive = 1; break;
		case 12: // padding
			d->dns._edns_padding = 1; break;
		case 13: // chain
			d->dns._edns_chain = 1; break;
		case 14: // keytag
			d->dns._edns_keytag = 1;
			while (optlen > 0) {
				keytag = (p[0] << 8) || p[1];
				p += 2;
				optlen -= 2;
				if (keytag == 0x4a5c) {
					d->dns._edns_keytag_4a5c = 1;
				} else if (keytag == 0x4f66) {
					d->dns._edns_keytag_4f66 = 1;
				}
			}
			break;
		case 65001: // SIT
			d->dns._edns_cookiesit = 1;
			d->dns._edns_cookie_len = optlen;
			break;
		case 65535: // Future use 
			d->dns._edns_future++; break;
		default:
			if (optcode <= 65000) { d->dns._edns_unassigned++;}
			else { d->dns._edns_experimental++;}
		}
		rdlen -= optlen;
		p += optlen;
		d->dns._edns_numopts++;
	}
	if (rdlen != 0)
		error =ParsePcap_EDNSError;
	d->dns.pointer += rdlen0;
	return error;
}
	
void parse_DNS_query(struct DNSdataControl *d)
{
	int c;
	int i;
	u_char *p;
	int rdlen;
	int optcode, optlen;

	d->dns.req_sport = d->dns.p_sport;
	d->dns.req_dport = d->dns.p_dport;
	d->dns.req_src = d->dns.p_src;
	d->dns.req_dst = d->dns.p_dst;

	d->ParsePcapCounter._dns_query++;
	if ((d->debug & FLAG_NO_INETNTOP) == 0) {
		inet_ntop(d->dns.af, d->dns.req_src, (char *)d->dns.s_src, sizeof(d->dns.s_src));
		inet_ntop(d->dns.af, d->dns.req_dst, (char *)d->dns.s_dst, sizeof(d->dns.s_dst));
	}

	if (d->debug & FLAG_DO_ADDRESS_CHECK)
		if (d->callback(d, CALLBACK_ADDRESSCHECK) == 0) {
			d->ParsePcapCounter._unknown_ipaddress++;
			return;
		}

	if (d->dns.version == 6 && (d->dns.p_src[0] & 0xfc) == 0xfc) {
		return;
	}
#if 0
	switch (d->dns.p_sport) {
	case 7: /* echo */
	case 13: /* daytime */
	case 19: /* chargen */
	case 37: /* time */
		return;
	}
#endif
	d->ParsePcapCounter._before_checking_dnsheader++;

	do {
		if (d->dns._opcode != 0 && d->dns._opcode != 5) {
			if (d->debug & FLAG_INFO) {
				hexdump("#Error:bad opcode",
					d->dns._ip, d->dns.len);
			}
			d->dns.error |= ParsePcap_DNSError;
			break;
		}
		if (d->dns._opcode == 0
		   && memcmp(d->dns.dns+4, _count, 7) != 0) {
			if (d->debug & FLAG_INFO)
				hexdump("#Error:op0, bad count",
					d->dns._ip, d->dns.len);
			d->dns.error |= ParsePcap_DNSError;
			break;
		}
		c = get_dname(&d->dns, d->dns.qname, sizeof(d->dns.qname),
		    	GET_DNAME_NO_COMP | GET_DNAME_SEPARATE,
			d->debug & FLAG_BIND9LOG);
		d->dns.qtype = get_uint16(&d->dns);
		d->dns.qclass = get_uint16(&d->dns);
		if (c <= 0 || d->dns.qtype < 0 || d->dns.qclass < 0
		    || strlen((char *)d->dns.qname) > 255) {
			d->dns.error |= ParsePcap_DNSError;
			break;
		}
		if (d->dns.dns[11] == 0) break; // non EDNS
		d->dns.error |= parse_edns(d);
	} while (0);
	if (d->dns.error & ParsePcap_EDNSError)
		d->ParsePcapCounter._edns_error++;
	d->ParsePcapCounter._parsed_dnsquery++;
	(void)(d->callback)(d, CALLBACK_PARSED);
}

void print_dns_answer(struct DNSdataControl *d)
{
	int c;
	u_char *p, *q;
	u_short *r;
	u_char rr_name[257], rr_rdata_name[257];
	int i, j, k, eflag;
	int rr_type, rr_class, rr_ttl, rr_rdlength;
	int anssec, authsec, additional;
	int rr_rdlength0;
	u_char *rr_rdata;
	int update_flag = 0;
	int print_refns = (d->debug & FLAG_PRINTANS_REFNS) || (d->debug & FLAG_PRINTANS_ALLRR);
	int print_refglue = (d->debug & FLAG_PRINTANS_REFGLUE) || (d->debug & FLAG_PRINTANS_ALLRR);
	int print_answer = (d->debug & FLAG_PRINTANS_ANSWER) || (d->debug & FLAG_PRINTANS_ALLRR);
	int print_soa = (d->debug & FLAG_PRINTANS_AUTHSOA) || (d->debug & FLAG_PRINTANS_ALLRR);
	int print_info = (d->debug & FLAG_PRINTANS_INFO) || (d->debug & FLAG_PRINTANS_ALLRR);
	int print_allrr = (d->debug & FLAG_PRINTANS_ALLRR);

	if (d->dns._qr == 0 && d->dns._opcode == 5) { update_flag = 1; }
	d->dns.pointer = 12;
	c = get_dname(&d->dns, rr_name, sizeof(rr_name), GET_DNAME_NO_COMP, d->debug & FLAG_BIND9LOG);
	rr_type = get_uint16(&d->dns);
	rr_class = get_uint16(&d->dns);
	if (d->dns.req_src[0] == 0) {
		inet_ntop(d->dns.af, d->dns.req_src, (char *)d->dns.s_src, sizeof(d->dns.s_src));
		inet_ntop(d->dns.af, d->dns.req_dst, (char *)d->dns.s_dst, sizeof(d->dns.s_dst));
	}
	if (print_info) {
		printf("%s.%d -> %s.%d: %s %d %d edns0=%d flag=%02x:%02x do=%d %d/%d/%d dnssecrr=%d iplen=%d dnslen=%d\n", d->dns.s_src, d->dns.req_sport, d->dns.s_dst, d->dns.req_dport, rr_name, rr_type, rr_class, d->dns._edns0, d->dns._flag1, d->dns._flag2, d->dns._do, d->dns.dns[7], d->dns.dns[9], d->dns.dns[11], d->dns.additional_dnssec_rr, d->dns.iplen, d->dns.dnslen);
	}
	anssec = d->dns.dns[7];
	authsec = d->dns.dns[9];
	additional = d->dns.dns[11];
	k = 0;
	while (anssec + authsec + additional > 0) {
	  i = get_dname(&d->dns, rr_name, sizeof(rr_name), 0, 0);
		if (i < 0) break;
		rr_type = get_uint16(&d->dns);
		rr_class = get_uint16(&d->dns);
		rr_ttl = get_uint32(&d->dns);
		rr_rdlength = get_uint16(&d->dns);
		if (rr_type == 41) {
			if (print_info && anssec == 0 && authsec == 0) {
				printf("Additional: %s %d %d %d OPT %d [", rr_name, rr_type, rr_class, rr_ttl, rr_rdlength);
				p = d->dns.dns + d->dns.pointer;
				rr_rdlength0 = rr_rdlength;
				while (rr_rdlength0-- > 0) {
					printf(" %02x", *p++);
				}
				printf(" ]\n");
			}
		} else
		if (rr_type == 5) {
			i = get_dname(&d->dns, rr_rdata_name, sizeof(rr_rdata_name), GET_DNAME_NO_SAVE, d->debug & FLAG_BIND9LOG);
			if (i < 0) break;
			if (print_answer && anssec > 0) {
				printf("ANSSEC: %s %d %d %d CNAME %s\n", rr_name, rr_type, rr_class, rr_ttl, rr_rdata_name);
			}
		} else
		if (rr_type == 2) {
		  	i = get_dname(&d->dns, rr_rdata_name, sizeof(rr_rdata_name), GET_DNAME_NO_SAVE, d->debug & FLAG_BIND9LOG);
			if (i < 0) break;
			if (print_refns && anssec == 0 && authsec > 0) {
				printf("REFNS: %s %d %d %d NS %s\n", rr_name, rr_type, rr_class, rr_ttl, rr_rdata_name);
			} else
			if (print_answer && anssec > 0) {
				printf("ANSSEC: %s %d %d %d NS %s\n", rr_name, rr_type, rr_class, rr_ttl, rr_rdata_name);
			}
		} else
		if (rr_type == 12) {
			i = get_dname(&d->dns, rr_rdata_name, sizeof(rr_rdata_name), GET_DNAME_NO_SAVE, d->debug & FLAG_BIND9LOG);
			if (i < 0) break;
			if (print_answer && anssec > 0) {
				printf("ANSSEC: %s %d %d %d PTR %s\n", rr_name, rr_type, rr_class, rr_ttl, rr_rdata_name);
			}
		} else
		if (rr_type == 1 && rr_rdlength == 4) {
			q = d->dns.dns + d->dns.pointer;
			if (print_refglue && anssec == 0 && authsec == 0) {
				printf("Glue: %s %d %d %d A %d.%d.%d.%d\n", rr_name, rr_type , rr_class, rr_ttl, q[0], q[1], q[2], q[3]);
			} else
			if (print_answer && anssec > 0) {
				printf("ANSSEC: %s %d %d %d A %d.%d.%d.%d\n", rr_name, rr_type , rr_class, rr_ttl, q[0], q[1], q[2], q[3]);
			} else
			if ((anssec == 0 && authsec == 0) && print_allrr) {
				printf("ADDITIONAL: %s %d %d %d A %d.%d.%d.%d\n", rr_name, rr_type , rr_class, rr_ttl, q[0], q[1], q[2], q[3]);
			}
		} else
		if (rr_type == 24 && rr_rdlength == 16) {
			r = (u_short *)d->dns.dns + d->dns.pointer;
			if (print_refglue && anssec == 0 && authsec == 0) {
				printf("Glue: %s %d %d %d AAAA %x:%x:%x:%x:%x:%x:%x:%x\n", rr_name, rr_type, rr_class, rr_ttl, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
			} else
			if (print_answer && anssec > 0) {
				printf("ANSSEC: %s %d %d %d AAAA %x:%x:%x:%x:%x:%x:%x:%x\n", rr_name, rr_type, rr_class, rr_ttl, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
			} else
			if ((anssec == 0 && authsec == 0) && print_allrr) {
				printf("ADDITIONAL: %s %d %d %d AAAA %x:%x:%x:%x:%x:%x:%x:%x\n", rr_name, rr_type, rr_class, rr_ttl, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
			}
		} else
		if (rr_type == 6) {
			if (print_soa && anssec == 0 && authsec > 0) {
				printf("AuthSOA: %s %d %d %d SOA %d\n", rr_name, rr_type, rr_class, rr_ttl, rr_rdlength);
			} else
			if (print_answer && anssec > 0) {
				printf("ANSSEC: %s %d %d %d SOA %d\n", rr_name, rr_type, rr_class, rr_ttl, rr_rdlength);
			}
		} else {
			if (print_answer && anssec > 0) {
				printf("ANSWER: %s %d %d %d rdlen=%d", rr_name, rr_type, rr_class, rr_ttl, rr_rdlength);
				p = d->dns.dns + d->dns.pointer;
				rr_rdlength0 = rr_rdlength;
				while (rr_rdlength0-- > 0) {
					printf(" %02x", *p++);
				}
				printf("\n");
			}
		}
		d->dns.pointer += rr_rdlength;
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

struct cname_list
{
	u_char owner[PcapParse_DNAMELEN];
	u_char target[PcapParse_DNAMELEN];
	int ttl;
	int used;
};
#define	NUM_CNAME	16

int _comp4(const void *p1, const void *p2)
{
	return memcmp(p1, p2, 4);
}

int _comp6(const void *p1, const void *p2)
{
	return memcmp(p1, p2, 16);
}

void parse_DNS_answer(struct DNSdataControl *d)
{
	int c;
	u_char *p, *q;
	u_short *r;
	int i, j, k, l, m, n, ttl, eflag, anssec, authsec, additional;
	u_char buff[PcapParse_DNAMELEN];
	u_char buff2[PcapParse_DNAMELEN];
	u_char qtype_name[PcapParse_DNAMELEN] = "";
	u_char soa_dom[PcapParse_DNAMELEN] = "";
	int soa_ttl = -1;
	int qtype_ttl = -1;
	int answer_ttl = -1;
	struct cname_list cname[NUM_CNAME];
	int ncname = 0;
	int cnamettl = -1;
	u_char *current;
	int found;

	d->ParsePcapCounter._dns_response++;

	d->dns.req_sport = d->dns.p_dport;
	d->dns.req_dport = d->dns.p_sport;
	d->dns.req_src = d->dns.p_dst;
	d->dns.req_dst = d->dns.p_src;
	d->dns.cname_ttl = -1;
	d->dns.answer_ttl = -1;
	d->dns.additional_dnssec_rr = 0;

	d->dns._auth_ns = 0;
	d->dns._auth_soa = 0;
	d->dns._auth_ds = 0;
	d->dns._auth_rrsig = 0;
	d->dns._auth_other = 0;
	d->dns._glue_a = 0;
	d->dns._glue_aaaa = 0;
	d->dns._answertype = _ANSWER_UNKNOWN;

	if (d->debug & FLAG_DO_ADDRESS_CHECK)
		if (d->callback(d, CALLBACK_ADDRESSCHECK) == 0) {
			d->ParsePcapCounter._unknown_ipaddress++;
			return;
		}

	d->ParsePcapCounter._before_checking_dnsheader++;

	memset(&cname, 0, sizeof cname);
	d->dns._opcode = (d->dns.dns[2] & 0x78) >> 3;
	if (d->dns._opcode != 0) return;
	d->dns._rcode = d->dns.dns[3] & 0x0f;
	if (d->dns._opcode != 0) return;
	d->dns._rd = (d->dns.dns[2] & 1);
	d->dns._cd = d->dns.dns[3] & 0x10;
	d->dns._id = (d->dns.dns[0] << 8) | d->dns.dns[1];
	if (d->dns.dns[4] != 0 && d->dns.dns[5] != 1) return;
	c = get_dname(&d->dns, d->dns.qname, sizeof(d->dns.qname), GET_DNAME_NO_COMP | GET_DNAME_SEPARATE, d->debug & FLAG_BIND9LOG);
	d->dns.qtype = get_uint16(&d->dns);
	d->dns.qclass = get_uint16(&d->dns);
	if (c <= 0 || d->dns.qtype < 0 || d->dns.qclass < 0) return;
	if (d->dns.qtype != 252 && (d->dns._rcode == 1 || d->dns._rcode == 5 || d->dns._rcode == 9)) return; /* FORMERR | REFUSED | NOTAUTH */
	d->dns._edns0 = (d->dns.endp - d->dns.dns > 512 && d->dns._ip[9] == 17) ? 1 : 0;
	anssec = d->dns.dns[7];
	authsec = d->dns.dns[9];
	additional = d->dns.dns[11];
	j = anssec + authsec + additional;
	k = 0;
	while (j > 0) {
		p = d->dns.dns + d->dns.pointer;
		if (p + 11 >= d->dns.endp &&
		    p[0] == 0 && p[1] == 0 && p[2] == 41) {
			j--;
			d->dns.error |= parse_edns(d);
			if (d->dns.error)
				break;
			continue;
		}
		i = get_dname(&d->dns, buff, sizeof(buff), 0, d->debug & FLAG_BIND9LOG);
		if (i < 0) break;
		l = get_uint16(&d->dns);
		m = get_uint16(&d->dns);
		ttl = get_uint32(&d->dns);
		n = get_uint16(&d->dns);
		if ((d->debug & FLAG_ANSWER_TTL_CNAME_PARSE) != 0) {
			if (anssec > 0) {
				if (l == d->dns.qtype && m == d->dns.qclass) {
					if (strcasecmp((char *)buff, (char *)d->dns.qname) == 0) {
						answer_ttl = ttl;
					} else {
						qtype_ttl = ttl;
						strcpy((char *)qtype_name, (char *)buff);
					}
					if (l == 1 && n == 4) {
						if (d->dns.n_ans_v4 < 16) {
							memcpy(&d->dns.ans_v4[d->dns.n_ans_v4], d->dns.dns + d->dns.pointer, n);
							d->dns.n_ans_v4++;
						}
					} else
					if (l == 28 && n == 16) {
						if (d->dns.n_ans_v6 < 16) {
							memcpy(&d->dns.ans_v6[d->dns.n_ans_v6], d->dns.dns + d->dns.pointer, n);
							d->dns.n_ans_v6++;
						}
					}
				}
				if (l == 5 && m == 1) { // IN CNAME
					i = get_dname(&d->dns, buff2, sizeof(buff2), GET_DNAME_NO_SAVE, d->debug & FLAG_BIND9LOG);
					if (i < 0) break;
					if (ncname < NUM_CNAME) {
						strcpy((char *)cname[ncname].owner, (char *)buff);
						strcpy((char *)cname[ncname].target, (char *)buff2);
						cname[ncname].ttl = ttl;
						ncname++;
					}
#ifdef DEBUG
					printf(" RR: %d  %s %d IN CNAME %s\n", j, buff, ttl, buff2);
#endif
				}
				anssec--; j--;
			} else
			if (authsec > 0) {
				if (m == 1 && l == 6) {
					strcpy((char *)soa_dom, (char *)buff);
					soa_ttl = ttl;
					d->dns._auth_soa++;
				} else
				if (m == 1 && l == 2) {
					d->dns._auth_ns++;
				} else
				if (m == 1 && l == 43) {
					d->dns._auth_ds++;
				} else
				if (m == 1 && l == 46) {
					d->dns._auth_rrsig++;
				} else {
					d->dns._auth_other++;
				}
				authsec--; j--;
			} else
			if (additional > 0) {
				if (m == 1 && l == 1) {
					d->dns._glue_a++;
				} else
				if (m == 1 && l == 24) {
					d->dns._glue_aaaa++;
				}
				additional--; j--;
			}
		}
		if ( (d->dns.qtype != 46 && l == 46)
		  || (d->dns.qtype != 47 && l == 47)
		  || (d->dns.qtype != 50 && l == 50) ) {
			d->dns.additional_dnssec_rr++;
		}
		if (n < 0) break;
		d->dns.pointer += n;
	}
	if (j != 0) {
		d->dns.error |= ParsePcap_AnswerAnalysisError;
	}
	inet_ntop(d->dns.af, d->dns.req_src, (char *)d->dns.s_src, sizeof(d->dns.s_src));
	inet_ntop(d->dns.af, d->dns.req_dst, (char *)d->dns.s_dst, sizeof(d->dns.s_dst));
	d->ParsePcapCounter._parsed_dnsquery++;

	if (d->dns.n_ans_v4 > 0) {
		qsort(&d->dns.ans_v4[0][0], d->dns.n_ans_v4, 4, _comp4);
	} else
	if (d->dns.n_ans_v6 > 0) {
		qsort(&d->dns.ans_v6[0][0], d->dns.n_ans_v6, 16, _comp6);
	}
	if ((d->debug & FLAG_ANSWER_TTL_CNAME_PARSE) != 0) {
		u_char *pp = d->dns.cnamelist;
		int pprest = sizeof(d->dns.cnamelist);
		int l;
		d->dns.answer_ttl = answer_ttl;
		d->dns.cnamelist[0] = 0;
		if (ncname > 0) {
			current = d->dns.qname;
			do {
				found = 0;
				for (i = 0; i < ncname; i++) {
					if (cname[i].used == 0 && strcasecmp((char *)cname[i].owner, (char *)current)==0) {
						found = 1;
						cname[i].used = 1;
						current = cname[i].target;
						if (cnamettl < 0 || cnamettl > cname[i].ttl)
							cnamettl = cname[i].ttl;
						l = strlen((char *)current);
						if (l+2 < pprest) {
							memcpy(pp, current, l);
							pp += l;
							*pp++ = '/';
							*pp = 0;
							pprest -= (l + 1);
						} else {
							d->dns.error |= ParsePcap_CnameError;
						}
						break;
					}
				}
			} while (found == 1);
			if (pp != d->dns.cnamelist) {
				pp[-1] = 0;
			} else {
				d->dns.error |= ParsePcap_CnameError;
			}
			d->dns.cname_ttl = cnamettl;
			if (qtype_name[0] != 0) {
				if (strcmp((char *)qtype_name, (char *)current) != 0) {
					d->dns.error |= ParsePcap_CnameError;
				} else {
					d->dns.answer_ttl = qtype_ttl;
				}
			}
			if (d->dns.answer_ttl < 0)
				d->dns.answer_ttl = soa_ttl;
		}
	}
	if (d->dns.answer_ttl < 0 && qtype_ttl >= 0) {
		d->dns.n_ans_v4 = 0;
		d->dns.n_ans_v6 = 0;
	}
	if (d->dns._ra != 0) {
		d->dns._answertype = _ANSWER_RECURSION;
	} else
	if (d->dns._rcode == 3) {
		d->dns._answertype = _ANSWER_NXDOMAIN;
	} else
	if (d->dns._ancount == 0 && d->dns._nscount > 0) {
		d->dns._answertype = _ANSWER_REF;
	} else
	if (d->dns._ancount > 0) {
		d->dns._answertype = _ANSWER_ANSWER;
	} else {
		d->dns._answertype = _ANSWER_UNKNOWN;
	}
	(void)(d->callback)(d, CALLBACK_PARSED);
}

void parse_DNS(struct DNSdataControl *d)
{
	d->dns._qr = (d->dns.dns[2] & 0x80) != 0;
	d->dns._flag1 = d->dns.dns[2];
	d->dns._flag2 = d->dns.dns[3];
	d->dns._opcode = (d->dns.dns[2] & 0x78) >> 3;
	d->dns._rcode = d->dns.dns[3] & 0x0f;
	d->dns._aa = (d->dns.dns[2] & 4);
	d->dns._tc = (d->dns.dns[2] & 2);
	d->dns._rd = (d->dns.dns[2] & 1);
	d->dns._ra = (d->dns.dns[3] & 0x80);
	d->dns._ad = d->dns.dns[3] & 0x20;
	d->dns._cd = d->dns.dns[3] & 0x10;
	d->dns._id = (d->dns.dns[0] << 8) | d->dns.dns[1];
	d->dns._qdcount = (d->dns.dns[4] << 8) | d->dns.dns[5];
	d->dns._ancount = (d->dns.dns[6] << 8) | d->dns.dns[7];
	d->dns._nscount = (d->dns.dns[8] << 8) | d->dns.dns[9];
	d->dns._arcount = (d->dns.dns[10] << 8) | d->dns.dns[11];
	memcpy(d->dns.portaddr_src+2, d->dns.p_src, d->dns.alen);
	memcpy(d->dns.portaddr_dst+2, d->dns.p_dst, d->dns.alen);
	if (d->dns._qr != 0 && (d->debug & FLAG_MODE_PARSE_ANSWER) != 0) {
		parse_DNS_answer(d);
	}
	if (d->dns._qr == 0 && (d->debug & FLAG_MODE_PARSE_QUERY) != 0) {
		parse_DNS_query(d);
	}
}

void parse_UDP(struct DNSdataControl *d)
{
	u_int32_t sum;
	u_short *sump;

	d->dns.p_sport = d->dns.protoheader[0] * 256 + d->dns.protoheader[1];
	d->dns.p_dport = d->dns.protoheader[2] * 256 + d->dns.protoheader[3];
	d->dns.portaddr_src[0] = d->dns.protoheader[0];
	d->dns.portaddr_src[1] = d->dns.protoheader[1];
	d->dns.portaddr_dst[0] = d->dns.protoheader[2];
	d->dns.portaddr_dst[1] = d->dns.protoheader[3];
	d->dns._udpsumoff = (*(u_short *)(d->dns.protoheader+6) == 0) ? 1 : 0;
	if (*(u_short *)(d->dns.protoheader+6) != 0 && d->dns._transport_type != T_UDP_FRAG) {
		if ((d->dns.iplen & 1) != 0 && (d->dns.iplen < 1600)) {
			*d->dns.endp = 0;
		}
		sum = 17 + d->dns.protolen;
		sump = (u_short *)d->dns.p_src;
		while((u_char *)sump < d->dns.endp) {
			sum += ntohs(*sump++);
			/*printf("sump=%lx endp=%lx sum=%lx\n", sump, d->dns.endp, sum);*/
		}
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum == 0xffff) ? sum : ((sum & 0xffff) + (sum >> 16));
		if (sum != 0xffff) {
			d->ParsePcapCounter._ipv4_headerchecksumerror++;
			d->dns.error |= ParsePcap_UDPchecksumError;
			if ((d->debug & FLAG_IGNOREERROR) == 0) {
				if (d->debug & FLAG_INFO) {
					printf("#Error:UdpChecksum:%x\n", sum);
					hexdump("", d->dns._ip, d->dns.len);
				}
				return;
			}
		}
	}
	d->dns.dns = d->dns.protoheader + 8;
	d->dns.dnslen = d->dns.protoheader[4] * 256 + d->dns.protoheader[5] - 8;
	parse_DNS(d);
}

void parse_TCP(struct DNSdataControl *d)
{
	int data_offset;
	int datalen;
	int max, found, free, j;
	int flag;
	int syn;
	u_char *p;

	d->dns.p_sport = d->dns.protoheader[0] * 256 + d->dns.protoheader[1];
	d->dns.p_dport = d->dns.protoheader[2] * 256 + d->dns.protoheader[3];
	d->dns.portaddr_src[0] = d->dns.protoheader[0];
	d->dns.portaddr_src[1] = d->dns.protoheader[1];
	d->dns.portaddr_dst[0] = d->dns.protoheader[2];
	d->dns.portaddr_dst[1] = d->dns.protoheader[3];
	data_offset = (d->dns.protoheader[12] >> 4) * 4;
	d->dns.dns = d->dns.protoheader + data_offset;
	datalen = d->dns.endp - d->dns.dns;
	if ((d->dns.protoheader[12] >> 4) < 5 || datalen < 0) {
		d->dns.error |= ParsePcap_TCPError;
		return;
	}
#if 0
	if (datalen < 0) { printf("Error:datalen=%d d->dns.len=%d file=%s ts=%ld.%6d\n", datalen, d->dns.len, d->filename, d->dns.tv_sec, d->dns.tv_usec); hexdump("", d->dns._ip, d->dns.len); fflush(stdout); }
#endif
	flag = d->dns.protoheader[13];
	syn = flag & 2;
#if 0
	if (flag & 4 || datalen <= 0) {
		d->ParsePcapCounter._tcpbuff_zerofin++;
		return;
	}
#endif
	if (tcpbuff_used < 0) {
		memset(&tcpbuff, 0, sizeof(tcpbuff));
		tcpbuff_used = 0;
	}
	/* search tcpbuff */
	max = -1;
	found = -1;
	free = -1;
	for (j = 0; j < tcpbuff_used; j++) {
		if (tcpbuff[j].used == 0) {
			if (free < 0)
				free = j;
			continue;
		}
		if (tcpbuff[j].timestamp < d->dns.tv_sec -60) {
			if (d->debug & FLAG_DEBUG_TCP) {
				printf("deleting tcpbuff[%d]  ", j);
				hexdump("", tcpbuff[j].buff, datalen);
				printf("tcpbuff[%d] is too old: %u %u\n",j, tcpbuff[j].timestamp, d->dns.tv_sec);
			}
			d->ParsePcapCounter._tcpbuff_unused++;
			tcpbuff[j].used = 0;
			if (free < 0)
				free = j;
			continue;
		}
		max = j;
		if (d->dns.version == 4) {
			if (memcmp(d->dns.p_src, tcpbuff[j].header+12, 4) == 0
			&& memcmp(d->dns.p_dst, tcpbuff[j].header+16, 4) == 0
			&& memcmp(d->dns.protoheader, tcpbuff[j].header+20, 4) == 0) {
				found = j;
				break;
			}
		} else {
#if 0
hexdump("tcpbuf:", tcpbuff[j].header, 44);
hexdump("p_src", d->dns.p_src, 16);
hexdump("p_dst", d->dns.p_dst, 16);
hexdump("proto", d->dns.protoheader, 4);
#endif
			if (memcmp(d->dns.p_src, tcpbuff[j].header+8, 16) == 0
			&& memcmp(d->dns.p_dst, tcpbuff[j].header+24, 16) == 0
			&& memcmp(d->dns.protoheader, tcpbuff[j].header+40, 4) == 0) {
				found = j;
				break;
			}
		}
	}
	if (found < 0 && max + 1 < tcpbuff_used)
		tcpbuff_used = max+1;
	if (syn) {
		if (found < 0 && free < 0) {
			if (tcpbuff_used < tcpbuff_max)
				free = tcpbuff_used;
			else
				free = random() % tcpbuff_max;
		}
		if (d->debug & FLAG_DEBUG_TCP)
			printf("#INFO_TCP:SYN:datalen=%d, free=%d found=%d\n", datalen, free, found);
		if (found >= 0) free = found;
		if (datalen > 2 + 12) {
			j = d->dns.dns[0] * 256 + d->dns.dns[1];
			if ((j == datalen - 2) || (datalen > 500 && j >= datalen - 2)) {
				if (j != datalen - 2) d->dns._transport_type = T_TCP_PARTIAL;
				datalen -= 2;
				d->dns.dns += 2;
				d->dns.dnslen = j;
				d->dns.endp = d->dns.dns + datalen;
				d->ParsePcapCounter._tcp_query++;
				if (d->debug & FLAG_DEBUG_TCP) {
					printf("#INFO_TCP:First:datalen=%d, dnslen=%d\n", datalen, j);
				}
				parse_DNS(d);
				return;
			}
		}
		tcpbuff[free].used = 1;
		tcpbuff[free].timestamp = d->dns.tv_sec;
		memcpy(tcpbuff[free].header, d->dns._ip, d->dns.len - datalen);
		memcpy(tcpbuff[free].buff, d->dns.dns, datalen);
		tcpbuff[free].headerlen = d->dns.len - datalen;
		tcpbuff[free].datalen = datalen;
		tcpbuff[free].count = 1;
		if (tcpbuff_used <= free) tcpbuff_used = free+1;
		if (d->debug & FLAG_DEBUG_TCP) {
			printf("#INFO_TCP:FirstBuff:datalen=%d, inserted=%d tcpbuff_used=%d\n", datalen, free, tcpbuff_used);
		}
		return;
	}
	if (d->debug & FLAG_DEBUG_TCP)
		printf("#INFO_TCP:NoSYN:datalen=%d, free=%d found=%d\n", datalen, free, found);
	if (found >= 0) {
		if (datalen <= tcpbuff[found].datalen) {
			if (memcmp(tcpbuff[found].buff+tcpbuff[found].datalen-datalen, d->dns.dns, datalen)==0) {
				/* Ignore possible duplicate packet */
				d->ParsePcapCounter._tcpbuff_unused++;
				return;
			}	
		}
		if (datalen + tcpbuff[found].datalen > TCPBUF_BUFFLEN) {
			if (d->debug & FLAG_DEBUG_TCP)
				printf("#Error:Too large data:size=%d\n", datalen + tcpbuff[found].datalen);
			tcpbuff[found].used = 0;
			d->ParsePcapCounter._tcpbuff_unused++;
			return;
		}
		memcpy(tcpbuff[found].buff + tcpbuff[found].datalen, d->dns.dns, datalen);
		tcpbuff[found].datalen += datalen;
		tcpbuff[found].count++;
		p = tcpbuff[found].buff;
		d->ParsePcapCounter._tcpbuff_merged++;
		j = p[0] * 256 + p[1];
		d->dns.dnslen = j;
		d->dns.dns = tcpbuff[found].buff + 2;
		d->dns.endp = tcpbuff[found].buff + tcpbuff[found].datalen;
		if (d->debug & FLAG_DEBUG_TCP) {
			printf("#INFO_TCP:Found:datalen=%d, dnslen=%d\n", tcpbuff[found].datalen, j);
		}
		if (j == tcpbuff[found].datalen - 2) {
			parse_DNS(d);
		 	tcpbuff[found].used = 0;
		} else
		if (tcpbuff[found].datalen > 512) {
			d->dns._transport_type = T_TCP_PARTIAL;
			if (d->debug & FLAG_DEBUG_TCP) {
				printf("#INFO_TCP:T_TCP_PARTIAL\n");
			}
			parse_DNS(d);
		 	tcpbuff[found].used = 0;
		}
		return;
	}
}

void parse_IPv6Fragment(struct DNSdataControl *d)
{
	u_char next_header = d->dns.protoheader[0];
	u_short frag_offset = (d->dns.protoheader[2] * 256 + d->dns.protoheader[3]) & 0x1fff;

	if (next_header == 17) {
		if (frag_offset == 0) {
			d->ParsePcapCounter._udp6_frag_first++;
			d->dns.protoheader += 8;
			d->dns.dns = d->dns.protoheader + 8;
			parse_DNS(d);
		} else {
			d->ParsePcapCounter._udp6_frag_next++;
#if 0
			hexdump("parse_IPv6Fragment following part", d->dns._ip, d->dns.len);
#endif
		}
	} else
	if (next_header == 6) {
		d->ParsePcapCounter._tcp6_frag++;
#if 0
		hexdump("parse_IPv6Fragment TCP", d->dns._ip, d->dns.len);
#endif
	} else {
		d->ParsePcapCounter._ipv6_unknownfragment++;
#if 0
		hexdump("parse_IPv6Fragment Unknown proto", d->dns._ip, d->dns.len);
#endif
	}
}

void parse_L3(struct DNSdataControl *d)
{
	int found;
	int j;
	u_int32_t sum;
	u_short *sump;
	u_char *qname;
	int c;
	struct tm *t;
	unsigned int ip_off;

	d->dns.error = 0;
	d->dns.version = d->dns._ip[0] / 16;
	d->dns.pointer = 12;
	d->dns.endp = d->dns._ip + d->dns.len;
	d->dns._fragSize = 0;

	if (d->dns.version == 4) {
		d->ParsePcapCounter._ipv4++;
		d->dns.af = AF_INET;
		d->dns.alen = 4;
		d->dns.protoheader = d->dns._ip + 20;
		d->dns.p_src = d->dns._ip + 12;
		d->dns.p_dst = d->dns._ip + 16;
		d->dns.dns_offset = 20 + 8;
		d->dns.proto = d->dns._ip[9];
		d->dns.iplen = d->dns._ip[2] * 256 + d->dns._ip[3];
		d->dns.protolen = d->dns.iplen - 20;
		if (d->dns.iplen < d->dns.len) {
			d->dns.len = d->dns.iplen;
			d->dns.endp = d->dns._ip + d->dns.iplen;
		}
#if 0
		if (d->dns.iplen > d->dns.len && d->dns.iplen - d->dns.len <= 4 && d->dns.iplen < 1500) {
			memset(d->dns._ip + d->dns.len, 0, d->dns.iplen - d->dns.len);
			d->dns.len = d->dns.iplen;
		}
		if (d->dns.len == 0 || d->dns.iplen == 0) {
			printf("input len = %d, ip_len = %d\n", d->dns.len, d->dns.iplen);
			hexdump("", d->dns._ip, d->dns.len);
		}
#endif
		sump = (u_short *)d->dns._ip;
		sum = 0;
		for (j = 0; j < 10; j++) {
			sum += ntohs(*sump++);
		}
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum == 0xffff) ? sum : ((sum & 0xffff) + (sum >> 16));
		if (sum != 0xffff) {
			d->ParsePcapCounter._ipv4_headerchecksumerror++;
			d->dns.error |= ParsePcap_IPv4ChecksumError;
			if ((d->debug & FLAG_IGNOREERROR) == 0) {
				if (d->debug & FLAG_INFO) {
					printf("#Error:Checksum:%x\n", sum);
					hexdump("", d->dns._ip, d->dns.len);
				}
				return;
			}
		}
		ip_off = (d->dns._ip[6] * 256 + d->dns._ip[7]) & 0x3fff;
		switch(d->dns.proto) {
		case 17:
			if (ip_off == 0) {
				d->ParsePcapCounter._udp4++;
				d->dns._transport_type = T_UDP;
				parse_UDP(d);
				return;
			} else
			if (ip_off == 0x2000) {
				d->ParsePcapCounter._udp4_frag_first++;
				d->dns._transport_type = T_UDP_FRAG;
				d->dns._fragSize = d->dns.iplen;
				// hexdump("IPv4 UDP Fragment: First", d->dns._ip, d->dns.len);
				parse_UDP(d);
				return;
			} else {
				d->ParsePcapCounter._udp4_frag_next++;
				// hexdump("IPv4 UDP Fragment: Next", d->dns._ip, d->dns.len);
				return;
			}
		case 6:
			if (ip_off == 0) {
				d->ParsePcapCounter._tcp4++;
				d->dns._transport_type = T_TCP;
				parse_TCP(d);
				return;
			} else {
				d->ParsePcapCounter._tcp4_frag++;
				d->dns._transport_type = T_TCP_FRAG;
				d->dns._fragSize = d->dns.iplen;
#if DEBUG
				hexdump("IPv4 TCP Fragment: First", d->dns._ip, d->dns.len);
#endif
				return;
			}
		case 1:
			return;
		}
		d->ParsePcapCounter._proto_mismatch++;
		if (d->debug & FLAG_DEBUG_UNKNOWNPROTOCOL) {
			printf("#Unknown protocol %d\n", d->dns.proto);
			printf("%u->%u\n", d->dns.tv_sec, d->dns.tv_usec);
			hexdump("",d->dns._ip, d->dns.len);
		}
	} else if (d->dns.version == 6) {
		d->ParsePcapCounter._ipv6++;
		d->dns.af = AF_INET6;
		d->dns.alen = 16;
		d->dns.protoheader = d->dns._ip + 40;
		d->dns.p_src = d->dns._ip + 8;
		d->dns.p_dst = d->dns._ip + 24;
		d->dns.dns_offset = 40 + 8;
		d->dns.proto = d->dns._ip[6];
		d->dns.protolen = d->dns._ip[4] * 256 + d->dns._ip[5];
		d->dns.iplen = d->dns.protolen + 40;
		if (d->dns.len > d->dns.iplen) {
			d->dns.len = d->dns.iplen;
			d->dns.endp =  d->dns._ip + d->dns.iplen;
		}
		if (d->dns.iplen != d->dns.len) {
			d->ParsePcapCounter._IPlenMissmatch++;
			if (d->debug & FLAG_IGNOREERROR) {
				d->dns.error |= ParsePcap_IPv6LengthError;
			} else {
				if (d->debug & FLAG_INFO) {
					printf("#ERROR:IPv6 length problem: %d %d	", d->dns.iplen,d->dns.len);
					hexdump("", d->dns._ip, d->dns.len);
				}
				return;
			}
		}
		switch(d->dns.proto) {
		case 17:
			d->ParsePcapCounter._udp6++;
			d->dns._transport_type = T_UDP;
			parse_UDP(d);
			return;
		case 6:
			d->ParsePcapCounter._tcp6++;
			d->dns._transport_type = T_TCP;
			parse_TCP(d);
			return;
		case 44: /* ipv6-frag */
			parse_IPv6Fragment(d);
			return;
		case 58: /* ICMP6 */
			return;
		}
		d->ParsePcapCounter._proto_mismatch++;
		if (d->debug & FLAG_DEBUG_UNKNOWNPROTOCOL) {
			printf("#Unknown protocol %d\n", d->dns.proto);
			printf("%u->%u\n", d->dns.tv_sec, d->dns.tv_usec);
			hexdump("",d->dns._ip, d->dns.len);
		}
	} else {
		d->ParsePcapCounter._version_unknown++;
		if (d->debug & FLAG_INFO)
			 printf("ERROR:IPversion != 4/6: %02x\n", d->dns._ip[0]);
		return;
	}
}

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

enum _state { err_date = 1, err_addr, err_port, err_qname, err_class, err_type, err_flag, err_server };

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

int parse_decimal2(u_char *x)
{
	if (x[0]<'0' || x[0]>'9' || x[1]<'0' || x[1]>'9') {
		return -1;
	}
	return (x[0]-'0')*10+x[1]-'0';
}

int parse_decimal3(u_char *x)
{
	if (x[0]<'0' || x[0]>'9' || x[1]<'0' || x[1]>'9' || x[2]<'0' || x[2]>'9') {
		return -1;
	}
	return (x[0]-'0')*100+(x[1]-'0')*10+x[2]-'0';
}

int parse_decimal4(u_char *x)
{
	if (x[0]<'0' || x[0]>'9' || x[1]<'0' || x[1]>'9' || x[2]<'0' || x[2]>'9' || x[3]<'0' || x[3]>'9') {
		return -1;
	}
	return (x[0]-'0')*1000+(x[1]-'0')*100+(x[2]-'0')*10+x[3]-'0';
}

int parse_line(struct DNSdataControl* c)
{
	u_char *p, *q, *r;
	u_char *_type = NULL, *_class = NULL;
	int _typelen = 0, _classlen = 0;
	int second, msec;
	struct tm tm;
	int len, i, j, k;
	struct types *tt;
	u_char ip_src[16];
	u_char ip_dst[16];

	p = c->raw;
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
	p += 4;
	c->dns._fragSize = 0;

	if (c->debug & FLAG_SCANONLY) {
		if (c->ParsePcapCounter.first_sec == 0) {
			c->ParsePcapCounter.first_sec = c->dns.tv_sec;
			c->ParsePcapCounter.first_usec = c->dns.tv_usec;
		}
		c->ParsePcapCounter.last_sec = c->dns.tv_sec;
		c->ParsePcapCounter.last_usec = c->dns.tv_usec;
		return 0;
	}
	// Test BIND 8 style ?
	q = (u_char *)strchr((char *)p, 'X');
	if (q != NULL && q[0] == 'X' && q[1] == 'X' && q[2] != 0 && q[3] == '/') {
		// BIND 8 mode
		c->dns._rd = (q[2] == '+') ? 1 : 0;
		p = q + 4;
		q = (u_char *)strchr((char *)p, '/');
		if (q == NULL) return err_addr;
		memcpy(c->dns.s_src, p, q - p);
		c->dns.s_src[q-p] = 0;
		c->dns.p_src = c->dns.req_src = ip_src;
		c->dns.p_dst = c->dns.req_dst = ip_dst;
		if (inet_pton(AF_INET, (char *)c->dns.s_src, c->dns.p_src) == 1) {
			c->dns.af = AF_INET;
			c->dns.alen = 4;
		} else
		if (inet_pton(AF_INET6, (char *)c->dns.s_src, c->dns.p_src) == 1) {
			c->dns.af = AF_INET6;
			c->dns.alen = 16;
		} else
			return err_addr;
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
		memcpy(c->dns.qname, p, q-p);
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
		q = (u_char *)strchr((char *)p, '#');
		if (q == NULL) return err_addr;
		for (r = q - 1; r >= p && *r != ' ' && *r != 0; r--);
		if (*r != ' ') return err_addr;
		p = r + 1;
		memcpy(c->dns.s_src, p, q - p);
		c->dns.s_src[q-p] = 0;
		c->dns.p_src = c->dns.req_src = ip_src;
		c->dns.p_dst = c->dns.req_dst = ip_dst;
		r = (u_char *)strchr((char *)c->dns.s_src, '%');
		if (r != NULL) *r = 0;
		if (inet_pton(AF_INET, (char *)c->dns.s_src, c->dns.p_src) == 1) {
			c->dns.af = AF_INET;
			c->dns.alen = 4;
		} else
		if (inet_pton(AF_INET6, (char *)c->dns.s_src, c->dns.p_src) == 1) {
			c->dns.af = AF_INET6;
			c->dns.alen = 16;
		} else
			return err_addr;

		p = q + 1;
		k = strtol((char *)p, (char **)&q, 10);
		if (k < 0 || k > 65535 || q == NULL || (*q != ':' && *q != ' ')) return err_port;
		c->dns.p_sport = k;
	
		p = q + 1;
		q = (u_char *)strrchr((char *)p, ':');
		if (q == NULL) return err_qname;
		if (q[1] == ' ') {
			p = q + 2;
		} else {
			for (r=q-1; r>p && (r[-1]!=':' || r[0]!=' '); r--);
			if (r <= p) return err_qname;
			p = r + 1;
		}
		q = (u_char *)strchr((char *)p, ' ');
		if (q == NULL) return err_qname;
		memcpy(c->dns.qname, p, q-p);
		c->dns.qname[q-p] = 0;
		p = q+1;
		q = (u_char *)strchr((char *)p, ' ');
		if (q == NULL) return err_class;
		len = q-p;
		if (strncasecmp((char *)p, "IN", len) == 0) {
			c->dns.qclass = 1;
		} else
		if (strncasecmp((char *)p, "CH", len) == 0) {
			c->dns.qclass = 3;
		} else
		if (strncasecmp((char *)p, "HS", len) == 0) {
			c->dns.qclass = 4;
		} else
		if (strncasecmp((char *)p, "ANY", len) == 0) {
			c->dns.qclass = 255;
		} else
		if (strncasecmp((char *)p, "CLASS", 5) == 0) {
			k = strtol((char *)p + 5, NULL, 10);
			if (k < 0 || k > 65535) return err_class;
			c->dns.qclass = k;
		} else
			return err_class;
	
		p = q + 1;
		q = (u_char *)strchr((char *)p, ' ');
		if (q == NULL) return err_type;
		len = q-p;
		k = -1;
		for (tt = types; tt->name != NULL; tt++) {
			if (strncasecmp((char *)p, tt->name, len) == 0) {
				k = tt->code;
				break;
			}
		}
		if (k == -1) {
			if (strncasecmp((char *)p, "TYPE", 4) == 0)
				k = strtol((char *)p + 4, NULL, 10);
		}
		if (k < 0 || k > 65535) return err_type;
		c->dns.qtype = k;
	
		p = q + 1;
		q = (u_char *)strchr((char *)p, ' ');
		if (q == NULL) {
			len = strlen((char *)p);
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
			q = (u_char *)strchr((char *)p, ')');
			if (q != NULL) {
				memcpy(c->dns.s_dst, p, q - p);
				c->dns.s_dst[q-p] = 0;
				if (inet_pton(c->dns.af, (char *)c->dns.s_dst, c->dns.p_dst) != 1) {
					fprintf(stderr, "Unparseable [%s] af=%d\n", c->dns.s_dst, c->dns.af);
					return err_server;
				}
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
	} else
	if (c->dns.af == AF_INET6) {
		c->dns.version = 6;
		c->ParsePcapCounter._ipv6++;
		if (c->dns._transport_type == T_TCP) {
			c->ParsePcapCounter._tcp6++;
		} else {
			c->ParsePcapCounter._udp6++;
		}
	}

/*
30-Jan-2011 00:00:01.852 queries: info: client 218.219.54.69#2582: query: ns.mednet.jp IN A -EDC (203.119.1.1)
01-Jul-2013 00:00:01.395 queries: info: client 163.139.21.201#2210 (lifemile.jp): query: lifemile.jp IN DS -EDC (203.119.1.1)
^(\d+)-\S+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)#(\d+)( \(\S+\))?:\s+\S+\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)\s+/
($_day, $_time, $addr, $port, $_name, $_type, $_flag) = ($1, $2, $3, $4, $6, $7, $8);
*/

	c->dns.p_dport = c->dns.req_dport = 53;
	c->dns.req_sport = c->dns.p_sport;
	c->ParsePcapCounter._dns_query++;

	if (c->debug & FLAG_DO_ADDRESS_CHECK)
		if (c->callback(c, CALLBACK_ADDRESSCHECK) == 0) {
			c->ParsePcapCounter._unknown_ipaddress++;
			return 0;
		}

	if (c->dns.version == 6 && (c->dns.p_src[0] & 0xfc) == 0xfc) {
		return 0;
	}

	c->ParsePcapCounter._before_checking_dnsheader++;

	strcpy((char *)c->dns.qnamebuf, (char *)c->dns.qname);
	p = c->dns.qnamebuf;
	i = 0;
	while (p != NULL && i < PcapParse_LABELS) {
		c->dns.label[i] = p;
		q = (u_char *)strchr((char *)p, '.');
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
	(void)(c->callback)(c, CALLBACK_PARSED);
	return 0;
}

int _parse_bind9log(FILE *fp, struct DNSdataControl *c)
{
	static long long lines = 0;
	long long line1 = 0;
	int ret;

	do {
		lines++;
		line1++;
		memset(&c->dns, 0, sizeof(c->dns));
		ret = parse_line(c);
		if (ret > 0 && ret < 10) {
			c->ParsePcapCounter.error[ret]++;
			fprintf(stderr, "error%02d: %s", ret, c->raw);
		}
	} while(fgets((char *)c->raw, sizeof(c->raw), fp) != NULL);
	fprintf(stderr, "Loaded %lld/%lld lines from %s\n", line1, lines, c->filename);
	fflush(stderr);
	return 0;
}


struct pcap_file_header {
	u_int32_t magic;
	u_short version_major;
	u_short version_minor;
	int32_t thiszone;	/* gmt to local correction */
	u_int32_t sigfigs;	/* accuracy of timestamps */
	u_int32_t snaplen;	/* max length saved portion of each pkt */
	u_int32_t linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_header {
	struct pcap_timeval {
		u_int32_t tv_sec;	/* seconds */
		u_int32_t tv_usec;	/* microseconds */
	} ts;				/* time stamp */
	int32_t caplen;	/* length of portion present */
	int32_t len;	/* length this packet (off wire) */
};
#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define	DLT_IP		101	/* IP packet directly */
#define DLT_LINUX_SLL	113	/* Linux cocked */
#define DLT_RAW		12	/* _ip IP */
#define	LINKTYPE_OPENBSD_LOOP	108

struct pcapng_section_header3 {
	u_int32_t block_type;
	u_int32_t length;
	u_int32_t magic;
};
struct pcapng_section_header2 {
	u_int32_t block_type;
	u_int32_t length;
};
struct pcapng_type6 {
	u_int32_t interfaceID;
	u_int32_t tv_h;
	u_int32_t tv_l;
	u_int32_t caplen;
	u_int32_t len;
};

struct pcapng_type1 {
	u_int16_t linktype;
	u_int16_t reserved;
	u_int32_t snaplen;
};

u_short swap16(u_short x)
{
	return ((x & 0xff) << 8) | (x >> 8);
}

u_long swap32(u_int32_t x)
{
	return ((x & 0xff) << 24)
	       | ((x & 0xff00) << 8)
	       | ((x & 0xff0000) >> 8)
	       | ((x & 0xff000000) >> 24);
}

int parse_l2(struct pcap_header *ph, struct DNSdataControl* c)
{
	int l2header = 0;

	if (c->linktype == DLT_NULL || c->linktype == LINKTYPE_OPENBSD_LOOP) {
		l2header = 4;
	} else
	if (c->linktype == DLT_EN10MB) {
		if (c->l2[12] == 0x81 && c->l2[13] == 0) { /* VLAN */
			l2header = 18;
		} else {
			l2header = 14;
		}
	} else
	if (c->linktype == DLT_LINUX_SLL) {
		l2header = 16;
	} else
	if (c->linktype == DLT_IP || c->linktype == DLT_RAW) {
		l2header = 0;
	} else {
		printf("#Error:unknownLinkType:%d", c->linktype);
		return ParsePcap_ERROR_UnknownLinkType;
	}
	if (c->debug & FLAG_DUMP)
		hexdump("packet", c->l2+l2header, c->caplen-l2header);
	memset(&c->dns, 0, sizeof(c->dns));
	c->dns._ip = c->l2 + l2header;
	c->dns.len = c->caplen - l2header;
	c->dns.tv_sec = ph->ts.tv_sec;
	c->dns.tv_usec = ph->ts.tv_usec;
	if (c->ParsePcapCounter.first_sec == 0) {
		c->ParsePcapCounter.first_sec = ph->ts.tv_sec;
		c->ParsePcapCounter.first_usec = ph->ts.tv_usec;
	}
	c->ParsePcapCounter.last_sec = ph->ts.tv_sec;
	c->ParsePcapCounter.last_usec = ph->ts.tv_usec;
	if ((c->debug & FLAG_SCANONLY) == 0)
		parse_L3(c);
	c->ParsePcapCounter._pcap++;
	return 0;
}

#define PCAP_FIRST_READ 12

int _parse_pcap(FILE *fp, struct DNSdataControl* c)
{
	struct pcap_header ph;
	struct pcap_file_header pf;
	struct pcapng_section_header2 png2;
	struct pcapng_section_header3 *png3p;
	struct pcapng_type6 *png6p;
	struct pcapng_type1 *png1p;
	u_char *p;
	int plen;
	int error;
	int rest;
	int needswap = 0;
	int len;
	int type;
	int l2header = 0;
	long long offset = 0;
	long long offset2;
	unsigned long long t64;

	c->ParsePcapCounter._numfiles++;
	len = fread(&pf, 1, PCAP_FIRST_READ, fp);
	offset = len;

 	if (len == 0) {
		if (len == 0) return 0; /* Ignore */
#if 0
		if (c->debug & FLAG_INFO) printf("#Empty:Empty");
		return ParsePcap_ERROR_Empty;
#endif
	}
	if (len != PCAP_FIRST_READ) {
		if (c->debug & FLAG_INFO) printf("#Empty:ERROR: short read: pcap_file_header");
		return ParsePcap_ERROR_BogusSavefile;
	}
	//hexdump("head", &pf, 12);
	needswap = 0;
	switch(pf.magic) {
	case 0xd4c3b2a1: // pcap mode big endian
		needswap = 1;
	case 0xa1b2c3d4: // pcap mode
		p = (u_char *)&pf;
		p += PCAP_FIRST_READ;
		plen = sizeof(pf) - PCAP_FIRST_READ;
		len = fread(p, 1, plen, fp);
		offset += len;
		if (len != plen) return 0; /* Ignore */
		if (needswap) {
			pf.version_major = swap16(pf.version_major);
			pf.version_minor = swap16(pf.version_minor);
			pf.thiszone = swap32(pf.thiszone);
			pf.sigfigs = swap32(pf.sigfigs);
			pf.snaplen = swap32(pf.snaplen);
			pf.linktype = swap32(pf.linktype);
		}
		c->linktype = pf.linktype;
		if (c->debug & FLAG_DUMP) {
			hexdump("pcap_file_header", (u_char *)&pf, sizeof(pf));
			printf("magic = %08x  version=%d.%d  thiszone=%d  sigflag=%d\n",
				pf.magic, pf.version_major, pf.version_minor,
				pf.thiszone, pf.sigfigs);
			printf("snaplen=%d  linktype=%d  needswap=%d\n", pf.snaplen, pf.linktype, needswap);
		}
		while((len = fread(&ph, 1, sizeof(ph), fp)) == sizeof(ph)) {
			offset += len;
			if (ph.len == 0 || ph.caplen == 0) {
				ph.ts.tv_usec = ph.caplen;
				len = fread(&ph.caplen, 1, 8, fp);
				offset += len;
				if (len != 8) { break; }
			}
			if (needswap) {
				ph.caplen = swap32(ph.caplen);
				ph.len = swap32(ph.len);
				ph.ts.tv_sec = swap32(ph.ts.tv_sec);
				ph.ts.tv_usec = swap32(ph.ts.tv_usec);
			}
			if (c->debug & FLAG_DUMP) {
				printf("time=%u.%06u  caplen=%d  len=%d\n", ph.ts.tv_sec, ph.ts.tv_usec, ph.caplen, ph.len);
				hexdump("pcap_header", (u_char *)&ph, len);
			}
			if (ph.caplen > 65535 || ph.len > 65535 || ph.caplen < 0) {
				printf("#Error:bogus savefile header:short read or broken ph.caplen=%d, ph.len=%d, offset=%lld\n", ph.caplen, ph.len, offset);
				return 0;
			}
			if ((len = fread(c->raw, 1, ph.caplen, fp)) != ph.caplen) {
				if (c->debug & FLAG_INFO) printf("#Error:Short read buffer: %d != %d", len, ph.caplen);
				return ParsePcap_ERROR_ShortRead;
			}
			offset += len;
			c->caplen = len;
			c->l2 = c->raw;
			//hexdump("fread", c->raw, c->caplen);
			error = parse_l2(&ph, c);
			if (error != 0) return error;
			offset2 = offset;
		}
		if (len == 0) return 0;
		if (c->debug & FLAG_INFO)
			printf("#Error:short read: %s\n",
				(len == sizeof ph) ? "Packet data":"Pcap header");
		return ParsePcap_ERROR_ShortRead;
	case 0x0a0d0d0a: // pcapng mode
		png3p = (struct pcapng_section_header3 *)(&pf);
		//printf("magic=%lx length=%lx\n", png3p->magic, png3p->length);
		if (png3p->magic == 0x1a2b3c4d) {
			needswap = 0;
		} else {
			needswap = 1;
		}
		rest = needswap ? swap32(png3p->length) : png3p->length;
		rest -= len;
		//printf("needswap=%d rest=%d\n", needswap, rest);
		if (fread(&c->raw, 1, rest, fp) != rest) {
			return ParsePcap_ERROR_BogusSavefile;
		}
		while((len = fread(&png2, 1, sizeof(png2), fp)) == sizeof(png2)) {
			offset += len;
			rest = needswap ? swap32(png2.length) : png2.length;
			rest -= sizeof(png2);
			type = needswap ? swap32(png2.block_type) : png2.block_type;
			len = fread(c->raw, 1, rest, fp);
			if (len != rest) return ParsePcap_ERROR_BogusSavefile;
			//printf("type=%d len=%d\n", type, len);
			//hexdump("data", c->raw, rest);
			if (type == 6) {
				png6p = (struct pcapng_type6 *)c->raw;
				ph.caplen = needswap?swap32(png6p->caplen):png6p->caplen;
				ph.len = needswap?swap32(png6p->len):png6p->len;
				t64 = ((unsigned long long)(needswap?swap32(png6p->tv_h):png6p->tv_h) << 32) + (needswap?swap32(png6p->tv_l):png6p->tv_l);
				ph.ts.tv_sec = t64 / 1000000;
				ph.ts.tv_usec = t64 % 1000000;
				//printf("t64=%lld tv_sec=%d:%06d len=%d caplen=%d\n", t64, ph.ts.tv_sec, ph.ts.tv_usec, png6p->len, png6p->caplen);
				c->l2 = c->raw + 20;
				c->caplen = ph.caplen;
				if (ph.caplen > 65535 || ph.len > 65535 || ph.caplen < 0) {
					printf("#Error:bogus savefile header:short read or broken ph.caplen=%d, ph.len=%d, offset=%lld\n", ph.caplen, ph.len, offset);
					return 0;
				}
				error = parse_l2(&ph, c);
				if (error != 0) return error;
			} else if (type == 1) {
				png1p = (struct pcapng_type1 *)c->raw;
				c->linktype = needswap?swap16(png1p->linktype):png1p->linktype;
				fprintf(stderr, "linktype=%d\n", c->linktype);
			}
		}
		return 0;
	default: // Query Log mode
		memcpy(c->raw, &pf.magic, len);
		if (fgets((char *)(c->raw + len), sizeof(c->raw) - len, fp) == NULL) {
			return ParsePcap_ERROR_BogusSavefile;
		}
		if (isdigit(c->raw[0]))
			_parse_bind9log(fp, c);
		else
		if (c->otherdata != NULL) {
			return c->otherdata(fp, c);
		}
		return 0;
	}
}

int parse_pcap(char *file, struct DNSdataControl* c)
{
	int ret;
	FILE *fp;
	int len;
	int close_status = 0;
	char buff[256];

	if (file == NULL)
		return _parse_pcap(stdin, c);
	c->filename = file;
	len = strlen(file);
	if (len > 4 && strcmp(file+len-4, ".bz2") == 0) {
		snprintf(buff, sizeof buff, "bzip2 -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c);
		close_status = pclose(fp);
	} else
	if (len > 3 && strcmp(file+len-3, ".gz") == 0) {
		snprintf(buff, sizeof buff, "gzip -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c);
		close_status = pclose(fp);
	} else
	if (len > 3 && strcmp(file+len-3, ".xz") == 0) {
		snprintf(buff, sizeof buff, "xz -cd %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c);
		close_status = pclose(fp);
	} else {
		if ((fp = fopen(file, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, c);
		close_status = fclose(fp);
	}
	if (ret == 0 && close_status > 0) {
		fprintf(stderr, "fclose_returned:%d/%d:%s\n", close_status, ret, file);
		return ParsePcap_ERROR_COMMAND;
	}
	return ret;
}

char *parse_pcap_error(int errorcode)
{
	switch(errorcode) {
	case ParsePcap_NoError:
		return "NoError";
	case ParsePcap_ERROR_Empty:
		return "Empty";
	case ParsePcap_ERROR_BogusSavefile:
		return "BogusSavefile";
	case ParsePcap_ERROR_ShortRead:
		return "ShortRead";
	case ParsePcap_ERROR_FILE_OPEN:
		return "Cannot Open File";
	case ParsePcap_ERROR_UnknownLinkType:
		return "Unknown Link Type";
	case ParsePcap_ERROR_COMMAND:
		return "Command execution error";
	case ParsePcap_ERROR_OutofPeriod:
		return "OutOfPeriod";
	default:
		return "Unknown";
	}
}

void Print_PcapStatistics(struct DNSdataControl *c)
{
#define NonzeroPrint(A,B)  { if ((B) != 0) printf("%s,%d\n", (A), (B)); }
	NonzeroPrint("#PcapStatistics._pcap", c->ParsePcapCounter._pcap);
	NonzeroPrint("#PcapStatistics._ipv4", c->ParsePcapCounter._ipv4);
	NonzeroPrint("#PcapStatistics._ipv6", c->ParsePcapCounter._ipv6);
	NonzeroPrint("#PcapStatistics._version_unknown", c->ParsePcapCounter._version_unknown);
	NonzeroPrint("#PcapStatistics._portmismatch", c->ParsePcapCounter._portmismatch);
	NonzeroPrint("#PcapStatistics._udp4", c->ParsePcapCounter._udp4);
	NonzeroPrint("#PcapStatistics._tcp4", c->ParsePcapCounter._tcp4);
	NonzeroPrint("#PcapStatistics._udp6", c->ParsePcapCounter._udp6);
	NonzeroPrint("#PcapStatistics._tcp6", c->ParsePcapCounter._tcp6);
	NonzeroPrint("#PcapStatistics._udp4_frag_first", c->ParsePcapCounter._udp4_frag_first);
	NonzeroPrint("#PcapStatistics._udp4_frag_next", c->ParsePcapCounter._udp4_frag_next);
	NonzeroPrint("#PcapStatistics._tcp4_frag", c->ParsePcapCounter._tcp4_frag);
	NonzeroPrint("#PcapStatistics._udp6_frag_first", c->ParsePcapCounter._udp6_frag_first);
	NonzeroPrint("#PcapStatistics._udp6_frag_next", c->ParsePcapCounter._udp6_frag_next);
	NonzeroPrint("#PcapStatistics._tcp6_frag", c->ParsePcapCounter._tcp6_frag);
	NonzeroPrint("#PcapStatistics._ipv6_unknownfragment", c->ParsePcapCounter._ipv6_unknownfragment);
	NonzeroPrint("#PcapStatistics._udp_query", c->ParsePcapCounter._udp_query);
	NonzeroPrint("#PcapStatistics._tcp_query", c->ParsePcapCounter._tcp_query);
	NonzeroPrint("#PcapStatistics._tcpbuff_unused", c->ParsePcapCounter._tcpbuff_unused);
	NonzeroPrint("#PcapStatistics._tcpbuff_merged", c->ParsePcapCounter._tcpbuff_merged);
	NonzeroPrint("#PcapStatistics._tcpbuff_zero_fin", c->ParsePcapCounter._tcpbuff_zerofin);
	NonzeroPrint("#PcapStatistics._proto_mismatch", c->ParsePcapCounter._proto_mismatch);
	NonzeroPrint("#PcapStatistics._ipv4_headerchecksumerror", c->ParsePcapCounter._ipv4_headerchecksumerror);
	NonzeroPrint("#PcapStatistics._udp_checksumerror", c->ParsePcapCounter._udp_checksumerror);
	NonzeroPrint("#PcapStatistics._before_checking_dnsheader", c->ParsePcapCounter._before_checking_dnsheader);
	NonzeroPrint("#PcapStatistics._dns_query", c->ParsePcapCounter._dns_query);
	NonzeroPrint("#PcapStatistics._dns_response", c->ParsePcapCounter._dns_response);
	NonzeroPrint("#PcapStatistics._parsed_dnsquery", c->ParsePcapCounter._parsed_dnsquery);
	NonzeroPrint("#PcapStatistics._IPlenMissmatch", c->ParsePcapCounter._IPlenMissmatch);
	NonzeroPrint("#PcapStatistics._unknown_ipaddress", c->ParsePcapCounter._unknown_ipaddress);
	NonzeroPrint("#PcapStatistics._numfiles", c->ParsePcapCounter._numfiles);
	NonzeroPrint("#PcapStatistics.error00", c->ParsePcapCounter.error[0]);
	NonzeroPrint("#PcapStatistics.error01", c->ParsePcapCounter.error[1]);
	NonzeroPrint("#PcapStatistics.error02", c->ParsePcapCounter.error[2]);
	NonzeroPrint("#PcapStatistics.error03", c->ParsePcapCounter.error[3]);
	NonzeroPrint("#PcapStatistics.error04", c->ParsePcapCounter.error[4]);
	NonzeroPrint("#PcapStatistics.error05", c->ParsePcapCounter.error[5]);
	NonzeroPrint("#PcapStatistics.error06", c->ParsePcapCounter.error[6]);
	NonzeroPrint("#PcapStatistics.error07", c->ParsePcapCounter.error[7]);
	NonzeroPrint("#PcapStatistics.error08", c->ParsePcapCounter.error[8]);
	NonzeroPrint("#PcapStatistics.error09", c->ParsePcapCounter.error[9]);
};

