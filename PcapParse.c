/*
	$Id: PcapParse.c,v 1.45 2012/06/12 03:01:58 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012 Japan Registry Servcies Co., Ltd.

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

static int get_uint32(struct DNSdata *d)
{
	u_char *p;

	p = d->dns + d->pointer;
	if (p + 4 > d->endp)
		return -1;
	d->pointer += 4;
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static int get_uint16(struct DNSdata *d)
{
	u_char *p;

	p = d->dns + d->pointer;
	if (p + 2 > d->endp)
		return -1;
	d->pointer += 2;
	return (p[0] << 8) | p[1];
}

static void labelcopy(u_char *dest, u_char *src, int count)
{
	u_char c;

	while (count-- > 0) {
		c = *src;
		if (c < 0x21 || c == ',' || c == ':' || (c >= 0x7f && c <= 0x9f)) {
			c = '!';
		}
		*dest++ = c;
		src++;
	}
}

static int labelcopy_bind9(u_char *dest, u_char *src, int count)
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

static int get_dname(struct DNSdata *d, u_char *o, int o_len, int mode)
{
	u_char *p;
	int olen = 0;
	int count;
	u_char *op = o;
	int newp = 0;
	
	p = d->dns + d->pointer;

	while (p < d->endp) {
		if (*p == 0) {
			if (op == o) {
				*op++ = '.';
				olen++;
			}
			*op = 0;
			if (newp == 0 && (mode & GET_DNAME_NO_SAVE) == 0) d->pointer = p + 1 - d->dns;
			return olen;
		} else if ((*p & 192) == 192) {
			if (mode & GET_DNAME_NO_COMP) return -1;
			if (newp == 0 && (mode & GET_DNAME_NO_SAVE) == 0) d->pointer = p + 2 - d->dns;
			newp = (p[0] & 0x3f) * 256 + p[1];
			if (newp >= (p - d->dns) || newp == 0)
				return -1;
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
			if (d->debug & FLAG_BIND9LOG) {
				count = labelcopy_bind9(op, p+1, *p);
				olen += count;
				op += count;
			} else {
				labelcopy(op, p+1, *p);
				olen += *p;
				op += *p;
			}
			p += *p + 1;
		}
	}
	return -1;
}

static u_char _count[] = { 0, 1, 0, 0, 0, 0, 0 };
static u_char _edns0[] = { 0, 0, 41 };

struct PcapStatistics ParsePcapCounter = { 0,0,0,0,0,0,0,0,0,0 };

#define TCPBUF_BUFFLEN 512
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

static void parse_DNS(struct DNSdata *d, int callback(struct DNSdata*, int), int debug)
{
	int c;
	u_char *p;

	d->req_sport = d->p_sport;
	d->req_dport = d->p_dport;
	d->req_src = d->p_src;
	d->req_dst = d->p_dst;

	if (d->debug & FLAG_DO_ADDRESS_CHECK)
		if (callback(d, CALLBACK_ADDRESSCHECK) == 0)
			return;

	if (d->version == 6 && (d->p_src[0] & 0xfc) == 0xfc)
		return;
	switch (d->p_sport) {
	case 7: /* echo */
	case 13: /* daytime */
	case 19: /* chargen */
	case 37: /* time */
		return;
	}
	if ((d->dns[2] & 0x80) != 0) return; /* require QR=0, OP=0, RD=1 */

	ParsePcapCounter._dns++;

	memcpy(&d->_flag, d->dns + 2, 2);
	d->_opcode = (d->dns[2] & 0x78) >> 3;
	d->_rcode = d->dns[3] & 0x0f;
	if (d->_opcode != 0) return;
	memcpy(&d->_flag, d->dns + 2, 2);
	d->_rd = (d->dns[2] & 1);
	d->_cd = d->dns[3] & 0x10;
	if (memcmp(d->dns+4, _count, 7)) return;
	if (d->dns[11] != 0) d->_edns0 = 1;
	c = get_dname(d, d->qname, sizeof(d->qname), GET_DNAME_NO_COMP);
	d->qtype = get_uint16(d);
	d->qclass = get_uint16(d);
	if (c <= 0 || d->qtype < 0 || d->qclass < 0) return;
	if (d->_edns0) {
		p = d->dns + d->pointer;
		if (p + 11 > d->endp
		    || p[0] != 0 || p[1] != 0 || p[2] != 41) {
			if (debug & FLAG_INFO) {
				hexdump("#Error:BrokenEDNS0", d->raw, d->len);
			}
			return;
		}
		d->_do = p[7] & 0x80;
	}
	inet_ntop(d->af, d->req_src, d->s_src, sizeof(d->s_src));
	inet_ntop(d->af, d->req_dst, d->s_dst, sizeof(d->s_dst));
	ParsePcapCounter._parsed_dnsquery++;
	(void)(callback)(d, CALLBACK_PARSED);
}

void print_dns_answer(struct DNSdata *d)
{
	int c;
	u_char *p, *q;
	u_short *r;
	u_char b1[257], b2[257];
	int i, j, k, l, m, n, ttl, eflag, anssec;

	d->pointer = 12;
	c = get_dname(d, b1, sizeof(b1), GET_DNAME_NO_COMP);
	i = get_uint16(d);
	j = get_uint16(d);
	printf("%s.%d -> %s.%d: %s %d %d edns0=%d flag=%04lx %d/%d/%d\n", d->s_src, d->req_sport, d->s_dst, d->req_dport, b1, i, j, d->_edns0, d->_flag, d->dns[7], d->dns[9], d->dns[11]);
	j = d->dns[7] + d->dns[9] + d->dns[11];
	k = 0;
	while (j > 0) {
		i = get_dname(d, b1, sizeof(b1), 0);
		if (i < 0) break;
		l = get_uint16(d);
		m = get_uint16(d);
		ttl = get_uint32(d);
		n = get_uint16(d);
		if (l == 41) {
			printf(" RR: %d  %s %d %d OPT %d\n", j, b1, m, ttl, n);
		} else
		if (l == 5 && m == 1) {
			i = get_dname(d, b2, sizeof(b2), GET_DNAME_NO_SAVE);
			if (i < 0) break;
			printf(" RR: %d  %s %d IN CNAME %s\n", j, b1, ttl, b2);
		} else
		if (l == 2 && m == 1) {
			i = get_dname(d, b2, sizeof(b2), GET_DNAME_NO_SAVE);
			if (i < 0) break;
			printf(" RR: %d  %s %d IN NS %s\n", j, b1, ttl, b2);
		} else
		if (l == 12 && m == 1) {
			i = get_dname(d, b2, sizeof(b2), GET_DNAME_NO_SAVE);
			if (i < 0) break;
			printf(" RR: %d  %s %d IN PTR %s\n", j, b1, ttl, b2);
		} else
		if (l == 1 && m == 1 && n == 4) {
			q = d->dns + d->pointer;
			printf(" RR: %d  %s %d IN A %d.%d.%d.%d\n", j, b1, ttl, q[0], q[1], q[2], q[3]);
		} else
		if (l == 24 && m == 1 && n == 16) {
			r = (u_short *)d->dns + d->pointer;
			printf(" RR: %d  %s %d IN AAAA %x:%x:%x:%x:%x:%x:%x:%x\n", j, b1, ttl, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
		} else
		if (m == 1 && l == 6) {
			printf(" RR: %d  %s %d IN SOA\n", j, b1, ttl);
		} else {
			printf(" RR: %d  %s %d %d %d %d  qtype=%d\n", j, b1, l, m, ttl, n, d->qtype);
		}
		d->pointer += n;
		j--;
	}
}

struct cname_list
{
	u_char owner[DNAMELEN];
	u_char target[DNAMELEN];
	int ttl;
	int used;
};
#define	NUM_CNAME	16

static void parse_DNS_answer(struct DNSdata *d, int callback(struct DNSdata*, int), int debug)
{
	int c;
	u_char *p, *q;
	u_short *r;
	int i, j, k, l, m, n, ttl, eflag, anssec;
	u_char buff[DNAMELEN];
	u_char buff2[DNAMELEN];
	u_char qtype_name[DNAMELEN] = "";
	u_char soa_dom[DNAMELEN] = "";
	int soa_ttl = -1;
	int qtype_ttl = -1;
	int answer_ttl = -1;
	struct cname_list cname[NUM_CNAME];
	int ncname = 0;
	int cnamettl = -1;
	u_char *current;
	int found;

	if ((d->dns[2] & 0x80) == 0) return;

	d->req_sport = d->p_dport;
	d->req_dport = d->p_sport;
	d->req_src = d->p_dst;
	d->req_dst = d->p_src;

	if (d->debug & FLAG_DO_ADDRESS_CHECK)
		if (callback(d, CALLBACK_ADDRESSCHECK) == 0)
			return;

	ParsePcapCounter._dns++;

	memset(&cname, 0, sizeof cname);
	memcpy(&d->_flag, d->dns + 2, 2);
	d->_opcode = (d->dns[2] & 0x78) >> 3;
	d->_rcode = d->dns[3] & 0x0f;
	if (d->_opcode != 0) return;
	// if ((d->dns[2] & 0x7e) != 0) return; /* require QR=1, OP=0, RD=1 */
	d->_rd = (d->dns[2] & 1);
	d->_cd = d->dns[3] & 0x10;
	if (d->dns[4] != 0 && d->dns[5] != 1) return;
	c = get_dname(d, d->qname, sizeof(d->qname), GET_DNAME_NO_COMP);
	d->qtype = get_uint16(d);
	d->qclass = get_uint16(d);
	if (c <= 0 || d->qtype < 0 || d->qclass < 0) return;
	if (d->qtype != 252 && (d->_rcode == 1 || d->_rcode == 5 || d->_rcode == 9)) return; /* FORMERR | REFUSED | NOTAUTH */
	if (d->endp - d->dns > 512 && d->raw[9] == 17) {
		d->_edns0 = 1;
	}
	j = d->dns[7] + d->dns[9] + d->dns[11];
	anssec = d->dns[7];
	k = 0;
	while (j > 0) {
		i = get_dname(d, buff, sizeof(buff), 0);
		if (i < 0) break;
		l = get_uint16(d);
		m = get_uint16(d);
		ttl = get_uint32(d);
		n = get_uint16(d);
		if ((d->debug & FLAG_ANSWER_TTL_CNAME_PARSE) != 0) {
			if (anssec > 0) {
				if ((l == d->qtype || d->qtype == 255) && m == d->qclass) {
					if (strcasecmp(buff, d->qname) == 0) {
						answer_ttl = ttl;
					} else {
						qtype_ttl = ttl;
						strcpy(qtype_name, buff);
					}
				}
				if (l == 5 && m == 1) {
					i = get_dname(d, buff2, sizeof(buff2), GET_DNAME_NO_SAVE);
					if (i < 0) break;
					if (ncname < NUM_CNAME) {
						strcpy(cname[ncname].owner, buff);
						strcpy(cname[ncname].target, buff2);
						cname[ncname].ttl = ttl;
						ncname++;
					}
#ifdef DEBUG
					printf(" RR: %d  %s %d IN CNAME %s\n", j, buff, ttl, buff2);
#endif
				}
			} else {
				if (anssec <= 0 && m == 1 && l == 6) {
					strcpy(soa_dom, buff);
					soa_ttl = ttl;
				}
			}
		}
		if ( (d->qtype != 46 && l == 46)
		  || (d->qtype != 47 && l == 47)
		  || (d->qtype != 50 && l == 50) ) {
			d->_do = 1;
			d->_edns0 = 1;
			break;
		}
		if (n < 0) break;
		d->pointer += n;
		if (strcmp(buff, ".") == 0 && l == 41) {
			d->_edns0 = 1;
			d->_do = (ttl & 0x8000) != 0;
			break;
		}
		j--;
		anssec--;
	}
	inet_ntop(d->af, d->req_src, d->s_src, sizeof(d->s_src));
	inet_ntop(d->af, d->req_dst, d->s_dst, sizeof(d->s_dst));
	ParsePcapCounter._parsed_dnsquery++;

	if ((d->debug & FLAG_ANSWER_TTL_CNAME_PARSE) != 0) {
		d->answer_ttl = answer_ttl;
		d->cname_target[0] = 0;
		if (ncname > 0) {
			current = d->qname;
			do {
				found = 0;
				for (i = 0; i < ncname; i++) {
					if (cname[i].used == 0 && strcasecmp(cname[i].owner, current)==0) {
						found = 1;
						cname[i].used = 1;
						current = cname[i].target;
						if (cnamettl < 0 || cnamettl > cname[i].ttl)
							cnamettl = cname[i].ttl;
						break;
					}
				}
			} while (found == 1);
			strcpy(d->cname_target, current);
			if (strcasecmp(current, qtype_name) == 0) {
				d->answer_ttl = qtype_ttl;
				if (cnamettl < qtype_ttl) d->answer_ttl = cnamettl;
			} else {
				d->answer_ttl = soa_ttl;
				if (cnamettl < soa_ttl) d->answer_ttl = cnamettl;
			}
			if (d->answer_ttl < 0) d->answer_ttl = cnamettl;
		}
		if (d->answer_ttl < 0) d->answer_ttl = soa_ttl;
	}

	(void)(callback)(d, CALLBACK_PARSED);
}

static void parse_L3(u_char *buff, int caplen, int32_t tv_sec, int32_t tv_usec, int callback(struct DNSdata*, int), int debug)
{
	int found;
	int j;
	int max;
	int free;
	int data_offset;
	int iplen;
	u_int32_t sum;
	u_short *sump;
	int datalen;
	int ansmode;
	struct DNSdata d;
	u_char *qname;
	u_char *p;
	int c;
	struct tm *t;
	time_t ttt;

	memset(&d, 0, sizeof(d));
	d.debug = debug;
	ansmode = debug & FLAG_MODE_PARSE_ANSWER;
	d.tv_sec = tv_sec;
	d.tv_usec = tv_usec;
	d.raw =	buff;
	d.len = caplen;
	d.version = buff[0] / 16;
	d.pointer = 12;
	d.endp = buff + caplen;

	if (d.version == 4) {
		ParsePcapCounter._ipv4++;
		d.af = AF_INET;
		d.protoheader = buff + 20;
		d.p_src = buff + 12;
		d.p_dst = buff + 16;
		d.dns_offset = 20 + 8;
		d.proto = buff[9];
		iplen = d.raw[2] * 256 + d.raw[3];
		d.protolen = iplen - 20;
		if (iplen < d.len) {
			d.len = iplen;
			d.endp = buff + iplen;
		}
#if 0
		if (iplen > d.len && iplen - d.len <= 4 && iplen < 1500) {
			memset(d.raw + d.len, 0, iplen - d.len);
			d.len = iplen;
		}
		if (d.len == 0 || iplen == 0) {
			printf("input len = %d, ip_len = %d\n", d.len, iplen);
			hexdump("", buff, d.len);
		}
#endif
		sump = (u_short *)d.raw;
		sum = 0;
		for (j = 0; j < 10; j++) {
			sum += ntohs(*sump++);
		}
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum == 0xffff) ? sum : ((sum & 0xffff) + (sum >> 16));
		if (sum != 0xffff) {
			ParsePcapCounter._ipv4_headerchecksumerror++;
			if (debug & FLAG_IGNOREERROR) {
				d.error |= ParsePcap_IPv4ChecksumError;
			} else {
				if (debug & FLAG_INFO) {
					printf("#Error:Checksum:%x\n", sum);
					hexdump("", buff, d.len);
				}
				return;
			}
		}
	} else if (d.version == 6) {
		ParsePcapCounter._ipv6++;
		d.af = AF_INET6;
		d.protoheader = buff + 40;
		d.p_src = buff + 8;
		d.p_dst = buff + 24;
		d.dns_offset = 40 + 8;
		d.proto = buff[6];
		d.protolen = d.raw[4] * 256 + d.raw[5];
		iplen = d.protolen + 40;
		if (d.len > iplen) {
			d.len = iplen;
			d.endp =  buff + iplen;
		}
		if (iplen != d.len) {
			ParsePcapCounter._IPlenMissmatch++;
			if (debug & FLAG_IGNOREERROR) {
				d.error |= ParsePcap_IPv6LengthError;
			} else {
				if (debug & FLAG_INFO) {
					printf("#ERROR:IPv6 length problem: %d %d	", iplen,d.len);
					hexdump("", buff, d.len);
				}
				return;
			}
		}
	} else {
		ParsePcapCounter._version_unknown++;
		if (debug & FLAG_INFO)
			 printf("ERROR:IPversion != 4/6: %02x\n", buff[0]);
		return;
	}
	if (d.proto == 17) {
		d.p_sport = d.protoheader[0] * 256 + d.protoheader[1];
		d.p_dport = d.protoheader[2] * 256 + d.protoheader[3];
		if (*(u_short *)(d.protoheader+6) != 0 && (d.raw[6] & 0x20) == 0) {
			if ((iplen & 1) != 0 && (iplen < 1600)) {
				*d.endp = 0;
			}
			sum = 17 + d.protolen;
			sump = (u_short *)d.p_src;
			while((u_char *)sump < d.endp) {
				sum += ntohs(*sump++);
				/*printf("sump=%lx endp=%lx sum=%lx\n", sump, d.endp, sum);*/
			}
			sum = (sum & 0xffff) + (sum >> 16);
			sum = (sum == 0xffff) ? sum : ((sum & 0xffff) + (sum >> 16));
			if (sum != 0xffff) {
				ParsePcapCounter._ipv4_headerchecksumerror++;
				if (debug & FLAG_IGNOREERROR) {
					d.error |= ParsePcap_UDPchecksumError;
				} else {
					if (debug & FLAG_INFO) {
						printf("#Error:UdpChecksum:%x\n", sum);
						hexdump("", buff, d.len);
					}
					return;
				}
			}
		}
		ParsePcapCounter._udp++;
		d.dns = d.protoheader + 8;
		if (ansmode) {
			parse_DNS_answer(&d, callback, debug);
		} else {
			parse_DNS(&d, callback, debug);
		}
		return;
	}
	if (d.proto == 6) {
		d.p_sport = d.protoheader[0] * 256 + d.protoheader[1];
		d.p_dport = d.protoheader[2] * 256 + d.protoheader[3];
		data_offset = (d.protoheader[12] >> 4) * 4;
		d.dns = d.protoheader + data_offset;
		datalen = d.endp - d.dns;
		if (d.protoheader[13] & 4 || datalen <= 0)
			return;
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
			if (tcpbuff[j].timestamp < tv_sec -60) {
				if (debug & FLAG_DEBUG_TCP) {
					printf("deleting tcpbuff[%d]  ", j);
					hexdump("", tcpbuff[j].buff, datalen);
					printf("tcpbuff[%d] is too old: %ld %ld\n",j, tcpbuff[j].timestamp, tv_sec);
				}
				tcpbuff[j].used = 0;
				if (free < 0)
					free = j;
				continue;
			}
			max = j;
			if (d.version == 4) {
				if (memcmp(d.p_src, tcpbuff[j].header+12, 4) == 0
				&& memcmp(d.p_dst, tcpbuff[j].header+16, 4) == 0
				&& memcmp(d.protoheader, tcpbuff[j].header+20, 4) == 0) {
					found = j;
					break;
				}
			} else {
				if (memcmp(d.p_src, tcpbuff[j].header+8, 16) == 0
				&& memcmp(d.p_dst, tcpbuff[j].header+24, 16) == 0
				&& memcmp(d.protoheader, tcpbuff[j].header+40, 4) == 0) {
					found = j;
					break;
				}
			}
		}
		if (found < 0 && max + 1 < tcpbuff_used)
			tcpbuff_used = max+1;
		if (found >= 0) {
			if (datalen <= tcpbuff[found].datalen) {
				if (memcmp(tcpbuff[found].buff+tcpbuff[found].datalen-datalen, d.dns, datalen)==0) {
					/* Ignore possible duplicate packet */
					return;
				}	
			}
			if (datalen + tcpbuff[found].datalen > TCPBUF_BUFFLEN) {				if (debug & FLAG_DEBUG_TCP)
					printf("#Error:Too large data:size=%d\n", datalen + tcpbuff[found].datalen);
				tcpbuff[found].used = 0;
				return;
			}
			memcpy(tcpbuff[found].buff + tcpbuff[found].datalen, d.dns, datalen);
			tcpbuff[found].datalen += datalen;
			tcpbuff[found].count++;
			p = tcpbuff[found].buff;
			j = p[0] * 256 + p[1];
			if (j == tcpbuff[found].datalen - 2) {
			 	d.dns = tcpbuff[found].buff + 2;
			 	d.endp = tcpbuff[found].buff + tcpbuff[found].datalen;
			 	parse_DNS(&d, callback, debug);
			 	tcpbuff[found].used = 0;
			}
			return;
		}
		if (free < 0) {
			if (tcpbuff_used < tcpbuff_max)
				free = tcpbuff_used;
			else
				free = random() % tcpbuff_max;
		}
		if ((d.dns[0] * 256 + d.dns[1] == datalen - 2) || (datalen > 500 && (d.dns[0] * 256 + d.dns[1]) >= datalen - 2)) {
			datalen -= 2;
			d.dns += 2;
			ParsePcapCounter._tcp++;
			if (ansmode) {
				parse_DNS_answer(&d, callback, debug);
			} else {
				parse_DNS(&d, callback, debug);
			}
			return;
		}
		if (d.len - datalen > TCPBUF_HEADERLEN || datalen > TCPBUF_BUFFLEN) {
			if (debug & FLAG_DEBUG_TCP) {
			 	printf("#ERROR:Too large data length at tcpbuf: %d, %d", d.len - datalen, datalen);
				hexdump("input", d.raw, d.len);
			}
			return;
		}
		if (tcpbuff_used <= free)
			tcpbuff_used = free + 1;

		if (datalen <= 0) {
			 	printf("#ERROR:datalen=%d <= 0\n", datalen);
				hexdump("input", d.raw, d.len);
				exit(1);
		}
		tcpbuff[free].used = 1;
		tcpbuff[free].timestamp = tv_sec;
		memcpy(tcpbuff[free].header, d.raw, d.len - datalen);
		memcpy(tcpbuff[free].buff, d.dns, datalen);
		tcpbuff[free].headerlen = d.len - datalen;
		tcpbuff[free].datalen = datalen;
		tcpbuff[free].count = 1;
		return;
	}
	if (d.proto == 1 || d.proto == 58)
		return;
	ParsePcapCounter._proto_mismatch++;
	if (debug & FLAG_DEBUG_UNKNOWNPROTOCOL) {
		printf("#Unknown protocol %d\n", d.proto);
		printf("%ld.%ld\n", tv_sec, tv_usec);
		hexdump("",d.raw, d.len);
	}
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
#define DLT_LINUX_SLL	113	/* Linux cocked */
#define DLT_RAW		12	/* raw IP */

static u_short swap16(u_short x)
{
	return ((x & 0xff) << 8) | (x >> 8);
}

static u_long swap32(u_int32_t x)
{
	return ((x & 0xff) << 24)
		| ((x & 0xff00) << 8)
		| ((x & 0xff000) >> 8)
		| ((x & 0xff000000) >> 24);
}

static int _parse_pcap(FILE *fp, int callback(struct DNSdata*, int), int debug)
{
	struct pcap_header ph;
	struct pcap_file_header pf;
	u_char buff[65536];
	int needswap = 0;
	int len;
	int l2header = 0;
	long long offset = 0;
	long long offset2;

	len = fread(&pf, 1, sizeof(pf), fp);
	offset += len;

 	if (len == 0) {
		if (debug & FLAG_INFO) printf("#Empty:Empty");
		return ParsePcap_ERROR_Empty;
	}
	if (len != sizeof(pf)) {
		if (debug & FLAG_INFO) printf("#Empty:ERROR: short read: pcap_file_header");
		return ParsePcap_ERROR_BogusSavefile;
	}
	if (pf.magic != 0xa1b2c3d4) {
		needswap = 1;
		pf.version_major = swap16(pf.version_major);
		pf.version_minor = swap16(pf.version_minor);
		pf.thiszone = swap32(pf.thiszone);
		pf.sigfigs = swap32(pf.sigfigs);
		pf.snaplen = swap32(pf.snaplen);
		pf.linktype = swap32(pf.linktype);
	}
	if (debug & FLAG_DUMP) {
		hexdump("pcap_file_header", (u_char *)&pf, sizeof(pf));
		printf("magic = %08lx  version=%d.%d  thiszone=%d  sigflag=%d\n",
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
		if (debug & FLAG_DUMP) {
			printf("time=%ld.%06ld  caplen=%d  len=%d\n", ph.ts.tv_sec, ph.ts.tv_usec, ph.caplen, ph.len);
			hexdump("pcap_header", (u_char *)&ph, len);
		}
		if (ph.caplen > 65535 || ph.len > 65535 || ph.caplen < 0) {
			printf("#Error:bogus savefile header:short read or broken ph.caplen=%d, ph.len=%d, offset=%lld\n", ph.caplen, ph.len, offset);
			return 0;
		}
		if ((len = fread(buff, 1, ph.caplen, fp)) != ph.caplen) {
			if (debug & FLAG_INFO) printf("#Error:Short read buffer: %d != %d", len, ph.caplen);	
			return ParsePcap_ERROR_ShortRead;
		}
		offset += len;
		if (pf.linktype == 0) {
			l2header = 4;
		} else
			if (pf.linktype == 1) {
				if (buff[12] == 0x81 && buff[13] == 0) { /* VLAN */
					l2header = 18;
				} else {
					l2header = 14;
				}
			}
		if (debug & FLAG_DUMP)
			hexdump("packet", buff+l2header, len-l2header);
		parse_L3(buff+l2header, len-l2header, ph.ts.tv_sec, ph.ts.tv_usec, callback, debug);
		ParsePcapCounter._pcap++;
		offset2 = offset;
	}
	if (len == 0)
		return 0;
	if (debug & FLAG_INFO)
		printf("#Error:short read: %s\n",
			(len == sizeof ph) ? "Packet data":"Pcap header");
	return ParsePcap_ERROR_ShortRead;
}

int parse_pcap(char *file, int callback(struct DNSdata*, int), int debug)
{
	int ret;
	FILE *fp;
	int len;
	char buff[256];

	if (file == NULL)
		return _parse_pcap(stdin, callback, debug);
	len = strlen(file);
	if (len > 3 && strcmp(file+len-3, ".gz") == 0) {
		snprintf(buff, sizeof buff, "gzip -cd < %s", file);
		if ((fp = popen(buff, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, callback, debug);
		pclose(fp);
	} else {
		if ((fp = fopen(file, "r")) == NULL)
			return ParsePcap_ERROR_FILE_OPEN;
		ret = _parse_pcap(fp, callback, debug);
		fclose(fp);
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
	default:
		return "Unknown";
	}
}
