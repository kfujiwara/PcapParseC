/*
	$Id: parse_DNS.c,v 1.10 2025/05/01 10:06:07 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ext/uthash.h"

#include "config.h"
#include "mytool.h"
#include "pcapparse.h"
#include "parse_int.h"

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

void labelcopy_ignorechar(u_char *dest, u_char *src, int count, struct case_stats *s, int mode)
{
	u_char c;

	while (count-- > 0) {
		c = *src;
		if (c < 0x21 || c == ',' || c == ':' || c >= 0x7f) {
			c = '!';
		} else {
			if (s != NULL) {
				if (islower(c)) { s->lowercase++; }
				else if (isupper(c)) { s->uppercase++; }
				else { s->nocase++; }
			}
			if (mode & GET_DNAME_LOWERCASE && isupper(c))
				c = tolower(c);
		}
		*dest++ = c;
		src++;
	}
}

int labelcopy_bind9(u_char *dest, u_char *src, int count, struct case_stats *s, int mode)
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
				if (s != NULL) {
					if (islower(c)) { s->lowercase++; }
					else if (isupper(c)) {
						s->uppercase++;
					} else { s->nocase++; }
				}
				if (mode & GET_DNAME_LOWERCASE && isupper(c))
					c = tolower(c);
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

int get_dname(struct DNSdata *d, char *o, int o_len, int mode, struct case_stats *s)
{
	unsigned char *p;
	int olen = 0;
	int count;
	u_char *op = (u_char *)o;
	int newp = 0;
	int nlabel = 0;
	u_char *wp = (u_char *)d->qnamebuf;
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
			if (op == (u_char *)o) {
				*op++ = '.';
				olen++;
			}
			*op = 0;
			if (newp == 0 && (mode & GET_DNAME_NO_SAVE) == 0) d->pointer = p + 1 - d->dns;
			if (mode & GET_DNAME_SEPARATE) {
				d->nlabel = nlabel;
				/* swap order */
				for (i = 0, j = nlabel - 1; i < j; i++, j--) {
					wp = (u_char *)d->label[i];
					d->label[i] = d->label[j];
					d->label[j] = (char *)wp;
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
			if (op != (u_char *)o) {
				*op++ = '.';
				olen++;
			}
			if (mode & GET_DNAME_IgnoreErrorChar) {
				labelcopy_ignorechar(op, p+1, *p, s, mode);
				olen += *p;
				op += *p;
			} else {
				count = labelcopy_bind9(op, p+1, *p, s, mode);
				olen += count;
				op += count;
			}
			if (mode & GET_DNAME_SEPARATE) {
				if (nlabel >= PcapParse_LABELS)
					return -1;
				d->label[nlabel] = (char *)wp;
				d->labellen[nlabel] = *p;
				nlabel++;
				labelcopy_bind9(wp, p+1, *p, NULL, mode);
				wp[*p] = 0;
				wp += *p + 1;
			}
			p += *p + 1;
		}
	}
	return -1;
}

static char _count[] = { 0, 1, 0, 0, 0, 0, 0 };
//static char _edns0[] = { 0, 0, 41 };

int parse_edns(struct DNSdataControl *d)
{
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
			hexdump("#Error:BrokenEDNS0: ",
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
			hexdump("#Error:BrokenEDNS0: ", d->dns._ip, d->dns.len);
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
				keytag = (p[0] << 8) | p[1];
				p += 2;
				optlen -= 2;
				switch(keytag) {
				case 0x4a5c: d->dns._edns_keytag_4a5c = 1;break;
				case 0x4f66: d->dns._edns_keytag_4f66 = 1;break;
				case 0x9728: d->dns._edns_keytag_9728 = 1;break;
				default: d->dns._edns_keytag_other = 1; break;
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

	d->ParsePcapCounter._dns_query++;
	d->ParsePcapCounter._before_checking_dnsheader++;

	do {
		if (d->dns._opcode != 0 && d->dns._opcode != 5) {
			if (d->debug & FLAG_INFO) {
				hexdump("#Error:bad opcode: ",
					d->dns._ip, d->dns.len);
			}
			d->dns.error |= ParsePcap_DNSError;
			break;
		}
		if (d->dns._opcode == 0
		   && memcmp(d->dns.dns+4, _count, 7) != 0) {
			if (d->debug & FLAG_INFO)
				hexdump("#Error:op0, bad count: ",
					d->dns._ip, d->dns.len);
			d->dns.error |= ParsePcap_DNSError;
			break;
		}
		memset(&d->dns.case_stats, 0, sizeof(d->dns.case_stats));
		c = get_dname(&d->dns, d->dns.qname, sizeof(d->dns.qname),
		    	GET_DNAME_NO_COMP | GET_DNAME_SEPARATE | d->getdname_options,
			&d->dns.case_stats);
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
	d->dns.datatype = DATATYPE_DNS;
	prepare_dns_substring(d);
	(void)(d->callback)(d, CALLBACK_PARSED);
}

struct cname_list
{
	char owner[PcapParse_DNAMELEN];
	char target[PcapParse_DNAMELEN];
	int ttl;
	int used;
};
#define	NUM_CNAME	16

static char *rcodestr[] = {
"NoError",
"FormErr",
"ServFail",
"NXDomain",
"NotImp",
"Refused",
"YXDomain",
"YXRRSet",
"NXRRSet",
"NotAuth",
"NotZone",
"Rcoed11",
"Rcode12",
"Rcode13",
"Rcode14",
"Rcode15",
"NoDATA",
"Referral",
"Truncated",
};
void parse_DNS_answer(struct DNSdataControl *d)
{
	int c;
	u_char *p;
	int i, j, l, m, n, ttl, anssec, authsec, additional;
	char buff[PcapParse_DNAMELEN];
	char buff2[PcapParse_DNAMELEN];
	char qtype_name[PcapParse_DNAMELEN] = "";
	int qtype_ttl = -1;
	int answer_ttl = -1;
	struct cname_list cname[NUM_CNAME];
	int ncname = 0;
	int cnamettl = -1;
	char *current;
	int found;

	d->ParsePcapCounter._dns_response++;

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
	d->dns.soa_ttl = -1;
	*(d->dns.soa_dom) = 0;

	d->ParsePcapCounter._before_checking_dnsheader++;
	if (d->dns._opcode != 0) return;
	if (d->dns.dns[4] != 0 && d->dns.dns[5] != 1) return;
	memset(&cname, 0, sizeof cname);
	memset(&d->dns.case_stats, 0, sizeof(d->dns.case_stats));
	c = get_dname(&d->dns, d->dns.qname, sizeof(d->dns.qname), GET_DNAME_NO_COMP | GET_DNAME_SEPARATE | d->getdname_options, &d->dns.case_stats);
	d->dns.qtype = get_uint16(&d->dns);
	d->dns.qclass = get_uint16(&d->dns);
	if (c <= 0 || d->dns.qtype < 0 || d->dns.qclass < 0) return;
	//if (d->dns.qtype != 252 && (d->dns._rcode == 1 || d->dns._rcode == 5 || d->dns._rcode == 9)) return; /* FORMERR | REFUSED | NOTAUTH */
	d->dns._edns0 = (d->dns.endp - d->dns.dns > 512 && d->dns._ip[9] == 17) ? 1 : 0;
	anssec = d->dns.dns[7];
	authsec = d->dns.dns[9];
	additional = d->dns.dns[11];
	if (d->dns._tc != 0) {
		d->dns.str_rcode = rcodestr[18]; // TC1
	} else
	if (d->dns._rcode == 0 && anssec == 0) {
		if (authsec != 0 && d->dns._aa == 0) {
			d->dns.str_rcode = rcodestr[17];
		} else {
			d->dns.str_rcode = rcodestr[16];
		}
	}
	j = anssec + authsec + additional;
	while (j > 0) {
		p = d->dns.dns + d->dns.pointer;
		if (p + 11 <= d->dns.endp &&
		    p[0] == 0 && p[1] == 0 && p[2] == 41) {
			j--;
			d->dns.error |= parse_edns(d);
			break;
		}
		i = get_dname(&d->dns, buff, sizeof(buff), d->getdname_options, NULL);
		if (i < 0) break;
		l = get_uint16(&d->dns);
		m = get_uint16(&d->dns);
		ttl = get_uint32(&d->dns);
		n = get_uint16(&d->dns);
		if ((d->mode & MODE_ANSWER_TTL_CNAME_PARSE) != 0) {
			if (anssec > 0) {
				if (l == d->dns.qtype && m == d->dns.qclass) {
					if (strcasecmp((char *)buff, (char *)d->dns.qname) == 0) {
						answer_ttl = ttl;
					} else {
						qtype_ttl = ttl;
						strcpy((char *)qtype_name, (char *)buff);
					}
					if (l == 1 && n == 4) {
						if (d->dns.n_ans_v4 < PcapParse_Naddr) {
							memcpy(&d->dns.ans_v4[d->dns.n_ans_v4], d->dns.dns + d->dns.pointer, n);
							d->dns.n_ans_v4++;
						}
					} else
					if (l == 28 && n == 16) {
						if (d->dns.n_ans_v6 < PcapParse_Naddr) {
							memcpy(&d->dns.ans_v6[d->dns.n_ans_v6], d->dns.dns + d->dns.pointer, n);
							d->dns.n_ans_v6++;
						}
					}
				}
				if (l == 5 && m == 1) { // IN CNAME
					i = get_dname(&d->dns, buff2, sizeof(buff2), GET_DNAME_NO_SAVE | d->getdname_options, NULL);
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
				anssec--; j--;
			} else
			if (authsec > 0) {
				if (m == 1 && l == 6) {
					strcpy((char *)d->dns.soa_dom, (char *)buff);
					d->dns.soa_ttl = ttl;
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
		} else {
			j--;
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
	d->ParsePcapCounter._parsed_dnsquery++;

	if ((d->mode & MODE_ANSWER_TTL_CNAME_PARSE) != 0) {
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
					if (cname[i].used == 0 && strcasecmp((char *)cname[i].owner, current)==0) {
						found = 1;
						cname[i].used = 1;
						current = cname[i].target;
						if (cnamettl < 0 || cnamettl > cname[i].ttl)
							cnamettl = cname[i].ttl;
						l = strlen(current);
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
				if (strcmp(qtype_name, current) != 0) {
					d->dns.error |= ParsePcap_CnameError;
				} else {
					d->dns.answer_ttl = qtype_ttl;
				}
			}
			if (d->dns.answer_ttl < 0)
				d->dns.answer_ttl = d->dns.soa_ttl;
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
	d->dns.datatype = DATATYPE_DNS;
	prepare_dns_substring(d);
	(void)(d->callback)(d, CALLBACK_PARSED);
}

void parse_DNS(struct DNSdataControl *d)
{
	d->dns.pointer = 12;
	d->dns._qr = (d->dns.dns[2] & 0x80) != 0 ? 1 : 0;
	d->dns._flag1 = d->dns.dns[2];
	d->dns._flag2 = d->dns.dns[3];
	d->dns._opcode = (d->dns.dns[2] & 0x78) >> 3;
	d->dns._rcode = d->dns.dns[3] & 0x0f;
	if (d->dns._qr != 0) d->dns.str_rcode = rcodestr[d->dns._rcode];
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
	if (d->dns._qr != 0 && (d->mode & MODE_PARSE_ANSWER) != 0) {
		parse_DNS_answer(d);
	}
	if (d->dns._qr == 0 && (d->mode & MODE_PARSE_QUERY) != 0) {
		parse_DNS_query(d);
	}
}

