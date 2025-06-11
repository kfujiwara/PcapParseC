/*
	$Id: parse_L3.c,v 1.19 2025/05/30 09:00:19 fujiwara Exp $

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
#include "load_ipv6list.h"
#include "pcapparse.h"
#include "pcap_data.h"
#include "parse_int.h"
#include "parse_L3.h"
#include "parse_DNS.h"

unsigned int checksum16(unsigned int sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

unsigned int calc_udptcpsum(u_char *data, u_char *endp, int udplen, int proto, unsigned int *sum0)
{
	unsigned short *p;
	unsigned int sum;

	sum = proto + udplen;
	p = (unsigned short *)data;
	while (p < (unsigned short *)endp) sum += ntohs(*p++);
	if (sum0 != NULL) *sum0 = sum;
	return checksum16(sum);
}

unsigned int calc_ipv4headersum(u_char *data)
{
	unsigned short *p;
	unsigned int sum;
	int j;

	p = (u_short *)data;
	sum = 0;
	for (j = 0; j < 10; j++) {
		sum += ntohs(*p++);
	}
	return sum;
}

unsigned int try_fix_ipv4address2(struct DNSdataControl *d, unsigned int sum0)
{
	// check IPv4 header checksum -> set error code
	// IPv4 UDP with UDP_checksum_error
	// fix source address if query
	// fix dest address if response
	
	u_char *addrp;
	u_short diff;
	u_char a3, a4, a3f, a4f;
	u_char *_ip = d->dns._ip;
	int len = d->dns.len;
	unsigned int sum, sum1, sum2;

	if (_ip[15] == 0) { // source
		addrp = _ip + 12;
	} else
	if (_ip[19] == 0) {
		addrp = _ip + 16;
	} else {
		return sum0;
	}
	a3 = addrp[2];
	a4 = addrp[2];
	//hexdump("try_fix_ipaddr: ", _ip, len);
	// try fix
	sum1 = sum0 - (a3 << 8);
	sum = checksum16(sum0);
	diff = (~sum ) & 0xffff;
	a3f = a3 + (diff >> 8);
	a4f = diff & 0xff;
	sum = checksum16(sum1 + (a3f << 8) + a4f);
	if (sum == 65534) { a4f++; sum = checksum16(sum1 + (a3f << 8) + a4f); }
	if (sum != 65535) {
		a4f--; if (a4f == 0) a3f--;
		sum = checksum16(sum1 + (a3f << 8) + a4f);
	}
	if (sum != 65535) {
		//printf("fix_failed:sum=%x sum0=%x %d.%d.%d.%d\n", sum, sum0, addrp[0],addrp[1],addrp[2],addrp[3]);
		return sum;
	}
	addrp[2] = a3f;
	addrp[3] = a4f;
	sum2 = checksum16(calc_ipv4headersum(_ip));
	if (sum2 == 65535) {
		//printf("fix_succeed:sum=%x sum0=%x %d.%d.%d.0 -> %d.%d sum2=%d\n", sum, sum0, addrp[0],addrp[1],addrp[2],a3f, a4f, sum2);
		d->dns.IPaddrUpdated = 1;
	} else {
		addrp[2] = a3;
		addrp[3] = a4;
		//printf("fix_failed:sum=%x sum0=%x %d.%d.%d.%d proposed=%d.%d sum2=%d\n", sum, sum0, addrp[0],addrp[1],addrp[2],addrp[3], a3f, a4f, sum2);
	}
	return sum;
}

unsigned int try_ipv4_fixaddr(struct DNSdataControl *d)
{
	// check UDP checksum -> set error code
	// IPv4 UDP with UDP_checksum_error
	// fix source address if query
	// fix dest address if response
	
	u_char *addrp;
	u_char a4, a4f;
	u_char *_ip = d->dns._ip;
	int len = d->dns.len;
	int port, sport;
	unsigned int sum, sum0, sum1, sum2;
	int proto = d->dns.proto;

	if (*(u_short *)(d->dns.protoheader+6) == 0) return 0;
	if ((d->dns.iplen & 1) != 0 && (d->dns.iplen < 1600)) {
		*d->dns.endp = 0;
	}
	sum = calc_udptcpsum(d->dns.p_src, d->dns.endp, d->dns.protolen, proto, &sum0);
	if (sum == 0xffff || (d->mode & MODE_FIX_IPV4ADDR) == 0) return sum;
	if (d->dns.p_dport == 53) {
		addrp = _ip + 12;
		port = d->dns.p_sport;
		sport = d->dns.p_dport;
	} else {
		addrp = _ip + 16;
		port = d->dns.p_dport;
		sport = d->dns.p_sport;
	}
	a4 = addrp[3];
	sum1 = sum0 - a4;
	//hexdump("try_fix_ipaddr: ", _ip, len);
	// try fix
	a4f = (a4 - (sum & 0xff)) & 0xff;
	sum = checksum16(sum1 + a4f);
	if (sum != 65535) {
		a4f--;
		sum = checksum16(sum1 + a4f);
	}
	if (sum != 65535) {
		//printf("fix_failed:proto=%d sum=%x sum0=%x sum1=%x %d.%d.%d.%d clientport=%d/%d\n", proto, sum, sum0, sum1, addrp[0],addrp[1],addrp[2],addrp[3], port, sport);
		return sum;
	}
	//printf("fix_succeed:proto=%d sum=%x sum0=%x sum1=%x %d.%d.%d.%d <- %d port=%d/%d\n", proto, sum, sum0, sum1, addrp[0],addrp[1],addrp[2],a4f,a4, port, sport);
	addrp[3] = a4f;
	//sum2 = calc_udptcpsum(d->dns.p_src, d->dns.endp, d->dns.protolen, proto, NULL);
	//if (sum != sum2) { printf("Checksum mismatch\n"); }
	d->dns.IPaddrUpdated = 1;
	return sum;
}

void check_ipv6_checksum(struct DNSdataControl *d)
{
	// check UDP/TCP checksum -> set error code
	
	u_char *addrp;
	u_char *_ip = d->dns._ip;
	int len = d->dns.len;
	int i, port, sport;
	unsigned int sum, sum0, sum1, sum2;
	unsigned short *sump;
	int proto = d->dns.proto;
	struct ipv6_prefix_hash *f;

	if (*(u_short *)(d->dns.protoheader+6) == 0) return;
	if ((d->dns.iplen & 1) != 0 && (d->dns.iplen < 1600)) {
		*d->dns.endp = 0;
	}
	sum = calc_udptcpsum(d->dns.p_src, d->dns.endp, d->dns.protolen, proto, &sum0);
	if (sum == 0xffff) return;
	if (d->v6hash != NULL) {
		if (d->dns.p_dport == 53) {
			addrp = _ip + 8;
		} else {
			addrp = _ip + 24;
		}
		sump = (unsigned short *)(addrp + 8);
		sum2 = ntohs(sump[0]) + ntohs(sump[1])
			+ ntohs(sump[2]) + ntohs(sump[3]);
		sum1 = sum0 - sum2;
		HASH_FIND(hh, d->v6hash, addrp, 8, f);
		if (f != NULL && f->used > 0) {
			for (i = 0; i < f->used; i++) {
				if (checksum16(sum1 + f->sump[i]) == 0xffff) {
       					memcpy(addrp + 8, &f->suffix[i], 8);
					d->dns.IPaddrUpdated = 1;
					sum = calc_udptcpsum(d->dns.p_src, d->dns.endp, d->dns.protolen, proto, &sum0);
					break;
				}
			}
		}
	}
	if (sum == 0xffff) return;
	d->ParsePcapCounter._ipv6_protochecksumerror++;
	d->dns.error |= ParsePcap_UDPchecksumError;
	if (d->debug & FLAG_INFO) {
		printf("#Error:UdpChecksum:%x\n", sum);
		hexdump("", d->dns._ip, d->dns.len);
	}
}

void parse_UDP(struct DNSdataControl *d)
{
	u_int32_t sum;
	u_short *sump;

	d->dns._udpsumoff = (*(u_short *)(d->dns.protoheader+6) == 0) ? 1 : 0;
	d->dns.dns = d->dns.protoheader + 8;
	d->dns.dnslen = d->dns.protoheader[4] * 256 + d->dns.protoheader[5] - 8;
	fixup_portaddr(d);
	parse_DNS(d);
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
			fixup_portaddr(d);
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
	int j;
	u_int32_t sum, sum0;
	u_short *sump;
	unsigned int ip_off;

	d->dns.error = 0;
	d->dns.version = d->dns._ip[0] / 16;
	d->dns.pointer = 12;
	d->dns.endp = d->dns._ip + d->dns.len;
	d->dns._fragSize = 0;
	d->dns.partial = 0;
	d->dns.ip_df = 0;

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
		} else
		if (d->dns.iplen > d->dns.len) {
			d->dns.partial = 1;
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
		sum0 = calc_ipv4headersum(d->dns._ip);
		sum = checksum16(sum0);
		if (sum != 0xffff && (d->mode & MODE_FIX_IPV4ADDR) != 0)
			sum = try_fix_ipv4address2(d, sum0);
		if (sum != 0xffff) {
			d->ParsePcapCounter._ipv4_headerchecksumerror++;
			d->dns.error |= ParsePcap_IPv4ChecksumError;
			if (d->debug & FLAG_INFO) {
				printf("#Error:Checksum:%x\n", sum);
				hexdump("", d->dns._ip, d->dns.len);
			}
		}
		d->dns.ip_df = (d->dns._ip[6] & 0x40) ? 1 : 0;
		ip_off = (d->dns._ip[6] * 256 + d->dns._ip[7]) & 0x3fff;
		d->dns.p_sport = d->dns.protoheader[0] * 256 + d->dns.protoheader[1];
		d->dns.p_dport = d->dns.protoheader[2] * 256 + d->dns.protoheader[3];
		if ((d->dns.proto == 17 || d->dns.proto == 6) && ip_off == 0) {
			if (try_ipv4_fixaddr(d) != 65535) {
				d->ParsePcapCounter._ipv4_protochecksumerror++;
				d->dns.error |= ParsePcap_UDPchecksumError;
				if (d->debug & FLAG_INFO) {
					printf("#Error:UdpChecksum:%x\n", sum);
					hexdump("", d->dns._ip, d->dns.len);
				}
			}
		}
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
				fixup_portaddr(d);
				parse_TCP(d);
				return;
			} else
			if (ip_off == 0x2000) {
				d->ParsePcapCounter._tcp4_frag++;
				d->dns._transport_type = T_TCP_FRAG;
				d->dns._fragSize = d->dns.iplen;
				d->dns.partial = 1;
#if DEBUG
				hexdump("IPv4 TCP Fragment: First", d->dns._ip, d->dns.len);
#endif
				fixup_portaddr(d);
				parse_TCP(d);
				return;
			} else {
				d->ParsePcapCounter._tcp4_frag_next++;
				// hexdump("IPv4 TCP Fragment: Next", d->dns._ip, d->dns.len);
				return;
			}
		case 1:
			return;
		}
		d->ParsePcapCounter._proto_mismatch++;
		if (d->debug & FLAG_DEBUG_UNKNOWNPROTOCOL) {
			printf("#Unknown protocol %d\n", d->dns.proto);
			printf("%lu\n", d->dns.ts);
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
		} else
		if (d->dns.iplen > d->dns.len) {
			d->dns.partial = 1;
		}
		if (d->dns.iplen != d->dns.len) {
			d->ParsePcapCounter._IPlenMissmatch++;
			d->dns.error |= ParsePcap_IPv6LengthError;
			if (d->debug & FLAG_INFO) {
				printf("#ERROR:IPv6 length problem: %d %d	", d->dns.iplen,d->dns.len);
				hexdump("", d->dns._ip, d->dns.len);
			}
		}
		d->dns.p_sport = d->dns.protoheader[0] * 256 + d->dns.protoheader[1];
		d->dns.p_dport = d->dns.protoheader[2] * 256 + d->dns.protoheader[3];
		if (d->dns.proto == 17 || d->dns.proto == 6) {
			check_ipv6_checksum(d);
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
			fixup_portaddr(d);
			parse_TCP(d);
			return;
		case 44: /* ipv6-frag */
			d->dns.p_sport = 0;
			d->dns.p_dport = 0;
			parse_IPv6Fragment(d);
			return;
		case 58: /* ICMP6 */
			return;
		}
		d->ParsePcapCounter._proto_mismatch++;
		if (d->debug & FLAG_DEBUG_UNKNOWNPROTOCOL) {
			printf("#Unknown protocol %d\n", d->dns.proto);
			printf("%lu\n", d->dns.ts);
			hexdump("",d->dns._ip, d->dns.len);
		}
	} else {
		d->ParsePcapCounter._version_unknown++;
		if (d->debug & FLAG_INFO)
			 printf("ERROR:IPversion != 4/6: %02x\n", d->dns._ip[0]);
		return;
	}
}

int parse_L2(struct pcap_header *ph, struct DNSdataControl* c)
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
	c->dns.ts = ph->ts.tv_sec * 1000000LU + ph->ts.tv_usec;
	if (c->ParsePcapCounter.first_ts == 0) {
		c->ParsePcapCounter.first_ts = c->dns.ts;
	}
	c->ParsePcapCounter.last_ts = c->dns.ts;
	if (c->do_scanonly == 0)
		parse_L3(c);
	c->ParsePcapCounter._pcap++;
	return 0;
}

