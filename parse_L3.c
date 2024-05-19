/*
	$Id: parse_L3.c,v 1.6 2024/05/09 15:15:28 fujiwara Exp $

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
#ifdef HAVE_SYS_TYPES_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "ext/uthash.h"

#include "mytool.h"
#include "PcapParse.h"
#include "pcap_data.h"
#include "parse_int.h"
#include "parse_L3.h"
#include "parse_DNS.h"

void parse_UDP(struct DNSdataControl *d)
{
	u_int32_t sum;
	u_short *sump;

	d->dns.p_sport = d->dns.protoheader[0] * 256 + d->dns.protoheader[1];
	d->dns.p_dport = d->dns.protoheader[2] * 256 + d->dns.protoheader[3];
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
			if ((d->mode & MODE_IGNORE_UDP_CHECKSUM_ERROR) == 0) {
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

void parse_IPv6Fragment(struct DNSdataControl *d)
{
	u_char next_header = d->dns.protoheader[0];
	u_short frag_offset = (d->dns.protoheader[2] * 256 + d->dns.protoheader[3]) & 0x1fff;

	if (next_header == 17) {
		if (frag_offset == 0) {
			d->ParsePcapCounter._udp6_frag_first++;
			d->dns.protoheader += 8;
			d->dns.dns = d->dns.protoheader + 8;
			memcpy(d->dns.portaddr, d->dns.protoheader, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen, d->dns.protoheader+2, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen*2, d->dns.protoheader, 2);
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
	u_int32_t sum;
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
			if ((d->mode & MODE_IGNOREERROR) == 0) {
				if (d->debug & FLAG_INFO) {
					printf("#Error:Checksum:%x\n", sum);
					hexdump("", d->dns._ip, d->dns.len);
				}
				return;
			}
		}
		d->dns.ip_df = (d->dns._ip[6] & 0x40) ? 1 : 0;
		ip_off = (d->dns._ip[6] * 256 + d->dns._ip[7]) & 0x3fff;
		d->dns.portaddrlen = d->dns.alen+2;
		memcpy(d->dns.portaddr+2, d->dns.p_src, d->dns.alen);
		memcpy(d->dns.portaddr+d->dns.portaddrlen+2, d->dns.p_dst, d->dns.alen);
		memcpy(d->dns.portaddr+d->dns.portaddrlen*2+2, d->dns.p_src, d->dns.alen);
		switch(d->dns.proto) {
		case 17:
			memcpy(d->dns.portaddr, d->dns.protoheader, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen, d->dns.protoheader+2, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen*2, d->dns.protoheader, 2);
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
				memcpy(d->dns.portaddr, d->dns.protoheader, 2);
				memcpy(d->dns.portaddr+d->dns.portaddrlen, d->dns.protoheader+2, 2);
				memcpy(d->dns.portaddr+d->dns.portaddrlen*2, d->dns.protoheader, 2);
				d->ParsePcapCounter._tcp4++;
				d->dns._transport_type = T_TCP;
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
		d->dns.portaddrlen = d->dns.alen+2;
		memcpy(d->dns.portaddr+2, d->dns.p_src, d->dns.alen);
		memcpy(d->dns.portaddr+d->dns.portaddrlen+2, d->dns.p_dst, d->dns.alen);
		memcpy(d->dns.portaddr+d->dns.portaddrlen*2+2, d->dns.p_src, d->dns.alen);
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
			if (d->mode & MODE_IGNOREERROR) {
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
			memcpy(d->dns.portaddr, d->dns.protoheader, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen, d->dns.protoheader+2, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen*2, d->dns.protoheader, 2);
			parse_UDP(d);
			return;
		case 6:
			d->ParsePcapCounter._tcp6++;
			d->dns._transport_type = T_TCP;
			memcpy(d->dns.portaddr, d->dns.protoheader, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen, d->dns.protoheader+2, 2);
			memcpy(d->dns.portaddr+d->dns.portaddrlen*2, d->dns.protoheader, 2);
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

