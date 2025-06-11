/*
	$Id: parse_tcp.c,v 1.8 2025/05/01 10:06:07 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/



#include <stdio.h>
#include <sys/types.h>

#include "ext/uthash.h"

#include "config.h"
#include "mytool.h"
#include "pcapparse.h"
#include "parse_int.h"
#include "parse_DNS.h"

#define TCPBUF_BUFFLEN 65540

struct TCPbuff {
	u_char portaddr[36]; // srcport, srcaddr, dstport, dstaddr
	u_char portaddrlen;  // 2        alen     2        alen
	u_char alen;
	u_char valid;
	int datalen;
	int count;
	int tcp_dnscount;
	u_int64_t ts_syn; 
	u_int64_t ts_ack; 
	u_int64_t ts_first_data;
	u_int64_t ts_fin;
	u_int64_t ts_last;
	int tcp_mss;
	int tcp_fastopen;
	int64_t tcp_delay;
	int64_t tcp_syn_ack_delay;
	u_char buff[TCPBUF_BUFFLEN];
	UT_hash_handle hh;
	struct TCPbuff *next;
};

static struct TCPbuff *tcpbuff_data = NULL;
static struct TCPbuff **tcpbuff_sort = NULL;
static struct TCPbuff *tcpbuff_unused = NULL;
static int tcpbuff_unused_count = 0;
static int tcpbuff_size = 4000;
static int tcpbuff_forcefree_size = 100;
static int64_t tcpbuff_last_get = 0;
static int64_t tcpbuff_last_gc = 0;
static struct TCPbuff *tcpbuff_hash = NULL;
static u_int64_t tcpbuff_last_ts = 0;
static u_int64_t tcpbuff_MSL = 60*1000000LL;
static int tcp_n_hash_find = 0;
static int tcp_n_hash_add = 0;
static int tcp_n_hash_del = 0;
static int tcp_n_loop = 0;
static int tcp_n_new = 0;
static int tcp_n_new_ok = 0;
static int tcp_n_free = 0;
static int tcp_n_forcefree = 0;
static int tcp_n_overwrite = 0;
static int tcp_n_fin = 0;
static int tcp_n_syn = 0;
static int tcp_n_ack = 0;
static int tcp_n_rst = 0;
static int tcp_n_psh = 0;
static int tcp_n_data = 0;

static void parse_TCP_data(struct DNSdataControl *d, int datalen, struct TCPbuff *t, int syn)
{
	u_char *p;
	int j;
	if (datalen <= 0) return;
	if (datalen + t->datalen > TCPBUF_BUFFLEN) {
		if (d->debug & FLAG_DEBUG_TCP)
			printf("#Error:Too large data:ts=%ld:size=%d:removed\n", d->dns.ts, datalen + t->datalen);
		d->ParsePcapCounter._tcpbuff_unused++;
		return;
	}
	memcpy(t->buff + t->datalen, d->dns.dns, datalen);
	if (d->debug & FLAG_DEBUG_TCP) printf("INFO_TCP:MergeData:prev=%d:add=%d:flag=%02x:firstword=%d\n", t->datalen, datalen, d->dns.protoheader[13], t->buff[0]*256+t->buff[1]);
	//hexdump("tcpbuff.buff\n", t->buff, t->datalen);
	//hexdump("packet\n", d->dns._ip, d->dns.iplen);

	t->datalen += datalen;
	t->count++;
	d->ParsePcapCounter._tcpbuff_merged++;

	// check received data
	while (t->datalen > 0) {
		p = t->buff;
		j = p[0] * 256 + p[1];
		if (j <= 17) {
			if (d->debug & FLAG_DEBUG_TCP) hexdump("#INFO_TCP:do parse_DNS:partial_strangeData_ignored", t->buff, t->datalen);
			t->datalen = 0;
		} else
		if (j <= t->datalen - 2) {
			if (d->dns.tcp_mss == 0) d->dns.tcp_mss = t->tcp_mss;
			if (d->dns.tcp_fastopen == 0) d->dns.tcp_fastopen = t->tcp_fastopen;
			d->dns.tcp_delay = t->tcp_delay;
			d->dns.tcp_syn_ack_delay = t->tcp_syn_ack_delay;
			//t->tcp_delay = -1;
			d->dns.dnslen = j;
			d->dns.dns = t->buff + 2;
			d->dns.endp = d->dns.dns + j;
			t->tcp_dnscount++;
			d->dns.tcp_dnscount = t->tcp_dnscount;
			//if (d->debug & FLAG_DEBUG_TCP)
			//	hexdump("#INFO_TCP:do parse_DNS\n", d->dns.dns, j);
			parse_DNS(d);
			d->dns.dns = NULL;
			d->dns.endp = NULL;
			t->datalen -= (j + 2);
			//	hexdump("#INFO_TCP:do parse_DNS_rest\n", t->buff+j+2, t->datalen);
			if (t->datalen > 0)
				memcpy(t->buff, t->buff+j+2, t->datalen);
		} else
		if (d->dns.partial == 0) {
			return;
		} else {
			if (t->datalen > 512 && j <= 16384 && t->buff[6] == 0 && t->buff[7] == 1 && d->dns.partial != 0) {
				d->dns._transport_type = T_TCP_PARTIAL;
				if (d->debug & FLAG_DEBUG_TCP)
					hexdump("#INFO_TCP:T_TCP_PARTIAL:do parse_DNS", t->buff+2, t->datalen-2);
				d->dns.dnslen = t->datalen - 2;
				d->dns.dns = t->buff + 2;
				d->dns.endp = d->dns.dns + d->dns.dnslen;
				if (d->dns.tcp_mss == 0) d->dns.tcp_mss = t->tcp_mss;
				if (d->dns.tcp_fastopen == 0) d->dns.tcp_mss = t->tcp_fastopen;
				d->dns.tcp_delay = t->tcp_delay;
				//t->tcp_delay = -1;
				parse_DNS(d);
			} else {
				//hexdump("#INFO_TCP:T_TCP_PARTIAL:do parse_DNS:partial_strangeData_ignored", t->buff, t->datalen);
			}
			t->datalen = 0;
		}
	}
}

static void parse_nosyn_data(struct DNSdataControl *d, int len)
{
	u_char *p = d->dns.dns;
	int j;

	j = p[0] * 256 + p[1];
	if (j <= 17) {
		if (d->debug & FLAG_DEBUG_TCP) hexdump("#INFO_TCP:do parse_nosyn_data:partial_strangeData_ignored\n", d->dns._ip, d->dns.iplen);
	} else
	if (j <= len - 2) {
		d->dns.tcp_delay = -1;
		d->dns.dnslen = j;
		d->dns.dns += 2;
		d->dns.endp = d->dns.dns + j;
		parse_DNS(d);
	} else
	if (len > 512 && j <= 16384 && p[6] == 0 && p[7] == 1) {
		d->dns._transport_type = T_TCP_PARTIAL;
		if (d->debug & FLAG_DEBUG_TCP)
			hexdump("#INFO_TCP:T_TCP_PARTIAL:do parse_DNS", p+2, len-2);
		d->dns.dnslen = len - 2;
		d->dns.dns += 2;
		d->dns.tcp_delay = -1;
		parse_DNS(d);
	} else {
		//printf("#INFO_TCP:NO_SYN_:partial_strangeData_ignored:datalen=%d:p=%d\n", len, j);
		//hexdump("#INFO_TCP:NO_SYN_:partial_strangeData_ignored\n", d->dns._ip, d->dns.iplen);
	}
}

static int64_t first_tcp_ts = 0;

void tcpbuff_statistics()
{
	printf("#TCP:find=%d, add=%d, del=%d, loop=%d, new=%d, new_ok=%d, free=%d, forcefree=%d, overwrite=%d\n",
		tcp_n_hash_find, tcp_n_hash_add, tcp_n_hash_del, tcp_n_loop,
		tcp_n_new, tcp_n_new_ok,
		tcp_n_free, tcp_n_forcefree, tcp_n_overwrite);
	printf("#TCP:syn=%d, ack=%d, fin=%d, rst=%d, psh=%d,data=%d\n",
		tcp_n_syn, tcp_n_ack, tcp_n_fin, tcp_n_rst, tcp_n_psh, tcp_n_data);
}

static int dump_tcpbuff_sort_sub(const void *aa, const void *bb)
{
	int64_t left, right;
	const struct TCPbuff **a = (const struct TCPbuff **)aa;
	const struct TCPbuff **b = (const struct TCPbuff **)bb;
	left = (*a)->ts_last;
	right = (*b)->ts_last;
	return (left > right) - (right > left);
}

void dump_tcpbuff()
{
	int i, j;
	struct TCPbuff *t, *tmp;
	int max = HASH_CNT(hh, tcpbuff_hash);
	int64_t last;

	if (max == 0) return;
	i = 0;
	HASH_ITER(hh, tcpbuff_hash, t, tmp) {
		tcpbuff_sort[i++] = t;
		if (i >= max) break;
	}
	qsort(tcpbuff_sort, max, sizeof(tcpbuff_sort[0]), dump_tcpbuff_sort_sub);
	last = tcpbuff_sort[max-1]->ts_last;
	for (i = 0; i < max; i++) {
		printf("%04d %ld %ld %d %d ", i, tcpbuff_sort[i]->ts_last, last-tcpbuff_sort[i]->ts_last,
			tcpbuff_sort[i]->datalen, tcpbuff_sort[i]->buff[0]*256+tcpbuff_sort[i]->buff[1]);
		for (j = 0; j < tcpbuff_sort[i]->portaddrlen*2; j++) {
			printf("%02x", tcpbuff_sort[i]->portaddr[j]);
		}
		printf("\n");
	}
}

static void init_tcpbuff_data()
{
	int s, i;

	tcpbuff_data = my_malloc(s=sizeof(struct TCPbuff)*tcpbuff_size);
	tcpbuff_sort = my_malloc(s=sizeof(struct TCPbuff*)*tcpbuff_size);
	memset(tcpbuff_data, 0, s);
	i = tcpbuff_size;
	// tcpbuff_data[i-1].next = 0;
	while (--i > 0) { tcpbuff_data[i-1].next = &tcpbuff_data[i]; }
	tcpbuff_unused = tcpbuff_data;
	tcpbuff_unused_count = tcpbuff_size;
}

static void tcpbuff_free(struct TCPbuff *t)
{
	t->valid = 0;
	t->next = tcpbuff_unused;
	tcpbuff_unused = t;
	tcpbuff_unused_count++;
}

static void tcpbuff_remove(struct TCPbuff *t)
{
	HASH_DELETE(hh, tcpbuff_hash, t);
	memset(t, 0, sizeof(*t));
	t->valid = 0;
	tcpbuff_free(t);
}

static struct TCPbuff *tcpbuff_get(int64_t ts)
{
	int i;
	int force_free = 0;
	int gc_free = 0;
	int64_t last;
	int64_t diff = ts - tcpbuff_last_get;
	int64_t gc_diff = ts - tcpbuff_last_gc;

	tcpbuff_last_get = ts;
	struct TCPbuff *t;
	if (tcpbuff_unused == NULL || gc_diff > tcpbuff_MSL) {
		tcpbuff_last_gc = ts;
		for (i = 0; i < tcpbuff_size; i++) {
			t = &tcpbuff_data[i];
			if (t->valid != 0) {
				last = t->ts_last;
				if (t->ts_fin > last) {
					last = t->ts_fin;
				}
				if (ts - last >= tcpbuff_MSL) {
					gc_free++;
					HASH_DELETE(hh, tcpbuff_hash, t);
					tcpbuff_free(t);
					tcp_n_hash_del++;
				}
			}
		}
	}
	if (tcpbuff_unused != NULL) {
	//	printf("tcpbuff_get:diff=%lld/%lld:gc_free=%d:unused=%d\n", diff, gc_diff, gc_free, tcpbuff_unused_count);
		t = tcpbuff_unused;
		tcpbuff_unused = t->next;
		tcpbuff_unused_count--;
		fflush(stdout);
		return t;
	}
	for (i = 0; i < tcpbuff_size; i++) {
		tcpbuff_sort[i] = &tcpbuff_data[i];
	}
	qsort(tcpbuff_sort, tcpbuff_size, sizeof(tcpbuff_sort[0]), dump_tcpbuff_sort_sub);
#if 0
	for (i = 0; i < tcpbuff_size; i++) {
		t = tcpbuff_sort[i];
		printf("tcpbuff_sort[%d]: valid=%d last=%ld / %ld\n", i, t->valid, t->ts_last, ts - t->ts_last);
	}
#endif
	//printf("tcpbuff_get:forcefree:get_diff=%lld/%lld:unused=%d ts-last=%ld/%ld//%ld//%ld/%ld\n", diff, gc_diff, tcpbuff_unused_count+tcpbuff_forcefree_size, ts-tcpbuff_sort[0]->ts_last, ts-tcpbuff_sort[tcpbuff_forcefree_size-1]->ts_last, ts-tcpbuff_sort[tcpbuff_forcefree_size]->ts_last, ts-tcpbuff_sort[tcpbuff_size-2]->ts_last, ts-tcpbuff_sort[tcpbuff_size-1]->ts_last);
	for (i = 0; i < tcpbuff_forcefree_size; i++) {
		t = tcpbuff_sort[i];
		tcpbuff_remove(t);
		tcp_n_hash_del++;
		tcp_n_forcefree++;
	}
	fflush(stdout);
	t = tcpbuff_unused;
	tcpbuff_unused = t->next;
	tcpbuff_unused_count--;
	return t;
}

void tcpbuff_remove_all()
{
	struct TCPbuff *t, *tmp;

	HASH_ITER(hh, tcpbuff_hash, t, tmp) {
		tcpbuff_remove(t);
		tcp_n_hash_del++;
	}
}

static void tcpbuff_debug_dump(struct TCPbuff *t, struct DNSdataControl *d, char *msg, char *tcpstr, int datalen)
{
	printf("#INFO_TCP:dump_debug:%s:ts=%ld flag=%s datalen=%d, found=%p mss=%d fastopen=%d portaddrlen=%d\n", msg, d->dns.ts, tcpstr, datalen, t, d->dns.tcp_mss, d->dns.tcp_fastopen, t->portaddrlen);
	hexdump("  portaddr:", t->portaddr, t->portaddrlen*2);
	if (t->datalen != 0) hexdump("  OLD data:", t->buff, t->datalen);
	hexdump("  Packet:", d->dns._ip, d->dns.len);
}

void parse_TCP(struct DNSdataControl *d)
{
	int data_offset;
	int datalen;
	int i;
	int flag;
	int syn, ack, fin, rst, psh;
	u_char const * p;
	struct TCPbuff *t, *found, *found_syn;
	char TcpStr[256];

	if (tcpbuff_data == NULL) {
		init_tcpbuff_data();
	} else
	if (tcpbuff_last_ts != 0 && tcpbuff_last_ts > d->dns.ts) {
		if (d->debug & FLAG_DEBUG_TCP)
			printf("#INFO_TCP:tcpbuff_remove:ALL %d removed\n", HASH_CNT(hh, tcpbuff_hash));
		tcpbuff_remove_all();
	}
	tcpbuff_last_ts = d->dns.ts;
	d->dns.p_sport = d->dns.protoheader[0] * 256 + d->dns.protoheader[1];
	d->dns.p_dport = d->dns.protoheader[2] * 256 + d->dns.protoheader[3];

	if ((d->dns.alen != 4 && d->dns.alen != 16) ||
	    ((d->dns.protoheader[12] >> 4) < 5)) {
		d->dns.error |= ParsePcap_TCPError;
		return;
	}
	if (first_tcp_ts == 0) first_tcp_ts = d->dns.ts;

	d->dns.p_sport = d->dns.protoheader[0] * 256 + d->dns.protoheader[1];
	d->dns.p_dport = d->dns.protoheader[2] * 256 + d->dns.protoheader[3];
	data_offset = (d->dns.protoheader[12] >> 4) * 4;
	d->dns.dns = d->dns.protoheader + data_offset;
	datalen = d->dns.endp - d->dns.dns;
	flag = d->dns.protoheader[13];
	syn = flag & 2;   if (syn) tcp_n_syn++;
	ack = flag & 16;  if (ack) tcp_n_ack++;
	fin = flag & 1;   if (fin) tcp_n_fin++;
	rst = flag & 4;   if (rst) tcp_n_rst++;
	psh = flag & 8;   if (psh) tcp_n_psh++;
	if (datalen > 0) tcp_n_data++;
	sprintf(TcpStr, "%s%s%s%s%s%s",
		flag&2?"Syn":"",
		flag&16?"Ack":"",
		flag&1?"Fin":"",
		flag&4?"Rst":"",
		flag&32?"Urg":"",
		flag&8?"Psh":""
		);
#if 0
	if (flag & 4 || datalen <= 0) {
		d->ParsePcapCounter._tcpbuff_zerofin++;
		return;
	}
#endif
	//hexdump("packet: ", d->dns.portaddr, d->dns.portaddrlen*2);

	found = NULL;
	found_syn = NULL;
	if (d->enable_tcp_state) {
		HASH_FIND(hh, tcpbuff_hash, d->dns.portaddr, d->dns.portaddrlen*2, found);
		tcp_n_hash_find++;
	}
	if (found != NULL && found->ts_fin > 0) {
	       if (d->dns.ts < found->ts_fin + tcpbuff_MSL) {
			// Ignore all
			if (d->debug & FLAG_DEBUG_TCP)
				tcpbuff_debug_dump(found, d, "FinIn120ignored", TcpStr, datalen);
			found->ts_syn = 0;
			return;
		} else {
			found->ts_fin = 0;
			if (d->debug & FLAG_DEBUG_TCP)
				tcpbuff_debug_dump(found, d, "FinClear", TcpStr, datalen);
			tcpbuff_remove(found);
			found = NULL;
		}
	}
	if (d->debug & FLAG_DEBUG_TCP) {
		if (found != NULL) {
			printf("INFO_TCP:%s:ts%ld:pre_ts=%ld size=%d\n", TcpStr, d->dns.ts, found->ts_last, found->datalen);
			hexdump("tcpbuff.buff\n", found->buff, found->datalen);
			hexdump("packet\n", d->dns._ip, d->dns.iplen);
		} else {
			printf("#INFO_TCP:%s:ts=%ld mss=%d fastopen=%d\n", TcpStr, d->dns.ts, d->dns.tcp_mss, d->dns.tcp_fastopen);
			hexdump("packet\n", d->dns._ip, d->dns.iplen);
		}
	}

	if (syn) {
		if (found) { tcpbuff_remove(found); found = NULL; }
		// Parse TCP_Options
		d->ParsePcapCounter._tcpbuff_syn++;
		d->dns.tcp_mss = 0;
		d->dns.tcp_fastopen = 0;
		p = d->dns.protoheader;
		i = 20;
		while(i+1 < data_offset && p[i] != 0) {
			switch (p[i]) {
			case 0:
			case 1: i++; continue;
			case 2: d->dns.tcp_mss = p[i+2] * 256 + p[i+3];
				i += 4; continue;
			case 6: case 7: i += 6; continue;
			case 8: i += 10; continue;
			case 9: i += 2; continue;
			case 34: d->dns.tcp_fastopen = 1; break;
			}
			if (p[i] > 1) {
				i += p[i];
			} else {
				break;
			}
		}
		if (d->debug & FLAG_DEBUG_TCP)
			printf("#INFO_TCP:SYN_Record:ts=%ld flag=%s datalen=%d\n", d->dns.ts, TcpStr, datalen);
		if (d->enable_tcpsyn_callback) {
			d->dns._id = flag;
			d->dns.datatype = DATATYPE_TCPSYN;
			(void)(d->callback)(d, CALLBACK_TCPSYN);
		}
		if (d->enable_tcp_state) {
			t = tcpbuff_get(d->dns.ts);
			memset(t, 0, sizeof(struct TCPbuff));
			t->valid = 1;
			int keylen = d->dns.portaddrlen*2;
			t->portaddrlen = d->dns.portaddrlen;
			memcpy(t->portaddr, d->dns.portaddr, d->dns.portaddrlen*2);
			tcp_n_hash_add++;
			t->ts_last = t->ts_syn = d->dns.ts;
			t->alen = d->dns.alen;
			t->datalen = 0;
			t->count = 1;
			t->tcp_mss = d->dns.tcp_mss;
			t->tcp_fastopen = d->dns.tcp_fastopen;
			t->tcp_delay = -1;
			t->ts_ack = 0;
			t->tcp_syn_ack_delay = -1;
			HASH_ADD(hh, tcpbuff_hash, portaddr, keylen, t);
			if (ack) {
				HASH_FIND(hh, tcpbuff_hash, d->dns.portaddr+d->dns.portaddrlen, d->dns.portaddrlen*2, found_syn);
				if (found_syn != NULL && found_syn->ts_ack == 0) {
					found_syn->ts_ack = d->dns.ts;
					found_syn->tcp_syn_ack_delay = d->dns.ts - found_syn->ts_syn;
				}
			}
		}
		return;
	}
	if (d->enable_tcp_state == 0 || found == NULL) {
		if (flag == 0x10 && datalen == 0) return;
		if (datalen > 0) {
			 parse_nosyn_data(d, datalen);
		} else
		if (d->debug & FLAG_DEBUG_TCP) {
			printf("#INFO_TCP:NoSYN:ts=%ld flag=%s datalen=%d\n", d->dns.ts, TcpStr, datalen);
			hexdump(" Packet:\n", d->dns._ip, d->dns.iplen);
		}
		if (fin && d->enable_tcp_state) goto othersidefin;
		return;
	}
	if (ack) {
		HASH_FIND(hh, tcpbuff_hash, d->dns.portaddr+d->dns.portaddrlen, d->dns.portaddrlen*2, found_syn);
		if (found_syn != NULL && found_syn->ts_ack == 0) {
			found_syn->ts_ack = d->dns.ts;
			found_syn->tcp_syn_ack_delay = d->dns.ts - found_syn->ts_syn;
		}
	}
	if (d->debug & FLAG_DEBUG_TCP) printf("#INFO_TCP:ACK:ts=%ld partial=%d flag=%s found=%p datalen=%d dnslen=%d\n", d->dns.ts, d->dns.partial, TcpStr, found, found->datalen, datalen);
	found->ts_last = d->dns.ts;
	if (d->debug & FLAG_DEBUG_256) {
		if (found->ts_syn != 0 && found->tcp_delay < 0) {
			found->tcp_delay = d->dns.ts - found->ts_syn;
			if (found->tcp_delay <= 0) found->tcp_delay = -1;
		}
	} else
	if (datalen > 0 && found->ts_first_data == 0) {
		found->ts_first_data = d->dns.ts;
		if (found->ts_syn != 0 && found->tcp_delay <= 0) {
			found->tcp_delay = d->dns.ts - found->ts_syn;
			if (found->tcp_delay <= 0) found->tcp_delay = -1;
		}
	}
	if (datalen > 0 && datalen <= found->datalen) {
		if (memcmp(found->buff+found->datalen-datalen, d->dns.dns, datalen)==0) {
			/* Ignore possible duplicate packet */
			d->ParsePcapCounter._tcpbuff_unused++;
			if (!fin) return;
			datalen = 0;
		}
	}
	if (datalen > 0) { parse_TCP_data(d, datalen, found, 0); datalen = 0; }
	if (fin || rst) {
		tcp_n_free++;
		if ((d->debug & FLAG_DEBUG_TCP) && found->datalen + d->dns.dnslen > 0) {
			printf("#INFO_TCP:FIN:ts=%ld partial=%d flag=%s datalen=%d dnslen=%d\n", d->dns.ts, d->dns.partial, TcpStr, found->datalen, d->dns.dnslen);
			if (found->datalen != 0) {
				hexdump("  RestDATA:", found->buff, found->datalen);
			}
			hexdump("Packet:\n", d->dns._ip, d->dns.iplen);
		}
		d->ParsePcapCounter._tcpbuff_fin++;
		found->ts_fin = found->ts_last = d->dns.ts;
		found->ts_syn = 0;
		found->datalen = 0;
		found->count = 0;
		found->tcp_mss = 0;
		found->tcp_fastopen = 0;
		found->tcp_delay = -1;
othersidefin:
		HASH_FIND(hh, tcpbuff_hash, d->dns.portaddr+d->dns.portaddrlen, d->dns.portaddrlen*2, found);
		tcp_n_hash_find++;
		if (found != NULL) {
			d->ParsePcapCounter._tcpbuff_fin++;
			found->ts_fin = d->dns.ts;
			found->ts_syn = 0;
			found->datalen = 0;
			found->count = 0;
			found->tcp_mss = 0;
			found->tcp_fastopen = 0;
			found->tcp_delay = -1;
		}
		return;
	}
	if (datalen == 0) return;
	return;
}

