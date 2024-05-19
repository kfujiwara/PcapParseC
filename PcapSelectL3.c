/*
	$Id: PcapSelectL3.c,v 1.38 2024/05/09 15:15:28 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.

	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include <stdio.h>

#include "config.h"

#define ENVNAME "PCAPGETQUERY_ENV"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDLIB_H
#include <unistd.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "ext/uthash.h"
#include "PcapParse.h"

long long begin = -1;
long long end = -1;
int time_offset = 0;
int accept_v4 = 0;
int accept_v6 = 0;
int accept_tcp = 0;
int accept_udp = 0;
int accept_frag = 0;
int accept_query = 0;
int accept_reply = 0;
double exact[100];
int nexact = 0;
int opt_v = 0;
int print_hash = 0;
int single_file = 0;
int ignore_shortread = 0;
int cut_num_packets = -1;
char *serverlist_file = NULL;
char *Logfile = NULL;
FILE * LogFP = NULL;

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

struct ipaddr_hash {
	int count;
	u_int alen;
	u_char addr[18];
	UT_hash_handle hh;
};

static struct ipaddr_hash *ipaddr1_hash = NULL;
static struct ipaddr_hash *ipaddr2_hash = NULL;

// ipaddr/portno
void register_ipaddr_port_hash(char *str, struct ipaddr_hash **hash)
{
	int alen = 0;
	u_char portaddr[18];
	struct ipaddr_hash *e;
	int port;
	char *p, *q, *r;
	int offset = 0;

	p = str;
	//printf("Input=%s\n", p);
	while (p != NULL && *p != 0) {
		q = strchr(p, ',');
		if (q != NULL && *q == ',') {
			*q++ = 0;
		} else {
			q = NULL;
		}
		r = strchr(p, '#');
		if (r == NULL || *r != '#') {
			port = -1;
		} else {
			port = atoi(r+1);
			*r = 0;
			offset = 2;
			portaddr[0] = ((port & 0xff00) >> 8);
			portaddr[1] = port & 0xff;
		}
		if (strchr(p, ':') != NULL) {
			if (inet_pton(AF_INET6,p,portaddr+offset)==0)
				err(1, "cannot parse6 %s", p);
			alen = 16;
		} else {
			if (inet_pton(AF_INET,p,portaddr+offset)==0)
				err(1, "cannot parse4 %s", p);
			alen = 4;
		}
		HASH_FIND(hh, (*hash), portaddr, alen+offset, e);
		if (e == NULL) {
			e = malloc(sizeof(struct ipaddr_hash));
			e->alen = alen+offset;
			memcpy(e->addr, portaddr, alen+offset);
			e->count = 0;
			HASH_ADD(hh, (*hash), addr, e->alen, e);
			if (opt_v) printf("Match_IP_address:%s %d\n", p, port);
		}
		p = q;
	}
}

void print_ipaddrlist_hash(struct ipaddr_hash *hash)
{
	struct ipaddr_hash *e, *tmp;
	int i;
	u_char *a;
	char s[256];

	HASH_ITER(hh, hash, e, tmp) {
		a = e->addr;
		switch(e->alen) {
		case 4:  printf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]); break;
		case 6:  printf("%d.%d.%d.%d#%d", a[2], a[3], a[4], a[5], a[0]*256+a[1]); break;
		case 16: printf("%s", inet_ntop(AF_INET6, a, s, sizeof s)); break;
		case 18: printf("%s#%d", inet_ntop(AF_INET6, a+2, s, sizeof s), a[0]*256+a[1]); break;
		}
		printf("   ");
		for (i = 0; i < e->alen; i++) {
			printf(" %02x", a[i]);
		}
		printf("\n");
	}
}

/*
			Supported Linktype: DLT_NULL, DLT_EN10MB, DLT_IP, DLT_LINUX_SLL
 */

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
//#define DLT_RAW		12	/* _ip IP */

#define SUBDIRLEN 65

struct PcapFiles {
	char *path;
	char subdir[SUBDIRLEN];
	FILE *fp;
	int is_popen;
	int l2header;
	int needswap;
	int iplen;
	u_char *_ip;
	long long offset;
	struct pcap_file_header pf;
	long long ts;
	struct pcap_header ph;
	u_char buff[65536];
};

static u_short swap16(u_short x)
{
	return ((x & 0xff) << 8) | (x >> 8);
}

static u_long swap32(u_int32_t x)
{
	return ((x & 0xff) << 24)
		| ((x & 0xff00) << 8)
		| ((x & 0xff0000) >> 8)
		| ((x & 0xff000000) >> 24);
}

int pcap_read(struct PcapFiles *pcap)
{
	int len;
	int error = 0;

	pcap->iplen = 0;
	pcap->_ip = NULL;
	if (pcap->fp == NULL) return ParsePcap_EOF;
	len = fread(&pcap->ph, 1, sizeof(struct pcap_header), pcap->fp);
	pcap->offset += len;
	if (len == 0) {
		error = ParsePcap_EOF;
	} else
	if (len != sizeof(struct pcap_header)) {
		error = ParsePcap_ERROR_ShortRead;
	} else
	if (pcap->ph.len == 0 || pcap->ph.caplen == 0) {
		pcap->ph.ts.tv_usec = pcap->ph.caplen;
		len = fread(&pcap->ph.caplen, 1, 8, pcap->fp);
		pcap->offset += len;
		if (len != 8) { error = ParsePcap_ERROR_ShortRead; }
	}
	// if (error == 0) hexdump("read", &pcap->ph, 16);
	if (error == 0 && pcap->needswap) {
		pcap->ph.caplen = swap32(pcap->ph.caplen);
		pcap->ph.len = swap32(pcap->ph.len);
		pcap->ph.ts.tv_sec = swap32(pcap->ph.ts.tv_sec);
		pcap->ph.ts.tv_usec = swap32(pcap->ph.ts.tv_usec);
	}
	// if (error == 0) hexdump("after swap", &pcap->ph, 16);
	if (error == 0 && (pcap->ph.caplen > 65535 || pcap->ph.len > 65535 || pcap->ph.caplen < 0)) {
		error= ParsePcap_ERROR_ShortRead;
	}
	len = 0;
	if (error == 0 && (len = fread(pcap->buff, 1, pcap->ph.caplen, pcap->fp)) != pcap->ph.caplen) {
		error = ParsePcap_ERROR_ShortRead;
	}
	pcap->offset += len;
	if (error != 0) {
		if (pcap->is_popen) {
			pclose(pcap->fp);
		} else {
			fclose(pcap->fp);
		}
		pcap->fp = NULL;
	} else {
		pcap->ts = pcap->ph.ts.tv_usec + pcap->ph.ts.tv_sec * 1000000LL;
		pcap->_ip = pcap->buff + pcap->l2header;
		pcap->iplen = pcap->ph.caplen - pcap->l2header;
		if (pcap->pf.linktype == DLT_EN10MB) {
			if (pcap->buff[12] == 0x81 && pcap->buff[13] == 0) { /* VLAN */
				pcap->_ip += 4;
				pcap->iplen -= 4;
			}
		}
	}
	return error;
}

void copy_subdir_name(char *path, char *dest, int len)
{
	char *slash1 = NULL, *slash2 = NULL, *p;
	p = path;
	while (p != NULL && *p != 0) {
		slash2 = slash1;
		slash1 = p;
		p = strchr(p+1, '/');
	}
	*dest = 0;
	if (slash2 != NULL && slash1 != NULL) {
		// slash2+1 .... slash1-1 ... slash1-slash2-1
		if (slash1 - slash2 < len) {
			memcpy(dest, slash2+1, slash1-slash2-1);
			dest[slash1-slash2] = 0;
		}
	}
}

int pcap_open(struct PcapFiles *pcap, char *file)
{
	int error = 0;
	char buff[1024];
	int len;

	pcap->path = file;
	len = strlen(file);
	pcap->is_popen = 1;

	copy_subdir_name(file, pcap->subdir, sizeof(pcap->subdir));

	if (len > 3 && strcmp(file+len-3, ".xz") == 0) {
		snprintf(buff, sizeof buff, "xz -cd %s", file);
	} else
	if (len > 4 && strcmp(file+len-4, ".bz2") == 0) {
		snprintf(buff, sizeof buff, "bzip2 -cd %s", file);
	} else
	if (len > 4 && strcmp(file+len-4, ".zst") == 0) {
		snprintf(buff, sizeof buff, "zstd -cd %s", file);
	} else
	if (len > 3 && strcmp(file+len-3, ".gz") == 0) {
		snprintf(buff, sizeof buff, "gzip -cd %s", file);
	} else {
		buff[0] = 0;
		pcap->is_popen = 0;
	}
	if (pcap->is_popen) {
		if ((pcap->fp = popen(buff, "r")) == NULL) {
			fprintf(stderr, "Cannot Open %s", buff);
			return ParsePcap_ERROR_FILE_OPEN;
		}
	} else {
		if ((pcap->fp = fopen(pcap->path, "r")) == NULL) {
			fprintf(stderr, "Cannot Open %s", file);
			return ParsePcap_ERROR_FILE_OPEN;
		}
	}
	len = fread(&pcap->pf, 1, sizeof(struct pcap_file_header), pcap->fp);
	pcap->offset = len;
 	if (len != sizeof(struct pcap_file_header)) {
		fprintf(stderr, "ShortRead_pcapfileheader:%d:%s\n", len, pcap->path);
		error = 1;
	} else
	if (pcap->pf.magic == 0xa1b2c3d4) { /* OK */
		pcap->needswap = 0;
	} else
	if (pcap->pf.magic == 0xd4c3b2a1) {
		pcap->needswap = 1;
		pcap->pf.version_major = swap16(pcap->pf.version_major);
		pcap->pf.version_minor = swap16(pcap->pf.version_minor);
		pcap->pf.thiszone = swap32(pcap->pf.thiszone);
		pcap->pf.sigfigs = swap32(pcap->pf.sigfigs);
		pcap->pf.snaplen = swap32(pcap->pf.snaplen);
		pcap->pf.linktype = swap32(pcap->pf.linktype);
	} else {
		error = ParsePcap_ERROR_ShortRead;
		fprintf(stderr, "BogusPcapHeader:%x:%s\n", pcap->pf.magic, pcap->path);
	}
	if (error == 0) {
		if (pcap->pf.linktype == DLT_NULL) {
			pcap->l2header = 4;
		} else
		if (pcap->pf.linktype == DLT_EN10MB) {
			pcap->l2header = 14;
		} else
		if (pcap->pf.linktype == DLT_LINUX_SLL) {
			pcap->l2header = 16;
		} else
		if (pcap->pf.linktype == DLT_IP) {
			pcap->l2header = 0;
		} else {
			fprintf(stderr, "#Error:unknownLinkType:%d", pcap->pf.linktype);
			error = ParsePcap_ERROR_UnknownLinkType;
		}
	}
	if (error == 0) {
		error = pcap_read(pcap);
		if (error) {
			fprintf(stderr, "ShortRead_pcapheader:readbytes=%lld:%s\n", pcap->offset, pcap->path);
		}
	}
	if (error != 0 && pcap->fp != NULL) {
		if (pcap->is_popen) {
			pclose(pcap->fp);
		} else {
			fclose(pcap->fp);
		}
		pcap->fp = NULL;
	}
	return error;
}


int parse_packet(FILE *wfp, long long ts, u_char *_ip, int _iplen)
{
	int i;
	int match_time = 0;
	int match_frag = 0;
	int match_proto = 0;
	int ignore;
	int ipv;
	double d = ts;
	struct ipaddr_hash *is1, *id1, *i1;
	struct ipaddr_hash *is2, *id2, *i2;
	u_char ip_src[18];
	u_char ip_dst[18];
	int alen;
	struct pcap_header ph;

	match_time = 0;
	match_frag = 0;
	ignore = 0;
	if (nexact > 0) {
		for (i = 0; i < nexact; i++) {
			if (exact[i] == d) {
				match_time = 1;
				break;
			}
		}
	} else if (begin >= 0 && d < begin) { 
		match_time =0;
	} else if (end >= 0 && d >= end) {
		match_time = 0;
	} else {
		match_time = 1;
	}
	ipv = _ip[0] >> 4;
	memset(ip_src, 0, sizeof(ip_src));
	memset(ip_dst, 0, sizeof(ip_dst));
	if (ipv == 4) {
		alen = 4;
		memcpy(ip_src+2, _ip + 12, 4);
		memcpy(ip_dst+2, _ip + 16, 4);
		if (_ip[9] == 17 || _ip[9] == 6) {
			memcpy(ip_src, _ip+20, 2);
			memcpy(ip_dst, _ip+22, 2);
		}
		if (_ip[9] == 17 && accept_udp) match_proto = 1;
		else if (_ip[9] == 6 && accept_tcp) match_proto = 1;
		if ((((_ip[6]<<8)|_ip[7]) & 0x3fff) != 0) {
			match_frag = 1;
		}
	} else
	if (ipv == 6) {
		alen = 16;
		memcpy(ip_src+2, _ip + 8, 16);
		memcpy(ip_dst+2, _ip+24, 16);
		if (_ip[6] == 17 || _ip[6] == 6) {
			memcpy(ip_src, _ip+40, 2);
			memcpy(ip_dst, _ip+42, 2);
		}
		if (_ip[6] == 17 && accept_udp) match_proto = 1;
		else if (_ip[6] == 6 && accept_tcp) match_proto = 1;
		if (_ip[6] == 44) {
			match_frag = 1;
		}
	}
	if (ipaddr1_hash != NULL) {
		if (accept_query) {
			HASH_FIND(hh, ipaddr1_hash, ip_src+2, alen, is1);
			if (is1 == NULL) HASH_FIND(hh, ipaddr1_hash, ip_src, alen+2, is1);
		}
		if (accept_reply) {
			HASH_FIND(hh, ipaddr1_hash, ip_dst+2, alen, id1);
			if (id1 == NULL) HASH_FIND(hh, ipaddr1_hash, ip_dst, alen+2, id1);
		}
		i1 = (is1 != NULL) ? is1 : id1;
	} else {
		i1 = NULL;
	}
	if (ipaddr2_hash != NULL) {
		if (accept_reply) {
			HASH_FIND(hh, ipaddr2_hash, ip_src+2, alen, is2);
			if (is2 == NULL) HASH_FIND(hh, ipaddr2_hash, ip_src, alen+2, is2);
		}
		if (accept_query) {
			HASH_FIND(hh, ipaddr2_hash, ip_dst+2, alen, id2);
			if (id2 == NULL) HASH_FIND(hh, ipaddr2_hash, ip_dst, alen+2, id2);
		}
		i2 = (is2 != NULL) ? is2 : id2;
	} else {
		i2 = NULL;
	}
	if (i1 != NULL) i1->count++;
	if (i2 != NULL) i2->count++;
	ignore = (ipaddr1_hash != NULL && i1 == NULL)
		|| (ipaddr2_hash != NULL && i2 == NULL)
		|| (accept_frag != 0 && match_frag != 0)
		|| (match_proto == 0 && match_frag == 0)
		|| !match_time;
	if (!ignore) {
		ph.ts.tv_sec = ts / 1000000LL;
		ph.ts.tv_usec = ts % 1000000LL;
		ph.caplen = _iplen;
		ph.len = _iplen;
		//hexdump("ph", &ph, sizeof(ph));
		fwrite(&ph, sizeof(ph), 1, wfp);
		//hexdump("_ip", _ip, iplen);
		fwrite(_ip, _iplen, 1, wfp);
		return 1;
	}
	return 0;
}

int pcap_cleanup(FILE *wfp, int argc, char **argv)
{
	int i;
	int ret;
	int error;
	int found;
	long long tt;
	int match_time = 0;
	int match_frag = 0;
	int ignore;
	long long prev = 0;
	u_char *_ip;
	int iplen;
 	struct PcapFiles *pcapfiles;
	int npcap = 0;
	int exist;
	int error_close_files = 0;

	pcapfiles = calloc(sizeof(struct PcapFiles), argc);
	if (pcapfiles == NULL) return ParsePcap_ERROR_Memory;
	if (single_file) {
		//// open single file at once
		for (i = 0; i < argc; i++) {
			if ((error = pcap_open(&pcapfiles[i], argv[i])) != 0) {
				error_close_files++;
			}
			while (pcapfiles[i]._ip != NULL) {
				_ip = pcapfiles[i]._ip;
				iplen = pcapfiles[i].iplen;
				ret = parse_packet(wfp, pcapfiles[i].ts,_ip, iplen);
				if (ret != 0) {
					prev = pcapfiles[i].ts;
					if (opt_v>0) printf("writing: %d bytes. ts=%lld delta=%lld path=%s\n", iplen, pcapfiles[i].ts, pcapfiles[i].ts-prev, pcapfiles[i].path);
				}
				error = pcap_read(&pcapfiles[i]);
				if (error != 0 && error != ParsePcap_EOF) {
					error_close_files++;
				}
			}
		}
		if (error_close_files != 0) {
			return ParsePcap_ERROR_ShortRead;
		}
		return 0;
	}
	/////// open all files at once
	for (i = 0; i < argc; i++) {
		if ((error = pcap_open(&pcapfiles[npcap], argv[i])) == 0) {
			npcap++;
		} else {
			error_close_files++;
		}
	}
	for (;;) {
		exist = 0;
		found = -1;
		tt = 0;
		for (i = 0; i < npcap; i++) {
			if (pcapfiles[i].fp != NULL) {
				exist++;
				if (tt == 0 || tt > pcapfiles[i].ts) {
					found = i;
					tt = pcapfiles[i].ts;
				}
			}
		}
		if (found == -1 || exist == 0) {
			break;
		}
		match_time = 0;
		match_frag = 0;
		ignore = 0;
		_ip = pcapfiles[found]._ip;
		iplen = pcapfiles[found].iplen;
		ret = parse_packet(wfp, pcapfiles[found].ts,_ip, iplen);
		if (ret != 0) {
			prev = pcapfiles[found].ts;
			if (opt_v>0) printf("writing: %d bytes. ts=%lld delta=%lld path=%s\n", iplen, pcapfiles[found].ts, pcapfiles[found].ts-prev, pcapfiles[found].path);
			if (--cut_num_packets == 0) return 0;
		}
		prev = pcapfiles[found].ts;
		error = pcap_read(&pcapfiles[found]);
		if (error != 0 && error != ParsePcap_EOF) {
			error_close_files++;
		}
	};
	if (error_close_files != 0) {
		return ParsePcap_ERROR_ShortRead;
	} else {
		return 0;
	}
}

char *pcap_cleanup_error(int errorcode)
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
	case ParsePcap_ERROR_Memory:
		return "Malloc";
	default:
		return "Unknown";
	}
}

void load_ipaddrlist(char *filename, struct ipaddr_hash **hash)
{
	char buff[512];
	int l;
	FILE *fp;

	if ((fp = fopen(filename, "r")) == NULL)
		err(1, "cannot open %s", filename);
	while(fgets(buff, sizeof buff, fp) != NULL) {
		if (buff[0] == '#') continue;
		l = strlen(buff);
		if (l > 0 && !isprint(buff[l-1])) buff[l-1] = 0;
		register_ipaddr_port_hash(buff, hash);
	}
	fclose(fp);
}

void load_ipaddrlist_tld(char *tld, struct ipaddr_hash **hash)
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
				register_ipaddr_port_hash(p, hash);
				p = q;
			} while (p != NULL);
		}
	}
	fclose(fp);
}

void usage(int c)
{
	printf("PcapSelectL3 [-T timezone offset] options OutputFile InputFiles....\n"
"time options: if specified, only matched packet will be written.\n"
"  -B begin\n"
"  -E end\n"
"  -e exact_match_time (multiple, max 10)\n"
"  -a ipaddr[#port],...   set ipaddress match list client side\n"
"  -I file      Load IPaddrlist into list1\n"
"  -b ipaddr#port[,ipaddr#port,..]  set ipaddress match list server side\n"
"  -f list	specify TLD/root server IP address list file\n"
"  -t TLD Match specify ipaddress match list server side to TLD servers\n"
"	    requires -f option\n"
"  -T       TCP only\n"
"  -U       UDP only\n"
"  -Q       Query (source== -a list, dest== -b list)\n"
"  -R       Response (query== -b list, dest== -a list)\n"
"  -S       Single file\n"
"  -n NN    Cut NN packets\n"
"fragment\n"
"  -f\n");

	exit(0);
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

void parse_args(int argc, char **argv, char *env)
{
	int ch;

	while ((ch = getopt_env(argc, argv, "vB:E:O:E:46a:b:f:t:FI:SsHL:TUn:QRe:", env)) != -1) {
	switch (ch) {
	case 'Q': accept_query = 1; break;
	case 'R': accept_reply = 1; break;
	case 'F': accept_frag = 1; break;
	case '4': accept_v4 = 1; break;
	case '6': accept_v6 = 1; break;
	case 'B': begin = (long long)(atof(optarg) * 1000000.0); break;
	case 'E': end = (long long)(atof(optarg) * 1000000.0); break;
	case 'O': time_offset = atoi(optarg); break;
	case 'e':
		exact[nexact++] = atof(optarg);
		/*printf("-E %s is parsed as tv_sec=%d tv_usec=%d\n", optarg, exact_time_sec, exact_time_usec);*/
		break;
	case 'a':
		register_ipaddr_port_hash(optarg, &ipaddr1_hash);
		break;
	case 'b':
		register_ipaddr_port_hash(optarg, &ipaddr2_hash);
		break;
	case 'v': opt_v++; break;
	case 'I': load_ipaddrlist(optarg, &ipaddr1_hash); break;
	case 'f': serverlist_file = optarg; break;
	case 't': if (serverlist_file != NULL) {
		  	load_ipaddrlist_tld(optarg, &ipaddr1_hash);
			break;
		  }
		  err(1, "specify TLD server list\n");
	case 'S': single_file = 1; break;
	case 's': ignore_shortread = 1; break;
	case 'L': Logfile = optarg; break;
	case 'H': print_hash = 1; break;
	case 'T': accept_tcp = 1; break;
	case 'U': accept_udp = 1; break;
	case 'n': cut_num_packets = atoi(optarg); break;
	case '?':
	default:
		usage(ch);
	}}
}

int main(int argc, char *argv[])
{
	int len;
	int ret;
	FILE *wfp;
	char *env;
	char *argvv[10];
	struct pcap_file_header pfw;
	char *p;
	char buff2[1000];

	env = getenv(ENVNAME);
	parse_args(argc, argv, env);
	argc -= optind;
	argv += optind;
	if (print_hash) {
		printf("begin=%lld end=%lld\n", begin, end);
		printf("ipaddr1_hash=\n");
		print_ipaddrlist_hash(ipaddr1_hash);
		printf("ipaddr2_hash=\n");
		print_ipaddrlist_hash(ipaddr2_hash);
		exit(1);
	}
	if (accept_v4 == 0 && accept_v6 == 0) {
	  accept_v4 = 1; accept_v6 = 1;
	}
	if (accept_tcp == 0 && accept_udp == 0) {
	  accept_tcp = 1; accept_udp = 1;
	}
	if (accept_query == 0 && accept_reply == 0) {
		accept_query = 1;
		accept_reply = 1;
	}
	if (argc < 1) { usage(-1); }
	if ((wfp = fopen(*argv, "wx")) == NULL) {
		printf("#Wrror:Cannot write %s", *argv); exit(1);
	}
	pfw.magic = 0xa1b2c3d4;
	pfw.version_major = 2;
	pfw.version_minor = 4;
	pfw.thiszone = 0;
	pfw.sigfigs = 0;
	pfw.snaplen = 1500;
	pfw.linktype = DLT_IP;
	fwrite(&pfw, sizeof(pfw), 1, wfp);
	argv++;
	argc--;
	if (Logfile != NULL) {
		if ((LogFP = fopen(Logfile, "w")) == NULL) {
			printf("#Error:CannotOpenLogfile:%s\n", Logfile);
			exit(1);
		}
	}
	if (argc == 0 && isatty(fileno(stdin))) { usage(0); }
	if (argc > 0) {
		ret = pcap_cleanup(wfp, argc, argv);
		if (ignore_shortread != 0 && ret == ParsePcap_ERROR_ShortRead) {
			exit(0);
		}
		if (ret != ParsePcap_NoError) {
			printf("#Error:%s:errno=%d\n", pcap_cleanup_error(ret), errno);
			exit(1);
		}
	} else {
		while (fgets(buff2, sizeof buff2, stdin) != NULL) {
			len = strlen(buff2);
			if (len > 0 && buff2[len-1] == '\n') {
				buff2[len-1] = 0;
			}
			p = strchr(buff2, ',');
			if (p != NULL && *p == ',') *p = 0;
			argvv[0] = buff2;
			argvv[1] = NULL;
			ret = pcap_cleanup(wfp, 1, argvv);
			if (ignore_shortread != 0 && ret == ParsePcap_ERROR_ShortRead) {
				exit(0);
			}
			if (ret != ParsePcap_NoError) {
				printf("#Error:%s:errno=%d\n", pcap_cleanup_error(ret), errno);
				exit(1);
			}
		}
	}
	exit(0);
}
