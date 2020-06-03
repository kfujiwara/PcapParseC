/*
		nexact++;
	$Id: PcapSelectL3.c,v 1.20 2020/05/21 12:52:31 fujiwara Exp $

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
#ifdef HAVE_ERR_H
#include <err.h>
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
#ifdef HAVE_APR_HASH_H
#include <apr_hash.h>
#endif

#include "PcapParse.h"

int begin = -1;
int end = -1;
int time_offset = 0;
int accept_v4 = 0;
int accept_v6 = 0;
int accept_frag = 0;
double exact[100];
int nexact = 0;
int opt_v = 0;
u_char src4[4] = { 255 };
u_char src6[16] = { 255 };
u_char dest4[4] = { 255 };
u_char dest6[16] = { 255 };
char *serverlist_file = NULL;

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

#ifdef HAVE_APR_HASH_H
struct ipaddr_list {
	int count;
	u_int alen;
	u_char addr[16];
};

static apr_pool_t *apr_pool = NULL;
static apr_hash_t *ipaddr_hash = NULL;
#endif

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

struct PcapFiles {
	char *path;
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

int pcap_open(struct PcapFiles *pcap, char *file)
{
	int error = 0;
	char buff[1024];
	int len;

	pcap->path = file;
	len = strlen(file);
	pcap->is_popen = 1;
	if (len > 3 && strcmp(file+len-4, ".xz") == 0) {
		snprintf(buff, sizeof buff, "xz -cd %s", file);
	} else
	if (len > 4 && strcmp(file+len-4, ".bz2") == 0) {
		snprintf(buff, sizeof buff, "bzip2 -cd %s", file);
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

int pcap_cleanup(FILE *wfp, int argc, char **argv)
{
	int i;
	int len;
	int error;
	long long offset = 0;
	long long offset2;
	int found;
	long long tt;
	int match_time = 0;
	int match_addr = 0;
	int match_frag = 0;
	int ignore;
	int ipv;
	int addrlen;
	long long prev = 0;
	double d;
#ifdef HAVE_APR_HASH_H
	struct ipaddr_list *e, *f;
#endif
	u_char *_ip;
	int iplen;
 	struct PcapFiles *pcapfiles;
	int npcap = 0;
	int exist;
	struct pcap_header ph;
	int error_close_files = 0;
	char buff[1024];

	pcapfiles = calloc(sizeof(struct PcapFiles), argc);
	if (pcapfiles == NULL) return ParsePcap_ERROR_Memory;
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
		match_addr = 0;
		match_frag = 0;
		d = (double)pcapfiles[found].ts;
		ignore = 0;
		_ip = pcapfiles[found]._ip;
		iplen = pcapfiles[found].iplen;
		if (begin >= 0 || end >= 0) {
			if (begin >= 0 && pcapfiles[found].ph.ts.tv_sec < begin) ignore=1;
			if (end >= 0 && pcapfiles[found].ph.ts.tv_sec >= end) ignore=1;
			match_time = !ignore;
		} else
		  if (nexact > 0) {
			for (i = 0; i < nexact; i++) {
				if (exact[i] == d) {
					match_time = 1;
					break;
				}
			}
		} else {
			match_time = 1;
		}
		ipv = _ip[0] >> 4;
		if (accept_frag) {
			// Test Fragment
			if (ipv == 4 && (((_ip[6]<<8)|_ip[7]) & 0x3fff) != 0) {
				match_frag = 1;
			} else
			if (ipv == 6 && _ip[6] == 44) {
				match_frag = 1;
			}
		} else {
			match_frag = 1;
		}
#ifdef HAVE_APR_HASH_H
		if (ipaddr_hash != NULL) {
			if (ipv == 4) {
				e = (struct ipaddr_list *)apr_hash_get(ipaddr_hash, _ip + 12, 4);
				f = (struct ipaddr_list *)apr_hash_get(ipaddr_hash, _ip + 16, 4);
			} else {
				e = (struct ipaddr_list *)apr_hash_get(ipaddr_hash, _ip + 12, 4);
				f = (struct ipaddr_list *)apr_hash_get(ipaddr_hash, _ip + 16, 4);
			}
			if (e != NULL || f != NULL) match_addr = 1;
		} else {
#endif
			if ((*src4 & *src6 & *dest4 & *dest6) == 255) {
			   	match_addr = 1;
			} else 	if (ipv == 4) {
				if ((*src4 & *dest4) == 255)
					ignore++;
				if (src4[0]!=255 && memcmp(src4,_ip+12,4) != 0)
					ignore++;
				if (dest4[0]!=255 && memcmp(dest4,_ip+16,4)!=0)
				   	ignore++;
			} else if (ipv == 6) {
				if ((*src6 & *dest6) == 255)
					ignore++;
				if (src6[0] != 255 && memcmp(src6, _ip+8, 16) != 0)
					ignore++;
				if (dest6[0] != 255 && memcmp(dest6, _ip+24, 16) != 0)
					ignore++;
			}
			match_addr = (ignore == 0) ? 1 : 0;
#ifdef HAVE_APR_HASH_H
		}
#endif
		ignore = (ignore || !match_time || !match_frag || !match_addr);
		if (opt_v>1) {
			printf("ts=%lld index=%d path=%s ignore=%d\n", tt, found, pcapfiles[found].path, ignore);
		}
		if (!ignore) {
			ph.ts.tv_sec = pcapfiles[found].ph.ts.tv_sec + time_offset;
			ph.ts.tv_usec = pcapfiles[found].ph.ts.tv_usec;
			ph.caplen = iplen;
			ph.len = iplen;
			//hexdump("ph", &ph, sizeof(ph));
			fwrite(&ph, sizeof(ph), 1, wfp);
			//hexdump("_ip", _ip, iplen);
			fwrite(_ip, iplen, 1, wfp);
			if (prev == 0) prev = pcapfiles[found].ts;
			if (opt_v>0) printf("writing: %d bytes. ts=%lld delta=%lld path=%s\n", iplen, pcapfiles[found].ts, pcapfiles[found].ts-prev, pcapfiles[found].path);
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

void load_ipaddrlist_tld(char *tld)
{
#ifdef HAVE_APR_HASH_H
	char buff[512];
	u_char addr[16];
	int alen;
	int l;
	FILE *fp;
	char *p, *q;
	struct ipaddr_list *e;

	ipaddr_hash = apr_hash_make(apr_pool);

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
				if (strchr(p, ':') != NULL) {
					if (inet_pton(AF_INET6, p, addr) == 0)
						err(1, "cannot parse %s", p);
					alen = 16;
				} else {
					if (inet_pton(AF_INET, p, addr) == 0)
						err(1, "cannot parse %s", p);
					alen = 4;
				}
				e = malloc(sizeof(struct ipaddr_list));
				e->alen = alen;
				memcpy(e->addr, addr, alen);
				e->count = 0;
				apr_hash_set(ipaddr_hash, e->addr, e->alen, e);
				//printf("Match_IP_address:%s:%s\n", tld, p);
				p = q;
			} while (p != NULL);
		}
	}
	fclose(fp);
#endif
}

void usage(int c)
{
	printf("PcapSelectL3 [-T timezone offset] options OutputFile InputFiles....\n"
"time options: if specified, only matched packet will be written.\n"
"  -b begin\n"
"  -e end\n"
"  -E exact_match_time (multiple, max 10)\n"
"address options: if specified, only matched packet will be written.\n"
"                 source & dest\n"
"  -s IPv4_source\n"
"  -d IPv4_destination\n"
"  -S IPv6_source\n"
"  -D IPv6_destination\n"
"fragment\n"
"  -f\n");

	exit(0);
}

int getopt_env_(char *str, char **envp)
{
	int ch = -1;
	int envfinish = 0;
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
	u_int32_t mask4, addr4;
	int print_answer_option = 0;

	while ((ch = getopt_env(argc, argv, "vb:e:T:E:46fs:S:d:D:f:t:F", env)) != -1) {
	switch (ch) {
	case 'F':
		accept_frag = 1;
		break;
	case '4':
		accept_v4 = 1;
		break;
	case '6':
		accept_v6 = 1;
		break;
	case 'e':
		end = atoi(optarg);
		break;
	case 'b':
		begin = atoi(optarg);
		break;
	case 'T':
		time_offset = atoi(optarg);
		break;
	case 'E':
		exact[nexact++] = atof(optarg);
		/*printf("-E %s is parsed as tv_sec=%d tv_usec=%d\n", optarg, exact_time_sec, exact_time_usec);*/
		break;
	case 's':
		if (inet_aton(optarg, (struct in_addr *)&src4) == 0)
			err(1, "bad IPv4 address: %s", optarg);
		break;
	case 'S':
		if (inet_pton(AF_INET6, optarg, src6) != 1)
			err(1, "bad IPv6 address: %s", optarg);
		break;
	case 'd':
		if (inet_aton(optarg, (struct in_addr *)&dest4) == 0)
			err(1, "bad IPv4 address: %s", optarg);
		break;
	case 'D':
		if (inet_pton(AF_INET6, optarg, dest6) != 1)
			err(1, "bad IPv6 address: %s", optarg);
		break;
	case 'v':
		opt_v++;
		break;
	case 'f': serverlist_file = optarg; break;
	case 't': if (serverlist_file != NULL) {
			load_ipaddrlist_tld(optarg);
			break;
		  }
		  err(1, "specify TLD server list\n");
	case '?':
	default:
		usage(ch);
	}}
}

int main(int argc, char *argv[])
{
	double d;
	int len;
	int ret;
	char *p, *q;
	FILE *wfp;
	char *env;
	struct pcap_file_header pfw;

#ifdef HAVE_APR_HASH_H
	apr_status_t apr_status;
	apr_initialize();
	apr_status = apr_pool_create(&apr_pool, NULL);
	if (apr_status != APR_SUCCESS) {
		printf("#Error:could not create apr_pool");
		exit(0);
	}
#endif
	env = getenv(ENVNAME);
	parse_args(argc, argv, env);
	argc -= optind;
	argv += optind;
	if (accept_v4 == 0 && accept_v6 == 0) {
	  accept_v4 = 1; accept_v6 = 1;
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
	if (argc > 0) {
		ret = pcap_cleanup(wfp, argc, argv);
		if (ret != ParsePcap_NoError) {
			printf("#Error:%s:%s:errno=%d\n", pcap_cleanup_error(ret), p, errno);
			exit(1);
		}
	} else {
		usage(0);
	}
	return 0;
}
