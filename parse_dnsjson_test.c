/*
	$Id: parse_dnsjson_test.c,v 1.5 2025/04/17 06:55:26 fujiwara Exp $

DEBUG:

zstd -cd  /logs/A.DNS.JP/202410/dns-a21.tyo/logs/dnstap/jp/dnstap.log.202410080047.zst | awk -F, '{print $3, $13}' | sed -e 's/"query-ip":"//' | sed -e 's/" "qname":"/ /' | sed 's/"//' > 2
./pcapgetquery -C  /logs/A.DNS.JP/202410/dns-a21.tyo/logs/dnstap/jp/dnstap.log.202410080047.zst | awk -F, '{print $2,$8}' > 1
zstd -cd  /logs/A.DNS.JP/202410/dns-a21.tyo/logs/dnstap/jp/dnstap.log.202410080047.zst| wc -l
wc -l 1 2

*/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <err.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ext/uthash.h"
#include "pcapparse.h"
#include "parse_int.h"

int callback(struct DNSdataControl *d, int mode)
{
	struct DNSdata *dns = &d->dns;

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	int lineno = 0;
	FILE *fp;
	struct DNSdataControl c;
	char buff[65536];
	u_char ip_src[16], ip_dst[16];

	memset(&c, 0, sizeof(c));
	c.raw = (u_char *)&buff;
	c.callback = callback;
	c.debug = FLAG_DEBUG_JSON;

	if (argc > 1) {
		fp = fopen(argv[1], "r");
		if (fp == NULL) { err(1, "cannot open %s", argv[1]); }
	} else {
		fp = stdin;
	}
	while(fgets(buff, sizeof buff, fp) != NULL) {
		lineno++;
		memset(&c.dns, 0, sizeof(c.dns));
		c.dns.p_src = ip_src;
		c.dns.p_dst = ip_dst;
		if ((ret = parse_dnsjson(&c)) != 0) {
			printf("parse_dnsjson returned %d, lineno %d\n", ret, lineno);
			break;
		}
	}
	if (fp != stdin) fclose(fp);
	return 0;
}

