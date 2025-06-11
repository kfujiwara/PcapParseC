#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ext/uthash.h"
#include "addrport_match.h"

// ipaddr#portno ... exact mach
// ipaddr/len ... prefix match .. len.. 8bit
// keylen   bit    ADDR/PORT
// 1        8000   /8 IPv4
// 2        4000   /16 IPv4
// 3        2000   /24 IPv4
// 4        1000   /32 IPv4
// 5        0800   /32 IPv6  pad byte 00
// 6        0400   /48 IPv6
// 7        0200   IPv4/32+port pad 0
// 8        0100   /64 IPv6
// 18       0080   IPv6/128+port
// 10       0040   IPv6/80
// 11       0020   IPv6/88
// 12       0010   IPv6/96
// 13       0008   IPv6/104
// 14       0004   IPv6/112
// 15       0002   IPv6/120
// 16       0001   IPv6/128
static uint16_t mask_bits[] = {
    0, 0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400, 0x0200, 
 // 0    1       2       3       4       5       6       7
    0x100, 0, 0x40, 0x20, 0x10, 8, 4, 2, 1, 0, 0x80 };
//  8      9    10    11    12 13 14 15 16 17  18

struct ipaddr_hash *
match_ipaddr_port(struct ipaddr_port_list *list, u_char *addr, int alen)
{
	struct ipaddr_hash *e = NULL;
	uint16_t bit;
	int i;
	u_char a[18];

	if (alen == 16) {
		memcpy(a, addr+2, 16);
		if (list->mask & 0x80) HASH_FIND(hh, (list->hash), addr, alen+2, e);
		if (e != NULL) return e;
		for (i = 16, bit = 1; i > 4; i--) {
			if (i == 7) continue;
			if (list->mask & bit) {
				HASH_FIND(hh, (list->hash), a, i, e); if (e != NULL) return e; }
			bit = bit << 1;
		}
		a[4] = 0;
		if (list->mask & 0x0800) HASH_FIND(hh, (list->hash), a, 5, e);
		return e;
	}
	addr[6] = 0;
	if (list->mask & 0x0200) {
		HASH_FIND(hh, (list->hash), addr, 7, e); if (e != NULL) return e; }
	for (i = 4, bit = 0x1000; i > 0; i--) {
		if (list->mask & bit) {
			HASH_FIND(hh, (list->hash), (addr+2), i, e); if (e != NULL) return e; }
		bit = bit << 1;
	}
	return NULL;
}

void register_ipaddr_port_hash(char *str, struct ipaddr_port_list *list, int opt_v)
{
	int plen, klen, i, offset, port, alen;
	u_char portaddr[18];
	struct ipaddr_hash *e, *hash;
	char *p, *next, *r, *endp;
	char buff[512];

	p = str;
	//printf("Input=%s\n", p);
	while (p != NULL && *p != 0) {
		next = strchr(p, ',');
		endp = next;
		if (next!=NULL && *next==',') {next++;} else {next=NULL;}
		plen = 0; offset = 0; port = -1;
		r = strchr(p, '#');
		if (r == NULL || *r != '#') {
			r = strchr(p, '/');
			if (r != NULL && *r == '/') {plen=atoi(r+1);endp=r;}
		} else {
			endp=r;
			port = atoi(r+1); offset = 2;
			portaddr[0] = ((port & 0xff00) >> 8);
			portaddr[1] = port & 0xff;
		}
		if (endp != NULL) {
			memcpy(buff, p, endp-p);
			buff[endp-p] = 0;
		} else {
			strcpy(buff, p);
		}
		if (strchr(buff, ':') != NULL) {
			if (inet_pton(AF_INET6,buff,portaddr+offset)==0)
				err(1, "cannot parse6 %s", buff);
			alen = 16;
		} else {
			if (inet_pton(AF_INET,buff,portaddr+offset)==0)
				err(1, "cannot parse4 %s", buff);
			alen = 4;
		}
		klen = alen;
		if (plen > 0) {
			i = plen / 8;
			if (i == 0 || (alen==4 && i > 3) ||
			 (alen==16 && (i < 4 || i==5 || i==7 || i==9)))
				err(1, "invalid prefix %s / %d", p, plen);
			if (i == 4) { i = 5; portaddr[4] = 0; }
			klen = i;
		} else {
			klen = alen + offset;
			if (klen == 6) { portaddr[6] = 0; klen++; }
		}
		HASH_FIND(hh, (list->hash), portaddr, klen, e);
		if (e == NULL) {
			e = malloc(sizeof(struct ipaddr_hash));
			e->klen = klen;
			memcpy(e->addr, portaddr, klen);
			e->count = 0;
			HASH_ADD(hh, (list->hash), addr, e->klen, e);
			if (opt_v) printf("Match_IP_address:%s port=%d klen=%d\n", p, port, klen);
			if (klen < 19) list->mask |= mask_bits[klen];
		}
		p = next;
	}
}

void print_ipaddrlist_hash(struct ipaddr_port_list *list)
{
	struct ipaddr_hash *e, *tmp;
	int i, klen;
	u_char *a;
	u_char addr[16];
	char s[256];

	printf("prefix_mask=%04x\n", list->mask);
	HASH_ITER(hh, (list->hash), e, tmp) {
		a = e->addr;
		klen = e->klen;
		switch(klen) {
		case 1:  printf("%d.0.0.0/8", a[0]); break;
		case 2:  printf("%d.%d.0.0/16", a[0], a[1]); break;
		case 3:  printf("%d.%d.%d.0/24", a[0], a[1], a[2]); break;
		case 4:  printf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]); break;
		case 7:  printf("%d.%d.%d.%d#%d", a[2], a[3], a[4], a[5], a[0]*256+a[1]); break;
		case 16: printf("%s", inet_ntop(AF_INET6, a, s, sizeof s)); break;
		case 18: printf("%s#%d", inet_ntop(AF_INET6, a+2, s, sizeof s), a[0]*256+a[1]); break;
		case 5: klen--;
		default: memset(addr, 0, 16); memcpy(addr, a, klen);
		  printf("%s/%d", inet_ntop(AF_INET6, addr, s, sizeof s), klen*8); break;
		}
		printf("   ");
		for (i = 0; i < klen; i++) {
			printf(" %02x", a[i]);
		}
		printf("\n");
	}
}

void load_ipaddrlist(char *filename, struct ipaddr_port_list *list)
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
		register_ipaddr_port_hash(buff, list, 0);
	}
	fclose(fp);
}

