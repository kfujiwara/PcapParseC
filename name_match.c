#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ext/uthash.h"
#include "pcapparse.h"
#include "name_match.h"

struct name_hash *
match_name(struct name_list *list, struct DNSdataControl *c)
{
	struct name_hash *e = NULL;
	uint16_t bit;
	int i;

	for (i = 0, bit = 1; i < c->dns.nsubstring && bit != 0; i++) {
		if (list->nlabels & bit) {
			HASH_FIND_STR((list->hash), c->dns.substring[i], e);
			if (e != NULL) return e;
		}
		bit <<= 1;
	}
	return NULL;
}

void register_name_list(char *str, struct name_list *list, int opt_v)
{
	int comma, mask, len;
	struct name_hash *e, *hash;
	char *p, *q, *next, *r, *endp, *new;
	char buff[256];

	p = str;
	len = strlen(str);
	//printf("Input=%s\n", p);
	while (p != NULL && *p != 0) {
		while (*p == ' ') p++;
		q = p;
		while(isalnum(*q) || *q == '.' || *q == '-') q++;
		len = q - p;
		if (len > 0 && len < 256) {
			for (comma = 0, mask = 1, r = p; r < q; r++) {
				if (*r == '.') { comma++; mask <<= 1; }
			}
			HASH_FIND_STR((list->hash), str, e);
			if (e == NULL) {
				e = malloc(sizeof(struct name_hash) + len);
				memcpy(e->name, p, len);
				e->name[len] = 0;
				e->count = 0;
				HASH_ADD_STR((list->hash), name, e);
				if (opt_v) printf("Match_qname:%s\n", e->name);
				list->nlabels |= mask;
			}
		}
		next = strchr(p, ',');
		if (next!=NULL && *next==',') {next++;} else {next=NULL;}
		p = next;
	}
}

void print_name_list(struct name_list *list)
{
	struct name_hash *e, *tmp;

	printf("nlabels=%04x\n", list->nlabels);
	HASH_ITER(hh, (list->hash), e, tmp) {
		printf(" %s\n", e->name);
	}
}

void load_name_list(char *filename, struct name_list *list)
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
		register_name_list(buff, list, 0);
	}
	fclose(fp);
}

