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
match_name(struct name_list *list, struct DNSdataControl *c, int mode)
{
	struct name_hash *e = NULL;
	int i;

	if (mode == MATCH_NAME_EXACT) {
		HASH_FIND_STR((list->hash), c->dns.qname, e);
		return e;
	}
	for (i = 0; i < c->dns.nsubstring; i++) {
		HASH_FIND_STR((list->hash), c->dns.substring[i], e);
		if (e != NULL) return e;
	}
	return NULL;
}

void register_name_list(char *str, struct name_list *list, int opt_v)
{
	int len;
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
			HASH_FIND_STR((list->hash), str, e);
			if (e == NULL) {
				e = malloc(sizeof(struct name_hash) + len);
				memcpy(e->name, p, len);
				e->name[len] = 0;
				e->count = 0;
				HASH_ADD_STR((list->hash), name, e);
				if (opt_v) printf("Match_qname:%s\n", e->name);
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

