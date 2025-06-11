#include "config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "mytool.h"
#include "bit.h"

#define	_64bit_allign 1

u_char *a_base = NULL;
size_t  a_pos = 0;
size_t  a_limit = 512 * 1024;
size_t  a_count = 0;

void *my_malloc(int _size)
{
	u_char *p;
	int a;

	if (a_base == NULL || a_pos + _size + 7 > a_limit) {
		if (a_limit < _size) {
			p = malloc(_size);
			memset((void *)p, 0, _size);
			if (p == NULL) {
				printf("#Error:malloc:size=%d\n", _size);
				exit(1);
			}
			return p;
		}
		a_base = malloc(a_limit);
		a_pos = 0;
		if (a_base == NULL) {
			printf("#Error:malloc:count=%zu:%p %zu %zu: %d : errno=%d\n", a_count, a_base, a_pos, a_limit, _size, errno);

			exit(1);
		}
		a_count++;
		// printf("alloc:%d*%d:%lp %d %d: %d\n", a_count, a_limit, a_base, a_pos, a_limit, _size);
	}
#ifdef _64bit_allign
	a = (unsigned long)(a_base + a_pos) & 7;
	if (a != 0) { a_pos += (8 - a); }
#endif
	p = a_base + a_pos;
	a_pos += _size;
	memset((void *)p, 0, _size);
	return (void *)p;
}

char *my_strdup(char *s)
{
	unsigned int len = strlen(s) + 1;
	char *new = my_malloc(len);
	memcpy((void *)new, (void *)s, len);
	return new;
}

char *my_strdup2(char *s, int len)
{
	char *new = my_malloc(len+1);
	memcpy((void *)new, (void *)s, len);
	new[len] = 0;
	return new;
}

long long getint(char *src, char **next, int *error, int errorcode)
{
	long long i;
	if (*error) return 0;
	if (!isdigit(*src) && *src != '-') { *error = errorcode; return 0; }
	i = strtoll(src, next, 10);
	if (errno == ERANGE) { *error = errorcode; return 0; }
	if (**next == ',')
		(*next)++;
	else
	if (**next == '/') {
	} else
	if (**next != 0) { *error = errorcode; return 0; }
	return i;
}

unsigned long long getuint(char *src, char **next, int *error, int errorcode)
{
	unsigned long long i;
	if (*error) return 0;
	if (!isdigit(*src)) { *error = errorcode; return 0; }
	i = strtoull(src, next, 10);
	if (errno == ERANGE) { *error = errorcode; return 0; }
	if (**next == ',')
		(*next)++;
	else
	if (**next != 0) { *error = errorcode; return 0; }
	return i;
}

long long gethexint(char *src, char **next, int *error, int errorcode)
{
	long long i;
	if (*error) return 0;
	if (!isxdigit(*src)) { *error = errorcode; return 0; }
	i = strtoll(src, next, 16);
	if (errno == ERANGE) { *error = errorcode; return 0; }
	if (**next == ',')
		(*next)++;
	else
	if (**next != 0) { *error = errorcode; return 0; }
	return i;
}

double getfloat(char *src, char **next, int *error, int errorcode)
{
	double d;
	if (*error) return 0;
	if (!isdigit(*src) && *src != '-') { *error = 1; return 0; }
	d = strtod(src, next);
	if (errno == ERANGE) { *error = errorcode; return 0; }
	if (**next == ',')
		(*next)++;
	else
	if (**next != 0) { *error = errorcode; return 0; }
	return d;
}

void getstring(char *src, char **next, int *error, int errorcode, char *str, int len)
{
	char *p;
	int l, ll;
	if (*error) return;
	if (src != NULL && *src != 0) {
		p = strchr(src, ',');
		if (p == NULL) {
			ll = strlen(src);
			l = ll;
			if (l >= len) { l = len - 1; }
			memcpy(str, src, l);
			str[l] = 0;
			*next = src+ll;
			return;
		}
		if (*p == ',') {
			l = p - src;
			if (l >= len) { l = len - 1; }
			memcpy(str, src, l);
			str[l] = 0;
			*next = p + 1;
			return;
		}
	}
	*error = errorcode;
}

void skipcomma(char *src, char **next, int num, int *error, int errorcode)
{
	char *p = src;
	while(num > 0 && *p != 0) {
		if (*p == ',') {
			num--;
		}
		p++;
	}
	if (num > 0 || *p == 0)
		*error = errorcode;
	*next = p;
}

/*
 hexdump for debug
 */

void hexdump(char *msg, u_char *data, int len)
{
	int addr = 0;
	if (msg != NULL)
		printf("%s", msg);
	while(len-- > 0) {
		if ((addr % 16) == 0) {
			printf("%s%04x ", (addr!=0)?"\n":"", addr);
		}
		printf("%02x ", *data++);
		addr++;
	}
	printf("\n");
}

int strdate2unixtime(int num)
{
	struct tm tt;

	memset(&tt, 0, sizeof(tt));
	if (num < 19800000) { return 0; };
	tt.tm_year = (num / 10000) - 1900;
	tt.tm_mon = ((num / 100) % 100) - 1;
	tt.tm_mday = num % 100;
	return mktime(&tt);
}

long long now()
{
	struct timeval t;
	long long tt;

	int r = gettimeofday(&t, NULL);
	tt = t.tv_sec * 1000000LL + t.tv_usec;
	return tt;
}

