#include <ctype.h>
#include <string.h>

int countbits(register unsigned long long n) {
	n = (n & 0x5555555555555555LL) + ((n >>  1) & 0x5555555555555555LL);
	n = (n & 0x3333333333333333LL) + ((n >>  2) & 0x3333333333333333LL);
	n = (n & 0x0f0f0f0f0f0f0f0fLL) + ((n >>  4) & 0x0f0f0f0f0f0f0f0fLL);
	n = (n & 0x00ff00ff00ff00ffLL) + ((n >>  8) & 0x00ff00ff00ff00ffLL);
	n = (n & 0x0000ffff0000ffffLL) + ((n >> 16) & 0x0000ffff0000ffffLL);
	n = (n & 0x00000000ffffffffLL) + ((n >> 32) & 0x00000000ffffffffLL);
	return n;
}

int bitmaptoindex(unsigned long long n)
{
	return countbits(n - 1);
}

int countbit256(unsigned char *p)
{
	return countbits(*(unsigned long long *)p)
	       + countbits(*(unsigned long long *)(p+8))
	       + countbits(*(unsigned long long *)(p+16))
	       + countbits(*(unsigned long long *)(p+24));
}

int countbit64k(unsigned char *p)
{
	unsigned long long *u = (unsigned long long *)p;
	int i;
	int sum = 0;
	for (i = 0; i < 1024; i++) {
		sum += countbits(*u++);
	}
	return sum;
}

#ifdef DEBUG_countbits
#include <stdio.h>

void main()
{
	char buff[512];
	unsigned long long l;

	while(fgets(buff, sizeof buff, stdin) != NULL) {
		if (sscanf(buff, "%llx", &l) == 1) {
			printf("%llx %d\n", l, bitmaptoindex(l));
		}
	}
}
#endif

void set_bitmap_func(unsigned char *base, int pos, int value)
{
	if (value) {
		base[pos/8] |= (128 >> (pos % 8));
	} else {
		base[pos/8] ^= ~(128 >> (pos % 8));
	}
}

int get_bitmap_func(unsigned char *base, int pos)
{
	return (base[pos/8] & (128 >> (pos % 8))) ? 1 : 0;
}

void merge_bitmap(unsigned char *dest, unsigned char *src, int length)
{
	int i, l;
	l = (length+7)/8;
	for (i = 0; i < l; i++) {
		dest[i] |= src[i];
	}
}

static int hextoint(char c)
{
	if (!isxdigit(c))
		return -1;
	if (isdigit(c))
		return c - '0';
	return (c & 0x0f) + 9;
}

int strtobitmap(char *string, char **next, unsigned char *bitmap, int limit)
{
	int h, l, count = 0;

	memset(bitmap, 0, limit);
	while (isxdigit(string[0]) && isxdigit(string[1]) && limit > 0) {
		h = hextoint(string[0]);
		l = hextoint(string[1]);
		if (h < 0 || l < 0)
			return -1;
		*bitmap++ = (h << 4) | l;
		limit--;
		string += 2;
		count++;
	}
	*next = string;
	return count;
}
