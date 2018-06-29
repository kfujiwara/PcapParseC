int countbits(unsigned long long n);
int bitmaptoindex(unsigned long long n);

#define set_bitmap(base, pos, value) \
	if ((value)) { \
		(base)[(pos)/8] |= (128 >> ((pos) % 8)); \
	} else { \
		(base)[(pos)/8] ^= ~(128 >> ((pos) % 8)); \
	}

#define set_bitmap1(base, pos) do { (base)[(pos)/8] |= (128 >> ((pos) % 8)); } while(0);

#define get_bitmap(base, pos) \
	(((base)[(pos)/8] & (128 >> ((pos) % 8))) ? 1 : 0)

void merge_bitmap(unsigned char *dest, unsigned char *src, int length);
int strtobitmap(char *string, char **next, unsigned char *bitmap, int limit);

