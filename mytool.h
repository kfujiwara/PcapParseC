void *my_malloc(size_t _size);
char *my_strdup(char *s);
char *my_strdup2(char *s, int len);

#ifndef HAVE_ERR
void err(int err, char *format, ...);
#endif

long long getint(char *src, char **next, int *error, int errorcode);
unsigned long long getuint(char *src, char **next, int *error, int errorcode);
long long gethexint(char *src, char **next, int *error, int errorcode);
double getfloat(char *src, char **next, int *error, int errorcode);
void skipcomma(char *src, char **next, int num, int *error, int errorcode);
int countbit256(u_char *p);
int countbit64k(u_char *p);

