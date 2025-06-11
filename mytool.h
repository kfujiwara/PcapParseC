void *my_malloc(int _size);
char *my_strdup(char *s);
char *my_strdup2(char *s, int len);

long long getint(char *src, char **next, int *error, int errorcode);
unsigned long long getuint(char *src, char **next, int *error, int errorcode);
long long gethexint(char *src, char **next, int *error, int errorcode);
double getfloat(char *src, char **next, int *error, int errorcode);
void getstring(char *src, char **next, int *error, int errorcode, char *str, int len);
void skipcomma(char *src, char **next, int num, int *error, int errorcode);
void hexdump(char *msg, u_char *data, int len);
int strdate2unixtime(int num);
long long now();
