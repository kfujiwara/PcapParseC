#include "maxminddb.h"

void geoip_close();
int geoip_open();
int geoip_lookup(char *ipstr, char *country, char *city, char *continent, int *asn, char *asname);

#define GEOIPLOOKUP_NAMELEN 100
