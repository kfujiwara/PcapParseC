#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include "geoiplookup.h"

int main(int argc, char *argv[])
{
	int i, error;
	char country[1024];
	char city[1024];
	char continent[1024];
	int asn;
	char asname[1024];
	char buff[1024], *p;
	error = geoip_open();
	if (error != 0) {
		err(1, "geoip_open returned %d", error);
	}
	if (argc < 2) {
		while(fgets(buff, sizeof buff, stdin) != NULL) {
			p = buff + strlen(buff) - 1;
			if (*p == '\n') *p = 0;
			error = geoip_lookup(buff, country, city, continent, &asn, asname);
			if (error == 0) {
				printf("ipaddr=%s country=%s city=%s continent=%s asn=%d asname=%s\n",
					buff, country, city, continent, asn, asname);
			} else {
				printf("ipaddr=%s error=%d\n", buff, error);
			}
		}
	} else {
	for (i = 1; i < argc; i++) {
		error = geoip_lookup(argv[i], country, city, continent, &asn, asname);
		if (error == 0) {
			printf("ipaddr=%s country=%s city=%s continent=%s asn=%d asname=%s\n",
				argv[i], country, city, continent, asn, asname);
		} else {
			printf("ipaddr=%s error=%d\n", argv[i], error);
		}
	}
	}
	geoip_close();
}

