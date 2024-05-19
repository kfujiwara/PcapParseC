#include "maxminddb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "geoiplookup.h"
#define LenLimit GEOIPLOOKUP_NAMELEN

static MMDB_s mmdb_c;
static MMDB_s mmdb_a;

void geoip_close()
{
	MMDB_close(&mmdb_c);
	MMDB_close(&mmdb_a);
}

int geoip_open()
{
	char *e = getenv("MMDBFILE");
	char *p, *q;
	int s;

	if (e == NULL) return -1;
	p = strchr(e, ':');
	if (p == NULL) return -2;
	q = p + 1;
	*p = 0;
	s = MMDB_open(e, MMDB_MODE_MMAP, &mmdb_c);
	if (MMDB_SUCCESS != s) {
	  fprintf(stderr, "Can't open %s - %s\n", e, MMDB_strerror(s));
	  return -3;
	}
	s = MMDB_open(q, MMDB_MODE_MMAP, &mmdb_a);
	if (MMDB_SUCCESS != s) {
	  fprintf(stderr, "Can't open %s - %s\n", q, MMDB_strerror(s));
	  return -4;
	}
	return 0;
}

const char * const lookup_path_country[] = { "country", "iso_code", NULL };
const char * const lookup_path_city[] = { "city", "names", "en", NULL };
const char * const lookup_path_continent[] = { "continent", "code", NULL };
const char * const lookup_path_asn[] = { "autonomous_system_number", NULL };
const char * const lookup_path_asname[] = { "autonomous_system_organization", NULL };

int geoip_lookup(char *ipstr, char *country, char *city, char *continent, int *asn, char *asname)
{
    int len;
    int i;
    char *p;
    int gai_error1, mmdb_error1;
    int gai_error2, mmdb_error2;
    //MMDB_entry_data_list_s *entry_data_list = NULL;
    int status;
    MMDB_entry_data_s entry_data;

    MMDB_lookup_result_s c1 =
      MMDB_lookup_string(&mmdb_c, ipstr, &gai_error1, &mmdb_error1);
    MMDB_lookup_result_s a1 =
      MMDB_lookup_string(&mmdb_a, ipstr, &gai_error2, &mmdb_error2);

    *country=0;
    *continent=0;
    *city=0;
    *asn=0;
    *asname=0;
    if (0 != gai_error1) {
        fprintf(stderr,
                "\n  Error from call to getaddrinfo for %s - %s\n\n",
                ipstr, gai_strerror(gai_error1));
        exit(3);
    }
    if (MMDB_SUCCESS != mmdb_error1) {
        fprintf(stderr, "\n  Got an error from the maxminddb library: %s\n\n",
                MMDB_strerror(mmdb_error1));
        exit(4);
    }
    if (0 != gai_error2) {
        fprintf(stderr,
                "\n  Error from call to getaddrinfo for %s - %s\n\n",
                ipstr, gai_strerror(gai_error2));
        exit(3);
    }
    if (MMDB_SUCCESS != mmdb_error2) {
        fprintf(stderr, "\n  Got an error from the maxminddb library: %s\n\n",
                MMDB_strerror(mmdb_error2));
        exit(4);
    }

    if (c1.found_entry) {
        status = MMDB_aget_value(&c1.entry, &entry_data, lookup_path_country);
        if (MMDB_SUCCESS == status && entry_data.has_data != 0 && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING && entry_data.data_size > 0 && entry_data.data_size < 10) {
		len = entry_data.data_size;
		if (len >= LenLimit) len = LenLimit-1;
		memcpy(country, entry_data.utf8_string, len);
		country[len] = 0;
	}
        status = MMDB_aget_value(&c1.entry, &entry_data, lookup_path_city);
        if (MMDB_SUCCESS == status && entry_data.has_data != 0 && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING && entry_data.data_size > 0 && entry_data.data_size < 10) {
		len = entry_data.data_size;
		if (len >= LenLimit) len = LenLimit-1;
		memcpy(city, entry_data.utf8_string, len);
		city[len] = 0;
	}
        status = MMDB_aget_value(&c1.entry, &entry_data, lookup_path_continent);
        if (MMDB_SUCCESS == status && entry_data.has_data != 0 && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING && entry_data.data_size > 0 && entry_data.data_size < 10) {
		len = entry_data.data_size;
		if (len >= LenLimit) len = LenLimit-1;
		memcpy(continent, entry_data.utf8_string, len);
		continent[len] = 0;
	}
    }
    if (a1.found_entry) {
        status = MMDB_aget_value(&a1.entry, &entry_data, lookup_path_asn);
        if (MMDB_SUCCESS == status && entry_data.has_data != 0 && entry_data.type == MMDB_DATA_TYPE_UINT32) {
		*asn = entry_data.uint32;
	}
        status = MMDB_aget_value(&a1.entry, &entry_data, lookup_path_asname);
        if (MMDB_SUCCESS == status && entry_data.has_data != 0 && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
		len = entry_data.data_size;
		if (len >= LenLimit) len = LenLimit-1;
		p = (char *)entry_data.utf8_string;
		for (i = 0; i < len; i++) {
			asname[i] = (p[i] == ' ' || p[i] == ',') ? '_' : p[i];
		}
		asname[len] = 0;
	}
    }
	return 0;
}
