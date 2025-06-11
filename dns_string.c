#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "ext/uthash.h"

#include "dns_string.h"

struct dns_types {
	char *name;
	int code;
	UT_hash_handle hh;
};

static struct dns_types *dns_types_hash = NULL;

static struct dns_types dns_types_static[] = {
{ "A", _TYPE_A, },
{ "AAAA", _TYPE_AAAA, },
{ "PTR", _TYPE_PTR, },
{ "MX", _TYPE_MX, },
{ "TXT", _TYPE_TXT, },
{ "NS", _TYPE_NS, },
{ "DS", _TYPE_DS, },
{ "SRV", _TYPE_SRV, },
{ "CNAME", _TYPE_CNAME, },
{ "SOA", _TYPE_SOA, },
{ "DNSKEY", _TYPE_DNSKEY, },
{ "ANY", _TYPE_ANY, },
{ "AXFR", _TYPE_AXFR, },
{ "TLSA", _TYPE_TLSA, },
{ "HINFO", _TYPE_HINFO, },
{ "A6", _TYPE_A6, },
{ "SPF", _TYPE_SPF, },
{ "ATMA", _TYPE_ATMA, },
{ "NAPTR", _TYPE_NAPTR, },
{ "KX", _TYPE_KX, },
{ "CERT", _TYPE_CERT, },
{ "DNAME", _TYPE_DNAME, },
{ "SINK", _TYPE_SINK, },
{ "OPT", _TYPE_OPT, },
{ "APL", _TYPE_APL, },
{ "SSHFP", _TYPE_SSHFP, },
{ "IPSECKEY", _TYPE_IPSECKEY, },
{ "RRSIG", _TYPE_RRSIG, },
{ "NSEC", _TYPE_NSEC, },
{ "DHCID", 49, },
{ "NSEC3", 50, },
{ "NSEC3PARAM", 51, },
{ "SMIMEA", 53, },
{ "HIP", 55, },
{ "NINFO", 56, },
{ "RKEY", 57, },
{ "TALINK", 58, },
{ "CDS", 59, },
{ "CDNSKEY", 60 },
{ "OPENPGPKEY", 61 },
{ "CSYNC", 62 },
{ "ZONEMD", 63 },
{ "SVCB", 64 },
{ "HTTPS", 65 },
{ "SPF", 99, },
{ "UINFO", 100, },
{ "UID", 101, },
{ "GID", 102, },
{ "UNSPEC", 103, },
{ "NID", 104 },
{ "L32", 105 },
{ "L64", 106 },
{ "LP", 107 },
{ "EUI48", 108 },
{ "EUI64", 109 },
{ "TKEY", 249, },
{ "TSIG", 250, },
{ "IXFR", 251, },
{ "MAILB", 253, },
{ "MAILA", 254, },
{ "*", 255, },
{ "URI", 256, },
{ "CAA", 257, },
{ "AVC", 258, },
{ "DOA", 259, },
{ "AMTRELAY", 260, },
{ "TA", 32768, },
{ "DLV", 32769, },
{ "RESERVED0", 0, },
{ "MD", 3, },
{ "MF", 4, },
{ "MB", 7, },
{ "MG", 8, },
{ "MR", 9, },
{ "NULL", 10, },
{ "WKS", 11, },
{ "MINFO", 14, },
{ "RP", 17, },
{ "AFSDB", 18, },
{ "X25", 19, },
{ "ISDN", 20, },
{ "RT", 21, },
{ "NSAP", 22, },
{ "NSAP-PTR", 23, },
{ "SIG", 24, },
{ "KEY", 25, },
{ "PX", 26, },
{ "GPOS", 27, },
{ "LOC", 29, },
{ "NXT", 30, },
{ "EID", 31, },
{ "NIMLOC", 32, },
{ NULL, -1 },
};

static struct dns_types *dns_rcode_hash = NULL;

static struct dns_types dns_rcode_static[] = {
{ "NOERROR", 0, },
{ "FORMERR", 1, },
{ "SERVFAIL", 2, },
{ "NXDOMAIN", 3, },
{ "NOTIMP", 4, },
{ "REFUSED", 5, },
{ "YXDOMAIN", 6, },
{ "YXRRSET", 7, },
{ "NXRRSET", 8, },
{ "NOTAUTH", 9, },
{ "NOTZONE", 10, },
{ "BADVERS", 16, },
{ "BADSIG", 16, },
{ "BADKEY", 17, },
{ "BADTIME", 18, },
{ "BADMODE", 19, },
{ "BADNAME", 20, },
{ "BADALG", 21, },
{ "BADTRUNC", 22, },
{ NULL, -1, }
};

int str2rcode(char *str)
{
	struct dns_types *h;
	int i;

	if (dns_rcode_hash == NULL) {
		for (i = 0; dns_rcode_static[i].name != NULL; i++) {
			h = &dns_rcode_static[i];
			HASH_ADD_STR(dns_rcode_hash, name, h);
		}
	}
	HASH_FIND_STR(dns_rcode_hash, str, h);
	if (h == NULL) return -1;
	return h->code;
}

int str2type(char *str)
{
	struct dns_types *h;
	int i;

	if (dns_types_hash == NULL) {
		for (i = 0; dns_types_static[i].name != NULL; i++) {
			h = &dns_types_static[i];
			HASH_ADD_STR(dns_types_hash, name, h);
		}
	}
	HASH_FIND_STR(dns_types_hash, str, h);
	if (h == NULL) {
		if (strncasecmp(str, "TYPE", 4) == 0) {
			return atoi(str+4);
		}
		return -1;
	}
	return h->code;
}

int str2class(char *str)
{
	int k;

	if (strcasecmp(str, "IN") == 0) {
		return _CLASS_IN;
	} else
	if (strcasecmp(str, "CHAOS") == 0) {
		return _CLASS_CH;
	} else
	if (strcasecmp(str, "HS") == 0) {
		return _CLASS_HS;
	} else
	if (strcasecmp(str, "BADCLASS") == 0) {
		return 0;
	} else
	if (strcasecmp(str, "ANY") == 0) {
		return _CLASS_ANY;
	}
	if (strncasecmp(str, "CLASS", 5) == 0) {
		k = strtol(str + 5, NULL, 10);
		if (k < 0 || k > 65535) return -1;
		return k;
	}
	return -1;
}

// 2024-11-01T11:53:12.801252Z
long long str2unixlltime(char *str)
{
	struct tm t;
	long vv;
	double d = 0;
	long long tt;

	if (sscanf(str, "%4d-%2d-%2dT%2d:%2d:%lfZ",
			&t.tm_year, &t.tm_mon, &t.tm_mday,
			&t.tm_hour, &t.tm_min, &d) != 6)
		return 0;
	t.tm_sec = (int)d;
	vv = (int)((d-t.tm_sec) * 1000000 + 0.5);
	t.tm_year -= 1900;
	t.tm_mon--;
	t.tm_isdst = 0;
	t.tm_zone = NULL;
	t.tm_gmtoff = 0;
	t.tm_wday = 0;
	t.tm_yday = 0;

	tt = timegm(&t) * 1000000LL + vv;
	return tt;
}
