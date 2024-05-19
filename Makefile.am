ACLOCAL_AMFLAGS = -I m4
LD_MAXMIND=-lm -L$(prefix)/lib -lmaxminddb
CFLAGS+=
EXTRA_DIST = JPRS-OSCL.txt
AM_CFLAGS =  -I$(prefix)/include -I/usr/local/include -Iext

PcapParseC = PcapParse.c PcapParse.h parse_DNS.c parse_DNS.h \
	parse_tcp.c parse_bind9log.c parse_testdata.c parse_testdata.h \
	parse_L3.c parse_tools.c parse_int.h mytool.c mytool.h bit.c bit.h
bin_PROGRAMS = pcapgetquery PcapSelectL3 PcapSelectDNS pcapinfo PcapL3Print geoiptest
pcapgetquery_SOURCES = pcapgetquery.c $(PcapParseC) print_dns_answer.c print_dns_answer.h
PcapSelectL3_SOURCES = PcapSelectL3.c PcapParse.h
PcapL3Print_SOURCES = PcapL3Print.c PcapParse.h
PcapSelectDNS_SOURCES = PcapSelectDNS.c $(PcapParseC)
geoiptest_SOURCES = geoiptest.c geoiplookup.c geoiplookup.h
geoiptest_LDADD = $(LD_MAXMIND)

