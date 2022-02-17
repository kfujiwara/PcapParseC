ACLOCAL_AMFLAGS = -I m4
LD_MAXMIND=-lm -L$(prefix)/lib -lmaxminddb
CFLAGS+=
EXTRA_DIST = JPRS-OSCL.txt
AM_CFLAGS =  -I$(prefix)/include -I/usr/local/include -Iext

bin_PROGRAMS = pcapgetquery PcapSelectL3 PcapSelectDNS pcapinfo PcapL3Print
pcapgetquery_SOURCES = pcapgetquery.c PcapParse.c PcapParse.h mytool.c mytool.h bit.c bit.h
PcapSelectL3_SOURCES = PcapSelectL3.c PcapParse.h
PcapL3Print_SOURCES = PcapL3Print.c PcapParse.h
PcapSelectDNS_SOURCES = PcapSelectDNS.c PcapParse.h PcapParse.c mytool.c mytool.h bit.c bit.h
