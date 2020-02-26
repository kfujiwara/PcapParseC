ACLOCAL_AMFLAGS = -I m4
LDADD=-lm
CFLAGS+=
EXTRA_DIST = JPRS-OSCL.txt tools/Log2pcap GenerateTLDlist TLDLIST
CLEANFILES = tldlist.c
AM_CFLAGS =  -I$(HOME)/.local/include -I/usr/local/include

bin_PROGRAMS = pcapgetquery PcapSelectL3 PcapSelectDNS pcapinfo PcapL3Print
pcapgetquery_SOURCES = pcapgetquery.c PcapParse.c PcapParse.h mytool.c mytool.h bit.c bit.h
PcapSelectL3_SOURCES = PcapSelectL3.c PcapParse.h
PcapSelectDNS_SOURCES = PcapSelectDNS.c PcapParse.c PcapParse.h
PcapL3Print_SOURCES = PcapL3Print.c
pcapinfo_SOURCES = pcapinfo.c
