ACLOCAL_AMFLAGS = -I m4
LDADD=-lm -L$(HOME)/.local/lib/ -lmaxminddb
CFLAGS+=
EXTRA_DIST = JPRS-OSCL.txt tools/Log2pcap GenerateTLDlist TLDLIST
CLEANFILES = tldlist.c
AM_CFLAGS =  -I$(HOME)/.local/include -I/usr/local/include

bin_PROGRAMS = pcapgetquery PcapSelectTime pcapChoose pcapinfo
pcapgetquery_SOURCES = pcapgetquery.c PcapParse.c PcapParse.h mytool.c mytool.h bit.c bit.h
PcapSelectTime_SOURCES = PcapSelectTime.c PcapParse.h
pcapChoose_SOURCES = pcapChoose.c PcapParse.h PcapParse.c
# pcapCount_SOURCES = pcapCount.c PcapParse.c PcapParse.h
