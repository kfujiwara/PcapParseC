ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = JPRS-OSCL.txt tools/Log2pcap CHANGES

bin_PROGRAMS = pcapgetquery
pcapgetquery_SOURCES = pcapgetquery.c PcapParse.c PcapParse.h

if APRexist
bin_PROGRAMS += pcapDNSKEY
pcapDNSKEY_SOURCES = pcapDNSKEY.c PcapParse.c
endif
