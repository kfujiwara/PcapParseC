ACLOCAL_AMFLAGS = -I m4
LD_MAXMIND=-lm -L$(prefix)/lib -lmaxminddb
CFLAGS+=
EXTRA_DIST = JPRS-OSCL.txt
AM_CFLAGS =  -I$(prefix)/include -I/usr/local/include -Iext

PcapParseC = parse_file.c pcapparse.h parse_DNS.c parse_DNS.h \
	dns_string.c dns_string.h parse_fixup_portaddr.c \
	parse_pcap.c \
	parse_bind9log.c parse_dnsjson.c parse_testdata.c parse_testdata.h \
	parse_tcp.c parse_L3.c parse_tools.c parse_int.h \
	mytool.c mytool.h bit.c bit.h
check_PROGRAMS = load_ipv6list_debug test_addrport_match geoiptest parse_dnsjson_test test_name_match geoiptest
bin_PROGRAMS = pcapgetquery pcapFindL3 pcapFindQname pcapinfo pcapNULL pcapV6addr
pcapinfo_SOURCES = pcapinfo.c dns_string.h dns_string.c mytool.c mytool.h
pcapgetquery_SOURCES = pcapgetquery.c load_ipv6list.c load_ipv6list.h $(PcapParseC) print_dns_answer.c print_dns_answer.h addrport_match.c addrport_match.h name_match.c name_match.h
pcapFindL3_SOURCES = pcapFindL3.c addrport_match.c addrport_match.h PcapParse.h
test_addrport_match_SOURCES = test_addrport_match.c addrport_match.c addrport_match.h
test_name_match_SOURCES = test_name_match.c name_match.c name_match.h parse_fixup_portaddr.c
pcapFindQname_SOURCES = pcapFindQname.c $(PcapParseC) name_match.c name_match.h
geoiptest_SOURCES = geoiptest.c geoiplookup.c geoiplookup.h
geoiptest_LDADD = $(LD_MAXMIND)
parse_dnsjson_test_SOURCES = parse_dnsjson.c parse_dnsjson_test.c dns_string.c dns_string.h parse_fixup_portaddr.c mytool.c mytool.h
load_ipv6list_debug_SOURCES = load_ipv6list.c load_ipv6list_debug.c mytool.c load_ipv6list.h mytool.h
pcapV6addr_SOURCES = pcapV6addr.c load_ipv6list.c load_ipv6list.h $(PcapParseC)
pcapNULL_SOURCES = pcapNULL.c $(PcapParseC)
