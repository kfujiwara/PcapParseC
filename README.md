PcapParseC is always under development.
It is a tool which the author want to use.
License is described in JPRS-OSCL.txt.

Currently, the author uses it to count 'Number of possible DNSSEC validators',
'JP server selection of full-resolvers' and 'analysis of stub-resolvers'.

It can be used to analyze large pcap files which recorded DNS packets.

You can use PcapParse.c as a PCAP parser
and you can evaluate anything you want to by writing C subroutine.

There is no documentation which describes how to use it as a library.

pcapDNSKEY.c and pcapgetquery.c are examples for PcapParse.c.

How to build:
	(libtoolize; automake --add-missing)
	autoreconf
	./configure
	make
	make install

Tested environment:
	FreeBSD 8.3
	Linux (CentOS 5.6 and old RHEL)
	Solaris 10

How to use:

pcapgetquery reads pcap files and outputs BIND 9 style query logs.
Or it can output CSV style query logs.

Usage: pcapgetquery [options] pcap files...

	-A	Parse response packets

	-L	BIND 9 querylog format
	-C	CSV output
	-c	Count mode

	-D num	Debug flag
	-4 v4	Specify DNS server's IPv4 address
	-6 v6	Specify DNS server's IPv6 address
	-e v4	Specify IPv4 address of excluded client
	-m v4	Specify netmask for -a option
	-a v4	Specify allowed client address prefix (IPv4 only)

pcapDNSKEY reads pcap files and counts that each query source IP address sent
how many queries for JP, JP DNSKEY, any.JP DS, IN-ADDR.ARPA, *.IN-ADDR.ARPA DNSKEY,
*.IN-ADDR.ARPA DS, *.BIND, *.SERVER and unknown TLDs.

Usage: pcapDNSKEY [options] pcap files...

	-4 v4	Specify DNS server's IPv4 address
	-6 v6	Specify DNS server's IPv6 address

---------------------------
Kazunori Fujiwara, Japan Registry Services Co., Ltd.
  <fujiwara@jprs.co.jp>, <fujiwara@wide.ad.jp>
