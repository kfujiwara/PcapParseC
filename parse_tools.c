/*
	$Id: parse_tools.c,v 1.2 2024/05/09 15:15:28 fujiwara Exp $

	Author: Kazunori Fujiwara <fujiwara@jprs.co.jp>

	Copyright (c) 2012-2013 Japan Registry Servcies Co., Ltd.
	This file is part of PcapParseC.

	PcapParseC is free software; you can use, redistribute and/or
 	modify it under the terms of the JPRS OPEN SOURCE CODE LICENSE
	written in JPRS-OSCL.txt.
*/

#include "config.h"

#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include "ext/uthash.h"
#include "mytool.h"
#include "PcapParse.h"
#include "parse_int.h"

char *parse_pcap_error(int errorcode)
{
	switch(errorcode) {
	case ParsePcap_NoError:
		return "NoError";
	case ParsePcap_ERROR_Empty:
		return "Empty";
	case ParsePcap_ERROR_BogusSavefile:
		return "BogusSavefile";
	case ParsePcap_ERROR_ShortRead:
		return "ShortRead";
	case ParsePcap_ERROR_FILE_OPEN:
		return "Cannot Open File";
	case ParsePcap_ERROR_UnknownLinkType:
		return "Unknown Link Type";
	case ParsePcap_ERROR_COMMAND:
		return "Command execution error";
	case ParsePcap_ERROR_OutofPeriod:
		return "OutOfPeriod";
	default:
		return "Unknown";
	}
}

void Print_PcapStatistics(struct DNSdataControl *c)
{
#define NonzeroPrint(A,B)  { if ((B) != 0) printf("%s,%d\n", (A), (B)); }
	NonzeroPrint("#PcapStatistics._pcap", c->ParsePcapCounter._pcap);
	NonzeroPrint("#PcapStatistics._ipv4", c->ParsePcapCounter._ipv4);
	NonzeroPrint("#PcapStatistics._ipv6", c->ParsePcapCounter._ipv6);
	NonzeroPrint("#PcapStatistics._version_unknown", c->ParsePcapCounter._version_unknown);
	NonzeroPrint("#PcapStatistics._portmismatch", c->ParsePcapCounter._portmismatch);
	NonzeroPrint("#PcapStatistics._udp4", c->ParsePcapCounter._udp4);
	NonzeroPrint("#PcapStatistics._tcp4", c->ParsePcapCounter._tcp4);
	NonzeroPrint("#PcapStatistics._udp6", c->ParsePcapCounter._udp6);
	NonzeroPrint("#PcapStatistics._tcp6", c->ParsePcapCounter._tcp6);
	NonzeroPrint("#PcapStatistics._udp4_frag_first", c->ParsePcapCounter._udp4_frag_first);
	NonzeroPrint("#PcapStatistics._udp4_frag_next", c->ParsePcapCounter._udp4_frag_next);
	NonzeroPrint("#PcapStatistics._tcp4_frag", c->ParsePcapCounter._tcp4_frag);
	NonzeroPrint("#PcapStatistics._udp6_frag_first", c->ParsePcapCounter._udp6_frag_first);
	NonzeroPrint("#PcapStatistics._udp6_frag_next", c->ParsePcapCounter._udp6_frag_next);
	NonzeroPrint("#PcapStatistics._tcp6_frag", c->ParsePcapCounter._tcp6_frag);
	NonzeroPrint("#PcapStatistics._ipv6_unknownfragment", c->ParsePcapCounter._ipv6_unknownfragment);
	NonzeroPrint("#PcapStatistics._udp_query", c->ParsePcapCounter._udp_query);
	NonzeroPrint("#PcapStatistics._tcp_query", c->ParsePcapCounter._tcp_query);
	NonzeroPrint("#PcapStatistics._tcpbuff_unused", c->ParsePcapCounter._tcpbuff_unused);
	NonzeroPrint("#PcapStatistics._tcpbuff_merged", c->ParsePcapCounter._tcpbuff_merged);
	NonzeroPrint("#PcapStatistics._tcpbuff_zero_fin", c->ParsePcapCounter._tcpbuff_zerofin);
	NonzeroPrint("#PcapStatistics._proto_mismatch", c->ParsePcapCounter._proto_mismatch);
	NonzeroPrint("#PcapStatistics._ipv4_headerchecksumerror", c->ParsePcapCounter._ipv4_headerchecksumerror);
	NonzeroPrint("#PcapStatistics._udp_checksumerror", c->ParsePcapCounter._udp_checksumerror);
	NonzeroPrint("#PcapStatistics._before_checking_dnsheader", c->ParsePcapCounter._before_checking_dnsheader);
	NonzeroPrint("#PcapStatistics._dns_query", c->ParsePcapCounter._dns_query);
	NonzeroPrint("#PcapStatistics._dns_response", c->ParsePcapCounter._dns_response);
	NonzeroPrint("#PcapStatistics._parsed_dnsquery", c->ParsePcapCounter._parsed_dnsquery);
	NonzeroPrint("#PcapStatistics._IPlenMissmatch", c->ParsePcapCounter._IPlenMissmatch);
	NonzeroPrint("#PcapStatistics._unknown_ipaddress", c->ParsePcapCounter._unknown_ipaddress);
	NonzeroPrint("#PcapStatistics._numfiles", c->ParsePcapCounter._numfiles);
	NonzeroPrint("#PcapStatistics.error00", c->ParsePcapCounter.error[0]);
	NonzeroPrint("#PcapStatistics.error01", c->ParsePcapCounter.error[1]);
	NonzeroPrint("#PcapStatistics.error02", c->ParsePcapCounter.error[2]);
	NonzeroPrint("#PcapStatistics.error03", c->ParsePcapCounter.error[3]);
	NonzeroPrint("#PcapStatistics.error04", c->ParsePcapCounter.error[4]);
	NonzeroPrint("#PcapStatistics.error05", c->ParsePcapCounter.error[5]);
	NonzeroPrint("#PcapStatistics.error06", c->ParsePcapCounter.error[6]);
	NonzeroPrint("#PcapStatistics.error07", c->ParsePcapCounter.error[7]);
	NonzeroPrint("#PcapStatistics.error08", c->ParsePcapCounter.error[8]);
	NonzeroPrint("#PcapStatistics.error09", c->ParsePcapCounter.error[9]);
};

int add_node_name(struct DNSdataControl *d, char *node)
{
	struct node_hash *ee;
	char *p;
	int len;

	HASH_FIND_STR(d->node_hash, node, ee);
	if (ee != NULL) return ee->index;
	if (d->node_name == NULL) {
		if (d->max_node_name <= 0) d->max_node_name = 1000;
		d->node_name = my_malloc(sizeof(d->node_name[0]) * d->max_node_name);
	} else
	if (d->num_node_name >= d->max_node_name) return 0;

	len = strlen(node);
	p = my_malloc(sizeof(struct node_hash)+len+1);
	strcpy(p, node);
	ee = (struct node_hash *)(p + len + 1);
	ee->node = p;
	ee->index = d->num_node_name;
	d->node_name[d->num_node_name] = ee;
	d->num_node_name++;
	HASH_ADD_STR(d->node_hash, node, ee);
	return ee->index;
}

char *get_node_name(struct DNSdataControl *d, int node_id)
{
	if (node_id < 0 || node_id >= d->num_node_name) return NULL;
	return d->node_name[node_id]->node;
}

void print_rusage()
{
	struct rusage usage;
	int r;

#define	PRINT_TV(X, Y) printf("#rusage:" #Y ",%ld.%06ld\n", X.Y.tv_sec, X.Y.tv_usec)
#define	PRINT_XX(X, Y) printf("#rusage:" #Y ",%ld\n", X.Y)
	r = getrusage(RUSAGE_SELF, &usage);
	PRINT_TV(usage, ru_utime);
	PRINT_TV(usage, ru_stime);
	PRINT_XX(usage, ru_maxrss);
	//PRINT_XX(usage, ru_ixrss);
	//PRINT_XX(usage, ru_idrss);
	//PRINT_XX(usage, ru_isrss);
	//PRINT_XX(usage, ru_minflt);
	//PRINT_XX(usage, ru_majflt);
	//PRINT_XX(usage, ru_nswap);
	//PRINT_XX(usage, ru_inblock);
	//PRINT_XX(usage, ru_oublock);
	//PRINT_XX(usage, ru_msgsnd);
	//PRINT_XX(usage, ru_msgrcv);
	//PRINT_XX(usage, ru_nsignals);
	//PRINT_XX(usage, ru_nvcsw);
	//PRINT_XX(usage, ru_nivcsw);
}

char *PcapParseC_datatype[] = { "DNS", "TCPSYN", NULL };

