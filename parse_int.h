int _parse_bind9log(FILE *fp, struct DNSdataControl *c);
int _parse_dnsjson(FILE *fp, struct DNSdataControl *c);
int parse_dnsjson(struct DNSdataControl *c);
char *parse_pcap_error(int errorcode);
void Print_PcapStatistics(struct DNSdataControl *c);
int parse_pcap(FILE *fp, struct DNSdataControl *c, u_char *pcap_first_read, int needswap);
int parse_pcapng(FILE *fp, struct DNSdataControl *c, u_char *pcap_first_read);
