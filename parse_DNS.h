void parse_DNS(struct DNSdataControl *d);
void parse_DNS_answer(struct DNSdataControl *d);
void parse_DNS_query(struct DNSdataControl *d);
unsigned long long int get_uint32(struct DNSdata *d);
unsigned int get_uint16(struct DNSdata *d);
int get_dname(struct DNSdata *d, char *o, int o_len, int mode, struct case_stats *s);
