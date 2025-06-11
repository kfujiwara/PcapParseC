struct ipaddr_hash {
	int count;
	u_int klen;
	u_char addr[18];
	UT_hash_handle hh;
};
struct ipaddr_port_list {
	struct ipaddr_hash *hash;
	uint16_t mask;
};

struct ipaddr_hash *
match_ipaddr_port(struct ipaddr_port_list *list, u_char *addr, int alen);
void register_ipaddr_port_hash(char *str, struct ipaddr_port_list *list, int opt_v);
void print_ipaddrlist_hash(struct ipaddr_port_list *list);
void load_ipaddrlist(char *filename, struct ipaddr_port_list *list);
