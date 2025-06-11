struct name_hash {
	UT_hash_handle hh;
	int count;
	char name[1];
};
struct name_list {
	struct name_hash *hash;
	uint16_t nlabels;
};

struct name_hash *match_name(struct name_list *list, struct DNSdataControl *c);
void register_name_list(char *str, struct name_list *list, int opt_v);
void print_name_list(struct name_list *list);
void load_name_list(char *filename, struct name_list *list);
