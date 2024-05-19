#define PCAP_FIRST_READ 12

struct pcap_file_header {
	u_int32_t magic;
	u_short version_major;
	u_short version_minor;
	int32_t thiszone;	/* gmt to local correction */
	u_int32_t sigfigs;	/* accuracy of timestamps */
	u_int32_t snaplen;	/* max length saved portion of each pkt */
	u_int32_t linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_header {
	struct pcap_timeval {
		u_int32_t tv_sec;	/* seconds */
		u_int32_t tv_usec;	/* microseconds */
	} ts;				/* time stamp */
	int32_t caplen;	/* length of portion present */
	int32_t len;	/* length this packet (off wire) */
};
#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define	DLT_IP		101	/* IP packet directly */
#define DLT_LINUX_SLL	113	/* Linux cocked */
#define DLT_RAW		12	/* _ip IP */
#define	LINKTYPE_OPENBSD_LOOP	108

struct pcapng_section_header3 {
	u_int32_t block_type;
	u_int32_t length;
	u_int32_t magic;
};
struct pcapng_section_header2 {
	u_int32_t block_type;
	u_int32_t length;
};
struct pcapng_type6 {
	u_int32_t interfaceID;
	u_int32_t tv_h;
	u_int32_t tv_l;
	u_int32_t caplen;
	u_int32_t len;
};

struct pcapng_type1 {
	u_int16_t linktype;
	u_int16_t reserved;
	u_int32_t snaplen;
};

