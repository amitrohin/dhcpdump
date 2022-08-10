#ifndef __dhcp_h__
#define __dhcp_h__

#include <sys/cdefs.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/queue.h>

DECL_ERROR(E_DHCPOPTDESC)
DECL_ERROR(E_DHCPOPTDESCDUP)
DECL_ERROR(E_DHCPOPTDESCADD)
DECL_ERROR(E_DHCPOPTDECODE)
DECL_ERROR(E_DHCPENDOFDATA)
DECL_ERROR(E_DHCPDATAINCOMPLETE)
DECL_ERROR(E_DHCPWRONGCOOKIE)
#if 0
#define E_DHCPOPTDESC		1
#define E_DHCPOPTDESCDUP	2
#define E_DHCPOPTDESCADD	3
#define	E_DHCPOPTDECODE		4
#define E_DHCPENDOFDATA		5	/* закончились данные в dhcp пакете */
#define E_DHCPDATAINCOMPLETE	6	/* опция требует данных, а их нет */
#define E_DHCPWRONGCOOKIE	7
#endif

__BEGIN_DECLS
void	printHexString(const uint8_t *data, int len, const char *sep);
void	printString(const uint8_t *data, int len);
__END_DECLS

/* UDP port numbers, server and client. */
#define IPPORT_BOOTPS		67
#define IPPORT_BOOTPC		68

#define DHCPHDR_CHADDR_LEN	16
#define DHCPHDR_SNAME_LEN	64
#define DHCPHDR_FILE_LEN	128
#define DHCPHDR_VEND_LEN	64
/* Overhead to fit a bootp message into an Ethernet packet. */
#define DHCPPDU_OVERHEAD	(14 + 20 + 8)   /* Ethernet + IP + UDP headers */

struct dhcphdr {
    uint8_t         op;                         /* packet opcode type */
    uint8_t         htype;                      /* hardware addr type */
    uint8_t         hlen;                       /* hardware addr length */
    uint8_t         hops;                       /* gateway hops */
    uint32_t        xid;                        /* transaction ID */
    uint16_t        secs;                       /* seconds since boot began */
    uint16_t	    flags;                      /* RFC1532 broadcast, etc. */
    struct in_addr  ciaddr;                     /* client IP address */
    struct in_addr  yiaddr;                     /* 'your' IP address */
    struct in_addr  siaddr;                     /* server IP address */
    struct in_addr  giaddr;                     /* gateway IP address */
    uint8_t         chaddr[DHCPHDR_CHADDR_LEN]; /* client hardware address */
    char            sname[DHCPHDR_SNAME_LEN];   /* server host name */
    char            file[DHCPHDR_FILE_LEN];     /* boot file name */
    u_char          options[];                  /* bootp vendor-specific area/dhcp options */
} __packed;

#define BOOTREQUEST             1
#define BOOTREPLY               2
static inline 
const char *dhcp_opcode(uint8_t opcode) 
{
	const char *s = NULL;
	switch (opcode) {
		case BOOTREQUEST: s = "BOOTREQUEST"; break;
		case BOOTREPLY:   s = "BOOTREPLY";   break;
	}
	return s;
}

/* Hardware types from Assigned Numbers RFC. */
#define HTYPE_ETHERNET          1
#define HTYPE_EXPETHERNET	2
#define HTYPE_AX25              3
#define HTYPE_PRONET            4
#define HTYPE_CHAOS             5
#define HTYPE_IEEE802           6
#define HTYPE_ARCNET            7
#define HTYPE_HYPERCHANNEL	8
#define HTYPE_LANSTAR		9
#define HTYPE_AUTONETSHORTADDR	10
#define HTYPE_LOCALTALK		11
#define HTYPE_LOCALNET		12
#define HTYPE_ULTRALINK		13
#define HTYPE_SMDS		14
#define HTYPE_FRAMERELAY	15
#define HTYPE_ATM16		16
#define HTYPE_HDLC		17
#define HTYPE_FIBRECHANNEL	18
#define HTYPE_ATM19		19
#define HTYPE_SERIALLINE	20
#define HTYPE_ATM21		21

__BEGIN_DECLS
const char *dhcp_htype(uint8_t htype);
__END_DECLS

struct pdu_dhcpopt {
        uint8_t code;
        uint8_t length;
	uint8_t value[];
} __packed;

#define DHCPOPT_F_NOLENGTH	1
#define DHCPOPT_F_NOVALUE	2
#define	DHCPOPT_F_PAD		4
#define	DHCPOPT_F_END		8

struct dhcpopt_descriptor {
        const char *    name;   /* option name */
	int		flags;	/* DHCPOPT_F_NOLENGTH, DHCPOPT_F_NOVALUE */
        uint8_t         code;   /* option code */
        uint8_t         elsz;   /* size of element. length of an option has to be multiple elsz. */
        uint8_t         min;    /* minimal length in bytes */
        uint8_t         max;    /* maximal length in bytes */
        const char *    metric;
        struct dhcpopt *(*decode)(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp);
        void            (*free)(struct dhcpopt *opt);
        void            (*show)(struct dhcpopt *opt, int indent, FILE *fp);
        const char *    (*enumfn)(struct dhcpopt_descriptor *optd, void *value);

	/* suboptions */
	int		(*init)(struct dhcpopt_descriptor *optd);
	void		(*fini)(struct dhcpopt_descriptor *optd);
        struct rbtree * dtree;
};

struct dhcpopt;
STAILQ_HEAD(dhcpoptlst, dhcpopt); 
struct dhcpopt {
        STAILQ_ENTRY(dhcpopt)		ent;
	struct dhcpopt_descriptor *	optd;
	uint8_t				code;
        uint8_t				length;
	union {
		uint8_t		value[0];

		int8_t		i8[0];
		uint8_t		u8[0];
		int16_t		i16[0];
		uint16_t	u16[0];
		int32_t		i32[0];
		uint32_t	u32[0];
		uint32_t	u32x2[0][2];
		char		s[0];		/* [!] malloc(length + 1) and s[length] = '\0' */

		struct dhcpoptlst	lst[0];

		struct {
			uint8_t		mandatory;
			uint32_t	u32[0];
		} opt78[0];

		struct {
			uint8_t		mandatory;
			char		s[0];
		} opt79[0];

		struct {
			union {
				struct {
					unsigned	S:1;
					unsigned	O:1;
					unsigned	E:1;
					unsigned	N:1;
					unsigned	MBZ:4;
				} __packed;
				uint8_t	flags;
			} __packed;
			uint8_t		rcode1;
			uint8_t		rcode2;
			uint8_t		u8[0];
		} __packed opt81[0];
	};
};

struct dhcp {
    uint8_t		op;                         /* packet opcode type */
    uint8_t		htype;                      /* hardware addr type */
    uint8_t		hlen;                       /* hardware addr length */
    uint8_t		hops;                       /* gateway hops */
    uint32_t		xid;                        /* transaction ID */
    uint16_t		secs;                       /* seconds since boot began */
    uint16_t		flags;                      /* RFC1532 broadcast, etc. */
    uint32_t		ciaddr;                     /* client IP address */
    uint32_t		yiaddr;                     /* 'your' IP address */
    uint32_t		siaddr;                     /* server IP address */
    uint32_t		giaddr;                     /* gateway IP address */
    uint8_t		chaddr[DHCPHDR_CHADDR_LEN]; /* client hardware address */
    char		sname[DHCPHDR_SNAME_LEN];   /* server host name */
    char		file[DHCPHDR_FILE_LEN];     /* boot file name */
    struct dhcpoptlst	opts[1];                    /* dhcp options */
};

enum dhcpopt82_type {
        DHCPOPT82_T_UNKNOWN,
        DHCPOPT82_T_DEFAULT,
        DHCPOPT82_T_IES1248,
        DHCPOPT82_T_IES5000,
	DHCPOPT82_T_CDRU	/* Circuit-ID: default, Remote-ID: userString */
};
struct dhcpopt82_value {
        enum dhcpopt82_type type;
        union {
                uint8_t u8[0];
                struct {
                        uint16_t vlanid;
                        uint8_t module, port;
                        struct ether_addr ether;
                } def[0];
                struct {
                        uint16_t vlanid;
                        uint8_t module, port;
			uint8_t slen;
                        char str[];
                } cdru[0];
        };
};

__BEGIN_DECLS
const char *		dhcp_option(struct rbtree *dtree, uint8_t option);

static inline 
uint8_t	
dhcpopt_code(struct dhcpopt *opt) 
{
	return opt->code;
}

static inline 
const char *
dhcpopt_name(struct dhcpopt *opt) 
{ 
	return opt->optd ? opt->optd->name : "???";
}

static inline 
uint8_t
dhcpopt_length(struct dhcpopt *opt) 
{
	return opt->length;
}

static inline 
void *
dhcpopt_value(struct dhcpopt *opt) 
{
	return opt->value;
}

static inline 
struct dhcpopt_descriptor *
dhcpopt_descriptor(struct dhcpopt *opt) 
{
	return opt->optd;
}

static inline 
int
dhcpopt_ispad(struct dhcpopt *opt) 
{
	return opt->optd ? (opt->optd->flags & DHCPOPT_F_PAD) : 0; 
}

static inline 
int
dhcpopt_isend(struct dhcpopt *opt) 
{
	return opt->optd ? (opt->optd->flags & DHCPOPT_F_END) : 0; 
}

struct dhcpopt *dhcpopt_decode(struct rbtree *dtree, const uint8_t **curp, const uint8_t *endp);
void		dhcpopt_free(struct dhcpopt *opt);
void		dhcpopt_show(struct dhcpopt *opt, int indent, FILE *fp);
const char *	dhcpopt_enum(struct dhcpopt_descriptor *optd, void *value);

/* XXX: подразумеваем, что опций в пакете мало и линейный поиск по списку не сожрёт процессор */
static inline
struct dhcpopt *
dhcpoptlst_find(struct dhcpoptlst *lst, uint8_t optcode)
{
	struct dhcpopt *opt;

	STAILQ_FOREACH(opt, lst, ent)
		if (dhcpopt_code(opt) == optcode)
			break;
	return opt;
}

/* пробует угадать, что за данные спрятаны в dhcp option 82 */
struct dhcpopt82_value *dhcpopt82_research(struct dhcpopt *opt);

void		dhcp_decode_opts(struct dhcpoptlst *lst, struct rbtree *dtree, const uint8_t **curp, const uint8_t *endp);
void		dhcp_free_opts(struct dhcpoptlst *lst);
struct dhcp *	dhcp_decode(const uint8_t **curp, const uint8_t *endp);
void		dhcp_free(struct dhcp *dp);
void		dhcp_show(struct dhcp *dp, int indent, FILE *fp);
__END_DECLS

#define DHCPOPT0_PAD				0	/* no value */
#define DHCPOPT1_SUBNET_MASK			1	/* u32[0] */
#define DHCPOPT2_TIME_OFFSET			2	/* i32[0] */
#define DHCPOPT3_ROUTERS			3	/* u32[] */ 
#define DHCPOPT4_TIME_SERVER			4	/* u32[] */
#define DHCPOPT5_NAME_SERVER			5	/* u32[] */
#define DHCPOPT6_DNS_SERVER			6	/* u32[] */
#define DHCPOPT7_LOG_SERVER			7	/* u32[] */
#define DHCPOPT8_COOKIE_SERVER			8	/* u32[] */
#define DHCPOPT9_LPR_SERVER			9	/* u32[] */
#define DHCPOPT10_IMPRESS_SERVER		10	/* u32[] */
#define DHCPOPT11_RESOURCE_LOCATION_SERVER	11	/* u32[] */
#define DHCPOPT12_HOST_NAME			12	/* s[] */
#define DHCPOPT13_BOOT_FILE_SIZE		13	/* u16[0] */
#define DHCPOPT14_MERIT_DUMP_FILE		14	/* s[] */
#define DHCPOPT15_DOMAIN_NAME			15	/* s[] */
#define DHCPOPT16_SWAP_SERVER			16	/* u32[0] */
#define DHCPOPT17_ROOT_PATH			17	/* s[] */
#define DHCPOPT18_EXTENSIONS_PATH		18	/* s[] */
#define DHCPOPT19_IP_FORWARDING			19	/* u8[0] */
#define DHCPOPT20_NON_LOCAL_SOURCE_ROUTING	20	/* u8[0] */
#define DHCPOPT21_POLICY_FILTER			21	/* u32x2[], 0 - netaddr, 1 - netmask */
#define DHCPOPT22_MAX_DATAGRAM_REASSEMBLY_SIZE	22	/* u16[0] */
#define DHCPOPT23_DEFAULT_IP_TTL		23	/* u8[0] */
#define DHCPOPT24_PATH_MTU_AGING_TIMEOUT	24	/* u32[0] */
#define DHCPOPT25_PATH_MTU_PLATEAU_TABLE	25	/* u16[] */
#define DHCPOPT26_INTERFACE_MTU			26	/* u16[0] */
#define DHCPOPT27_ALL_SUBNETS_LOCAL		27	/* u8[0] */
#define DHCPOPT28_BROADCAST_ADDRESS		28	/* u32[0] */
#define DHCPOPT29_PERFORM_MASK_DISCOVERY	29	/* u8[0] */
#define DHCPOPT30_MASK_SUPPLIER			30	/* u8[0] */
#define DHCPOPT31_PERFORM_ROUTER_DISCOVERY	31	/* u8[0] */
#define DHCPOPT32_ROUTER_SOLICITATION_ADDRESS	32	/* u32[0] */
#define DHCPOPT33_STATIC_ROUTE			33	/* u32x2[], 0 - hostaddr, 1 - router */
#define DHCPOPT34_TRAILER_ENCAPSULATION		34	/* u8[0] */
#define DHCPOPT35_ARP_CACHE_TIMEOUT		35	/* u32[0] */
#define DHCPOPT36_ETHERNET_ENCAPSULATION	36	/* u8[0] */
#define	ETHERNET_II_ENCAP	0
#define	ETHERNET_8023_ENCAP	1
#define DHCPOPT37_TCP_DEFAULT_TTL		37	/* u8[0] */
#define DHCPOPT38_TCP_KEEPALIVE_INTERVAL	38	/* u32[0] */
#define DHCPOPT39_TCP_KEEPALIVE_GARBAGE		39	/* u8[0] */
#define	DHCPOPT40_NIS_DOMAIN			40	/* s[] */
#define DHCPOPT41_NIS_SERVERS			41	/* u32[] */
#define DHCPOPT42_NTP_SERVERS			42	/* u32[] */
#define DHCPOPT43_VENDOR_SPECIFIC_INFORMATION	43	/* u8[] */
#define DHCPOPT44_NETBIOS_NAME_SERVER		44	/* u32[] */
#define DHCPOPT45_NETBIOS_DD_SERVER		45	/* u32[] */
#define DHCPOPT46_NETBIOS_NODE_TYPE		46	/* u8[0] */
#define NETBIOS_B_NODE	1
#define NETBIOS_P_NODE	2
#define NETBIOS_M_NODE	4
#define NETBIOS_H_NODE	8
#define DHCPOPT47_NETBIOS_SCOPE			47	/* s[] */
#define DHCPOPT48_XWINDOW_FONT_SERVER		48	/* u32[] */
#define DHCPOPT49_XWINDOW_DISPLAY_MANAGER	49	/* u32[] */
#define DHCPOPT50_REQUESTED_IP_ADDRESS		50	/* u32[0] */
#define DHCPOPT51_IP_ADDRESS_LEASE_TIME		51	/* u32[0] */
#define DHCPOPT52_OPTION_OVERLOAD		52	/* u8[0] */
#define	DHCPOVERLOAD_FILE  1
#define DHCPOVERLOAD_SNAME 2
#define DHCPOVERLOAD_BOTH  3
#define DHCPOPT53_DHCP_MESSAGE_TYPE		53	/* u8[0] */
#define	DHCPDISCOVER	1
#define	DHCPOFFER	2
#define	DHCPREQUEST	3
#define	DHCPDECLINE	4
#define	DHCPACK		5
#define	DHCPNAK		6
#define	DHCPRELEASE	7
#define	DHCPINFORM	8
#define	DHCPOPT54_SERVER_IDENTIFIER		54	/* u32[0] */
#define	DHCPOPT55_PARAMETER_REQUEST_LIST	55	/* u8[] */
#define	DHCPOPT56_MESSAGE			56	/* s[] */
#define	DHCPOPT57_MAXIMUM_DHCP_MESSAGE_SIZE	57	/* u16[0] */
#define	DHCPOPT58_RENEWAL_TIME_VALUE		58	/* u32[0] */
#define DHCPOPT58_T1				DHCPOPT58_RENEWAL_TIME_VALUE
#define	DHCPOPT59_REBINDING_TIME_VALUE		59	/* u32[0] */
#define	DHCPOPT59_T2				DHCPOPT59_REBINDING_TIME_VALUE
#define DHCPOPT60_VENDOR_CLASS_IDENTIFIER	60	/* u8[] */
#define	DHCPOPT61_CLIENT_IDENTIFIER		61	/* u8[] */

/* XXX rfc2242 */
#define	DHCPOPT62_NETWAREIP_DOMAIN_NAME		62	/* s[] */
#define	DHCPOPT63_NETWAREIP_INFORMATION		63	/* u8[] XXX */
#define	DHCPOPT63_SUBOPT1_NWIP_DOES_NOT_EXIST		1
#define	DHCPOPT63_SUBOPT2_NWIP_EXIST_IN_OPTIONS_AREA	2
#define	DHCPOPT63_SUBOPT3_NWIP_EXIST_IN_SNAME_FILE	3
#define	DHCPOPT63_SUBOPT4_NWIP_EXIST_BUT_TOO_BIG	4
#define	DHCPOPT63_SUBOPT5_NSQ_BROADCAST			5
#define	DHCPOPT63_SUBOPT6_PREFERRED_DSS			6
#define	DHCPOPT63_SUBOPT7_NEAREST_NWIP_SERVER		7
#define	DHCPOPT63_SUBOPT8_AUTORETRIES			8
#define	DHCPOPT63_SUBOPT9_AUTORETRY_SECS		9
#define	DHCPOPT63_SUBOPT10_NWIP_1_1			10
#define	DHCPOPT63_SUBOPT11_PRIMARY_DSS			11

#define DHCPOPT64_NISPLUS_DOMAIN		64	/* s[] */
#define	DHCPOPT65_NISPLUS_SERVERS		65	/* u32[] */
#define	DHCPOPT66_TFTP_SERVER_NAME		66	/* s[] */
#define	DHCPOPT67_BOOTFILE_NAME			67	/* s[] */
#define DHCPOPT68_MOBILE_IP_HOME_AGENT		68	/* u32[] */
#define DHCPOPT69_SMTP_SERVER			69	/* u32[] */
#define	DHCPOPT70_POP3_SERVER			70	/* u32[] */
#define	DHCPOPT71_NNTP_SERVER			71	/* u32[] */
#define	DHCPOPT72_WWW_SERVER			72	/* u32[] */
#define	DHCPOPT73_FINGER_SERVER			73	/* u32[] */
#define	DHCPOPT74_IRC_SERVER			74	/* u32[] */
#define	DHCPOPT75_STREETTALK_SERVER		75	/* u32[] */
#define	DHCPOPT76_STREETTALK_DIRECTORY_ASSISTANCE_SERVER 76 /* u32[] */
#define	DHCPOPT77_USER_CLASS			77	/* u8[] */
#define DHCPOPT78_SLP_DIRECTORY_AGENT		78	/* opt78[0]{ mandatory, u32[] } */
#define DHCPOPT79_SLP_SERVICE_SCOPE		79	/* opt79[0]{ mandatory, s[] } */
#define	DHCPOPT80_RAPID_COMMIT			80	/* no value */
#define	DHCPOPT81_CLIENT_FQDN			81	/* opt81[0]{ flags, rcode1, rcode2, u8[] } */

#define DHCPOPT82_RELAYAGENTINFORMATION		82	/* rfc3046 */
#define DHCPOPT82_SUBOPT1_CIRCUITID	1
#define DHCPOPT82_SUBOPT2_REMOTEID	2
static inline
const char *
dhcpopt82_subopt(uint8_t subopt)
{
	const char *s = NULL;
	switch (subopt) {
		case DHCPOPT82_SUBOPT1_CIRCUITID:
			s = "Circuit-ID";
			break;
		case DHCPOPT82_SUBOPT2_REMOTEID:
			s = "Remote-ID";
			break;
	}
	return s;
}
#define DHCPOPT255_END				255	/* no length, no value */

#endif
