#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <err.h>
#include <unistd.h>
#include <syslog.h>

#include "foo.h"
#include "dhcp.h"

#ifdef linux
#include <time.h>
#include <netinet/ether.h>
#endif

DEFN_ERROR(E_PCAPOPEN, "pcap is unable to open device.")
DEFN_ERROR(E_NOTETHERIFACE, "Required ethernet interface.")
DEFN_ERROR(E_PCAPCOMPILE, "Unable compile pcap filter.")
DEFN_ERROR(E_PCAPSETFILTER, "Unable set pcap filter.")
DEFN_ERROR(E_PCAPLOOP, "pcap loop error occured.")
#if 0
#define E_PCAPOPEN	1
#define	E_NOTETHERIFACE	2
#define	E_PCAPCOMPILE	3
#define E_PCAPSETFILTER	4
#define	E_PCAPLOOP	5
#endif

char	errbuf[PCAP_ERRBUF_SIZE];

static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);

static void dumphexascii(const u_char *data, int len, int indent);
static void dumphex(const u_char *data, int len, int indent);

static
void __attribute__((__noreturn__))
usage() 
{
	printf("Usage: $0 -x {-i <interface>|-r <pcapfile>} [-t vllst] [-c chaddr] [-s swmac] [-U remote-id-user-string] [-p cport] [-v cvlan]\n");
	exit(0);
}

static int f_hexdump = 0;
static char *iface = NULL;
static char *ifile_name = NULL;
static int defined_chaddr = 0, defined_ra_etheraddr = 0, defined_ra_cvlan = 0, defined_ra_cport = 0, defined_ra_ru = 0;
static struct ether_addr chaddr, ra_etheraddr;
static uint16_t ra_cvlan, ra_cport;
static char *ra_ru;
static int vltags[8], nvltags = 0;

int
main(int argc, char *argv[])
{
	static struct ectlfr fr[1];
	static struct ectlno ex[1];
	pcap_t *cap;
	struct bpf_program fp;

	openlog("dhcpdump", LOG_PID|LOG_PERROR|LOG_NDELAY, LOG_USER);
	ectlfr_begin(fr, L_0);
	ectlno_begin(ex);

	for (int c; (c = getopt(argc, argv, "c:i:p:r:s:t:U:v:x")) != -1; ) {
		switch (c) {
		case 'c': {
				struct ether_addr *p;
				if ((p = ether_aton(optarg)) == NULL)
					errx(1, "ether_aton(\"%s\"): syntax error", optarg);
				memcpy(&chaddr, p, sizeof(struct ether_addr));
				defined_chaddr = 1;
			}
			break;
		case 'i':
			if (ifile_name) {
				ectlno_setposixerror(EINVAL);
				ectlno_printf("%s(),%d: Option -i and -r are mutual exclusive.\n", 
					__func__, __LINE__);
				ectlfr_goto(fr);
			}
			iface = optarg;
			break;
		case 'p': {
				char *endptr;
				errno = 0;
				ra_cport = strtoul(optarg, &endptr, 0);
				if (errno) {
					ectlno_setposixerror(errno);
					ectlno_printf("%s,%d: strtoul(\"%s\"): %s\n", 
						__func__, __LINE__, optarg, strerror(errno));
					ectlfr_goto(fr);
				}
				defined_ra_cport = 1;
			}
			break;
		case 'r':
			if (iface) {
				ectlno_setposixerror(EINVAL);
				ectlno_printf("%s(),%d: Option -i and -r are mutual exclusive.\n",
					__func__, __LINE__);
				ectlfr_goto(fr);
			}
			ifile_name = optarg;
			break;
		case 's': {
				struct ether_addr *p;
				if ((p = ether_aton(optarg)) == NULL) {
					ectlno_setposixerror(EINVAL);
					ectlno_printf("%s(),%d: ether_aton(\"%s\"): syntax error.\n", 
						__func__, __LINE__, optarg);
					ectlfr_goto(fr);
				}
				memcpy(&ra_etheraddr, p, sizeof(struct ether_addr));
				defined_ra_etheraddr = 1;
			}
			break;
		case 't': {
				if (nvltags) {
					ectlno_setposixerror(EINVAL);
					ectlno_printf("%s,%d: option -t cannot be used more than once.\n", 
						__func__, __LINE__);
					ectlfr_goto(fr);
				}
				for (char *p = optarg;; nvltags++) {
					for (;; p++)
						if (!isspace(*p))
							break;
					if (nvltags == sizeof vltags/sizeof vltags[0]) {
						ectlno_setposixerror(EINVAL);
						ectlno_printf("%s,%d: too many vlans: %s\n", 
							__func__, __LINE__, optarg);
						ectlfr_goto(fr);
					}
					vltags[nvltags] = 0;
					for (;; p++) {
						if (!*p) {
							nvltags++;
							goto L_endloop;
						}
						if (isspace(*p)) {
							while (isspace(*p)) p++;
							if (!*p) {
								nvltags++;
								goto L_endloop;
							}
							if (*p == '.' || *p == ',') {
								p++;
								break;
							}
							ectlno_setposixerror(EINVAL);
							ectlno_printf("%s,%d: expected number: %s\n", 
								__func__, __LINE__, optarg);
							ectlfr_goto(fr);
						}
						if (*p == '.' || *p == ',') {
							p++;
							break;
						}
						if (!isdigit(*p)) {
							ectlno_setposixerror(EINVAL);
							ectlno_printf("%s,%d: expected number: %s\n", 
								__func__, __LINE__, optarg);
							ectlfr_goto(fr);
						}
						vltags[nvltags] = vltags[nvltags] * 10 + (*p - '0');
						if (vltags[nvltags] > 4094) {
							ectlno_setposixerror(EINVAL);
							ectlno_printf("%s,%d: illegal value of vlan tag: %s\n", 
								__func__, __LINE__, optarg);
							ectlfr_goto(fr);
						}
					}
				}
			L_endloop:
#if 0
				printf("vltags[%d] -> %d", nvltags, vltags[0]);
				for (int i = 1; i < nvltags; i++)
					printf(".%d", vltags[i]);
				printf("\n");
#endif
				break;
			}
		case 'v': {
				char *endptr;
				errno = 0;
				ra_cvlan = strtoul(optarg, &endptr, 0);
				if (errno) {
					ectlno_setposixerror(errno);
					ectlno_printf("%s(),%d: strtoul(\"%s\"): %s\n", 
						__func__, __LINE__, optarg, strerror(errno));
					ectlfr_goto(fr);
				}
				if (ra_cvlan > 4094) {
					ectlno_setposixerror(EINVAL);
					ectlno_printf("%s(),%d: wrong vlan id: %u\n", __func__, __LINE__, ra_cvlan);
					ectlfr_goto(fr);
				}
				defined_ra_cvlan = 1;
			}
			break;
		case 'U':
			ra_ru = optarg;
			defined_ra_ru = 1;
			break;
		case 'x':
			f_hexdump = 1;
			break;
		case '?':
		default:
			usage();
		}
	}

#if 0
	if (iface)
		printf("        iface: %s\n", iface);
	if (defined_chaddr)
		printf("ra.ether_addr: %s\n", ether_ntoa(&ra_etheraddr));
	if (defined_ra_cport)
		printf("     ra.cport: %" PRIu16 "\n", ra_cport);
	printf("\n");
#endif

	if (iface) {
		if ((cap = pcap_open_live(iface, 1500, 1, 100, errbuf)) == NULL) {
			ectlno_seterror(E_PCAPOPEN);
			ectlno_printf("%s(),%d: pcap_open_live(): %s\n", __func__, __LINE__, errbuf);
			ectlfr_goto(fr);
		}
		ectlfr_ontrap(fr, L_1);
		if (pcap_datalink(cap) != DLT_EN10MB) {
			ectlno_seterror(E_NOTETHERIFACE);
			ectlno_printf("%s(),%d: Ethernet interface is required.\n", __func__, __LINE__);
			ectlfr_goto(fr);
		}
	} else if (ifile_name) {
		if ((cap = pcap_open_offline(ifile_name, errbuf)) == NULL) {
			ectlno_seterror(E_PCAPOPEN);
			ectlno_printf("%s(),%d: pcap_open_offline(%s): %s", 
				__func__, __LINE__, ifile_name, errbuf);
			ectlfr_goto(fr);
		}
		ectlfr_ontrap(fr, L_1);
	} else {
		ectlno_setposixerror(EINVAL);
		ectlno_printf("%s(),%d: Option -i or -r is mandatory.\n", __func__, __LINE__);
		ectlfr_goto(fr);
	}

	do {
/* [vlan XXXX and_]*[udp and (port bootpc or port bootps_]*/
#define FMT_FLTR_VLAN	"vlan XXXX and"
#define FMT_FLTR_DHCP	"udp and (port bootpc or port bootps)"

		char fltr[nvltags * sizeof FMT_FLTR_VLAN + sizeof FMT_FLTR_DHCP], *p = fltr;
		for (int i = 0; i < nvltags; i++) {
			if (!vltags[i])
				p += sprintf(p, "vlan and ");
			else
				p += sprintf(p, "vlan %d and ", vltags[i]);
			/* printf("[%s]\n", fltr); */
		}
		p += sprintf(p, FMT_FLTR_DHCP);
		printf("pcap filter: %s\n", fltr);

#if 0
		printf("fltr: %p, fltr_end: %p, p: %p\n", fltr, fltr + sizeof fltr, p);
		assert(p <= fltr + sizeof fltr);
#endif

		if (pcap_compile(cap, &fp, fltr, 0, 0) < 0) {
			ectlno_seterror(E_PCAPCOMPILE);
			ectlno_printf("%s(),%d: pcap_compile(): %s\n", __func__, __LINE__, pcap_geterr(cap));
			ectlfr_goto(fr);
		}
		if (pcap_setfilter(cap, &fp) < 0) {
			ectlno_seterror(E_PCAPSETFILTER);
			ectlno_printf("%s(),%d: pcap_setfilter(): %s\n", __func__, __LINE__, pcap_geterr(cap));
			pcap_freecode(&fp);
			ectlfr_goto(fr);
		}
	} while (0);

	if (pcap_loop(cap, -1, pcap_callback, (u_char *)cap) == -1) {
		ectlno_seterror(E_PCAPLOOP);
		ectlno_printf("%s(),%d: pcap_loop(%s): %s", __func__, __LINE__, iface, pcap_geterr(cap));
		ectlfr_goto(fr);
	}
	if (ectlno_iserror())
		ectlfr_goto(fr);

	pcap_close(cap);
	ectlno_end(ex);
	ectlfr_end(fr);
	return EXIT_SUCCESS;

L_1:	ectlfr_ontrap(fr, L_0);
	pcap_close(cap);
L_0:	ectlno_log();
	ectlno_clearmessage();
	ectlno_end(ex);
	ectlfr_end(fr);
	return EXIT_FAILURE;
}

static 
void 
pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) 
{
	struct ectlfr fr[1];
	struct ectlno ex[1];
	const uint8_t *cp = sp, *cp_end;
	pcap_t *volatile cap = (pcap_t *)user;
	struct ether_header *eh;
	uint16_t ether_type;
	int tags[8], ntags = 0;		/* [!] ntags может быть больше, чем размер массива tags */
	struct ip *ip;
	struct udphdr *udp;
	struct dhcphdr *dh;
	int dh_len;
	uint16_t sport, dport;
	struct servent *se;
	char *sport_name, sport_namebuf[8], *dport_name, dport_namebuf[8];
	char timestamp[40];	// timestamp on header
	char smac[20];		// mac address of origin
	char dmac[20];		// mac address of destination
	char sip[16];		// ip address of origin
	char dip[16];		// ip address of destination
	u_char optnum, optlen;
	const u_char *optdat, *optdat_end;
	struct dhcp *volatile dp = NULL;
	struct dhcpopt *opt82 = NULL;
	struct dhcpopt82_value *volatile optval = NULL;

	ectlfr_begin(fr, L_0);
	ectlno_begin(ex);

	if (h->caplen < ETHER_HDR_LEN) {
		ectlno_printf("%s(),%d: Short ethernet packet: %d bytes.\n", 
			__func__, __LINE__, h->caplen);
		ectlfr_goto(fr);
	}
	eh = (struct ether_header *)cp;
	cp += ETHER_HDR_LEN;

	ether_type = ntohs(eh->ether_type);
	if (ether_type == ETHERTYPE_VLAN) {
		cp = (const uint8_t *)&eh->ether_type;
		do {
			cp += 2;
			if (ntags < sizeof tags/sizeof tags[0])
				tags[ntags] = EVL_VLANOFTAG(ntohs(*(uint16_t *)cp));
			ntags++;
			cp += 2;
			ether_type = ntohs(*(uint16_t *)cp);
		} while (ether_type == ETHERTYPE_VLAN);
		cp += 2;
	}
	if (ether_type != ETHERTYPE_IP) { 
		ectlno_printf("%s(),%d: Non-IP packet: 0x%04x.\n", 
			__func__, __LINE__, ether_type);
		ectlfr_goto(fr);
	}

	if (h->caplen < cp - sp + sizeof(struct ip)) {
		ectlno_printf("%s(),%d: Short IPv4 packet: %d bytes.\n", 
			__func__, __LINE__, h->caplen);
		ectlfr_goto(fr);
	}
	ip = (struct ip *)cp;
	cp += ip->ip_hl * 4;

	if (ip->ip_v != IPVERSION) {
		ectlno_printf("%s(),%d: Non-IPv4 packet: %u (ip version)\n", 
			__func__, __LINE__, ip->ip_v);
		ectlfr_goto(fr);
	}
	if (ip->ip_p != IPPROTO_UDP) {
		ectlno_printf("%s(),%d: Non-UDP packet: %u (ip protocol)\n", 
			__func__, __LINE__, ip->ip_p);
		ectlfr_goto(fr);
	}

	if (h->caplen < cp - sp + sizeof(struct udphdr)) {
		ectlno_printf("%s(),%d: Short UDPv4 packet: %d bytes\n", 
			__func__, __LINE__, h->caplen);
		ectlfr_goto(fr);
	}
	udp = (struct udphdr *)cp;
	cp += sizeof(struct udphdr);

	do {
		struct timeval tp;
		size_t len;

		gettimeofday(&tp, NULL);
		len = strftime(timestamp, sizeof(timestamp), "%Y%m%d %H:%M:%S.", localtime(&tp.tv_sec));
		snprintf(timestamp + len, sizeof(timestamp) - len, "%03ld", tp.tv_usec / 1000);
	} while (0);

	strcpy(smac, ether_ntoa((struct ether_addr *)eh->ether_shost));
	strcpy(dmac, ether_ntoa((struct ether_addr *)eh->ether_dhost));

	strcpy(sip, inet_ntoa(ip->ip_src));
	strcpy(dip, inet_ntoa(ip->ip_dst));

	dh_len = ntohs(udp->uh_ulen);
	if (dh_len < sizeof(struct dhcphdr) + 4) {
		ectlno_printf("%s(),%d: Short UDPv4 header: %d bytes\n", 
			__func__, __LINE__, dh_len);
		ectlfr_goto(fr);
	}
	dh = (struct dhcphdr *)cp;

	/* cookie 63:82:53:63 */
	if (*(uint32_t *)dh->options != htonl(0x63825363)) {
		ectlno_printf("%s(),%d: Wrong cookie in DHCP packet options field.\n", 
			__func__, __LINE__);
		ectlfr_goto(fr);
	}

	sport = ntohs(udp->uh_sport);
	if (sport == IPPORT_BOOTPS)
		sport_name = "bootps";
	else if (sport == IPPORT_BOOTPC)
		sport_name = "bootpc";
	else {
		snprintf(sport_namebuf, sizeof sport_namebuf, "%u", sport);
		sport_name = sport_namebuf;
	}
	dport = ntohs(udp->uh_dport);
	if (dport == IPPORT_BOOTPS)
		dport_name = "bootps";
	else if (dport == IPPORT_BOOTPC)
		dport_name = "bootpc";
	else {
		snprintf(dport_namebuf, sizeof dport_namebuf, "%u", dport);
		dport_name = dport_namebuf;
	}

	if (defined_chaddr && (dh->htype != HTYPE_ETHERNET || dh->hlen != ETHER_ADDR_LEN ||
					memcmp(&chaddr, dh->chaddr, ETHER_ADDR_LEN)))
		ectlfr_goto(fr);

	cp_end = (u_char *)udp + udp->uh_ulen;

	dp = dhcp_decode(&cp, cp_end);
	ectlfr_ontrap(fr, L_1);

	opt82 = dhcpoptlst_find(dp->opts, DHCPOPT82_RELAYAGENTINFORMATION);
	if (opt82)
		optval = dhcpopt82_research(opt82);

	if (optval)
		switch (optval->type) {
			case DHCPOPT82_T_DEFAULT:
			case DHCPOPT82_T_IES1248:
			case DHCPOPT82_T_IES5000:
				if (!defined_ra_etheraddr && !defined_ra_cport && !defined_ra_cvlan)
					break;
				if ((defined_ra_etheraddr && !memcmp(&optval->def[0].ether, &ra_etheraddr, ETHER_ADDR_LEN)) &&
				    (defined_ra_cport && ra_cport == optval->def[0].port) &&
				    (defined_ra_cvlan && ra_cvlan == optval->def[0].vlanid))
					break;
				goto L_skip_show;
			case DHCPOPT82_T_CDRU:
				if (!defined_ra_ru && !defined_ra_cport && !defined_ra_cvlan)
					break;
				if ((defined_ra_ru && !strcmp(optval->cdru[0].str, ra_ru)) &&
				    (defined_ra_cport && ra_cport == optval->def[0].port) &&
				    (defined_ra_cvlan && ra_cvlan == optval->def[0].vlanid))
					break;
				goto L_skip_show;
			case DHCPOPT82_T_UNKNOWN:
				fputs("[!] UNKNOWN DHCP RA OPTION (option 82) FORMAT IN PACKET:\n", stdout);
				break;
		}
	else
		if (defined_ra_etheraddr || defined_ra_cvlan || defined_ra_cport || defined_ra_ru)
			goto L_skip_show;

L_show:
	fprintf(stdout, "%s %s > %s", timestamp, smac, dmac);
	if (ntags) {
		fprintf(stdout, " [%d", tags[0]);
		for (int i = 1; i < ntags; i++) {
			if (i == sizeof tags/sizeof tags[0]) {
				fprintf(stdout, ".[...]");
				break;
			}
			fprintf(stdout, ".%d", tags[i]);
		}
		fprintf(stdout, "]");
	}
	fprintf(stdout, " %s:%s > %s:%s\n", sip, sport_name, dip, dport_name);
	dhcp_show(dp, 2, stdout);
	if (optval) {
		switch (optval->type) {
			case DHCPOPT82_T_DEFAULT:
			case DHCPOPT82_T_IES1248:
			case DHCPOPT82_T_IES5000:
				fprintf(stdout, "\tvlanid: %" PRIu16 ", module: %" PRIu8 ", port: %" PRIu8 ", ether: %s\n", 
					optval->def[0].vlanid, optval->def[0].module, optval->def[0].port,
					ether_ntoa(&optval->def[0].ether));
				break;
			case DHCPOPT82_T_CDRU:
				fprintf(stdout, "\tvlanid: %" PRIu16 ", module: %" PRIu8 ", port: %" PRIu8 ", remote-id user: [%" PRIu8 "] \"%s\"\n", 
					optval->cdru[0].vlanid, optval->cdru[0].module, optval->cdru[0].port,
					optval->cdru[0].slen, optval->cdru[0].str);
				break;
			case DHCPOPT82_T_UNKNOWN:
				break;
		}
	}
	fprintf(stdout, "\n");
L_skip_show:
	if (optval)
		free(optval);

L_1:	ectlfr_ontrap(fr, L_0);
	dhcp_free(dp);
L_0:	if (ectlno_iserror()) {
		ectlno_setparenterror(ex);
		pcap_breakloop(cap);
	} else {
		ectlno_log();
		ectlno_clearmessage();
	}
	ectlno_end(ex);
	ectlfr_end(fr);
}

/* 00|72 65 71 75 65 73 74 65 64 20 61 64 64 72 65 73| requested addres
 * 10|73 20 6e 6f 74 20 61 76 61 69 6c 61 62 6c 65   | s not available
 */
static
void 
dumphexascii(const u_char *data, int len, int indent) 
{
	int nrows, nlastcols;

	if (!len)
		return;

	nrows = len / 16;
	nlastcols = len % 16;
	/* printf("len: %d, nrows: %d, nlastcols: %d\n", len, nrows, nlastcols); */

	for (int row = 0; row < nrows; row++) {
		printf("%*s%02x|%02x", indent, "", row * 16, *data);
		for (int col = 1; col < 16; col++)
			printf(" %02x", data[col]);
		printf("| ");
		for (int col = 0; col < 16; col++)
			printf("%c", isprint(data[col]) ? data[col] : '.');
		printf("\n");
		data += 16;
	}
	if (nlastcols) { 
		int col;

		printf("%*s%02x|%02x", indent, "", nrows * 16, *data);
		for (col = 1; col < nlastcols; col++)
			printf(" %02x", data[col]);
		for (; col < 16; col++)
			printf(" %2s", "");
		printf("| ");
		for (int col = 0; col < nlastcols; col++)
			printf("%c", isprint(data[col]) ? data[col] : '.');
		printf("\n");
	}
}

static
void 
dumphex(const u_char *data, int len, int indent) 
{
	int nrows, nlastcols;

	if (!len)
		return;

	nrows = len / 16;
	nlastcols = len % 16;

	for (int row = 0; row < nrows; row++) {
		printf("%*s%02x|%02x", indent, "", row * 16, *data);
		for (int col = 1; col < 16; col++)
			printf(" %02x", data[col]);
		printf("\n");
		data += 16;
	}
	if (nlastcols) { 
		printf("%*s%02x|%02x", indent, "", nrows * 16, *data);
		for (int col = 1; col < nlastcols; col++)
			printf(" %02x", data[col]);
		printf("\n");
	}
}



