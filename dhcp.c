#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include "foo.h"
#include "ip.h"

#include "dhcp.h"

DEFN_ERROR(E_DHCPOPTDESC,	"Wrong DHCP option description.")
DEFN_ERROR(E_DHCPOPTDESCDUP,	"DHCP option already defined.")
DEFN_ERROR(E_DHCPOPTDESCADD,	"Unable to add DHCP option (rbtree_insert() failed).")
DEFN_ERROR(E_DHCPOPTDECODE,	"DHCP option decoding error occured.\n")
DEFN_ERROR(E_DHCPENDOFDATA,	"Unexpected end of received DHCP data.")
DEFN_ERROR(E_DHCPDATAINCOMPLETE,"DHCP data is incomplete.")
DEFN_ERROR(E_DHCPWRONGCOOKIE,	"DHCP packet has wrong cookie.")

void
printHexString(const uint8_t *data, int len, const char *sep)
{
        if (len) {
                printf("%02x", data[0]);
                for (int i = 1; i < len; i++)
                        printf("%s%02x", sep, data[i]);
        }
}
void
printString(const uint8_t *data, int len)
{
        for (const char *p = (const char *)data; p < (char *)data + len; p++)
                printf("%c", isprint(*p) ? *p : '.');
}
void
printStringAscii(const uint8_t *data, int len)
{
        for (const char *p = (const char *)data; p < (char *)data + len; p++)
                printf("%c", (isascii(*p) && isprint(*p)) ? *p : '.');
}

const char *
dhcp_htype(uint8_t htype)
{
        static const char *htypes[] = {		/* RFC1700 */
                [HTYPE_ETHERNET]        = "Ethernet",
                [HTYPE_EXPETHERNET]     = "Experimental Ethernet",
                [HTYPE_AX25]            = "Amateur Radio AX.25",
                [HTYPE_PRONET]          = "Proteon ProNET Token Ring",
                [HTYPE_CHAOS]           = "Chaos",
                [HTYPE_IEEE802]         = "IEEE 802 Networks",
                [HTYPE_ARCNET]          = "ARCNET",
                [HTYPE_HYPERCHANNEL]    = "Hyperchannel",
                [HTYPE_LANSTAR]         = "Lanstar",
                [HTYPE_AUTONETSHORTADDR]= "Autonet Short Address",
                [HTYPE_LOCALTALK]       = "LocalTalk",
                [HTYPE_LOCALNET]        = "LocalNet (IBM PCNet or SYTEK LocalNET)",
                [HTYPE_ULTRALINK]       = "Ultra link",
                [HTYPE_SMDS]            = "SMDS",
                [HTYPE_FRAMERELAY]      = "Frame Relay",
                [HTYPE_ATM16]           = "ATM",
                [HTYPE_HDLC]            = "HDLC",
                [HTYPE_FIBRECHANNEL]    = "Fibre Channel",
                [HTYPE_ATM19]           = "ATM",
                [HTYPE_SERIALLINE]      = "Serial Line",
                [HTYPE_ATM21]           = "ATM"
        };
        const char *s = NULL;
        if (htype > 0 && htype < sizeof htypes/sizeof htypes[0])
                s = htypes[htype];
        return s;
}


static
int
dhcpopt_descriptor_cmp(const struct dhcpopt_descriptor *a, const struct dhcpopt_descriptor *b)
{
	return (int)a->code - (int)b->code;
}
static
void 
dhcpopt_descriptor_free(struct dhcpopt_descriptor *optd)
{
	if (optd->fini)
		optd->fini(optd);
}
static inline
void
dhcpopt_dtree_destroy(struct rbtree *dtree)
{
	rbtree_destroy(dtree, DFREE_CAST(dhcpopt_descriptor_free));
}
static
struct rbtree *
dhcpopt_dtree_create(struct dhcpopt_descriptor **ddtab, int n)
{
	struct ectlfr fr[1];
	struct rbtree *volatile dtree;

	ectlfr_begin(fr, L_0);

	dtree = rbtree_create(DCMP_CAST(dhcpopt_descriptor_cmp));
	ectlfr_ontrap(fr, L_1);

	for (int i = 0; i < n; i++) {
		struct rbglue *g, *cg;

		if (ddtab[i]->flags & DHCPOPT_F_NOVALUE) {
			if (ddtab[i]->elsz || ddtab[i]->min || ddtab[i]->max) {
				ectlno_seterror(E_DHCPOPTDESC);
				ectlno_printf("%s(),%d: {%s} dhcp option %" PRIu8 " %s is no value. elsz, min and max fields must be zero.\n", 
					__func__, __LINE__, error_name(ectlno_error), ddtab[i]->code, ddtab[i]->name);
				ectlfr_goto(fr);
			}
		} else if (ddtab[i]->flags & DHCPOPT_F_NOLENGTH) {
			/* XXX: Нет поля длины, но есть поле данных. Я такой опции не встречал,
			 * но в принципе такое возможно (код опции определяет фиксированную для
			 * себя длину поля данных. почему бы и нет?).
			 */
			if (ddtab[i]->min != ddtab[i]->elsz || ddtab[i]->max != ddtab[i]->elsz) {
				ectlno_seterror(E_DHCPOPTDESC);
				ectlno_printf("%s(),%d: {%s} dhcp option %" PRIu8 " %s defined as DHCPOPT_F_NOLENGTH only, "
					"but elsz != min or elsz != max (strict dhcpopt_descriptor).\n",
					__func__, __LINE__, error_name(ectlno_error), ddtab[i]->code, ddtab[i]->name);
				ectlfr_goto(fr);
			}
		} else {
			if (!ddtab[i]->elsz) {
				ectlno_seterror(E_DHCPOPTDESC);
				ectlno_printf("%s(),%d: {%s} dhcp option %" PRIu8 " %s: elsz (%" PRIu8 ") is 0.\n", 
					__func__, __LINE__, error_name(ectlno_error), 
					ddtab[i]->code, ddtab[i]->name, ddtab[i]->elsz);
				ectlfr_goto(fr);
			}
			if (ddtab[i]->min % ddtab[i]->elsz) {
				ectlno_seterror(E_DHCPOPTDESC);
				ectlno_printf("%s(),%d: {%s} dhcp option %" PRIu8 " %s: min (%" PRIu8 ") "
					"shall be the multiple elsz (%" PRIu8 ").\n", 
					__func__, __LINE__, error_name(ectlno_error), 
					ddtab[i]->code, ddtab[i]->name, ddtab[i]->min, ddtab[i]->elsz);
				ectlfr_goto(fr);
			}
			if (ddtab[i]->max % ddtab[i]->elsz) {
				ectlno_seterror(E_DHCPOPTDESC);
				ectlno_printf("%s(),%d: {%s} dhcp option %" PRIu8 " %s: max (%" PRIu8 ") "
					"shall be the multiple elsz (%" PRIu8 ").\n", 
					__func__, __LINE__, error_name(ectlno_error),
					ddtab[i]->code, ddtab[i]->name, ddtab[i]->max, ddtab[i]->elsz);
				ectlfr_goto(fr);
			}
			if (ddtab[i]->max && ddtab[i]->max < ddtab[i]->min) {
				ectlno_seterror(E_DHCPOPTDESC);
				ectlno_printf("%s(),%d: {%s} dhcp option %" PRIu8 " %s: "
					"condition max (%" PRIu8 ") < min(%" PRIu8 ") is wrong.\n", 
					__func__, __LINE__, error_name(ectlno_error), ddtab[i]->code, ddtab[i]->name, ddtab[i]->max, ddtab[i]->min);
				ectlfr_goto(fr);
			}
		}

		if (ddtab[i]->init)
			ddtab[i]->init(ddtab[i]);

		g = rbtree_insert(dtree, ddtab[i], &cg);
		if (!g) {
			if (cg) {
				ectlno_seterror(E_DHCPOPTDESCDUP);
				ectlno_printf("%s(),%d: {%s} dhcpopt_description collision for code %d.\n", 
					__func__, __LINE__, error_name(ectlno_error), ddtab[i]->code);
			} else {
				ectlno_seterror(E_DHCPOPTDESCADD);
				ectlno_printf("%s(),%d: {%s} rbtree_insert() error. %s\n", 
					__func__, __LINE__, error_name(ectlno_error), error_desc(ectlno_error));
			}
			ectlfr_goto(fr);
		}
	}

	ectlfr_end(fr);
	return dtree;

L_1:	ectlfr_ontrap(fr, L_0);
	dhcpopt_dtree_destroy(dtree);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}


static struct rbtree *dhcpopt_dtree = NULL;

struct dhcpopt_descriptor *
dhcp_getoptdescriptor(struct rbtree *dtree, int code)
{
	struct dhcpopt_descriptor dd, *ddp;
	struct rbglue *g;

	if (!dtree)
		dtree = dhcpopt_dtree;
	dd.code = code;
	ddp = NULL;
	g = rbtree_find(dtree, &dd);
	if (g)
		ddp = (struct dhcpopt_descriptor *)rbglue_dptr(g);
	return ddp;
}
const char *
dhcp_option(struct rbtree *dtree, uint8_t code)
{
	const char *s = NULL;
	struct dhcpopt_descriptor *optd;

	optd = dhcp_getoptdescriptor(dtree, code);
	if (optd)
		s = optd->name;
	return s;
}


/* Ширина поля вывода названия опции для функций dhcpopt_show_XXX().
 * Есть опции с названиями длиннее чем здесь выбрано, просто они должны
 * редко встречаться и мы закрываем глаза на небольшой сдвиг вывода.
 */
#define DHCPOPTNAME_MAX		40

static
struct dhcpopt *
dhcpopt_decode_novalue(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt *opt;

	opt = MALLOC(sizeof(struct dhcpopt));
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = 0;
	(*curp)++;
	return opt;
}

static 
struct dhcpopt *
dhcpopt_decode_u8(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp) 
{
	struct dhcpopt *opt;
	uint8_t length;
	int sz;

	length = *(*curp + 1);
	sz = offsetof(struct dhcpopt, u8) + length;
	opt = MALLOC(sz);
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = length;
	memcpy(opt->u8, *curp + 2, length);
	*curp += 2 + length;
	return opt;
}
#define dhcpopt_decode_i8	dhcpopt_decode_u8

static
const char *
dhcpopt_enumfn_u8_no_yes(struct dhcpopt_descriptor *optd __unused, void *value)
{
	const char *s = NULL;
	switch (*(uint8_t *)value) {
		case 0:
			s = "no";
			break;
		case 1:
			s = "yes";
			break;
	}
	return s;
}

static 
struct dhcpopt *
dhcpopt_decode_u16(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt *opt;
	uint8_t length, n;
	int sz;

	length = *(*curp + 1);
	n = length / sizeof(uint16_t);
	sz = offsetof(struct dhcpopt, u16) + n * sizeof(uint16_t);
	opt = MALLOC(sz);
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = length;
	memcpy(opt->u16, *curp + 2, length);
	for (int i = 0; i < n; i++)
		opt->u16[i] = ntohs(opt->u16[i]);
	*curp += 2 + length;
	return opt;
}
#define dhcpopt_decode_i16	dhcpopt_decode_u16

static 
struct dhcpopt *
dhcpopt_decode_u32(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt *opt;
	uint8_t length, n;
	int sz;

	length = *(*curp + 1);
	n = length / sizeof(uint32_t);
	sz = offsetof(struct dhcpopt, u32) + n * sizeof(uint32_t);
	opt = MALLOC(sz);
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = length;
	memcpy(opt->u32, *curp + 2, length);
	for (int i = 0; i < n; i++)
		opt->u32[i] = ntohl(opt->u32[i]);
	*curp += 2 + length;
	return opt;
}
#define dhcpopt_decode_i32	dhcpopt_decode_u32

static 
struct dhcpopt *
dhcpopt_decode_u32x2(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt *opt;
	uint8_t length, n;
	int sz;

	length = *(*curp + 1);
	n = length / sizeof(uint32_t [2]);
	sz = offsetof(struct dhcpopt, u32x2) + n * sizeof(uint32_t [2]);
	opt = MALLOC(sz);
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = length;
	memcpy(opt->u32x2, *curp + 2, length);
	for (int i = 0; i < n; i++) {
		opt->u32x2[i][0] = ntohl(opt->u32x2[i][0]);
		opt->u32x2[i][1] = ntohl(opt->u32x2[i][1]);
	}
	*curp += 2 + length;
	return opt;
}

static
struct dhcpopt *
dhcpopt_decode_s(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt *opt;
	uint8_t length;
	int n;

	length = *(*curp + 1);
	n = offsetof(struct dhcpopt, s) + length + 1;
	opt = MALLOC(n);
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = length;
	memcpy(opt->value, *curp + 2, length);
	opt->value[length] = 0;
	*curp += 2 + length;
	return opt;
}

void
dhcp_decode_opts(struct dhcpoptlst *lst, struct rbtree *dtree, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt *opt;

	if (!dtree)
		dtree = dhcpopt_dtree;
	while (*curp < endp) {
		opt = dhcpopt_decode(dtree, curp, endp);
		if (dhcpopt_ispad(opt)) {
			dhcpopt_free(opt);
			continue;
		}
		if (dhcpopt_isend(opt)) {
			dhcpopt_free(opt);
			break;
		}
		STAILQ_INSERT_TAIL(lst, opt, ent);
	}
}
void
dhcp_free_opts(struct dhcpoptlst *lst)
{
	for (struct dhcpopt *p = STAILQ_FIRST(lst), *q; p; p = q) {
		q = STAILQ_NEXT(p, ent);
		dhcpopt_free(p);
	}
	STAILQ_INIT(lst);
}

static
struct dhcpopt *
dhcpopt_decode_lst(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp)
{
	struct ectlfr fr[1];
	struct dhcpopt *volatile opt;
	uint8_t length;
	int n;
	const uint8_t *p;

	length = (*curp)[1];
	n = offsetof(struct dhcpopt, lst) + sizeof(struct dhcpoptlst [1]);
	opt = MALLOC(n);
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = length;
	ectlfr_begin(fr, L_1);

	STAILQ_INIT(opt->lst);
	p = *curp + 2;
	dhcp_decode_opts(opt->lst, optd->dtree, &p, p + length);
	*curp += 2 + length;

	ectlfr_end(fr);
	return opt;

L_1:	ectlfr_ontrap(fr, L_0);
	dhcpopt_free(opt);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}
static
void
dhcpopt_free_lst(struct dhcpopt *opt)
{
	dhcp_free_opts(opt->lst);
	free(opt);
}
static 
void
dhcpopt_show_lst(struct dhcpopt *opt, int indent, FILE *fp)
{
	struct dhcpopt *p;

	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s\n", 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name);
	STAILQ_FOREACH(p, opt->lst, ent)
		dhcpopt_show(p, indent + 2, fp);
}

static
void
dhcpopt_show_novalue(struct dhcpopt *opt, int indent, FILE *fp)
{
	fprintf(fp, "%*soption %3" PRIu8 " (  0) %s\n", 
		indent, "", opt->code, opt->optd->name);
}

static
void
dhcpopt_show_u8(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length;
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %" PRIu8, 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, opt->u8[0]);
	if (opt->optd->enumfn) {
		const char *s;
		s = opt->optd->enumfn(opt->optd, opt->u8);
		if (!s)
			s = "???";
		fprintf(fp, " %s\n", s);
		for (int i = 1; i < n; i++) {
			s = opt->optd->enumfn(opt->optd, opt->u8 + i);
			if (!s)
				s = "???";
			fprintf(fp, "%*s%*s %3s  %3s  %*s %" PRIu8 " %s\n", 
				indent, "", (int)sizeof "option" - 1, "", "", "", DHCPOPTNAME_MAX, "",
				opt->u8[i], s);
		}
	} else {
		for (int i = 1; i < n; i++)
			fprintf(fp, ", %" PRIu8, opt->u8[i]);
		if (opt->optd->metric)
			fprintf(fp, " (%s)", opt->optd->metric);
		fprintf(fp, "\n");
	}
}
static
void
dhcpopt_show_i8(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length;
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %" PRIi8, 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, opt->i8[0]);
	for (int i = 1; i < n; i++)
		fprintf(fp, ", %" PRIi8, opt->i8[i]);
	if (opt->optd->metric)
		fprintf(fp, " (%s)\n", opt->optd->metric);
	else
		fprintf(fp, "\n");
}
static
void
dhcpopt_show_x8(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length;
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %02" PRIx8, 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, opt->u8[0]);
	for (int i = 1; i < n; i++)
		fprintf(fp, ":%02" PRIx8, opt->u8[i]);
	if (opt->optd->metric)
		fprintf(fp, " (%s)\n", opt->optd->metric);
	else
		fprintf(fp, "\n");
}

static
void
dhcpopt_show_u16(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length / sizeof(uint16_t);
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %" PRIu16, 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, opt->u16[0]);
	if (opt->optd->enumfn) {
		fprintf(fp, " %s\n", opt->optd->enumfn(opt->optd, opt->u16));
		for (int i = 1; i < n; i++)
			fprintf(fp, "%*s%*s %3s  %3s  %*s %" PRIu16 " %s\n", 
				indent, "", (int)sizeof "option" - 1, "", "", "", DHCPOPTNAME_MAX, "",
				opt->u16[i], opt->optd->enumfn(opt->optd, opt->u16 + i));
	} else {
		for (int i = 1; i < n; i++)
			fprintf(fp, ", %" PRIu16, opt->u16[i]);
		if (opt->optd->metric)
			fprintf(fp, " (%s)", opt->optd->metric);
		fprintf(fp, "\n");
	}
}
static
void
dhcpopt_show_i16(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length / sizeof(int16_t);
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %" PRIi16, 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, opt->i16[0]);
	for (int i = 1; i < n; i++)
		fprintf(fp, ", %" PRIi16, opt->i16[i]);
	if (opt->optd->metric)
		fprintf(fp, " (%s)\n", opt->optd->metric);
	else
		fprintf(fp, "\n");
}

static
void
dhcpopt_show_u32(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length / sizeof(uint32_t);
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %" PRIu32, 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, opt->u32[0]);
	for (int i = 1; i < n; i++)
		fprintf(fp, ", %" PRIu32, opt->u32[i]);
	if (opt->optd->metric)
		fprintf(fp, " (%s)\n", opt->optd->metric);
	else
		fprintf(fp, "\n");
}
static
void
dhcpopt_show_i32(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length / sizeof(int32_t);
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %" PRIi32, 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, opt->i32[0]);
	for (int i = 1; i < n; i++)
		fprintf(fp, ", %" PRIi32, opt->i32[i]);
	if (opt->optd->metric)
		fprintf(fp, " (%s)\n", opt->optd->metric);
	else
		fprintf(fp, "\n");
}
static
void
dhcpopt_show_u32_ip(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length / sizeof(uint32_t);
	union { uint8_t u8[4]; uint32_t ip; } u;

	u.ip = htonl(opt->u32[0]);
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8, 
		indent, "", opt->code, opt->length, DHCPOPTNAME_MAX, opt->optd->name, 
		u.u8[0], u.u8[1], u.u8[2], u.u8[3]);
	for (int i = 1; i < n; i++) {
		u.ip = htonl(opt->u32[i]);
		fprintf(fp, ", %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
			u.u8[0], u.u8[1], u.u8[2], u.u8[3]);
	}
	fprintf(fp, "\n");
}
static
void
dhcpopt_show_u32x2_ip_and_mask(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length / sizeof(uint32_t [2]);
	union { uint8_t u8[4]; uint32_t ip; } u[2];

	u[0].ip = htonl(opt->u32x2[0][0]);
	u[1].ip = htonl(opt->u32x2[0][1]);
	fprintf(fp, "%*soption %3"PRIu8" (%3"PRIu8") %-*s %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"/%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8, 
		indent, "", opt->code, opt->length, DHCPOPTNAME_MAX, opt->optd->name, 
		u[0].u8[0], u[0].u8[1], u[0].u8[2], u[0].u8[3],
		u[1].u8[0], u[1].u8[1], u[1].u8[2], u[1].u8[3]);
	for (int i = 1; i < n; i++) {
		u[0].ip = htonl(opt->u32x2[i][0]);
		u[1].ip = htonl(opt->u32x2[i][1]);
		fprintf(fp, ", %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"/%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
			u[0].u8[0], u[0].u8[1], u[0].u8[2], u[0].u8[3],
			u[1].u8[0], u[1].u8[1], u[1].u8[2], u[1].u8[3]);
	}
	fprintf(fp, "\n");
}

static
void
dhcpopt_show_s(struct dhcpopt *opt, int indent, FILE *fp)
{
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s ", 
		indent, "", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name);
        for (const char *p = opt->s; p < opt->s + opt->length; p++)
                fprintf(fp, "%c", (isascii(*p) && isprint(*p)) ? *p : '.');
	fprintf(fp, "\n");
}



#if 0
3.1. Pad Option

   The pad option can be used to cause subsequent fields to align on
   word boundaries.

   The code for the pad option is 0, and its length is 1 octet.

    Code
   +-----+
   |  0  |
   +-----+
#endif 
static struct dhcpopt_descriptor dhcpoptd0_pad[1] = {{
		.name	= "Pad",
		.flags	= DHCPOPT_F_NOLENGTH|DHCPOPT_F_NOVALUE|DHCPOPT_F_PAD,
		.code	= 0,
		.elsz	= 0,
		.min	= 0,
		.max	= 0,
		.metric = NULL,
		.decode = dhcpopt_decode_novalue,
		.free   = NULL,
		.show	= dhcpopt_show_novalue,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.3. Subnet Mask

   The subnet mask option specifies the client's subnet mask as per RFC
   950 [5].

   If both the subnet mask and the router option are specified in a DHCP
   reply, the subnet mask option MUST be first.

   The code for the subnet mask option is 1, and its length is 4 octets.

    Code   Len        Subnet Mask
   +-----+-----+-----+-----+-----+-----+
   |  1  |  4  |  m1 |  m2 |  m3 |  m4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd1_subnet_mask[1] = {{
		.name	= "Subnet Mask",
		.flags	= 0,
		.code	= 1,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.4. Time Offset

   The time offset field specifies the offset of the client's subnet in
   seconds from Coordinated Universal Time (UTC).  The offset is
   expressed as a two's complement 32-bit integer.  A positive offset
   indicates a location east of the zero meridian and a negative offset
   indicates a location west of the zero meridian.

   The code for the time offset option is 2, and its length is 4 octets.

    Code   Len        Time Offset
   +-----+-----+-----+-----+-----+-----+
   |  2  |  4  |  n1 |  n2 |  n3 |  n4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd2_time_offset[1] = {{
		.name	= "Time Offset",
		.flags	= 0,
		.code	= 2,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= "seconds",
		.decode	= dhcpopt_decode_i32,
		.free   = NULL,
		.show	= dhcpopt_show_i32,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.5. Router Option

   The router option specifies a list of IP addresses for routers on the
   client's subnet.  Routers SHOULD be listed in order of preference.

   The code for the router option is 3.  The minimum length for the
   router option is 4 octets, and the length MUST always be a multiple
   of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  3  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd3_routers[1] = {{
		.name	= "Routers",
		.flags	= 0,
		.code	= 3,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.6. Time Server Option

   The time server option specifies a list of RFC 868 [6] time servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the time server option is 4.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  4  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd4_time_server[1] = {{
		.name	= "Time Server",
		.flags	= 0,
		.code	= 4,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};



#if 0
3.7. Name Server Option

   The name server option specifies a list of IEN 116 [7] name servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the name server option is 5.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  5  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd5_name_server[1] = {{
		.name	= "Name Server",
		.flags	= 0,
		.code	= 5,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.8. Domain Name Server Option

   The domain name server option specifies a list of Domain Name System
   (STD 13, RFC 1035 [8]) name servers available to the client.  Servers
   SHOULD be listed in order of preference.

   The code for the domain name server option is 6.  The minimum length
   for this option is 4 octets, and the length MUST always be a multiple
   of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  6  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd6_dns_server[1] = {{
		.name	= "DNS Server",
		.flags	= 0,
		.code	= 6,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.9. Log Server Option

   The log server option specifies a list of MIT-LCS UDP log servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the log server option is 7.  The minimum length for this
   option is 4 octets, and the length MUST always be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  7  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd7_log_server[1] = {{
		.name	= "Log Server",
		.flags	= 0,
		.code	= 7,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};



#if 0
3.10. Cookie Server Option

   The cookie server option specifies a list of RFC 865 [9] cookie
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for the log server option is 8.  The minimum length for this
   option is 4 octets, and the length MUST always be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  8  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd8_cookie_server[1] = {{
		.name	= "Cookie Server",
		.flags	= 0,
		.code	= 8,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.11. LPR Server Option

   The LPR server option specifies a list of RFC 1179 [10] line printer
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for the LPR server option is 9.  The minimum length for this
   option is 4 octets, and the length MUST always be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  9  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd9_lpr_server[1] = {{
		.name	= "LPR Server",
		.flags	= 0,
		.code	= 9,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.12. Impress Server Option

   The Impress server option specifies a list of Imagen Impress servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the Impress server option is 10.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  10 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd10_impress_server[1] = {{
		.name	= "Impress Server",
		.flags	= 0,
		.code	= 10,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.13. Resource Location Server Option

   This option specifies a list of RFC 887 [11] Resource Location
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for this option is 11.  The minimum length for this option
   is 4 octets, and the length MUST always be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  11 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd11_resource_location_server[1] = {{
		.name	= "Resource Location Server",
		.flags	= 0,
		.code	= 11,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.14. Host Name Option

   This option specifies the name of the client.  The name may or may
   not be qualified with the local domain name (see section 3.17 for the
   preferred way to retrieve the domain name).  See RFC 1035 for
   character set restrictions.

   The code for this option is 12, and its minimum length is 1.

    Code   Len                 Host Name
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  12 |  n  |  h1 |  h2 |  h3 |  h4 |  h5 |  h6 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd12_host_name[1] = {{
		.name	= "Host Name",
		.flags	= 0,
		.code	= 12,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free   = NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.15. Boot File Size Option

   This option specifies the length in 512-octet blocks of the default
   boot image for the client.  The file length is specified as an
   unsigned 16-bit integer.

   The code for this option is 13, and its length is 2.

    Code   Len   File Size
   +-----+-----+-----+-----+
   |  13 |  2  |  l1 |  l2 |
   +-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd13_boot_file_size[1] = {{
		.name	= "Boot File Size",
		.flags	= 0,
		.code	= 13,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= "512-octet blocks",
		.decode	= dhcpopt_decode_u16,
		.free   = NULL,
		.show	= dhcpopt_show_u16,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.16. Merit Dump File

   This option specifies the path-name of a file to which the client's
   core image should be dumped in the event the client crashes.  The
   path is formatted as a character string consisting of characters from
   the NVT ASCII character set.

   The code for this option is 14.  Its minimum length is 1.

    Code   Len      Dump File Pathname
   +-----+-----+-----+-----+-----+-----+---
   |  14 |  n  |  n1 |  n2 |  n3 |  n4 | ...
   +-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd14_merit_dump_file[1] = {{
		.name	= "Merit Dump File",
		.flags	= 0,
		.code	= 14,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free   = NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.17. Domain Name

   This option specifies the domain name that client should use when
   resolving hostnames via the Domain Name System.

   The code for this option is 15.  Its minimum length is 1.

    Code   Len        Domain Name
   +-----+-----+-----+-----+-----+-----+--
   |  15 |  n  |  d1 |  d2 |  d3 |  d4 |  ...
   +-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd15_domain_name[1] = {{
		.name	= "Domain Name",
		.flags	= 0,
		.code	= 15,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free   = NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.18. Swap Server

   This specifies the IP address of the client's swap server.

   The code for this option is 16 and its length is 4.

    Code   Len    Swap Server Address
   +-----+-----+-----+-----+-----+-----+
   |  16 |  n  |  a1 |  a2 |  a3 |  a4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd16_swap_server[1] = {{
		.name	= "Swap Server",
		.flags	= 0,
		.code	= 16,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.19. Root Path

   This option specifies the path-name that contains the client's root
   disk.  The path is formatted as a character string consisting of
   characters from the NVT ASCII character set.

   The code for this option is 17.  Its minimum length is 1.

    Code   Len      Root Disk Pathname
   +-----+-----+-----+-----+-----+-----+---
   |  17 |  n  |  n1 |  n2 |  n3 |  n4 | ...
   +-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd17_root_path[1] = {{
		.name	= "Root Path",
		.flags	= 0,
		.code	= 17,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free   = NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3.20. Extensions Path

   A string to specify a file, retrievable via TFTP, which contains
   information which can be interpreted in the same way as the 64-octet
   vendor-extension field within the BOOTP response, with the following
   exceptions:

          - the length of the file is unconstrained;
          - all references to Tag 18 (i.e., instances of the
            BOOTP Extensions Path field) within the file are
            ignored.

   The code for this option is 18.  Its minimum length is 1.

    Code   Len      Extensions Pathname
   +-----+-----+-----+-----+-----+-----+---
   |  18 |  n  |  n1 |  n2 |  n3 |  n4 | ...
   +-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd18_extensions_path[1] = {{
		.name	= "Extensions Path",
		.flags	= 0,
		.code	= 18,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric = NULL,
		.decode	= dhcpopt_decode_s,
		.free   = NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4.1. IP Forwarding Enable/Disable Option

   This option specifies whether the client should configure its IP
   layer for packet forwarding.  A value of 0 means disable IP
   forwarding, and a value of 1 means enable IP forwarding.

   The code for this option is 19, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  19 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd19_ip_forwarding[1] = {{
		.name	= "IP Forwarding",
		.flags	= 0,
		.code	= 19,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4.2. Non-Local Source Routing Enable/Disable Option

   This option specifies whether the client should configure its IP
   layer to allow forwarding of datagrams with non-local source routes
   (see Section 3.3.5 of [4] for a discussion of this topic).  A value
   of 0 means disallow forwarding of such datagrams, and a value of 1
   means allow forwarding.

   The code for this option is 20, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  20 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd20_non_local_source_routing[1] = {{
		.name	= "Non-Local Source Routing",
		.flags	= 0,
		.code	= 20,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4.3. Policy Filter Option

   This option specifies policy filters for non-local source routing.
   The filters consist of a list of IP addresses and masks which specify
   destination/mask pairs with which to filter incoming source routes.

   Any source routed datagram whose next-hop address does not match one
   of the filters should be discarded by the client.

   See [4] for further information.

   The code for this option is 21.  The minimum length of this option is
   8, and the length MUST be a multiple of 8.

    Code   Len         Address 1                  Mask 1
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
   |  21 |  n  |  a1 |  a2 |  a3 |  a4 |  m1 |  m2 |  m3 |  m4 |
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
           Address 2                  Mask 2
   +-----+-----+-----+-----+-----+-----+-----+-----+---
   |  a1 |  a2 |  a3 |  a4 |  m1 |  m2 |  m3 |  m4 | ...
   +-----+-----+-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd21_policy_filter[1] = {{
		.name	= "Policy Filter",
		.flags	= 0,
		.code	= 21,
		.elsz	= 8,
		.min	= 8,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32x2,
		.free   = NULL,
		.show	= dhcpopt_show_u32x2_ip_and_mask,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4.4. Maximum Datagram Reassembly Size

   This option specifies the maximum size datagram that the client
   should be prepared to reassemble.  The size is specified as a 16-bit
   unsigned integer.  The minimum value legal value is 576.

   The code for this option is 22, and its length is 2.

    Code   Len      Size
   +-----+-----+-----+-----+
   |  22 |  2  |  s1 |  s2 |
   +-----+-----+-----+-----+
#endif
#if 0
static
int
dhcpopt22_chkval(union dhcpopt_value *value)
{
	if (value->u16[0] < 576)
		syslog(LOG_WARNING, "%s(),%d: <%" PRIu8 " %s, %" PRIu8 "> u16 = %" PRIu16 ":"
			" The minimum legal value is 576 (rfc).",
			__func__, __LINE__, 22, dhcp_option(22), 2, value->u16[0]);
	return 0;
}
#endif
struct dhcpopt_descriptor dhcpoptd22_max_datagram_reassembly_size[1] = {{
		.name	= "Maximum Datagram Reassembly Size",
		.flags	= 0,
		.code	= 22,
		.elsz	= 2,
		.min	= 2,
		.max	= 2,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u16,
		.free   = NULL,
		.show	= dhcpopt_show_u16,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4.5. Default IP Time-to-live

   This option specifies the default time-to-live that the client should
   use on outgoing datagrams.  The TTL is specified as an octet with a
   value between 1 and 255.

   The code for this option is 23, and its length is 1.

    Code   Len   TTL
   +-----+-----+-----+
   |  23 |  1  | ttl |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd23_default_ip_ttl[1] = {{
		.name	= "Deafult IP TTL",
		.flags	= 0,
		.code	= 23,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4.6. Path MTU Aging Timeout Option

   This option specifies the timeout (in seconds) to use when aging Path
   MTU values discovered by the mechanism defined in RFC 1191 [12].  The
   timeout is specified as a 32-bit unsigned integer.

   The code for this option is 24, and its length is 4.

    Code   Len           Timeout
   +-----+-----+-----+-----+-----+-----+
   |  24 |  4  |  t1 |  t2 |  t3 |  t4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd24_path_mtu_aging_timeout[1] = {{
		.name	= "Path MTU Aging Timeout",
		.flags	= 0,
		.code	= 24,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= "seconds",
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4.7. Path MTU Plateau Table Option

   This option specifies a table of MTU sizes to use when performing
   Path MTU Discovery as defined in RFC 1191.  The table is formatted as
   a list of 16-bit unsigned integers, ordered from smallest to largest.
   The minimum MTU value cannot be smaller than 68.

   The code for this option is 25.  Its minimum length is 2, and the
   length MUST be a multiple of 2.

    Code   Len     Size 1      Size 2
   +-----+-----+-----+-----+-----+-----+---
   |  25 |  n  |  s1 |  s2 |  s1 |  s2 | ...
   +-----+-----+-----+-----+-----+-----+---
#endif
#if 0
static 
struct dhcpopt *
dhcpopt25_decode(uint8_t code, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt_u16a *opt;
	uint8_t length, n;
	uint16_t value;
	int optsz;

	opt = NULL;
	length = *(*curp + 1);
	n = length / 2;

	value = ntohs(*(uint16_t *)(*curp + 2));
	if (value < 68)
		syslog(LOG_WARNING, "%s(),%d: <%" PRIu8 " %s, u16[0] = %" PRIu16 ">: The minimum legal value is 576.",
			__func__, __LINE__, code, dhcp_option(code), value);
	for (int i = 1; i < n; i++) {
		uint16_t v = ntohs(*(uint16_t *)(*curp + 2 + 2*i));
		if (v < value)
			syslog(LOG_WARNING, "%s(),%d: <%" PRIu8 " %s, %" PRIu8 ">: u16[%d] = %" PRIu16 " > u16[%d] = %" PRIu16 ">:"
				" The table must be ordered from smallest to largest.", 
				__func__, __LINE__, code, dhcp_option(code), length, i-1, value, i, v);
		value = v;
	}

	optsz = offsetof(struct dhcpopt_u16a, u16) + n * sizeof(uint16_t);
	opt = MALLOC(optsz);
	opt->flags = 0;
	opt->code = code;
	opt->length = length;
	opt->n = n;
	for (int i = 0; i < n; i++)
		opt->u16[i] = ntohs(*(uint16_t *)(*curp + 2 + 2*i));
	*curp += 2 + length;
	return (struct dhcpopt *)opt;
}
#endif
struct dhcpopt_descriptor dhcpoptd25_path_mtu_plateau_table[1] = {{
		.name	= "Path MTU Plateau Table",
		.flags	= 0,
		.code	= 25,
		.elsz	= 2,
		.min	= 2,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u16,
		.free   = NULL,
		.show	= dhcpopt_show_u16,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.1. Interface MTU Option

   This option specifies the MTU to use on this interface.  The MTU is
   specified as a 16-bit unsigned integer.  The minimum legal value for
   the MTU is 68.

   The code for this option is 26, and its length is 2.

    Code   Len      MTU
   +-----+-----+-----+-----+
   |  26 |  2  |  m1 |  m2 |
   +-----+-----+-----+-----+
#endif
#if 0
static
int
dhcpopt26_chkval(uint16_t value)
{
	if (value < 68)
		syslog(LOG_WARNING, "%s(),%d: <%" PRIu8 " %s, %" PRIu8 "> u16 = %" PRIu16 ":"
			" The minimum legal value is 68.",
			__func__, __LINE__, 26, dhcp_option(26), 2, value);
}
#endif
struct dhcpopt_descriptor dhcpoptd26_interface_mtu[1] = {{
		.name	= "Interface MTU",
		.flags	= 0,
		.code	= 26,
		.elsz	= 2,
		.min	= 2,
		.max	= 2,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u16,
		.free   = NULL,
		.show	= dhcpopt_show_u16,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.2. All Subnets are Local Option

   This option specifies whether or not the client may assume that all
   subnets of the IP network to which the client is connected use the
   same MTU as the subnet of that network to which the client is
   directly connected.  A value of 1 indicates that all subnets share
   the same MTU.  A value of 0 means that the client should assume that
   some subnets of the directly connected network may have smaller MTUs.

   The code for this option is 27, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  27 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd27_all_subnets_local[1] = {{
		.name	= "All Subnets Local",
		.flags	= 0,
		.code	= 27,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.3. Broadcast Address Option

   This option specifies the broadcast address in use on the client's
   subnet.  Legal values for broadcast addresses are specified in
   section 3.2.1.3 of [4].

   The code for this option is 28, and its length is 4.

    Code   Len     Broadcast Address
   +-----+-----+-----+-----+-----+-----+
   |  28 |  4  |  b1 |  b2 |  b3 |  b4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd28_broadcast_address[1] = {{
		.name	= "Broadcast Address",
		.flags	= 0,
		.code	= 28,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.4. Perform Mask Discovery Option

   This option specifies whether or not the client should perform subnet
   mask discovery using ICMP.  A value of 0 indicates that the client
   should not perform mask discovery.  A value of 1 means that the
   client should perform mask discovery.

   The code for this option is 29, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  29 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd29_perform_mask_discovery[1] = {{
		.name	= "Perform Mask Discovery",
		.flags	= 0,
		.code	= 29,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.5. Mask Supplier Option

   This option specifies whether or not the client should respond to
   subnet mask requests using ICMP.  A value of 0 indicates that the
   client should not respond.  A value of 1 means that the client should
   respond.

   The code for this option is 30, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  30 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd30_mask_supplier[1] = {{
		.name	= "Mask Supplier",
		.flags	= 0,
		.code	= 30,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.6. Perform Router Discovery Option

   This option specifies whether or not the client should solicit
   routers using the Router Discovery mechanism defined in RFC 1256
   [13].  A value of 0 indicates that the client should not perform
   router discovery.  A value of 1 means that the client should perform
   router discovery.

   The code for this option is 31, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  31 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd31_perform_router_discovery[1] = {{
		.name	= "Perform Router Discovery",
		.flags	= 0,
		.code	= 31,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.7. Router Solicitation Address Option

   This option specifies the address to which the client should transmit
   router solicitation requests.

   The code for this option is 32, and its length is 4.

    Code   Len            Address
   +-----+-----+-----+-----+-----+-----+
   |  32 |  4  |  a1 |  a2 |  a3 |  a4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd32_router_solicitation_address[1] = {{
		.name	= "Router Solicitation Address",
		.flags	= 0,
		.code	= 32,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
5.8. Static Route Option

   This option specifies a list of static routes that the client should
   install in its routing cache.  If multiple routes to the same
   destination are specified, they are listed in descending order of
   priority.

   The routes consist of a list of IP address pairs.  The first address
   is the destination address, and the second address is the router for
   the destination.

   The default route (0.0.0.0) is an illegal destination for a static
   route.  See section 3.5 for information about the router option.

   The code for this option is 33.  The minimum length of this option is
   8, and the length MUST be a multiple of 8.

    Code   Len         Destination 1           Router 1
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
   |  33 |  n  |  d1 |  d2 |  d3 |  d4 |  r1 |  r2 |  r3 |  r4 |
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
           Destination 2           Router 2
   +-----+-----+-----+-----+-----+-----+-----+-----+---
   |  d1 |  d2 |  d3 |  d4 |  r1 |  r2 |  r3 |  r4 | ...
   +-----+-----+-----+-----+-----+-----+-----+-----+---
#endif
static
void
dhcpopt33_show(
	struct dhcpopt *opt, 
	int indent, 
	FILE *fp)
{
	int n = opt->length / sizeof(uint32_t [2]);
	union { uint8_t u8[4]; uint32_t ip; } u[2];

	u[0].ip = htonl(opt->u32x2[0][0]);
	u[1].ip = htonl(opt->u32x2[0][1]);
	fprintf(fp, "%*s %3"PRIu8" (%3"PRIu8") %-*s "
			"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8" -> %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n", 
		indent, "option", opt->code, opt->length, 
		DHCPOPTNAME_MAX, opt->optd->name, 
		u[0].u8[0], u[0].u8[1], u[0].u8[2], u[0].u8[3],
		u[1].u8[0], u[1].u8[1], u[1].u8[2], u[1].u8[3]);
	for (int i = 1; i < n; i++) {
		u[0].ip = htonl(opt->u32x2[i][0]);
		u[1].ip = htonl(opt->u32x2[i][1]);
		fprintf(fp, "%*s %3s  %3s  %*s "
				"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8" -> %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n", 
			indent, "", "", "", DHCPOPTNAME_MAX, "", 
			u[0].u8[0], u[0].u8[1], u[0].u8[2], u[0].u8[3],
			u[1].u8[0], u[1].u8[1], u[1].u8[2], u[1].u8[3]);
	}
	fprintf(fp, "\n");
}
struct dhcpopt_descriptor dhcpoptd33_static_route[1] = {{
		.name	= "Static Route",
		.flags	= 0,
		.code	= 33,
		.elsz	= 8,
		.min	= 8,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32x2,
		.free   = NULL,
		.show	= dhcpopt33_show,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
6.1. Trailer Encapsulation Option

   This option specifies whether or not the client should negotiate the
   use of trailers (RFC 893 [14]) when using the ARP protocol.  A value
   of 0 indicates that the client should not attempt to use trailers.  A
   value of 1 means that the client should attempt to use trailers.

   The code for this option is 34, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  34 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd34_trailer_encapsulation[1] = {{
		.name	= "Trailer Encapsulation",
		.flags	= 0,
		.code	= 34,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
6.2. ARP Cache Timeout Option

   This option specifies the timeout in seconds for ARP cache entries.
   The time is specified as a 32-bit unsigned integer.

   The code for this option is 35, and its length is 4.

    Code   Len           Time
   +-----+-----+-----+-----+-----+-----+
   |  35 |  4  |  t1 |  t2 |  t3 |  t4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd35_arp_cache_timeout[1] = {{
		.name	= "ARP Cache Timeout",
		.flags	= 0,
		.code	= 35,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
6.3. Ethernet Encapsulation Option

   This option specifies whether or not the client should use Ethernet
   Version 2 (RFC 894 [15]) or IEEE 802.3 (RFC 1042 [16]) encapsulation
   if the interface is an Ethernet.  A value of 0 indicates that the
   client should use RFC 894 encapsulation.  A value of 1 means that the
   client should use RFC 1042 encapsulation.

   The code for this option is 36, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  36 |  1  | 0/1 |
   +-----+-----+-----+
#endif
static
const char *
dhcpopt36_enumfn(struct dhcpopt_descriptor *optd, void *value)
{
        const char *s = NULL;
        switch (*(uint8_t *)value) {
                case ETHERNET_II_ENCAP:
                        s = "Ethernet II";
                        break;
                case ETHERNET_8023_ENCAP:
                        s = "IEEE 802.3";
                        break;
        }
        return s;
}
struct dhcpopt_descriptor dhcpoptd36_ethernet_encapsulation[1] = {{
		.name	= "Ethernet Encapsulation",
		.flags	= 0,
		.code	= 36,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt36_enumfn,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
7.1. TCP Default TTL Option

   This option specifies the default TTL that the client should use when
   sending TCP segments.  The value is represented as an 8-bit unsigned
   integer.  The minimum value is 1.

   The code for this option is 37, and its length is 1.

    Code   Len   TTL
   +-----+-----+-----+
   |  37 |  1  |  n  |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd37_tcp_default_ttl[1] = {{
		.name	= "TCP Default TTL",
		.flags	= 0,
		.code	= 37,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
i7.2. TCP Keepalive Interval Option

   This option specifies the interval (in seconds) that the client TCP
   should wait before sending a keepalive message on a TCP connection.
   The time is specified as a 32-bit unsigned integer.  A value of zero
   indicates that the client should not generate keepalive messages on
   connections unless specifically requested by an application.

   The code for this option is 38, and its length is 4.

    Code   Len           Time
   +-----+-----+-----+-----+-----+-----+
   |  38 |  4  |  t1 |  t2 |  t3 |  t4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd38_tcp_keepalive_interval[1] = {{
		.name	= "TCP Keepalive Interval",
		.flags	= 0,
		.code	= 38,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= "seconds",
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
7.3. TCP Keepalive Garbage Option

   This option specifies the whether or not the client should send TCP
   keepalive messages with a octet of garbage for compatibility with
   older implementations.  A value of 0 indicates that a garbage octet
   should not be sent. A value of 1 indicates that a garbage octet
   should be sent.

   The code for this option is 39, and its length is 1.

    Code   Len  Value
   +-----+-----+-----+
   |  39 |  1  | 0/1 |
   +-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd39_tcp_keepalive_garbage[1] = {{
		.name	= "TCP Keepalive Garbage",
		.flags	= 0,
		.code	= 39,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt_enumfn_u8_no_yes,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.1. Network Information Service Domain Option

   This option specifies the name of the client's NIS [17] domain.  The
   domain is formatted as a character string consisting of characters
   from the NVT ASCII character set.

   The code for this option is 40.  Its minimum length is 1.

    Code   Len      NIS Domain Name
   +-----+-----+-----+-----+-----+-----+---
   |  40 |  n  |  n1 |  n2 |  n3 |  n4 | ...
   +-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd40_nis_domain[1] = {{
		.name	= "NIS Domain",
		.flags	= 0,
		.code	= 40,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free   = NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.2. Network Information Servers Option

   This option specifies a list of IP addresses indicating NIS servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for this option is 41.  Its minimum length is 4, and the
   length MUST be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  41 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd41_nis_servers[1] = {{
		.name	= "NIS Servers",
		.flags	= 0,
		.code	= 41,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.3. Network Time Protocol Servers Option

   This option specifies a list of IP addresses indicating NTP [18]
   servers available to the client.  Servers SHOULD be listed in order
   of preference.

   The code for this option is 42.  Its minimum length is 4, and the
   length MUST be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  42 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd42_ntp_servers[1] = {{
		.name	= "NTP Servers",
		.flags	= 0,
		.code	= 42,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.4. Vendor Specific Information

   This option is used by clients and servers to exchange vendor-
   specific information.  The information is an opaque object of n
   octets, presumably interpreted by vendor-specific code on the clients
   and servers.  The definition of this information is vendor specific.
   The vendor is indicated in the vendor class identifier option.
   Servers not equipped to interpret the vendor-specific information
   sent by a client MUST ignore it (although it may be reported).
   Clients which do not receive desired vendor-specific information
   SHOULD make an attempt to operate without it, although they may do so
   (and announce they are doing so) in a degraded mode.

   If a vendor potentially encodes more than one item of information in
   this option, then the vendor SHOULD encode the option using
   "Encapsulated vendor-specific options" as described below:

   The Encapsulated vendor-specific options field SHOULD be encoded as a
   sequence of code/length/value fields of identical syntax to the DHCP
   options field with the following exceptions:

      1) There SHOULD NOT be a "magic cookie" field in the encapsulated
         vendor-specific extensions field.

      2) Codes other than 0 or 255 MAY be redefined by the vendor within
         the encapsulated vendor-specific extensions field, but SHOULD
         conform to the tag-length-value syntax defined in section 2.

      3) Code 255 (END), if present, signifies the end of the
         encapsulated vendor extensions, not the end of the vendor
         extensions field. If no code 255 is present, then the end of
         the enclosing vendor-specific information field is taken as the
         end of the encapsulated vendor-specific extensions field.

   The code for this option is 43 and its minimum length is 1.

   Code   Len   Vendor-specific information
   +-----+-----+-----+-----+---
   |  43 |  n  |  i1 |  i2 | ...
   +-----+-----+-----+-----+---

   When encapsulated vendor-specific extensions are used, the
   information bytes 1-n have the following format:

    Code   Len   Data item        Code   Len   Data item       Code
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
   |  T1 |  n  |  d1 |  d2 | ... |  T2 |  n  |  D1 |  D2 | ... | ... |
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
#endif
/* XXX */
struct dhcpopt_descriptor dhcpoptd43_vendor_specific_information[1] = {{
		.name	= "Vendor Specific Information",
		.flags	= 0,
		.code	= 43,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_x8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.5. NetBIOS over TCP/IP Name Server Option

   The NetBIOS name server (NBNS) option specifies a list of RFC
   1001/1002 [19] [20] NBNS name servers listed in order of preference.

   The code for this option is 44.  The minimum length of the option is
   4 octets, and the length must always be a multiple of 4.

    Code   Len           Address 1              Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
   |  44 |  n  |  a1 |  a2 |  a3 |  a4 |  b1 |  b2 |  b3 |  b4 | ...
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
#endif
struct dhcpopt_descriptor dhcpoptd44_netbios_name_server[1] = {{
		.name	= "NetBIOS Name Server",
		.flags	= 0,
		.code	= 44,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.6. NetBIOS over TCP/IP Datagram Distribution Server Option

   The NetBIOS datagram distribution server (NBDD) option specifies a
   list of RFC 1001/1002 NBDD servers listed in order of preference. The
   code for this option is 45.  The minimum length of the option is 4
   octets, and the length must always be a multiple of 4.

    Code   Len           Address 1              Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
   |  45 |  n  |  a1 |  a2 |  a3 |  a4 |  b1 |  b2 |  b3 |  b4 | ...
   +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
#endif
struct dhcpopt_descriptor dhcpoptd45_netbios_dd_server[1] = {{
		.name	= "NetBIOS Datagram Distribution Server",
		.flags	= 0,
		.code	= 45,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.7. NetBIOS over TCP/IP Node Type Option

   The NetBIOS node type option allows NetBIOS over TCP/IP clients which
   are configurable to be configured as described in RFC 1001/1002.  The
   value is specified as a single octet which identifies the client type
   as follows:

      Value         Node Type
      -----         ---------
      0x1           B-node
      0x2           P-node
      0x4           M-node
      0x8           H-node

   In the above chart, the notation '0x' indicates a number in base-16
   (hexadecimal).

   The code for this option is 46.  The length of this option is always
   1.

    Code   Len  Node Type
   +-----+-----+-----------+
   |  46 |  1  | see above |
   +-----+-----+-----------+
#endif
static
const char *
dhcpopt46_enumfn(struct dhcpopt_descriptor *optd __unused, void *value)
{
        const char *s = NULL;
        switch (*(uint8_t *)value) {
                case NETBIOS_B_NODE: s = "B-node"; break;
                case NETBIOS_P_NODE: s = "P-node"; break;
                case NETBIOS_M_NODE: s = "M-node"; break;
                case NETBIOS_H_NODE: s = "H-node"; break;
        }
        return s;
}
struct dhcpopt_descriptor dhcpoptd46_netbios_node_type[1] = {{
		.name	= "NetBIOS over TCP/IP Node Type",
		.flags	= 0,
		.code	= 46,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free   = NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt46_enumfn,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.8. NetBIOS over TCP/IP Scope Option

   The NetBIOS scope option specifies the NetBIOS over TCP/IP scope
   parameter for the client as specified in RFC 1001/1002. See [19],
   [20], and [8] for character-set restrictions.

   The code for this option is 47.  The minimum length of this option is
   1.

    Code   Len       NetBIOS Scope
   +-----+-----+-----+-----+-----+-----+----
   |  47 |  n  |  s1 |  s2 |  s3 |  s4 | ...
   +-----+-----+-----+-----+-----+-----+----
#endif
struct dhcpopt_descriptor dhcpoptd47_netbios_scope[1] = {{
		.name	= "NetBIOS Scope",
		.flags	= 0,
		.code	= 47,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free   = NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.9. X Window System Font Server Option

   This option specifies a list of X Window System [21] Font servers
   available to the client. Servers SHOULD be listed in order of
   preference.

   The code for this option is 48.  The minimum length of this option is
   4 octets, and the length MUST be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+---
   |  48 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |   ...
   +-----+-----+-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd48_xwindow_font_server[1] = {{
		.name	= "X Window System Font Server",
		.flags	= 0,
		.code	= 48,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.10. X Window System Display Manager Option

   This option specifies a list of IP addresses of systems that are
   running the X Window System Display Manager and are available to the
   client.

   Addresses SHOULD be listed in order of preference.

   The code for the this option is 49. The minimum length of this option
   is 4, and the length MUST be a multiple of 4.

    Code   Len         Address 1               Address 2

   +-----+-----+-----+-----+-----+-----+-----+-----+---
   |  49 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |   ...
   +-----+-----+-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd49_xwindow_display_manager[1] = {{
		.name	= "X Window System Display Manager",
		.flags	= 0,
		.code	= 49,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free   = NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.1. Requested IP Address

   This option is used in a client request (DHCPDISCOVER) to allow the
   client to request that a particular IP address be assigned.

   The code for this option is 50, and its length is 4.

    Code   Len          Address
   +-----+-----+-----+-----+-----+-----+
   |  50 |  4  |  a1 |  a2 |  a3 |  a4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd50_requested_ip_address[1] = {{
		.name	= "Requested IP Address",
		.flags	= 0,
		.code	= 50,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric = NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.2. IP Address Lease Time

   This option is used in a client request (DHCPDISCOVER or DHCPREQUEST)
   to allow the client to request a lease time for the IP address.  In a
   server reply (DHCPOFFER), a DHCP server uses this option to specify
   the lease time it is willing to offer.

   The time is in units of seconds, and is specified as a 32-bit
   unsigned integer.

   The code for this option is 51, and its length is 4.

    Code   Len         Lease Time
   +-----+-----+-----+-----+-----+-----+
   |  51 |  4  |  t1 |  t2 |  t3 |  t4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd51_ip_address_lease_time[1] = {{
		.name	= "IP Address Lease Time",
		.flags	= 0,
		.code	= 51,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= "seconds",
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.3. Option Overload

   This option is used to indicate that the DHCP 'sname' or 'file'
   fields are being overloaded by using them to carry DHCP options. A
   DHCP server inserts this option if the returned parameters will
   exceed the usual space allotted for options.

   If this option is present, the client interprets the specified
   additional fields after it concludes interpretation of the standard
   option fields.

   The code for this option is 52, and its length is 1.  Legal values
   for this option are:

           Value   Meaning
           -----   --------
             1     the 'file' field is used to hold options
             2     the 'sname' field is used to hold options
             3     both fields are used to hold options

    Code   Len  Value
   +-----+-----+-----+
   |  52 |  1  |1/2/3|
   +-----+-----+-----+
#endif
/* XXX */
static
const char *
dhcpopt52_enumfn(struct dhcpopt_descriptor *optd, void *value)
{
        const char *s = NULL;
        switch (*(uint8_t *)value) {
                case DHCPOVERLOAD_FILE:
                        s = "The 'file' field is used to hold options.";
                        break;
                case DHCPOVERLOAD_SNAME:
                        s = "The 'sname' field is used to hold options.";
                        break;
                case DHCPOVERLOAD_BOTH:
                        s = "Both fields ('file' and 'sname') are used to hold options.";
                        break;
        }
        return s;
}
struct dhcpopt_descriptor dhcpoptd52_option_overload[1] = {{
		.name	= "Option Overload",
		.flags	= 0,
		.code	= 52,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt52_enumfn,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.6. DHCP Message Type

   This option is used to convey the type of the DHCP message.  The code
   for this option is 53, and its length is 1.  Legal values for this
   option are:

           Value   Message Type
           -----   ------------
             1     DHCPDISCOVER
             2     DHCPOFFER
             3     DHCPREQUEST
             4     DHCPDECLINE
             5     DHCPACK
             6     DHCPNAK
             7     DHCPRELEASE
             8     DHCPINFORM

    Code   Len  Type
   +-----+-----+-----+
   |  53 |  1  | 1-9 |
   +-----+-----+-----+
#endif
static
const char *
dhcpopt53_enumfn(struct dhcpopt_descriptor *optd __unused, void *value)
{
        const char *s = NULL;
        switch (*(uint8_t *)value) {
                case DHCPDISCOVER:
                        s = "DHCPDISCOVER";
                        break;
                case DHCPOFFER:
                        s = "DHCPOFFER";
                        break;
                case DHCPREQUEST:
                        s = "DHCPREQUEST";
                        break;
                case DHCPDECLINE:
                        s = "DHCPDECLINE";
                        break;
                case DHCPACK:
                        s = "DHCPACK";
                        break;
                case DHCPNAK:
                        s = "DHCPNAK";
                        break;
                case DHCPRELEASE:
                        s = "DHCPRELEASE";
                        break;
                case DHCPINFORM:
                        s = "DHCPINFORM";
                        break;
        }
        return s;
}
struct dhcpopt_descriptor dhcpoptd53_dhcp_message_type[1] = {{
		.name	= "DHCP Message Type",
		.flags	= 0,
		.code	= 53,
		.elsz	= 1,
		.min	= 1,
		.max	= 1,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt53_enumfn,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.7. Server Identifier

   This option is used in DHCPOFFER and DHCPREQUEST messages, and may
   optionally be included in the DHCPACK and DHCPNAK messages.  DHCP
   servers include this option in the DHCPOFFER in order to allow the
   client to distinguish between lease offers.  DHCP clients use the
   contents of the 'server identifier' field as the destination address
   for any DHCP messages unicast to the DHCP server.  DHCP clients also
   indicate which of several lease offers is being accepted by including
   this option in a DHCPREQUEST message.

   The identifier is the IP address of the selected server.

   The code for this option is 54, and its length is 4.

    Code   Len            Address
   +-----+-----+-----+-----+-----+-----+
   |  54 |  4  |  a1 |  a2 |  a3 |  a4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd54_server_identifier[1] = {{
		.name	= "Server Identifier",
		.flags	= 0,
		.code	= 54,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.8. Parameter Request List

   This option is used by a DHCP client to request values for specified
   configuration parameters.  The list of requested parameters is
   specified as n octets, where each octet is a valid DHCP option code
   as defined in this document.

   The client MAY list the options in order of preference.  The DHCP
   server is not required to return the options in the requested order,
   but MUST try to insert the requested options in the order requested
   by the client.

   The code for this option is 55.  Its minimum length is 1.

    Code   Len   Option Codes
   +-----+-----+-----+-----+---
   |  55 |  n  |  c1 |  c2 | ...
   +-----+-----+-----+-----+---
#endif
static
const char *
dhcpopt55_enumfn(struct dhcpopt_descriptor *optd __unused, void *value)
{
	return dhcp_option(dhcpopt_dtree, *(uint8_t *)value);
}
struct dhcpopt_descriptor dhcpoptd55_parameter_request_list[1] = {{
		.name	= "Parameter Request List",
		.flags	= 0,
		.code	= 55,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_u8,
		.enumfn	= dhcpopt55_enumfn,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.9. Message

   This option is used by a DHCP server to provide an error message to a
   DHCP client in a DHCPNAK message in the event of a failure. A client
   may use this option in a DHCPDECLINE message to indicate the why the
   client declined the offered parameters.  The message consists of n
   octets of NVT ASCII text, which the client may display on an
   available output device.

   The code for this option is 56 and its minimum length is 1.

    Code   Len     Text
   +-----+-----+-----+-----+---
   |  56 |  n  |  c1 |  c2 | ...
   +-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd56_message[1] = {{
		.name	= "Message",
		.flags	= 0,
		.code	= 56,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free	= NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.10. Maximum DHCP Message Size

   This option specifies the maximum length DHCP message that it is
   willing to accept.  The length is specified as an unsigned 16-bit
   integer.  A client may use the maximum DHCP message size option in
   DHCPDISCOVER or DHCPREQUEST messages, but should not use the option
   in DHCPDECLINE messages.

   The code for this option is 57, and its length is 2.  The minimum
   legal value is 576 octets.

    Code   Len     Length
   +-----+-----+-----+-----+
   |  57 |  2  |  l1 |  l2 |
   +-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd57_maximum_dhcp_message_size[1] = {{
		.name	= "Maximum DHCP Message Size",
		.flags	= 0,
		.code	= 57,
		.elsz	= 2,
		.min	= 2,
		.max	= 2,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u16,
		.free	= NULL,
		.show	= dhcpopt_show_u16,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.11. Renewal (T1) Time Value

   This option specifies the time interval from address assignment until
   the client transitions to the RENEWING state.

   The value is in units of seconds, and is specified as a 32-bit
   unsigned integer.

   The code for this option is 58, and its length is 4.

    Code   Len         T1 Interval
   +-----+-----+-----+-----+-----+-----+
   |  58 |  4  |  t1 |  t2 |  t3 |  t4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd58_renewal_time_value[1] = {{
		.name	= "Renewal (T1) Time Value",
		.flags	= 0,
		.code	= 58,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= "seconds",
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.12. Rebinding (T2) Time Value

   This option specifies the time interval from address assignment until
   the client transitions to the REBINDING state.

   The value is in units of seconds, and is specified as a 32-bit
   unsigned integer.

   The code for this option is 59, and its length is 4.

    Code   Len         T2 Interval
   +-----+-----+-----+-----+-----+-----+
   |  59 |  4  |  t1 |  t2 |  t3 |  t4 |
   +-----+-----+-----+-----+-----+-----+
#endif
struct dhcpopt_descriptor dhcpoptd59_rebinding_time_value[1] = {{
		.name	= "Rebinding (T1) Time Value",
		.flags	= 0,
		.code	= 59,
		.elsz	= 4,
		.min	= 4,
		.max	= 4,
		.metric	= "seconds",
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.13. Vendor class identifier

   This option is used by DHCP clients to optionally identify the vendor
   type and configuration of a DHCP client.  The information is a string
   of n octets, interpreted by servers.  Vendors may choose to define
   specific vendor class identifiers to convey particular configuration
   or other identification information about a client.  For example, the
   identifier may encode the client's hardware configuration.  Servers
   not equipped to interpret the class-specific information sent by a
   client MUST ignore it (although it may be reported). Servers that
   respond SHOULD only use option 43 to return the vendor-specific
   information to the client.

   The code for this option is 60, and its minimum length is 1.

   Code   Len   Vendor class Identifier
   +-----+-----+-----+-----+---
   |  60 |  n  |  i1 |  i2 | ...
   +-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd60_vendor_class_identifier[1] = {{
		.name	= "Vendor class identifier",
		.code	= 60,
		.flags	= 0,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_x8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.14. Client-identifier

   This option is used by DHCP clients to specify their unique
   identifier.  DHCP servers use this value to index their database of
   address bindings.  This value is expected to be unique for all
   clients in an administrative domain.

   Identifiers SHOULD be treated as opaque objects by DHCP servers.

   The client identifier MAY consist of type-value pairs similar to the
   'htype'/'chaddr' fields defined in [3]. For instance, it MAY consist
   of a hardware type and hardware address. In this case the type field
   SHOULD be one of the ARP hardware types defined in STD2 [22].  A
   hardware type of 0 (zero) should be used when the value field
   contains an identifier other than a hardware address (e.g. a fully
   qualified domain name).

   For correct identification of clients, each client's client-
   identifier MUST be unique among the client-identifiers used on the
   subnet to which the client is attached.  Vendors and system
   administrators are responsible for choosing client-identifiers that
   meet this requirement for uniqueness.

   The code for this option is 61, and its minimum length is 2.

   Code   Len   Type  Client-Identifier
   +-----+-----+-----+-----+-----+---
   |  61 |  n  |  t1 |  i1 |  i2 | ...
   +-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd61_client_identifier[1] = {{
		.name	= "Client-identifier",
		.flags	= 0,
		.code	= 61,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_x8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
RFC 2242         NetWare/IP Domain Name and Information    November 1997

2. The NetWare/IP Domain Name option

   This option code is used to convey the NetWare/IP domain name used by
   the NetWare/IP product. The NetWare/IP Domain in the option is an NVT
   ASCII [RFC 854] string whose length is inferred from the option 'len'
   field.

   The code for this option is 62, and its maximum length is 255.

          Code  Len    NetWare/IP Domain Name
        +-----+-----+------+------+------+-----
        |  62 |  n  |  c1  |  c2  |  c3  |  ...
        +-----+-----+------+------+------+-----

   The 'len' field gives the length of the NetWare/IP Domain Name.

3. The NetWare/IP Information option

   The NetWare/IP option code will be used to convey all the NetWare/IP
   related information except for the NetWare/IP domain name.

   The code for this option is 63, and its maximum length is 255. A
   number of NetWare/IP sub-options will be conveyed using this option
   code.  The 'len' field for this option gives the length of the option
   data, which includes the sub-option code, length and data fields.

   Each sub-option contains in sequential order, a one byte sub-option
   code, a one byte length, and an optional multiple byte value field.
   The sub-option length gives the length of the value field for the
   sub-option. The example below illustrates the use of the 'len' and
   sub-option length fields in this option.

   One and only one of the following four sub-options must be the first
   sub-option to be present in option 63 encoding. Each of them is
   simply a type length pair with length set to zero.

   Sub-options:

   NWIP_DOES_NOT_EXIST (code 1)

      The responding DHCP server does not have any NetWare/IP
      information configured.

   NWIP_EXIST_IN_OPTIONS_AREA (code 2)

      All NetWare/IP information is present in the 'options' area of the
      DHCP response packet.

   NWIP_EXIST_IN_SNAME_FILE (code 3)

      All NetWare/IP information is present in the 'sname' and, if
      necessary, 'file' fields of the DHCP response packet. If used, the
      following DHCP server behavior is required: within the 'options'
      area, option 63 is present with its length field set to 2. The
      first byte of the value field is set to NWIP_EXIST_IN_SNAME_FILE
      tag and the second byte is set to zero.  Both option 62 and option
      63 will be placed in the area covered by the sname and file
      fields. Option 62 is encoded normally. Option 63 is encoded with
      its tag, length and value. The value field does not contain any of
      the first four sub-options described herein.

   NWIP_EXIST_BUT_TOO_BIG (code 4)

      Neither 'options' area nor 'sname' field can accommodate the
      NetWare/IP information.

   If either NWIP_EXIST_IN_OPTIONS_AREA or NWIP_EXIST_IN_SNAME_FILE
   sub-options is set, one or more of the following sub-options may be
   present.

   NSQ_BROADCAST (code 5)

      Length is 1 and a value of 1 or 0.  If the value is 1, the client
      SHOULD perform a NetWare Nearest Server Query to find out its
      nearest NetWare/IP server.

   PREFERRED_DSS (code 6)

      Length is (n * 4) and the value is an array of n IP addresses,
      each four bytes in length. The maximum number of addresses is 5
      and therefore the maximum length value is 20. The list contains
      the addresses of n NetWare Domain SAP/RIP Server (DSS).

   NEAREST_NWIP_SERVER (code 7)

      Length is (n * 4) and the value is an array of n IP addresses,
      each four bytes in length. The maximum number of addresses is 5
      and therefore the maximum length value is 20. The list contains
      the addresses of n Nearest NetWare/IP servers.

   AUTORETRIES (code 8)

      Length is 1 and the value is a one byte integer value indicating
      the number of times a NetWare/IP client should attempt to
      communicate with a given DSS server at startup.

   AUTORETRY_SECS (code 9)

      Length is 1 and the value is a one byte integer value indicating
      the amount of delay in seconds in between each NetWare/IP client
      attempt to communicate with a given DSS server at startup.

   NWIP_1_1 (code 10)

      Length is 1 and the value is 1 or 0.  If the value is 1, the
      NetWare/IP client SHOULD support NetWare/IP Version 1.1
      compatibility. A NetWare/IP client only needs this compatibility
      if it will contact a NetWare/IP version 1.1 server.

   PRIMARY_DSS (code 11)

      Length of 4, and the value is a single IP address.  This field
      identifies the Primary Domain SAP/RIP Service server (DSS) for
      this NetWare/IP domain. NetWare/IP administration utility uses
      this value as Primary DSS server when configuring a secondary DSS
      server.

   An example of option 63 encoding is provided below.

    Code   Len  NetWare/IP General Info
   +-----+-----+----+----+
   | 63  | 11  | 2  |  0 |
   +-----+-----+----+----+
                NWIP_EXIST_IN_OPTIONS_AREA (length 0)

               +----+----+----+
               |  5 |  1 |  1 |
               +----+----+----+
                NSQ_BROADCAST_SERVER (length 1)
                value is YES

               +----+----+------------+
               |  7 |  4 | IP address |
               +----+----+------------+
                NEAREST_NWIP_SERVER (length 4)
                value is IP address of server
#endif
/* XXX Эти опции требуют особой обработки, поскольку влияют
 *     на интерпретацию полей 'file' и 'sname' пакета dhcp.
 */
struct dhcpopt_descriptor dhcpoptd62_netwareip_domain_name[1] = {{
		.name	= "The NetWare/IP Domain Name",
		.flags	= 0,
		.code	= 62,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free	= NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};
struct dhcpopt_descriptor dhcpoptd63_netwareip_information[1] = {{
		.name	= "The NetWare/IP Information",
		.flags	= 0,
		.code	= 63,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_x8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL	/* XXX */
	}};



#if 0
8.11. Network Information Service+ Domain Option

   This option specifies the name of the client's NIS+ [17] domain.  The
   domain is formatted as a character string consisting of characters
   from the NVT ASCII character set.

   The code for this option is 64.  Its minimum length is 1.

    Code   Len      NIS Client Domain Name
   +-----+-----+-----+-----+-----+-----+---
   |  64 |  n  |  n1 |  n2 |  n3 |  n4 | ...
   +-----+-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd64_nisplus_domain[1] = {{
		.name	= "Network Information Service+ Domain",
		.flags	= 0,
		.code	= 64,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free	= NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.12. Network Information Service+ Servers Option

   This option specifies a list of IP addresses indicating NIS+ servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for this option is 65.  Its minimum length is 4, and the
   length MUST be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   |  65 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd65_nisplus_servers[1] = {{
		.name	= "Network Information Service+ Servers",
		.flags	= 0,
		.code	= 65,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.4 TFTP server name

   This option is used to identify a TFTP server when the 'sname' field
   in the DHCP header has been used for DHCP options.

   The code for this option is 66, and its minimum length is 1.

       Code  Len   TFTP server
      +-----+-----+-----+-----+-----+---
      | 66  |  n  |  c1 |  c2 |  c3 | ...
      +-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd66_tftp_server_name[1] = {{
		.name	= "TFTP server name",
		.flags	= 0,
		.code	= 66,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free	= NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
9.5 Bootfile name

   This option is used to identify a bootfile when the 'file' field in
   the DHCP header has been used for DHCP options.

   The code for this option is 67, and its minimum length is 1.

       Code  Len   Bootfile name
      +-----+-----+-----+-----+-----+---
      | 67  |  n  |  c1 |  c2 |  c3 | ...
      +-----+-----+-----+-----+-----+---
#endif
struct dhcpopt_descriptor dhcpoptd67_bootfile_name[1] = {{
		.name	= "Bootfile name",
		.flags	= 0,
		.code	= 67,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s,
		.free	= NULL,
		.show	= dhcpopt_show_s,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.13. Mobile IP Home Agent option

   This option specifies a list of IP addresses indicating mobile IP
   home agents available to the client.  Agents SHOULD be listed in
   order of preference.

   The code for this option is 68.  Its minimum length is 0 (indicating
   no home agents are available) and the length MUST be a multiple of 4.
   It is expected that the usual length will be four octets, containing
   a single home agent's address.

    Code Len    Home Agent Addresses (zero or more)
   +-----+-----+-----+-----+-----+-----+--
   | 68  |  n  | a1  | a2  | a3  | a4  | ...
   +-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd68_mobile_ip_home_agent[1] = {{
		.name	= "Mobile IP Home Agent",
		.flags	= 0,
		.code	= 68,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.14. Simple Mail Transport Protocol (SMTP) Server Option

   The SMTP server option specifies a list of SMTP servers available to
   the client.  Servers SHOULD be listed in order of preference.

   The code for the SMTP server option is 69.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 69  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd69_smtp_server[1] = {{
		.name	= "SMTP Server",
		.flags	= 0,
		.code	= 69,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.15. Post Office Protocol (POP3) Server Option

   The POP3 server option specifies a list of POP3 available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the POP3 server option is 70.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 70  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd70_pop3_server[1] = {{
		.name	= "POP3 Server",
		.flags	= 0,
		.code	= 70,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.16. Network News Transport Protocol (NNTP) Server Option

   The NNTP server option specifies a list of NNTP available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the NNTP server option is 71. The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 71  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd71_nntp_server[1] = {{
		.name	= "NNTP Server",
		.flags	= 0,
		.code	= 71,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.17. Default World Wide Web (WWW) Server Option

   The WWW server option specifies a list of WWW available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the WWW server option is 72.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 72  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd72_www_server[1] = {{
		.name	= "WWW Server",
		.flags	= 0,
		.code	= 72,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.18. Default Finger Server Option

   The Finger server option specifies a list of Finger available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the Finger server option is 73.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 73  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd73_finger_server[1] = {{
		.name	= "Finger Server",
		.flags	= 0,
		.code	= 73,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.19. Default Internet Relay Chat (IRC) Server Option

   The IRC server option specifies a list of IRC available to the
   client.  Servers SHOULD be listed in order of preference.

   The code for the IRC server option is 74.  The minimum length for
   this option is 4 octets, and the length MUST always be a multiple of
   4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 74  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd74_irc_server[1] = {{
		.name	= "IRC Server",
		.flags	= 0,
		.code	= 74,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
8.20. StreetTalk Server Option

   The StreetTalk server option specifies a list of StreetTalk servers
   available to the client.  Servers SHOULD be listed in order of
   preference.

   The code for the StreetTalk server option is 75.  The minimum length
   for this option is 4 octets, and the length MUST always be a multiple
   of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 75  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd75_streettalk_server[1] = {{
		.name	= "StreetTalk Server",
		.flags	= 0,
		.code	= 75,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};



#if 0
8.21. StreetTalk Directory Assistance (STDA) Server Option

   The StreetTalk Directory Assistance (STDA) server option specifies a
   list of STDA servers available to the client.  Servers SHOULD be
   listed in order of preference.

   The code for the StreetTalk Directory Assistance server option is 76.
   The minimum length for this option is 4 octets, and the length MUST
   always be a multiple of 4.

    Code   Len         Address 1               Address 2
   +-----+-----+-----+-----+-----+-----+-----+-----+--
   | 76  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
   +-----+-----+-----+-----+-----+-----+-----+-----+--
#endif
struct dhcpopt_descriptor dhcpoptd76_streettalk_directory_assistance_server[1] = {{
		.name	= "StreetTalk Directory Assistance Server",
		.flags	= 0,
		.code	= 76,
		.elsz	= 4,
		.min	= 4,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u32,
		.free	= NULL,
		.show	= dhcpopt_show_u32_ip,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4. User Class option

   This option is used by a DHCP client to optionally identify the type
   or category of user or applications it represents.  A DHCP server
   uses the User Class option to choose the address pool it allocates an
   address from and/or to select any other configuration option.

   This option is a DHCP option [1, 2].

   This option MAY carry multiple User Classes.  Servers may interpret
   the meanings of multiple class specifications in an implementation
   dependent or configuration dependent manner, and so the use of
   multiple classes by a DHCP client should be based on the specific
   server implementation and configuration which will be used to process
   that User class option.

   The format of this option is as follows:

         Code   Len   Value
        +-----+-----+---------------------  . . .  --+
        | 77  |  N  | User Class Data ('Len' octets) |
        +-----+-----+---------------------  . . .  --+

   where Value consists of one or more instances of User Class Data.
   Each instance of User Class Data is formatted as follows:

         UC_Len_i     User_Class_Data_i
        +--------+------------------------  . . .  --+
        |  L_i   | Opaque-Data ('UC_Len_i' octets)   |
        +--------+------------------------  . . .  --+

   Each User Class value (User_Class_Data_i) is indicated as an opaque
   field.  The value in UC_Len_i does not include the length field
   itself and MUST be non-zero.  Let m be the number of User Classes
   carried in the option.  The length of the option as specified in Len
   must be the sum of the lengths of each of the class names plus m:
   Len= UC_Len_1 + UC_Len_2 + ... + UC_Len_m + m.  If any instances of
   User Class Data are present, the minimum value of Len is two (Len =
   UC_Len_1 + 1 = 1 + 1 = 2).

   The Code for this option is 77.

   A server that is not equipped to interpret any given user class
   specified by a client MUST ignore it (although it may be reported).
   If a server recognizes one or more user classes specified by the
   client, but does not recognize one or more other user classes
   specified by the client, the server MAY use the user classes it
   recognizes.

   DHCP clients implementing this option SHOULD allow users to enter one
   or more user class values.
#endif
struct dhcpopt_descriptor dhcpoptd77_user_class[1] = {{
		.name	= "User Class",
		.flags	= 0,
		.code	= 77,
		.elsz	= 1,
		.min	= 1,	/* XXX: rfc require 2 bytes */
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_x8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
3. SLP Directory Agent Option

   This option specifies the location of one or more SLP Directory
   Agents.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Code = 78   |    Length     |   Mandatory   |      a1       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      a2       |       a3      |       a4      |      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The SLP Directory Agent Option specifies a list of IP addresses for
   Directory Agents.  Directory Agents MUST be listed in order of
   preference, if there is an order of preference.

   The Length value must include one for the 'Mandatory' byte and
   include four for each Directory Agent address which follows.  Thus,
   the Length minus one of the option MUST always be divisible by 4 and
   has a minimum value of 5.

   The address of the Directory Agent is given in network byte order.

   The 'Mandatory' byte in the Directory Agent option may be set to
   either 0 or 1.  If it is set to 1, the SLP User Agent or Service
   Agent so configured MUST NOT employ either active or passive
   multicast discovery of Directory Agents.

   Note that for backward compatibility with some deployed software the
   Mandatory byte MUST NOT be set to any byte value for which the high
   order bit (0x80) is set.

   The Directory Agents listed in this option MUST be configured with
   the a non-empty subset of the scope list that the Agent receiving the
   Directory Agent Option is configured with.  See the notes below.

   The SLPv2 specification [3] defines how to use this option.
#endif
static 
struct dhcpopt *
dhcpopt78_decode(struct dhcpopt_descriptor *optd, const uint8_t **curp, const uint8_t *endp) 
{
	struct dhcpopt *opt;
	uint8_t length, n;
	int sz;

	length = *(*curp + 1);
	if ((length - 1) % sizeof(uint32_t)) {
		ectlno_seterror(E_DHCPOPTDECODE);
		ectlno_printf("%s(),%d: {%s} The option %" PRIu8 " (%s) length-1 (%" PRIu8 ")"
			" isn't multiple %" PRIu8 ".",
			__func__, __LINE__, error_name(ectlno_error), 
			optd->code, optd->name, length-1, optd->elsz);
		ectlfr_trap();
	}
	n = (length - 1) / sizeof(uint32_t);
	sz = offsetof(struct dhcpopt, opt78[0].u32) + n * sizeof(uint32_t);
	opt = MALLOC(sz);
	opt->optd = optd;
	opt->code = optd->code;
	opt->length = length;
	opt->opt78[0].mandatory = *(*curp + 2);
	for (int i = 0; i < n; i++)
		opt->opt78[0].u32[i] = ntohl(*(uint32_t *)(*curp + 3 + sizeof(uint32_t)*i));
	*curp += 2 + length;
	return opt;
}
static
void
dhcpopt78_show(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = (opt->length - 1) / sizeof(uint32_t);
	union { uint8_t u8[4]; uint32_t ip; } u;

	u.ip = htonl(opt->opt78[0].u32[0]);
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s "
				"mandatory: %" PRIu8 "\n"
		    "%*s       %3s  %3s  %*s "
				"     addr: %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8, 
		indent, "", opt->code, opt->length, DHCPOPTNAME_MAX, opt->optd->name, 
			opt->opt78[0].mandatory, 
		indent, "", "", "", DHCPOPTNAME_MAX, "", 
			u.u8[0], u.u8[1], u.u8[2], u.u8[3]);
	for (int i = 1; i < n; i++) {
		u.ip = htonl(opt->opt78[0].u32[i]);
		fprintf(fp, "%*s       %3s  %3s  %*s "
				"     addr: %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8, 
			indent, "", "", "", DHCPOPTNAME_MAX, "", 
				u.u8[0], u.u8[1], u.u8[2], u.u8[3]);
	}
	fprintf(fp, "\n");
}
struct dhcpopt_descriptor dhcpoptd78_slp_directory_agent[1] = {{
		.name	= "SLP Directory Agent",
		.flags	= 0,
		.code	= 78,
		.elsz	= 1,
		.min	= 5,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt78_decode,
		.free	= NULL,
		.show	= dhcpopt78_show,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
4. SLP Service Scope Option

   The scope list is a comma delimited list which indicates the scopes
   that a SLP Agent is configured to use.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Code = 79   |     Length    |   Mandatory   | <Scope List>...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The Length indicates the number of bytes which follow.  Since the
   Scope-List String is encoded using UTF-8 [5] characters, it may be
   the cast that the Length is not the same as the number of characters
   in the Scope-List String.  The Length value must include one for the
   'Mandatory' byte.

   The 'Mandatory' byte determines whether SLP Agents override their
   static configuration for scopes with the <Scope List> string provided
   by the option.  This allows DHCP administrators to implement a policy
   of assigning a set of scopes to Agents for service provision.  If the
   Mandatory byte is 0, static configuration takes precedence over the
   DHCP provided scope list.  If the Mandatory byte is 1, the <Scope
   List> provided in this option MUST be used by the SLP Agent.

   The Scope List String syntax and usage are defined in the SLPv2
   specification [3].

4.1. Zero Length Scope-List String Configuration

   A SLP Service Scope Option which indicates a Length of 1 (in other
   words, omitting the <Scope List> string entirely) validly configures
   the SLP User Agent to use "User Selectable Scopes."

   The SLP Agent will use the aggregated list of scopes of all known
   DAs.  If no DAs are known, the UA will use SA discovery to determine
   the list of scopes on the network, as defined in  [3].

   Note that this configuration is tantamount to removing all
   centralized control of the scope configuration of hosts on the
   network.  This makes it possible for every User Agent to see every
   service.  This may not be desirable as users may not be able to or
   desire to decide which services are appropriate for them.
#endif
static
void
dhcpopt79_show(struct dhcpopt *opt, int indent, FILE *fp)
{
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s mandatory: %" PRIu8 "\n"
		    "%*s       %3s  %3s  %*s "               "    scope: %s\n",
		indent, "", opt->code, opt->length, DHCPOPTNAME_MAX, opt->optd->name, 
			opt->opt79[0].mandatory, 
		indent, "", "", "", DHCPOPTNAME_MAX, "", 
			opt->opt79[0].s);
}
struct dhcpopt_descriptor dhcpoptd79_slp_service_scope[1] = {{
		.name	= "SLP Service Scope",
		.flags	= 0,
		.code	= 79,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_s, /* XXX как ни странно */
		.free	= NULL,
		.show	= dhcpopt79_show,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};

#if 0
4.  Rapid Commit Option Format

   The Rapid Commit option is used to indicate the use of the two-
   message exchange for address assignment.  The code for the Rapid
   Commit option is 80.  The format of the option is:

           Code  Len
         +-----+-----+
         |  80 |  0  |
         +-----+-----+

   A client MUST include this option in a DHCPDISCOVER message if the
   client is prepared to perform the DHCPDISCOVER-DHCPACK message
   exchange described earlier.

   A server MUST include this option in a DHCPACK message sent in a
   response to a DHCPDISCOVER message when completing the DHCPDISCOVER-
   DHCPACK message exchange.
#endif
struct dhcpopt_descriptor dhcpoptd80_rapid_commit[1] = {{
		.name	= "Rapid Commit",
		.flags	= DHCPOPT_F_NOVALUE,
		.code	= 80,
		.elsz	= 0,
		.min	= 0,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_novalue,
		.free	= NULL,
		.show	= dhcpopt_show_novalue,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
2.  The Client FQDN Option

   To update the IP-address-to-FQDN mapping, a DHCP server needs to know
   the FQDN of the client to which the server leases the address.  To
   allow the client to convey its FQDN to the server, this document
   defines a new DHCP option, called "Client FQDN".  The Client FQDN
   option also contains Flags, which DHCP servers can use to convey
   information about DNS updates to clients, and two deprecated RCODEs.

   Clients MAY send the Client FQDN option, setting appropriate Flags
   values, in both their DHCPDISCOVER and DHCPREQUEST messages.  If a
   client sends the Client FQDN option in its DHCPDISCOVER message, it
   MUST send the option in subsequent DHCPREQUEST messages though the
   contents of the option MAY change.

   Only one Client FQDN option MAY appear in a message, though it may be
   instantiated in a message as multiple options [9].  DHCP clients and
   servers supporting this option MUST implement DHCP option
   concatenation [9].  In the terminology of [9], the Client FQDN option
   is a concatenation-requiring option.

   The code for this option is 81.  Len contains the number of octets
   that follow the Len field, and the minimum value is 3 (octets).

   The format of the Client FQDN option is:

        Code   Len    Flags  RCODE1 RCODE2   Domain Name
       +------+------+------+------+------+------+--
       |  81  |   n  |      |      |      |       ...
       +------+------+------+------+------+------+--

   The above figure follows the conventions of [12].

2.1.  The Flags Field

   The format of the 1-octet Flags field is:

        0 1 2 3 4 5 6 7
       +-+-+-+-+-+-+-+-+
       |  MBZ  |N|E|O|S|
       +-+-+-+-+-+-+-+-+

   The "S" bit indicates whether the server SHOULD or SHOULD NOT perform
   the A RR (FQDN-to-address) DNS updates.  A client sets the bit to 0
   to indicate the server SHOULD NOT perform the updates and 1 to
   indicate the server SHOULD perform the updates.  The state of the bit
   in the reply from the server indicates the action to be taken by the
   server; if 1, the server has taken responsibility for A RR updates
   for the FQDN.

   The "O" bit indicates whether the server has overridden the client's
   preference for the "S" bit.  A client MUST set this bit to 0.  A
   server MUST set this bit to 1 if the "S" bit in its reply to the
   client does not match the "S" bit received from the client.

   The "N" bit indicates whether the server SHOULD NOT perform any DNS
   updates.  A client sets this bit to 0 to request that the server
   SHOULD perform updates (the PTR RR and possibly the A RR based on the
   "S" bit) or to 1 to request that the server SHOULD NOT perform any
   DNS updates.  A server sets the "N" bit to indicate whether the
   server SHALL (0) or SHALL NOT (1) perform DNS updates.  If the "N"
   bit is 1, the "S" bit MUST be 0.

   The "E" bit indicates the encoding of the Domain Name field. 1
   indicates canonical wire format, without compression, as described in
   [3], Section 3.1.  This encoding SHOULD be used by clients and MUST
   be supported by servers. 0 indicates a now-deprecated ASCII encoding
   (see Section 2.3.1).  A server MUST use the same encoding as that
   used by the client.  A server that does not support the deprecated
   ASCII encoding MUST ignore Client FQDN options that use that
   encoding.

# RFC1035
# 3.1. Name space definitions
#
#	Domain names in messages are expressed in terms of a sequence of labels.
#	Each label is represented as a one octet length field followed by that
#	number of octets.  Since every domain name ends with the null label of
#	the root, a domain name is terminated by a length byte of zero.  The
#	high order two bits of every length octet must be zero, and the
#	remaining six bits of the length field limit the label to 63 octets or
#	less.
#
#	To simplify implementations, the total length of a domain name (i.e.,
#	label octets and label length octets) is restricted to 255 octets or
#	less.
#
#	Although labels can contain any 8 bit values in octets that make up a
#	label, it is strongly recommended that labels follow the preferred
#	syntax described elsewhere in this memo, which is compatible with
#	existing host naming conventions.  Name servers and resolvers must
#	compare labels in a case-insensitive manner (i.e., A=a), assuming ASCII
#	with zero parity.  Non-alphabetic codes must match exactly.

   The remaining bits in the Flags field are reserved for future
   assignment.  DHCP clients and servers that send the Client FQDN
   option MUST clear the MBZ bits, and they MUST ignore these bits.

2.2.  The RCODE Fields

   The two 1-octet RCODE1 and RCODE2 fields are deprecated.  A client
   SHOULD set these to 0 when sending the option and SHOULD ignore them
   on receipt.  A server SHOULD set these to 255 when sending the option
   and MUST ignore them on receipt.

   As this option with these fields is already in wide use, the fields
   are retained.  These fields were originally defined for use by a DHCP
   server to indicate to a DHCP client the Response Code from any A
   (RCODE1) or PTR (RCODE2) RR DNS updates it has performed, or a value
   of 255 was used to indicate that an update had been initiated but had
   not yet completed.  Each of these fields is one octet long.  These
   fields were defined before EDNS0 [13], which describes a mechanism
   for extending the length of a DNS RCODE to 12 bits, which is another
   reason to deprecate them.

   If the client needs to confirm that the DNS update has been done, it
   MAY use a DNS query to check whether the mapping is up to date.
   However, depending on the load on the DHCP and DNS servers and the
   DNS propagation delays, the client can only infer success.  If the
   information is not found to be up to date in DNS, the authoritative
   servers might not have completed the updates or zone transfers, or
   caching resolvers may yet have updated their caches.

2.3.  The Domain Name Field

   The Domain Name part of the option carries all or part of the FQDN of
   a DHCP client.  The data in the Domain Name field SHOULD appear in
   canonical wire format as specified in [3], Section 3.1.  If the DHCP
   client uses the canonical wire format, it MUST set the "E" bit in the
   Flags field to 1.  In order to determine whether the FQDN has changed
   between message exchanges, the client and server MUST NOT alter the
   Domain Name field contents unless the FQDN has actually changed.

   A client MAY be configured with a fully qualified domain name or with
   a partial name that is not fully qualified.  If a client knows only
   part of its name, it MAY send a name that is not fully qualified,
   indicating that it knows part of the name but does not necessarily
   know the zone in which the name is to be embedded.

   To send a fully qualified domain name, the Domain Name field is set
   to the DNS-encoded domain name including the terminating zero-length
   label.  To send a partial name, the Domain Name field is set to the
   DNS encoded domain name without the terminating zero-length label.

   A client MAY also leave the Domain Name field empty if it desires the
   server to provide a name.

2.3.1.  Deprecated ASCII Encoding

   A substantial population of clients implemented an earlier draft of
   this specification, which permitted an ASCII encoding of the Domain
   Name field.  Server implementations SHOULD be aware that clients that
   send the Client FQDN option with the "E" bit set to 0 are using an
   ASCII encoding of the Domain Name field.  Servers MAY be prepared to
   return an ASCII-encoded version of the Domain Name field to such
   clients.  Servers that are not prepared to return an ASCII-encoded
   version MUST ignore the Client FQDN option if the "E" bit is 0.  The
   use of ASCII encoding in this option SHOULD be considered deprecated.

   A DHCP client that used ASCII encoding was permitted to suggest a
   single label if it was not configured with a fully qualified name.
   Such clients send a single label as a series of ASCII characters in
   the Domain Name field, excluding the "." (dot) character.

   Clients and servers SHOULD follow the character set rules of [6],
   fourth section ("Assumptions"), first 5 sentences, as modified by
   [7], Section 2.1.  However, implementers SHOULD also be aware that
   some client software may send data intended to be in other character
   sets.  This specification does not require support for other
   character sets.
#endif
static
void
dhcpopt81_show(struct dhcpopt *opt, int indent, FILE *fp)
{
	int n = opt->length - 3;
	fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s "
				" flags: %02" PRIx8 " [S:%u O:%u E:%u N:%u MBZ:%u]\n"
		    "%*s       %3s  %3s  %*s "
				"rcode1: %" PRIu8 "\n"
		    "%*s       %3s  %3s  %*s "
				"rcode2: %" PRIu8 "\n" 
		    "%*s       %3s  %3s  %*s ",
		indent, "", opt->code, opt->length, DHCPOPTNAME_MAX, opt->optd->name, 
			opt->opt81[0].flags, opt->opt81[0].S, opt->opt81[0].O, 
					     opt->opt81[0].E, opt->opt81[0].N, 
					     opt->opt81[0].MBZ,
		indent, "", "", "", DHCPOPTNAME_MAX, "", 
			opt->opt81[0].rcode1, 
		indent, "", "", "", DHCPOPTNAME_MAX, "", 
			opt->opt81[0].rcode2,
		indent, "", "", "", DHCPOPTNAME_MAX, "");
	if (opt->opt81[0].E) {
		for (int j, i = 0; i < n; i += j) {
			int len = opt->opt81[0].u8[i++];
			if (!len)
				break;
			if (i + len > n)
				break;
			for (j = 0; j < len; j++) {
				int c = opt->opt81[0].u8[i + j];
				printf("%c", (isascii(c) && isprint(c)) ? c : '.');
			}
			printf(".");
		}
	} else {
		fprintf(fp, "%s", (char *)opt->opt81[0].u8);
	}
	fprintf(fp, "\n");
}
struct dhcpopt_descriptor dhcpoptd81_client_fqdn[1] = {{
		.name	= "Client FQDN",
		.flags	= 0,
		.code	= 81,
		.elsz	= 1,
		.min	= 3,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,	/* XXX */
		.free	= NULL,
		.show	= dhcpopt81_show,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
RFC 3046          DHCP Relay Agent Information Option       January 2001

2.0 Relay Agent Information Option

   This document defines a new DHCP Option called the Relay Agent
   Information Option.  It is a "container" option for specific agent-
   supplied sub-options.  The format of the Relay Agent Information
   option is:

          Code   Len     Agent Information Field
         +------+------+------+------+------+------+--...-+------+
         |  82  |   N  |  i1  |  i2  |  i3  |  i4  |      |  iN  |
         +------+------+------+------+------+------+--...-+------+

   The length N gives the total number of octets in the Agent
   Information Field.  The Agent Information field consists of a
   sequence of SubOpt/Length/Value tuples for each sub-option, encoded
   in the following manner:

          SubOpt  Len     Sub-option Value
         +------+------+------+------+------+------+--...-+------+
         |  1   |   N  |  s1  |  s2  |  s3  |  s4  |      |  sN  |
         +------+------+------+------+------+------+--...-+------+
          SubOpt  Len     Sub-option Value
         +------+------+------+------+------+------+--...-+------+
         |  2   |   N  |  i1  |  i2  |  i3  |  i4  |      |  iN  |
         +------+------+------+------+------+------+--...-+------+

   No "pad" sub-option is defined, and the Information field shall NOT
   be terminated with a 255 sub-option.  The length N of the DHCP Agent
   Information Option shall include all bytes of the sub-option
   code/length/value tuples.  Since at least one sub-option must be
   defined, the minimum Relay Agent Information length is two (2).  The
   length N of the sub-options shall be the number of octets in only
   that sub-option's value field.  A sub-option length may be zero.  The
   sub-options need not appear in sub-option code order.

   The initial assignment of DHCP Relay Agent Sub-options is as follows:

                 DHCP Agent              Sub-Option Description
                 Sub-option Code
                 ---------------         ----------------------
                     1                   Agent Circuit ID Sub-option
                     2                   Agent Remote ID Sub-option
#endif
struct dhcpopt_descriptor dhcpoptd82_1_circuit_id[1] = {{
		.name	= "Circuit-ID",
		.flags	= 0,
		.code	= 1,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_x8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
}};
struct dhcpopt_descriptor dhcpoptd82_2_remote_id[1] = {{
		.name	= "Remote-ID",
		.flags	= 0,
		.code	= 2,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_u8,
		.free	= NULL,
		.show	= dhcpopt_show_x8,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
}};
static
int
dhcpoptd82_init(struct dhcpopt_descriptor *optd)
{
	struct dhcpopt_descriptor *ddtab[] = {
		dhcpoptd82_1_circuit_id,
		dhcpoptd82_2_remote_id
	};
	optd->dtree = dhcpopt_dtree_create(ddtab, sizeof ddtab/sizeof ddtab[0]);
	return optd->dtree ? 0 : 1;
	
}
static
void
dhcpoptd_fini(struct dhcpopt_descriptor *optd)
{
	dhcpopt_dtree_destroy(optd->dtree);
	optd->dtree = NULL;
}
struct dhcpopt_descriptor dhcpoptd82_relay_agent_information[1] = {{
		.name	= "Relay Agent Information",
		.flags	= 0,
		.code	= 82,
		.elsz	= 1,
		.min	= 1,
		.max	= 0,
		.metric	= NULL,
		.decode	= dhcpopt_decode_lst,
		.free	= dhcpopt_free_lst,
		.show	= dhcpopt_show_lst,
		.enumfn	= NULL,
		.init	= dhcpoptd82_init,
		.fini	= dhcpoptd_fini,
		.dtree	= NULL
	}};


#if 0
RFC 3397               DHCP Domain Search Option           November 2002

2.  Domain Search Option Format

   The code for this option is 119.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     119       |     Len       |         Searchstring...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Searchstring...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   In the above diagram, Searchstring is a string specifying the
   searchlist.  If the length of the searchlist exceeds the maximum
   permissible within a single option (255 octets), then multiple
   options MAY be used, as described in "Encoding Long Options in the
   Dynamic Host Configuration Protocol (DHCPv4)" [RFC3396].


   To enable the searchlist to be encoded compactly, searchstrings in
   the searchlist MUST be concatenated and encoded using the technique
   described in section 4.1.4 of "Domain Names - Implementation And
   Specification" [RFC1035].  In this scheme, an entire domain name or a
   list of labels at the end of a domain name is replaced with a pointer
   to a prior occurrence of the same name.  Despite its complexity, this
   technique is valuable since the space available for encoding DHCP
   options is limited, and it is likely that a domain searchstring will
   contain repeated instances of the same domain name.  Thus the DNS
   name compression is both useful and likely to be effective.

   For use in this specification, the pointer refers to the offset
   within the data portion of the DHCP option (not including the
   preceding DHCP option code byte or DHCP option length byte).

   If multiple Domain Search Options are present, then the data portions
   of all the Domain Search Options are concatenated together as
   specified in "Encoding Long DHCP Options in the Dynamic Host
   Configuration Protocol (DHCPv4)" [RFC3396] and the pointer indicates
   an offset within the complete aggregate block of data.

3.  Example

   Below is an example encoding of a search list consisting of
   "eng.apple.com." and "marketing.apple.com.":

   +---+---+---+---+---+---+---+---+---+---+---+
   |119| 9 | 3 |'e'|'n'|'g'| 5 |'a'|'p'|'p'|'l'|
   +---+---+---+---+---+---+---+---+---+---+---+

   +---+---+---+---+---+---+---+---+---+---+---+
   |119| 9 |'e'| 3 |'c'|'o'|'m'| 0 | 9 |'m'|'a'|
   +---+---+---+---+---+---+---+---+---+---+---+

   +---+---+---+---+---+---+---+---+---+---+---+
   |119| 9 |'r'|'k'|'e'|'t'|'i'|'n'|'g'|xC0|x04|
   +---+---+---+---+---+---+---+---+---+---+---+

   Note:

   i.    The encoding has been split (for this example) into three
         Domain Search Options.  All Domain Search Options are logically
         concatenated into one block of data before being interpreted by
         the client.

   ii.   The encoding of "eng.apple.com." ends with a zero, the null
         root label, to mark the end of the name, as required by RFC
         1035.
   iii.  The encoding of "marketing" (for "marketing.apple.com.") ends
         with the two-octet compression pointer C004 (hex), which points
         to offset 4 in the complete aggregated block of Domain Search
         Option data, where another validly encoded domain name can be
         found to complete the name ("apple.com.").

   Every search domain name must end either with a zero or with a two-
   octet compression pointer.  If the receiver is part-way through
   decoding a search domain name when it reaches the end of the complete
   aggregated block of the searchlist option data, without finding a
   zero or a valid two-octet compression pointer, then the partially
   read name MUST be discarded as invalid.
#endif
/* XXX */


#if 0
Classless Route Option Format

   The code for this option is 121, and its minimum length is 5 bytes.
   This option can contain one or more static routes, each of which
   consists of a destination descriptor and the IP address of the router
   that should be used to reach that destination.

    Code Len Destination 1    Router 1
   +-----+---+----+-----+----+----+----+----+----+
   | 121 | n | d1 | ... | dN | r1 | r2 | r3 | r4 |
   +-----+---+----+-----+----+----+----+----+----+

    Destination 2       Router 2
   +----+-----+----+----+----+----+----+
   | d1 | ... | dN | r1 | r2 | r3 | r4 |
   +----+-----+----+----+----+----+----+

   In the above example, two static routes are specified.







Lemon, et. al.              Standards Track                     [Page 3]

RFC 3442        Classless Static Route Option for DHCPv4   December 2002


   Destination descriptors describe the IP subnet number and subnet mask
   of a particular destination using a compact encoding.  This encoding
   consists of one octet describing the width of the subnet mask,
   followed by all the significant octets of the subnet number.

   The width of the subnet mask describes the number of one bits in the
   mask, so for example a subnet with a subnet number of 10.0.127.0 and
   a netmask of 255.255.255.0 would have a subnet mask width of 24.

   The significant portion of the subnet number is simply all of the
   octets of the subnet number where the corresponding octet in the
   subnet mask is non-zero.  The number of significant octets is the
   width of the subnet mask divided by eight, rounding up, as shown in
   the following table:

        Width of subnet mask     Number of significant octets
                     0                     0
                  1- 8                     1
                  9-16                     2
                 17-24                     3
                 25-32                     4

   The following table contains some examples of how various subnet
   number/mask combinations can be encoded:

   Subnet number   Subnet mask      Destination descriptor
   0               0                0
   10.0.0.0        255.0.0.0        8.10
   10.0.0.0        255.255.255.0    24.10.0.0
   10.17.0.0       255.255.0.0      16.10.17
   10.27.129.0     255.255.255.0    24.10.27.129
   10.229.0.128    255.255.255.128  25.10.229.0.128
   10.198.122.47   255.255.255.255  32.10.198.122.47

Local Subnet Routes

   In some cases more than one IP subnet may be configured on a link.
   In such cases, a host whose IP address is in one IP subnet in the
   link could communicate directly with a host whose IP address is in a
   different IP subnet on the same link.  In cases where a client is
   being assigned an IP address on an IP subnet on such a link, for each
   IP subnet in the link other than the IP subnet on which the client
   has been assigned the DHCP server MAY be configured to specify a
   router IP address of 0.0.0.0.







Lemon, et. al.              Standards Track                     [Page 4]

RFC 3442        Classless Static Route Option for DHCPv4   December 2002


   For example, consider the case where there are three IP subnets
   configured on a link: 10.0.0/24, 192.168.0/24, 10.0.21/24.  If the
   client is assigned an IP address of 10.0.21.17, then the server could
   include a route with a destination of 10.0.0/24 and a router address
   of 0.0.0.0, and also a route with a destination of 192.168.0/24 and a
   router address of 0.0.0.0.

   A DHCP client whose underlying TCP/IP stack does not provide this
   capability MUST ignore routes in the Classless Static Routes option
   whose router IP address is 0.0.0.0.  Please note that the behavior
   described here only applies to the Classless Static Routes option,
   not to the Static Routes option nor the Router option.

DHCP Client Behavior

   DHCP clients that do not support this option MUST ignore it if it is
   received from a DHCP server.  DHCP clients that support this option
   MUST install the routes specified in the option, except as specified
   in the Local Subnet Routes section.  DHCP clients that support this
   option MUST NOT install the routes specified in the Static Routes
   option (option code 33) if both a Static Routes option and the
   Classless Static Routes option are provided.

   DHCP clients that support this option and that send a DHCP Parameter
   Request List option MUST request both this option and the Router
   option [4] in the DHCP Parameter Request List.

   DHCP clients that support this option and send a parameter request
   list MAY also request the Static Routes option, for compatibility
   with older servers that don't support Classless Static Routes.  The
   Classless Static Routes option code MUST appear in the parameter
   request list prior to both the Router option code and the Static
   Routes option code, if present.

   If the DHCP server returns both a Classless Static Routes option and
   a Router option, the DHCP client MUST ignore the Router option.

   Similarly, if the DHCP server returns both a Classless Static Routes
   option and a Static Routes option, the DHCP client MUST ignore the
   Static Routes option.

   After deriving a subnet number and subnet mask from each destination
   descriptor, the DHCP client MUST zero any bits in the subnet number
   where the corresponding bit in the mask is zero. In other words, the
   subnet number installed in the routing table is the logical AND of
   the subnet number and subnet mask given in the Classless Static
   Routes option. For example, if the server sends a route with a
   destination of 129.210.177.132 (hexadecimal 81D4B184) and a subnet



Lemon, et. al.              Standards Track                     [Page 5]

RFC 3442        Classless Static Route Option for DHCPv4   December 2002


   mask of 255.255.255.128 (hexadecimal FFFFFF80), the client will
   install a route with a destination of 129.210.177.128 (hexadecimal
   81D4B180).

Requirements to Avoid Sizing Constraints

   Because a full routing table can be quite large, the standard 576
   octet maximum size for a DHCP message may be too short to contain
   some legitimate Classless Static Route options.  Because of this,
   clients implementing the Classless Static Route option SHOULD send a
   Maximum DHCP Message Size [4] option if the DHCP client's TCP/IP
   stack is capable of receiving larger IP datagrams.  In this case, the
   client SHOULD set the value of this option to at least the MTU of the
   interface that the client is configuring.  The client MAY set the
   value of this option higher, up to the size of the largest UDP packet
   it is prepared to accept.  (Note that the value specified in the
   Maximum DHCP Message Size option is the total maximum packet size,
   including IP and UDP headers.)

   DHCP clients requesting this option, and DHCP servers sending this
   option, MUST implement DHCP option concatenation [5].  In the
   terminology of RFC 3396 [5], the Classless Static Route Option is a
   concatenation-requiring option.
#endif
/* XXX */


#if 0
3.2. End Option

   The end option marks the end of valid information in the vendor
   field.  Subsequent octets should be filled with pad options.

   The code for the end option is 255, and its length is 1 octet.

    Code
   +-----+
   | 255 |
   +-----+
#endif
struct dhcpopt_descriptor dhcpoptd255_end[1] = {{
		.name	= "End",
		.flags	= DHCPOPT_F_NOLENGTH|DHCPOPT_F_NOVALUE|DHCPOPT_F_END,
		.code	= 255,
		.elsz	= 0,
		.min	= 0,
		.max	= 0,
		.metric = NULL,
		.decode = dhcpopt_decode_novalue,
		.free   = NULL,
		.show	= dhcpopt_show_novalue,
		.enumfn	= NULL,
		.init	= NULL,
		.fini	= NULL,
		.dtree	= NULL
	}};


#if 0
		/*  83 */ "Agent Remote ID",
		/*  84 */ "Agent Subnet Mask",
		/*  85 */ "NDS server",
		/*  86 */ "NDS tree name",
		/*  87 */ "NDS context",
		/*  88 */ "IEEE 1003.1 POSIX",
		/*  89 */ "FQDN",
		/*  90 */ "Authentication",
		/*  91 */ "Vines TCP/IP",
		/*  92 */ "Server Selection",
		/*  93 */ "Client System",
		/*  94 */ "Client NDI",
		/*  95 */ "LDAP",
		/*  96 */ "IPv6 Transitions",
		/*  97 */ "UUID/GUID",
		/*  98 */ "UPA servers",
		/* 100 */ "Printer Name",
		/* 101 */ "MDHCP",
		/* 108 */ "Swap Path",
		/* 110 */ "IPX Compatability",
		/* 112 */ "Netinfo Address",
		/* 113 */ "Netinfo Tag",
		/* 114 */ "URL",
		/* 115 */ "DHCP Failover",
		/* 116 */ "DHCP Autoconfiguration",
		/* 117 */ "Name Service Search",
		/* 118 */ "Subnet selection",
		/* 119 */ "Domain Search",
		/* 120 */ "SIP Servers DHCP Option",
		/* 121 */ "Classless Static Route",
		/* 126 */ "Extension",
		/* 127 */ "Extension",
		/* 144 */ "HP - TFTP file",
		/* 210 */ "Authenticate",
		/* 249 */ "MSFT - Classless route",
		/* 252 */ "MSFT - WinSock Proxy Auto Detect",
#endif

static
void
dhcpopt_chktlv(struct dhcpopt_descriptor *optd, const uint8_t *begp, const uint8_t *endp)
{
	uint8_t code, length;
	const uint8_t *p;

	if (begp >= endp) {
		ectlno_seterror(E_DHCPENDOFDATA);
		ectlno_printf("%s(),%d: {%s} %s.\n", __func__, __LINE__, 
			error_name(ectlno_error), error_desc(ectlno_error));
		ectlfr_trap();
	}
	p = begp;

	code = *p++;
	if (optd && optd->flags & DHCPOPT_F_NOLENGTH) {
		if (optd->flags & DHCPOPT_F_NOVALUE) return;
		length = optd->elsz;
	} else {
		if (p >= endp) {
			ectlno_seterror(E_DHCPDATAINCOMPLETE);
			ectlno_printf("%s(),%d: {%s} Unable to determine the length of dhcp option %" 
				PRIu8 " (%s) because the received data have ended.\n",
				__func__, __LINE__, error_name(ectlno_error), code, optd ? optd->name : "???");
			ectlfr_trap();
		}
		length = *p++;
	}
	if (p + length > endp) {
		ectlno_seterror(E_DHCPOPTDECODE);
		ectlno_printf("%s(),%d: {%s} The dhcp option %" PRIu8 " (%s) has length %" PRIu8 
			" which oversteps the bounds of the received data.\n", 
			__func__, __LINE__, error_name(ectlno_error), 
			code, optd ? optd->name : "???", length);
		ectlfr_trap();
	}
	if (optd) {
		if (optd->min && length < optd->min) {
			ectlno_seterror(E_DHCPOPTDECODE);
			ectlno_printf("%s(),%d: {%s} The option %" PRIu8 " (%s) length (%" PRIu8 ") is"
				" less than expected minimum (%" PRIu8 " octets).\n",
				__func__, __LINE__, error_name(ectlno_error), 
				code, optd->name, length, optd->min);
			ectlfr_trap();
		}
		if (optd->max && length > optd->max) {
			ectlno_seterror(E_DHCPOPTDECODE);
			ectlno_printf("%s(),%d: {%s} The option %" PRIu8 " (%s) length (%" PRIu8 ") is"
				" more than expected miximum (%" PRIu8 " octets).\n",
				__func__, __LINE__, error_name(ectlno_error), 
				code, optd->name, length, optd->max);
			ectlfr_trap();
		}
		if (optd->elsz && (length % optd->elsz)) {
			ectlno_seterror(E_DHCPOPTDECODE);
			ectlno_printf("%s(),%d: {%s} The option %" PRIu8 " (%s) length (%" PRIu8 ")"
				" isn't multiple %" PRIu8 ".\n",
				__func__, __LINE__, error_name(ectlno_error), 
				code, optd->name, length, optd->elsz);
			ectlfr_trap();
		}
	}
}

struct dhcpopt *
dhcpopt_decode(struct rbtree *dtree, const uint8_t **curp, const uint8_t *endp)
{
	struct dhcpopt *opt = NULL;
	struct dhcpopt_descriptor *optd;
	uint8_t code, length;

	code = **curp;
	optd = dhcp_getoptdescriptor(dtree, code);
	dhcpopt_chktlv(optd, *curp, endp);
	if (optd)
		opt = optd->decode(optd, curp, endp);
	else {
		length = (*curp)[1];
		opt = MALLOC(offsetof(struct dhcpopt, u8) + length);
		opt->optd = NULL;
		opt->code = code;
		opt->length = length;
		memcpy(opt->u8, *curp + 2, length);
		*curp += 2 + length;
	}
	return opt;
}

void
dhcpopt_free(struct dhcpopt *opt)
{
	if (opt->optd && opt->optd->free)
		opt->optd->free(opt);
	else
		free(opt);
}

void
dhcpopt_show(struct dhcpopt *opt, int indent, FILE *fp)
{
	if (opt->optd && opt->optd->show)
		opt->optd->show(opt, indent, fp);
	else {
		fprintf(fp, "%*soption %3" PRIu8 " (%3" PRIu8 ") %-*s ", 
			indent, "", opt->code, opt->length, 
			DHCPOPTNAME_MAX, opt->optd ? opt->optd->name : "???");
		for (const char *p = opt->s; p < opt->s + opt->length; p++)
			fprintf(fp, "%c", (isascii(*p) && isprint(*p)) ? *p : '.');
		fprintf(fp, "\n");
	}
}

const char *
dhcpoptval_enum(struct dhcpopt_descriptor *optd, void *value)
{
	const char *s = NULL;
	if (optd && optd->enumfn)
		s = optd->enumfn(optd, value);
	return s;
}

static 
void __attribute__((__constructor__)) 
dhcp_module_init()
{
	struct ectlfr fr[1];
	struct ectlno ex[1];
	struct dhcpopt_descriptor *ddtab[] = {
		dhcpoptd1_subnet_mask,
		dhcpoptd2_time_offset,
		dhcpoptd3_routers,
		dhcpoptd4_time_server,
		dhcpoptd5_name_server,
		dhcpoptd6_dns_server,
		dhcpoptd7_log_server,
		dhcpoptd8_cookie_server,
		dhcpoptd9_lpr_server,
		dhcpoptd10_impress_server,
		dhcpoptd11_resource_location_server,
		dhcpoptd12_host_name,
		dhcpoptd13_boot_file_size,
		dhcpoptd14_merit_dump_file,
		dhcpoptd15_domain_name,
		dhcpoptd16_swap_server,
		dhcpoptd17_root_path,
		dhcpoptd18_extensions_path,
		dhcpoptd19_ip_forwarding,
		dhcpoptd20_non_local_source_routing,
		dhcpoptd21_policy_filter,
		dhcpoptd22_max_datagram_reassembly_size,
		dhcpoptd23_default_ip_ttl,
		dhcpoptd24_path_mtu_aging_timeout,
		dhcpoptd25_path_mtu_plateau_table,
		dhcpoptd26_interface_mtu,
		dhcpoptd27_all_subnets_local,
		dhcpoptd28_broadcast_address,
		dhcpoptd29_perform_mask_discovery,
		dhcpoptd30_mask_supplier,
		dhcpoptd31_perform_router_discovery,
		dhcpoptd32_router_solicitation_address,
		dhcpoptd33_static_route,
		dhcpoptd34_trailer_encapsulation,
		dhcpoptd35_arp_cache_timeout,
		dhcpoptd36_ethernet_encapsulation,
		dhcpoptd37_tcp_default_ttl,
		dhcpoptd38_tcp_keepalive_interval,
		dhcpoptd39_tcp_keepalive_garbage,
		dhcpoptd40_nis_domain,
		dhcpoptd41_nis_servers,
		dhcpoptd42_ntp_servers,
		dhcpoptd43_vendor_specific_information,
		dhcpoptd44_netbios_name_server,
		dhcpoptd45_netbios_dd_server,
		dhcpoptd46_netbios_node_type,
		dhcpoptd47_netbios_scope,
		dhcpoptd48_xwindow_font_server,
		dhcpoptd49_xwindow_display_manager,
		dhcpoptd50_requested_ip_address,
		dhcpoptd51_ip_address_lease_time,
		dhcpoptd52_option_overload,
		dhcpoptd53_dhcp_message_type,
		dhcpoptd54_server_identifier,
		dhcpoptd55_parameter_request_list,
		dhcpoptd56_message,
		dhcpoptd57_maximum_dhcp_message_size,
		dhcpoptd58_renewal_time_value,
		dhcpoptd59_rebinding_time_value,
		dhcpoptd60_vendor_class_identifier,
		dhcpoptd61_client_identifier,
		dhcpoptd62_netwareip_domain_name,
		dhcpoptd63_netwareip_information,
		dhcpoptd64_nisplus_domain,
		dhcpoptd65_nisplus_servers,
		dhcpoptd66_tftp_server_name,
		dhcpoptd67_bootfile_name,
		dhcpoptd68_mobile_ip_home_agent,
		dhcpoptd69_smtp_server,
		dhcpoptd70_pop3_server,
		dhcpoptd71_nntp_server,
		dhcpoptd72_www_server,
		dhcpoptd73_finger_server,
		dhcpoptd74_irc_server,
		dhcpoptd75_streettalk_server,
		dhcpoptd76_streettalk_directory_assistance_server,
		dhcpoptd77_user_class,
		dhcpoptd78_slp_directory_agent,
		dhcpoptd79_slp_service_scope,
		dhcpoptd81_client_fqdn,
		dhcpoptd82_relay_agent_information,
		dhcpoptd255_end
	};

	ectlfr_begin(fr, L_0);
	ectlno_begin(ex);
	dhcpopt_dtree = dhcpopt_dtree_create(ddtab, sizeof ddtab/sizeof ddtab[0]);
	ectlno_end(ex);
	ectlfr_end(fr);
	return;

L_0:	ectlno_log();
	ectlno_clearmessage();
	ectlno_end(ex);
	ectlfr_end(fr);
	exit(1);
}

static
void __attribute__((__destructor__))
dhcp_module_fini()
{
	if (dhcpopt_dtree) {
		dhcpopt_dtree_destroy(dhcpopt_dtree);
		dhcpopt_dtree = NULL;
	}
}


struct dhcp *
dhcp_decode(const uint8_t **curp, const uint8_t *endp)
{
	struct dhcp *volatile dp;
	struct dhcphdr *dhp;
	const uint8_t *cp;
        struct dhcpopt *opt;
	struct ectlfr fr[1];

	dp = NULL;
	dhp = (struct dhcphdr *)*curp;
        /* cookie 63:82:53:63 */
        if (dhp->options[0] != 0x63 || dhp->options[1] != 0x82 || 
			dhp->options[2] != 0x53 || dhp->options[3] != 0x63) {
		ectlno_seterror(E_DHCPWRONGCOOKIE);
                ectlno_printf("%s(),%d: {%s} %s\n", __func__, __LINE__, 
			error_name(ectlno_error), error_desc(ectlno_error));
		ectlfr_trap();
	}

	dp = MALLOC(sizeof(struct dhcp));
	dp->op = dhp->op;
	dp->htype = dhp->htype;
	dp->hlen = dhp->hlen;
	dp->hops = dhp->hops;
	dp->xid = ntohl(dhp->xid);
	dp->secs = ntohs(dhp->secs);
	dp->flags = ntohs(dhp->flags);
	dp->ciaddr = ntohl(*(uint32_t *)&dhp->ciaddr);
	dp->yiaddr = ntohl(*(uint32_t *)&dhp->yiaddr);
	dp->siaddr = ntohl(*(uint32_t *)&dhp->siaddr);
	dp->giaddr = ntohl(*(uint32_t *)&dhp->giaddr);
	memcpy(dp->chaddr, dhp->chaddr, dhp->hlen);
	memcpy(dp->sname, dhp->sname, DHCPHDR_SNAME_LEN);
	strlcpy(dp->file, dhp->file, DHCPHDR_FILE_LEN);
	STAILQ_INIT(dp->opts);
	ectlfr_begin(fr, L_1);

	cp = dhp->options + 4; /* skip cookie 63:82:53:63 */
	dhcp_decode_opts(dp->opts, dhcpopt_dtree, &cp, endp);
	*curp = cp;

	ectlfr_end(fr);
	return dp;

L_1:	ectlfr_ontrap(fr, L_0);
	dhcp_free(dp);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}
void
dhcp_free(struct dhcp *dp)
{
	if (dp) {
		dhcp_free_opts(dp->opts);
		free(dp);
	}
}

static inline
int
hexchar2number(int c)
{
	int n = -1;
	if (isdigit(c))
		n = tolower(c) - '0';
	else if (isxdigit(c))
		n = tolower(c) - 'a' + 10;
	return n;
}

struct dhcpopt82_value *
dhcpopt82_research(struct dhcpopt *opt)
{
#if 0
        option  82 ( 18) Relay Agent Information
          option   1 (  6) Circuit-ID       00:04:0a:42:00:0e
          option   2 (  8) Remote-ID        00:06:00:26:5a:96:52:e0
#endif
        struct dhcpopt82_value *optval;
        struct dhcpopt *circuit_id, *remote_id;
	uint16_t vlanid;
	uint8_t module, port;
	struct ether_addr ether;
	uint8_t slen;
	char *str;

        circuit_id = dhcpoptlst_find(opt->lst, DHCPOPT82_SUBOPT1_CIRCUITID);
        remote_id = dhcpoptlst_find(opt->lst, DHCPOPT82_SUBOPT2_REMOTEID);

        if (dhcpopt_length(opt) == 18 &&
                circuit_id && dhcpopt_length(circuit_id) == 6 &&
                        circuit_id->u8[0] == 0 && circuit_id->u8[1] == 4 &&
                remote_id && dhcpopt_length(remote_id) == 8 &&
                        remote_id->u8[0] == 0 && remote_id->u8[1] == 6)
        {
                vlanid = ntohs(*(uint16_t *)(circuit_id->u8 + 2));
                if (vlanid < 1 || vlanid > 4094)
                        goto L_not_default;
                module = circuit_id->u8[4];
                port = circuit_id->u8[5];
                ether = *(struct ether_addr *)(remote_id->u8 + 2);

                optval = MALLOC(offsetof(struct dhcpopt82_value, u8) + sizeof(optval->def[0]));
		optval->type = DHCPOPT82_T_DEFAULT;
		optval->def[0].vlanid = vlanid;
		optval->def[0].module = module;
		optval->def[0].port = port;
		optval->def[0].ether = ether;
                return optval;
        }
L_not_default:

#if 0
	option  82 ( 38) Relay Agent Information
          option   1 (  8) Circuit-ID   00 /*slot*/ : 26 /*port*/ : 0f:ad /*vid*/ : 70:6f:72:74 /*port*/
          option   2 ( 26) Remote-ID    33:38 : 2f : 30:30:31:39:63:62:38:65:61:35:63:34 : 2f : 32:32:31:30:30:34:30:31:37 : 2f
	26 00:19:cb:8e:a5:c4 
#endif
	if (circuit_id && dhcpopt_length(circuit_id) == 8 && !memcmp(circuit_id->u8 + 4, "port", 4) && 
		remote_id && dhcpopt_length(remote_id) >= 15 && remote_id->u8[2] == '/') {
		vlanid = ntohs(*(uint16_t *)(circuit_id->u8 + 2));
                if (vlanid < 1 || vlanid > 4094)
                        goto L_not_zyxel;
		module = circuit_id->u8[0];
		port = circuit_id->u8[1];
		for (int i = 0; i < ETHER_ADDR_LEN; i++)
			ether.octet[i] = hexchar2number(remote_id->u8[3+2*i]) * 16 + 
				hexchar2number(remote_id->u8[4+2*i]);
		optval = MALLOC(offsetof(struct dhcpopt82_value, u8) + sizeof(optval->def[0]));
		optval->type = DHCPOPT82_T_IES1248;
		optval->def[0].vlanid = vlanid;
		optval->def[0].module = module;
		optval->def[0].port = port;
		optval->def[0].ether = ether;
		return optval;
	}
L_not_zyxel:

#if 0
	agent.circuit-id = 9(slot) : 36(port) : 7:d0(vlanid) : 30:30:31:39:63:62:32:64:62:31:31:30(mac ascii string)
#endif
	if (dhcpopt_length(opt) == 18 && circuit_id && dhcpopt_length(circuit_id) == 16 && !remote_id) {
		vlanid = ntohs(*(uint16_t *)(circuit_id->u8 + 2));
                if (vlanid < 1 || vlanid > 4094)
                        goto L_not_zyxel_ies5000;
		module = circuit_id->u8[0];
		port = circuit_id->u8[1];
		for (int i = 0; i < ETHER_ADDR_LEN; i++)
			ether.octet[i] = hexchar2number(circuit_id->u8[4 + 2*i]) * 16 + 
				hexchar2number(circuit_id->u8[5 + 2*i]);
		optval = MALLOC(offsetof(struct dhcpopt82_value, u8) + sizeof(optval->def[0]));
		optval->type = DHCPOPT82_T_IES5000;
		optval->def[0].vlanid = vlanid;
		optval->def[0].module = module;
		optval->def[0].port = port;
		optval->def[0].ether = ether;
		return optval;
	}
L_not_zyxel_ies5000:

#if 0
	  option  82 ( 22) Relay Agent Information
	    option   1 (  6) Circuit-ID     00:04:0b:58:00:01
	    option   2 ( 12) Remote-ID      01: 0a(длина строки) : 31:30:2e:32:2e:34:34:2e:32:33(сама строка)
#endif
        if (circuit_id && dhcpopt_length(circuit_id) == 6 && circuit_id->u8[0] == 0 && circuit_id->u8[1] == 4 &&
			remote_id && remote_id->u8[0] == 1 && dhcpopt_length(remote_id)-2 == remote_id->u8[1]) {
                vlanid = ntohs(*(uint16_t *)(circuit_id->u8 + 2));
                if (vlanid < 1 || vlanid > 4094)
                        goto L_not_cdru;
                module = circuit_id->u8[4];
                port = circuit_id->u8[5];
                slen = remote_id->u8[1];
		str = (char *)remote_id->u8 + 2;
		for (size_t i = 0; i < slen; i++)
			if (!isprint(str[i]))
				goto L_not_cdru;

                optval = MALLOC(offsetof(struct dhcpopt82_value, u8) + sizeof(optval->cdru[0]) + slen + 1);
		optval->type = DHCPOPT82_T_CDRU;
		optval->cdru[0].vlanid = vlanid;
		optval->cdru[0].module = module;
		optval->cdru[0].port = port;
		optval->cdru[0].slen = slen;
		memcpy(optval->cdru[0].str, str, slen);
		optval->cdru[0].str[slen] = 0;
                return optval;
        }
L_not_cdru:

        return NULL;
}


void
dhcp_show(struct dhcp *dp, int indent, FILE *fp)
{
	char ciaddr_str[16], yiaddr_str[16], giaddr_str[16];
	struct dhcpopt *opt;

	ip_to_cstr(dp->ciaddr, ciaddr_str, sizeof ciaddr_str);
	ip_to_cstr(dp->yiaddr, yiaddr_str, sizeof yiaddr_str);
	ip_to_cstr(dp->giaddr, giaddr_str, sizeof giaddr_str);
        fprintf(fp, "%*sop: %" PRIu8 " (%s), htype: %" PRIu8 " (%s), hlen: %" PRIu8 ", hops: %" PRIu8 ", "
				"xid: 0x%08" PRIx32 ", secs: %" PRIu16 "\n"
		    "%*sflags: 0x%" PRIx16 "\n"
		    "%*sciaddr: %s, yiaddr: %s, giaddr: %s, chaddr: ",
		indent, "", dp->op, dhcp_opcode(dp->op), dp->htype, dhcp_htype(dp->htype), dp->hlen, dp->hops, 
				dp->xid, dp->secs,
		indent, "", dp->flags,
		indent, "", ciaddr_str, yiaddr_str, giaddr_str);
	if (dp->hlen) {
		fprintf(fp, "%02x", dp->chaddr[0]);
		for (int i = 1; i < dp->hlen; i++)
			fprintf(fp, ":%02x", dp->chaddr[i]);
	}
	fprintf(fp, "\n"
		"%*ssname: %s\n"
		"%*sfile: %s\n",
		indent, "", dp->sname, 
		indent, "", dp->file);
        STAILQ_FOREACH(opt, dp->opts, ent)
                dhcpopt_show(opt, indent, stdout);
}
