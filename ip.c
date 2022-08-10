#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/types.h>

#include "foo.h"
#include "ip.h"

#ifndef lint
static const char rcsid[] = 
	"$Id: ip.c,v 1.13 2020/06/20 19:32:56 swp Exp $";
#endif /* !lint */

int
netmask_to_nbits(uint32_t mask)
{
	int nbits, nm;
	uint32_t m, mh, ml;
	char mask_cstr[MAX_IP_CSTR];

	nbits = 32;
	if (mask != (uint32_t)-1) {
		m = (uint32_t)-1;
		nm = 32;
		nbits = 0;
		do {
			nm >>= 1;
			if (!nm)
				break;
			mh = (m << nm) & m;
			ml = (m >> nm) & m;
			/* printf("-> %08" PRIx32 " [%d] | %08x %" PRId32 " %08" PRIx32 " %08" PRIx32 "\n", 
				mask, nbits, m, nm, mh, ml); */
			if ((mask & mh) == mh) {
				m = ml;
				nbits += nm;
				continue;
			}
			if ((mask & ml) == 0) {
				m = mh;
				continue;
			}
			ip_to_cstr(mask, mask_cstr, sizeof mask_cstr);
			ECTL_PTRAP(EINVAL, "The mask %s can't be expressed by number of bits.\n", mask_cstr);
		} while (1);
	}
	return nbits;
}

#define	__TRAP(_q, _ec, _bp, _ep,  ec, bp, ep, FMT, ...) do {			\
		__auto_type _ec = (ec);						\
		__auto_type _bp = (bp);						\
		__auto_type _ep = (ep);						\
										\
		ectlno_setposixerror(_ec);					\
		ectlno_printf("%s(),%d: {%s} \"",				\
			__func__, __LINE__, error_name(ectlno_error));		\
		for (const char *_q = _bp; _q < _ep; _q++)			\
			ectlno_printf("%c", isprint(*_q) ? *_q : '.');		\
		ectlno_printf("\" [%c] ... : " FMT,				\
			isprint(*_ep) ? *ep : '.', ##__VA_ARGS__);		\
		ectlfr_trap();							\
	} while (0)
#define	TRAP(e, bp, ep, FMT, ...)						\
		__TRAP(AUTONAME, AUTONAME, AUTONAME, AUTONAME,			\
					e, bp, ep, FMT, ##__VA_ARGS__)

uint32_t *
cstr_to_ip(uint32_t *ip, const char *begp, const char **endp)
{
	int a[4], i, c, cc;
	uint32_t ipaddr;
	const char *curp = begp;

	void *L = &&sL_START;

	for (c = -1; 1; curp++) {
		cc = c;
		c = *curp;
		goto *L;

	sL_START:
		if (!c)
			return NULL;
		if (isspace(c))
			continue;
		if (isdigit(c)) {
			if (c == '0') {
				L = &&sL_0;
				continue;
			}
			L = &&sL_IP;
			i = 0;
			a[i] = c - '0';
			continue;
		}
		TRAP(EINVAL, begp, curp, "syntax error.\n");

	sL_0:
		if (c == 'x') {
			L = &&sL_0x;
			continue;
		}
		if (c == '.') {
			L = &&sL_IP;
			a[0] = 0;
			a[1] = 0;
			i = 1;
			continue;
		}
		ipaddr = 0;
		if (!c || isspace(c) || ispunct(c))
			break;
		TRAP(EINVAL, begp, curp, "syntax error.\n");

	sL_0x:
		if (isxdigit(c)) {
			ipaddr = XDC2NUM(c);
			L = &&sL_HEX;
			continue;
		}
		TRAP(EINVAL, begp, curp, "syntax error.\n");

	sL_HEX:
		if (!c)
			break;
		if (isxdigit(c)) {
			uint32_t x = ipaddr * 16 + XDC2NUM(c);
			if (x < ipaddr) {
				ectlno_printf("%s(),%d: {%s} 0x%" PRIx32 "0(+0x%c): overflow uint32_t.\n",
					__func__, __LINE__, error_name(E_POSIX_ERANGE), ipaddr, c);
				TRAP(ERANGE, begp, curp, "syntax error.\n");
			}
			ipaddr = x;
			continue;
		}
		if (isspace(c) || ispunct(c))
			break;
		TRAP(EINVAL, begp, curp, "syntax error.\n");

	sL_IP:
		if (isdigit(c)) {
			if (!a[i] && cc == '0')
				TRAP(EINVAL, begp, curp, "syntax error.\n");
			a[i] = a[i]*10 + c - '0';
			if (a[i] & ~0x0ff) {
				if (!i) {
					L = &&sL_NUM;
					ipaddr = a[0];
					continue;
				}
				TRAP(EINVAL, begp, curp, "syntax error.\n");
			}
			continue;
		}
		if (c == '.') {
			if (++i == 4) {
				uint8_t ipa[4] = {a[0], a[1], a[2], a[3]};
				ipaddr = ntohl(*(uint32_t *)ipa);
				break;
			}
			a[i] = 0;
			continue;
		}
		if (!c || isspace(c) || ispunct(c)) {
			if (!i) {
				ipaddr = a[0];
				break;
			} else if (i == 1 && cc == '.') {
				curp--;
			} else if (i == 3) {
				uint8_t ipa[4] = {a[0], a[1], a[2], a[3]};
				ipaddr = ntohl(*(uint32_t *)ipa);
				break;
			}
		}
		TRAP(EINVAL, begp, curp, "syntax error.\n");

	sL_NUM:
		if (!c || isspace(c) || ispunct(c))
			break;
		if (isdigit(c)) {
			uint32_t x = ipaddr * 10 + c - '0';
			if (x < ipaddr) {
				ectlno_printf("%s(),%d: {%s} 0x%" PRIu32 "0(+0x%c): overflow uint32_t.\n",
					__func__, __LINE__, error_name(E_POSIX_ERANGE), ipaddr, c);
				TRAP(ERANGE, begp, curp, "syntax error.\n");
			}
			ipaddr = x;
			continue;
		}
		TRAP(EINVAL, begp, curp, "syntax error.\n");
	}
	*ip = ipaddr;
	if (endp)
		*endp = curp;
	return ip;
}

struct ipseg *
cstr_to_ipseg(struct ipseg *seg, const char *begp, const char **endp)
{
	uint32_t ip[2];
	const char *bp, *ep = NULL;
	long d;

	bp = begp;
	if (!cstr_to_ip(ip, bp, &ep))
		return NULL;
	do {
		if (*ep == '/' && isdigit(ep[1])) {
			bp = ep + 1;

			d = strtol(bp, (char **)&ep, 0);
			if ((!d && errno == EINVAL) || ((d == LONG_MIN || d == LONG_MAX) && errno == ERANGE))
				ECTL_PTRAP(errno, "strtoul(\"%s\"): %s.\n", bp, strerror(errno));
			if (!*ep || isspace(*ep) || (*ep != '.' && ispunct(*ep))) {
				if (d >= 0 && d <= 32) {
					ip[1] = nbits_to_netmask(d);
					seg->a = ip[0] &  ip[1];
					seg->b = ip[0] | ~ip[1];
					break;
				}
				goto L_syntax_error;
			}
			if (*ep != '.')
				goto L_syntax_error;
			cstr_to_ip(ip + 1, bp, &ep);
			if (*ep && !isspace(*ep) && !ispunct(*ep))
L_syntax_error:			TRAP(EINVAL, begp, ep, "syntax error.\n");
			netmask_to_nbits(ip[1]);
			seg->a = ip[0] &  ip[1];
			seg->b = ip[0] | ~ip[1];
			break;
		}
		if (*ep == '-') {
			bp = ep + 1;
			if (cstr_to_ip(ip + 1, bp, &ep)) {
				if (*ep && !isspace(*ep) && !ispunct(*ep))
					goto L_syntax_error;
				if (ip[0] > ip[1])
					goto L_syntax_error;
				seg->a = ip[0];
				seg->b = ip[1];
				break;
			}
			goto L_syntax_error;
		}
		if (*ep && !isspace(*ep) && !ispunct(*ep))
			goto L_syntax_error;
		seg->a = seg->b = ip[0];
	} while (0);
	if (endp)
		*endp = ep;
	return seg;
}

