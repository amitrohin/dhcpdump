/* $Id: ip.h,v 1.7 2019/05/12 18:09:31 swp Exp $ */

#ifndef __foo_ip_h__
#define __foo_ip_h__

#include <sys/cdefs.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include <foo.h>

#define MAX_IP_CSTR	16

static inline
uint32_t	octets_to_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) 
{
	return ntohl(a|(b<<8)|(c<<16)|(d<<24));
}
static inline
void		ip_to_octets(uint32_t ip, uint8_t *a, uint8_t *b, uint8_t *c, uint8_t *d)
{
	ip = htonl(ip);
	*a = ((uint8_t *)&ip)[0];
	*b = ((uint8_t *)&ip)[1];
	*c = ((uint8_t *)&ip)[2];
	*d = ((uint8_t *)&ip)[3];
}
static inline
int		ip_to_cstr(uint32_t ip, char *buf, int n)
{
	uint8_t a, b, c, d;

	ip_to_octets(ip, &a, &b, &c, &d);
	return snprintf(buf, n, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, a, b, c, d);
}

__BEGIN_DECLS
uint32_t *	cstr_to_ip(uint32_t *ip, const char *begp, const char **endp);
int		netmask_to_nbits(uint32_t);
__END_DECLS

static inline
uint32_t	nbits_to_netmask(int nbits)
{
	if (nbits < 0 || nbits > 32) {
		ectlno_setposixerror(EINVAL);
		ectlno_printf("%s(),%d: {%s} wrong network mask /%d.\n", 
			__func__, __LINE__, error_name(ectlno_error), nbits);
		ectlfr_trap();
	}
	return nbits ? (uint32_t)-1 << (32 - nbits) : 0;
}


struct ipseg {
	uint32_t a, b;
};
#define MAX_IPSEG_CSTR	(MAX_IP_CSTR * 2)

static inline
int		ipseg_to_cstr(struct ipseg *seg, char *buf, int n)
{
	int len;
	uint8_t a0, a1, a2, a3, b0, b1, b2, b3;

	ip_to_octets(seg->a, &a0, &a1, &a2, &a3);
	if (seg->a == seg->b)
		len = snprintf(buf, n, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, a0, a1, a2, a3);
	else {
		ip_to_octets(seg->b, &b0, &b1, &b2, &b3);
		len = snprintf(buf, n, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 
				"-%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, 
			a0, a1, a2, a3, b0, b2, b2, b3);
	}
	return len;
}

__BEGIN_DECLS
struct ipseg *	cstr_to_ipseg(struct ipseg *seg, const char *begp, const char **endp);

struct rbtree *	ipmap_create();
void		ipmap_clear(struct rbtree *);
void		ipmap_destroy(struct rbtree *);
struct rbtree *	ipmap_dup(struct rbtree *);

static inline
int
ipmap_empty(struct rbtree *tree)
{
	return rbtree_empty(tree);
}

int		ipmap_isset(struct rbtree *, uint32_t);
void		ipmap_map(struct rbtree *, uint32_t, uint32_t);
void		ipmap_unmap(struct rbtree *, uint32_t, uint32_t);

void		ipmap_dump(FILE *, struct rbtree *, const char *fmt, ...);

struct rbtree *	ipmap_not(struct rbtree *);
struct rbtree *	ipmap_cross(struct rbtree *, struct rbtree *);
struct rbtree *	ipmap_union(struct rbtree *, struct rbtree *);
struct rbtree *	ipmap_subtr(struct rbtree *, struct rbtree *);

int		ipmap_isequal(struct rbtree *, struct rbtree *);

/* ip_subnets()
 *
 * для указанного диапазона ip адресов [start, end] будет произведено
 * разбиение на подсети по ближайшей маске (построено оптимальное покрытие)
 * и для каждого получившегося диапазона вызвана функция callback().
 *
 * callback() принимает параметры:
 *   1. cookie 	- указатель на пользовательские данные, который передается
 *                из параметра cookie функции ip_subnets_call_cb()
 *   2. subnet  - адрес сети (host byte order)
 *   3. netmask - маска сети (host byte order). example: 255.255.255.0
 *   4. nbits   - маска сети в количестве битов (0 <= nbits <= 32)
 *
 * example:
 *
 * static
 * void
 * callback(void *cookie __unused, uint32_t start, uint32_t mask __unused, int nbits)
 * {
 *         struct in_addr a;
 *	   a.s_addr = htonl(start);
 *         printf("%s/%d\n", inet_ntoa(a), nbits);
 * }
 *
 * Если функция cb == 0, то будет вывод на экран сети (аналогично примеру). 
 * cookie воспринимается как FILE * в который нужно осуществить вывод. Если
 * cookie == 0, то подразумевается stdout.
 *
 * example:
 *
 *	ip_subnets(start, end, 0, 0);
 */
void ip_subnets(uint32_t start, uint32_t end, void *cookie, 
			void (*callback)(void *, uint32_t, uint32_t, int));

__END_DECLS

#endif
