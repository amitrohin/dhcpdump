#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>

#include "foo.h"
#include "ip.h"

#ifndef lint
static char const rcsid[] = 
	"$Id: ipmap.c,v 1.8 2020/03/16 13:30:28 swp Exp $";
#endif /* !lint */

#define	ipseg_alloc()	MALLOC(sizeof(struct ipseg))
#define	ipseg_free	free

static
struct ipseg *
ipseg_dup(struct ipseg *s)
{
	struct ipseg *d;

	d = ipseg_alloc();
	*d = *s;
	return d;
}

/* 
 * сегмены в дереве никогда не пересекаются. достаточно сравнить
 * какое-нибудь из значений от каждого сегмента. возьмём например
 * левую (нижнюю) границу.
 */
static
int 
ipseg_cmp(struct ipseg *a, struct ipseg *b)
{
	int rc;

	rc = 0;
	if (a->a < b->a)
		rc = -1;
	else if (a->a > b->a)
		rc = 1;
	return rc;
}



/* часто используемые операции:
 *	getab(), geta(), getb(), addab()
 */
static inline
void
getab(struct rbglue *g, uint32_t *a, uint32_t *b)
{
	struct ipseg *s = (struct ipseg *)rbglue_dptr(g);
	*a = s->a;
	*b = s->b;
}

static inline
uint32_t
geta(struct rbglue *g)
{
	return (*(struct ipseg *)rbglue_dptr(g)).a;
}

static inline
uint32_t
getb(struct rbglue *g)
{
	return (*(struct ipseg *)rbglue_dptr(g)).b;
}

static
struct rbglue *
addab(struct rbtree *m, uint32_t a, uint32_t b)
{
	struct ectlfr fr[1];
	struct ipseg *s;
	struct rbglue *cg, *g;

	ectlfr_begin(fr, L_0);
	g = 0;
	s = ipseg_alloc();
	ectlfr_ontrap(fr, L_1);
	s->a = a;
	s->b = b;

	g = rbtree_insert(m, s, &cg);
	if (!g)
		ipseg_free(s);
	ectlfr_end(fr);
	return g;

L_1:	ectlfr_ontrap(fr, L_0);
	ipseg_free(s);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}

struct rbtree * 
ipmap_create()
{
	return rbtree_create(RBTREE_DCMP_CAST(ipseg_cmp));
}
void
ipmap_destroy(struct rbtree *map)
{
	rbtree_destroy(map, RBTREE_DFREE_CAST(ipseg_free));
}
void
ipmap_clear(struct rbtree *map)
{
	rbtree_clear(map, RBTREE_DFREE_CAST(ipseg_free));
}
struct rbtree *
ipmap_dup(struct rbtree *src)
{
	return rbtree_dup(src, RBTREE_DDUP_CAST(ipseg_dup), RBTREE_DFREE_CAST(ipseg_free));
}


/* Ищет сегмент в дереве, куда попадает ip. При присутствии такого сегмента возвращается NULL
 * и параметры *L, *R будут указывать на левый и правый узел (если что-то из этого есть), 
 * между которыми должен вставляться ip.
 */
static
struct rbglue *
ipmap_findip_private(struct rbtree *map, uint32_t ip, struct rbglue **L, struct rbglue **R)
{
	struct rbglue *p, *l, *r;

	for (l = r = NULL, p = rbtree_root(map); p; ) {
		uint32_t a, b;

		getab(p, &a, &b);
		if (b < ip) { 
			l = p; 
			p = rbglue_right(p); 
		} else if (a > ip) { 
			r = p;
			p = rbglue_left(p);
		} else
			break;
	}
	if (!p) {
		if (L)
			*L = l;
		if (R)
			*R = r;
	}
	return p;
}

int
ipmap_isset(struct rbtree *map, uint32_t a)
{
	return ipmap_findip_private(map, a, 0, 0) != 0;
}

static 
struct rbglue *
ipmap_map_private(struct rbtree *map, uint32_t a, uint32_t b)
{
	struct rbglue *ap, *al, *ar, *xp, *p, *q;
	struct ipseg *xs;
	uint32_t xa, xb;

	if (a > b)
		ECTL_PTRAP(EINVAL, "Wrong ip interval: 0x%08" PRIx32 "-0x08%" PRIx32 ".\n", a, b);

	/* Ищем сегмент с которым пересекается/касается новый сегмент.
	 * Получаем указатель на интервал
	 */
	ap = ipmap_findip_private(map, a, &al, &ar);
	if (ap) {
		/* Начало нового сегмента попало внутрь существующего. */
		xp = ap;
		xs = (struct ipseg *)rbglue_dptr(xp);
		if (b <= xs->b)
			return xp;
		xa = xs->a;
		xb = b;
	} else if (al && a && getb(al) == a - 1) {		
		/* Новый сегмент - смежный для левого сегмента. Расширяем левый сегмент. */
		xp = al;
		xs = (struct ipseg *)rbglue_dptr(xp);
		xa = xs->a;
		xb = b;
	} else if (ar && geta(ar) && geta(ar)-1 <= b) {
		/* Новый сегмент - не смежный для левого сегмента, но смежный для 
		   правого или пересекает его. Расширяем правый сегмент. */
		xp = ar;
		xs = (struct ipseg *)rbglue_dptr(xp);
		xa = a;
		xb = xs->b < b ? b : xs->b;
	} else
		return addab(map, a, b);

	for (p = rbglue_next(xp); p; p = q) {
		uint32_t a, b;

		getab(p, &a, &b);
		if (xb < a-1)
			break;
		q = rbglue_next(p);
		rbtree_remove(p, DFREE_CAST(ipseg_free));
		if (xb < b) {
			xb = b;
			break;
		}
	}
	xs->a = xa;
	xs->b = xb;
	return xp;
}

void
ipmap_map(struct rbtree *map, uint32_t a, uint32_t b)
{
	ipmap_map_private(map, a, b);
}

void
ipmap_unmap(struct rbtree *map, uint32_t a, uint32_t b)
{
	struct rbglue *p, *q;
	struct ipseg *s;

	p = ipmap_findip_private(map, a, 0, &q);
	if (!p)
		p = q;

	for (; p; p = q) {
		q = rbglue_next(p);
		s = (struct ipseg *)rbglue_dptr(p);
		if (a <= s->a) {
			if (b < s->a)
				break;
			if (b < s->b) {
				s->a = b + 1;
				break;
			}
			rbtree_remove(p, DFREE_CAST(ipseg_free));
		} else if (a <= s->b) {
			if (b < s->b) {
				uint32_t sb = s->b;
				s->b = a - 1;
				s = ipseg_alloc();
				s->a = b + 1;
				s->b = sb;
				rbtree_insert(map, s, NULL);
				break;
			}
			s->b = a - 1;
		} else
			ECTL_TRAP(E_GENERIC, "Programming error. Unreachable code.\n");
	}
}

struct rbtree *
ipmap_not(struct rbtree *map)
{
	struct ectlfr fr[1];
	struct rbtree *m;
	struct rbglue *p;
	uint32_t A, a, b;

	ectlfr_begin(fr, L_0);
	m = ipmap_create();
	ectlfr_ontrap(fr, L_1);
	A = 0;
	p = rbtree_min(map);
	if (!p)
		goto L_lastseg;
	getab(p, &a, &b);
	if (!a) {
		if (b == 0x0ffffffff)
			goto L_exit;
		A = b + 1;
		p = rbglue_next(p);
		if (!p)
			goto L_lastseg;
		getab(p, &a, &b);
	}
	for (;;) {
		addab(m, A, a - 1);
		if (b == 0x0ffffffff)
			goto L_exit;
		A = b + 1;
		p = rbglue_next(p);
		if (!p)
			break;
		getab(p, &a, &b);
	}
L_lastseg:	
	addab(m, A, 0x0ffffffff);
L_exit:	ectlfr_end(fr);
	return m;

L_1:	ectlfr_ontrap(fr, L_0);
	ipmap_destroy(m);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}

struct rbtree *
ipmap_cross(struct rbtree *m1, struct rbtree *m2)
{
	struct ectlfr fr[1];
	struct rbtree *m;
	struct rbglue *g1, *g2;
	uint32_t a, b, a1, b1, a2, b2, s1b, s2b;

	ectlfr_begin(fr, L_0);
	m = ipmap_create();
	ectlfr_ontrap(fr, L_1);

	g1 = rbtree_min(m1);
	if (!g1)
		return m;
	g2 = rbtree_min(m2);
	if (!g2)
		return m;

	getab(g1, &a1, &b1);
	getab(g2, &a2, &b2);
	for (;;) {
		if (a1 < a2) {
			if (b1 < a2) {
				/* s1 левее s2 (не пересекает его) */
				goto L_shift;
			}
			if (b1 >= b2) {
				/* s1 содержит в себе s2 */
				a = a2;
				b = b2;
			} else {
				/* s1 левой стороной не попадает в s2, а правой попадает */
				a = a2;
				b = b1;
			}
		} else if (a1 <= b2) {
			if (b1 <= b2) {
				/* s1 содержится в s2 */
				a = a1;
				b = b1;
			} else {
				/* s1 левой стороной стороной попадает внутрь s2, а 
				   правой выходит за правую сторону s2 */
				a = a1;
				b = b2;
			}
		} else {
			/* s1 правее s2 (не пересекает его) */
			goto L_shift;
		}

		addab(m, a, b);

	L_shift:
		/* [!] три случая:
		 *	1. s1b < s2b
		 *		g1 = next g1;
		 *	2. s1b = s2b
		 *		g1 = next g1;
		 *		g2 = next g2;
		 *	3. s1b > s2b
		 *		g2 = next g2;
		 */
		s1b = b1;
		s2b = b2;
		if (s1b <= s2b) {
			g1 = rbglue_next(g1);
			if (!g1)
				break;
			getab(g1, &a1, &b1);
		} 
		if (s1b >= s2b) {
			g2 = rbglue_next(g2);
			if (!g2)
				break;
			getab(g2, &a2, &b2);
		}
	}
	ectlfr_end(fr);
	return m;

L_1:	ectlfr_ontrap(fr, L_0);
	ipmap_destroy(m);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}

struct rbtree *
ipmap_union(struct rbtree *m1, struct rbtree *m2)
{
	struct ectlfr fr[1];
	struct rbtree *m;
	struct rbglue *g1, *g2, *g;
	uint32_t a, b, a1, b1, a2, b2;

	ectlfr_begin(fr, L_0);
	m = ipmap_create();
	ectlfr_ontrap(fr, L_1);

	g1 = rbtree_min(m1);
	g2 = rbtree_min(m2);

	if (!g1) {
		g = g2;
		goto L_map_tail;
	}
	if (!g2) {
		g = g1;
		goto L_map_tail;
	}

	getab(g1, &a1, &b1);
	getab(g2, &a2, &b2);
	for (;;) {
		a = a1;
		if (a1 < a2) {
	L_a1_lt_a2:
			/* проверка на то, что [a1, b1] левее и 
			   не пересекает/касается [a2, b2] */
			if (b1 < a2 && a2 - b1 > 1) {
				b = b1;
				g1 = rbglue_next(g1);
				if (g1)
					getab(g1, &a1, &b1);
				goto L_map_ab;
			}
		} else if (a1 > a2) {
			a = a2;
	L_a1_gt_a2:
			/* проверка на то, что [a2, b2] левее и 
			   не пересекает/касается [a1, b1] */
			if (b2 < a1 && a1 - b2 > 1) {
				b = b2;
				g2 = rbglue_next(g2);
				if (g2)
					getab(g2, &a2, &b2);
				goto L_map_ab;
			}
		}
	L_a1_eq_a2:

		/* в этом месте "a" должно содержать меньшее из "a1" и "a2" */

		if (b1 < b2) {
			b = b2;
			g1 = rbglue_next(g1);
			if (!g1)
				goto L_map_ab;
			getab(g1, &a1, &b1);
		} else {
			b = b1;
			g2 = rbglue_next(g2);
			if (!g2)
				goto L_map_ab;
			getab(g2, &a2, &b2);
		}
		if (a1 < a2)
			goto L_a1_lt_a2;
		else if (a1 > a2)
			goto L_a1_gt_a2;
		else
			goto L_a1_eq_a2;

	L_map_ab:
		addab(m, a, b);

		if (!g1) {
			g = g2;
			break;
		}
		if (!g2) {
			g = g1;
			break;
		}
	}

	/* пропускаем все интервалы, которые левее "b" */
	for (; g; g = rbglue_next(g))
		if (getb(g) > b)
			break;
L_map_tail:
	for (; g; g = rbglue_next(g)) {
		uint32_t a, b;
		getab(g, &a, &b);
		addab(m, a, b);
	}
	ectlfr_end(fr);
	return m;

L_1:	ectlfr_ontrap(fr, L_0);
	ipmap_destroy(m);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}

struct rbtree *
ipmap_subtr(struct rbtree *m1, struct rbtree *m2)
{
	struct ectlfr fr[1];
	struct rbtree *m;
	struct rbglue *g1, *g2;
	uint32_t a, b, a1, b1, a2, b2, A, B;

	g1 = rbtree_min(m1);
	if (!g1)
		return ipmap_create();
	g2 = rbtree_min(m2);
	if (!g2)
		return ipmap_dup(m1);

	ectlfr_begin(fr, L_0);
	m = ipmap_create();
	ectlfr_ontrap(fr, L_1);

	/* [a1, b1]	- текущий сегмент g1 (уменьшаемое)
	 * [a2, b2]	- текущий сегмент g2 (вычитаемое)
	 * [A, B]	- сегмент из которого на самом деле нужно отсекать [a2, b2],
	 *		  может не совпадать с [a1, b1] из-за уже отрезанных кусков.
	 * [a, b]	- сегмент, который нужно добавить к результирующему множеству
	 *		  (разность)
	 */
	getab(g1, &a1, &b1);
	getab(g2, &a2, &b2);
	A = a1, B = b1;
	while (1) {
		if (A < a2) {
			a = A;
			if (B < a2) {
				b = B;
				/* [A, B < a2] -> [a = A, b = B], shift g1:AB */
			} else {
				b = a2 - 1;
				if (B > b2)
					A = b2 + 1;
				/* [A < a2, B <= b2] -> [a = A, b = a2 - 1], shift g1:AB(=g2) */
				/* [A < a2, B >  b2] -> [a = A, b = a2 - 1], A = b2 + 1, shift g2 */
			}
			addab(m, a, b);
		} else {
			if (A <= b2 && B > b2)
				A = b2 + 1;
			/* [A >= a2, B <= b2] -> [], shift g1:AB(=g2) */
			/* [A >= a2, B >  b2, A <= b2] -> [], A = b2 + 1, shift g2 */
			/* [A >= a2, B >  b2, A >  b2] -> [], shift g2 */
		}

		{
			uint32_t B1 = b1, B2 = b2;
			if (B1 <= B2) {
				g1 = rbglue_next(g1);
				if (!g1)
					break;
				getab(g1, &a1, &b1);
				A = a1, B = b1;
			} 
			if (B1 >= B2) {
				g2 = rbglue_next(g2);
				if (!g2) {
					addab(m, A, B);

					/* пропускаем все интервалы, которые левее "b" */
					for (; g1; g1 = rbglue_next(g1))
						if (getb(g1) > B)
							break;
					/* остаток дописываем */
					for (; g1; g1 = rbglue_next(g1)) {
						getab(g1, &a, &b);
						addab(m, a, b);
					}

					break;
				}
				getab(g2, &a2, &b2);
			}
		}
	}
	ectlfr_end(fr);
	return m;

L_1:	ectlfr_ontrap(fr, L_0);
	ipmap_destroy(m);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}

int
ipmap_isequal(struct rbtree *m1, struct rbtree *m2)
{
	struct rbglue *g1, *g2;
	uint32_t a1, b1, a2, b2;

	g1 = rbtree_min(m1);
	g2 = rbtree_min(m2);
	for (;;) {
		if (!g1 && !g2)
			break;
		if (!g1 || !g2)
			return 0;
		getab(g1, &a1, &b1);
		getab(g2, &a2, &b2);
		if (a1 != a2 || b1 != b2)
			return 0;
		g1 = rbglue_next(g1);
		g2 = rbglue_next(g2);
	}
	return 1;
}

void
ipmap_dump(FILE *fp, struct rbtree *map, const char *fmt, ...)
{
	va_list ap;
	struct rbglue *p;
	uint32_t a, b;
	char buf[MAX_IP_CSTR];

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fprintf(fp, "{\n");
	RBTREE_FOREACH(p, map) {
		getab(p, &a, &b);
		ip_to_cstr(a, buf, sizeof buf);
		fprintf(fp, "  %s", buf);
		if (a != b) {
			ip_to_cstr(b, buf, sizeof buf);
			fprintf(fp, "-%s", buf);
		}
		fprintf(fp, "\n");
	}
	fprintf(fp, "}\n");
}

#if 0
static
int
hibit1(uint32_t n) {
        uint32_t m, w, b, x;

        for (m = -1, w = 32, b = 0; w != 1; ) {
                w >>= 1;
                m >>= w;
                x = n & ~m;
                if (x) {
                        b += w;
                        n = x >> w;
                } else
                        n &= m;
        }
        if (!n)
                b = -1;
        return b;
}
#endif

void
ip_subnets(uint32_t a, uint32_t b, void *cookie, void (*callback)(void *, uint32_t, uint32_t, int))
{
	int hb;
	uint32_t x, m1, m2, b1;

	assert(a <= b);

        x = a ^ b;      /* отличающиеся биты */
        hb = FIND_HI_BIT1(x); /* старший из отличающихся (нумерация с 0) */

        /* маска сети - общей части a и b */
        b1 = 32;
        m1 = (uint32_t)-1;
        if (hb >= 0) {
                m1 = ((uint32_t)-1 << hb) << 1;
                b1 -= hb + 1;
        }
        m2 = ~m1;       /* wildcard mask */

        if ((a & m1) == a && (a | m2) == b) {
		if (!callback) {
			char buf[MAX_IP_CSTR];
			ip_to_cstr(a, buf, sizeof buf);
        		fprintf(cookie ? (FILE *)cookie : stdout, "%s/%d\n", buf, b1);
		} else
                	callback(cookie, a, m1, b1);
        } else {
                ip_subnets(a, a | (m2>>1), cookie, callback);
		ip_subnets(b & ~(m2>>1), b, cookie, callback);
	}
}

