#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include "foo.h"

#ifndef lint
static const char rcsid[] = 
	"$Id: rbtree.c,v 1.6 2020/03/16 13:30:28 swp Exp $";
#endif /* !lint */

int
rbglue_cmp(struct rbglue *a, struct rbglue *b)
{
	return a->rbtree->cmp(a->data, b->data);
}
RB_GENERATE(rbtreehead, rbglue, ent, rbglue_cmp);

void
rbtree_clear(struct rbtree *t, void (*dfree)(void *))
{
	struct rbglue **gg;

	gg = &RB_ROOT(t->tree);
	if (*gg) {
		struct ectlfr fr[1];

		ectlfr_begin(fr, L0);
		for (struct rbglue **ggtmp, *p, *pp;;) {
			ggtmp = &RB_LEFT(*gg, ent);
			if (*ggtmp) {
				gg = ggtmp;
				continue;
			}
			ggtmp = &RB_RIGHT(*gg, ent);
			if (*ggtmp) {
				gg = ggtmp;
				continue;
			}
			p = RB_PARENT(*gg, ent);
			if (dfree)
				ectlfr_call_no_exceptions(fr, dfree((*gg)->data));
			free(*gg);
			*gg = NULL;
			if (!p)
				break;
			pp = RB_PARENT(p, ent);
			if (!pp) {
				gg = &RB_ROOT(t->tree);
				continue;
			}
			ggtmp = &RB_LEFT(pp, ent);
			if (*ggtmp == p) {
				gg = ggtmp;
				continue;
			}
			gg = &RB_RIGHT(pp, ent);
		}
L0:		ectlfr_end(fr);
	}
}

struct rbtree *
rbtree_dup(struct rbtree *src, void *(*ddup)(void *), void (*dfree)(void *))
{
	struct ectlfr fr[1];
	struct rbtree *volatile dst;
	struct rbglue *p, *cg;
	void *volatile dat;

	ectlfr_begin(fr, L_0);
	dst = rbtree_create(src->cmp);
	ectlfr_ontrap(fr, L_1);
	RBTREE_FOREACH(p, src) {
		dat = ddup(rbglue_dptr(p));
		ectlfr_ontrap(fr, L_2);
		rbtree_insert(dst, dat, &cg);
		ectlfr_ontrap(fr, L_1);
	}
	ectlfr_end(fr);
	return dst;

L_2:	ectlfr_ontrap(fr, L_1);
	dfree(dat);
L_1:	ectlfr_ontrap(fr, L_0);
	rbtree_destroy(dst, dfree);
L_0:	ectlfr_end(fr);
	ectlfr_trap();
}

void
rbtree_remove(struct rbglue *glue, void (*dfree)(void *))
{
	struct ectlfr fr[1];
	struct ectlno ex[1];

	ectlfr_begin(fr, L_1);
	ectlno_begin(ex);
	RB_REMOVE(rbtreehead, glue->rbtree->tree, glue);
	if (dfree)
		dfree(glue->data);
	free(glue);
	goto L_0;

L_1:	free(glue);
	ectlno_log();
	ectlno_clearmessage();
L_0:	ectlno_end(ex);
	ectlfr_end(fr);
}

