/* vim:set tabstop=4:shiftwidth=4:expandtab */

#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/queue.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>

#include "foo.h"

#ifndef lint
static const char rcsid[] =
        "$Id: core.c,v 1.9 2019/10/14 16:06:47 swp Exp $";
#endif /* !lint */

syslogproc_t syslogproc = syslog;

void
log_buffer(int prio, char *buf)
{
	char *p, *b, *e;

        for (p = buf;;) {
                for (;; p++) {
                        if (!*p)
                                return;
                        if (isprint(*p) && !isspace(*p))
				break;
                }
		for (b = e = p++;; p++) {
			if (!*p)
				break;
			if (*p == '\r' || *p == '\n') {
				p++;
				break;
			}
			if (isprint(*p) && !isspace(*p))
				e = p;
		}
                char c = *++e; *e = '\0'; syslogproc(prio, "%s", b); *e = c;
        }
}

void
buf_addc(int ch, char **cp, char **buf, size_t *n)
{
	if (*cp == *buf + *n) {
		int nn = *n & ~0x0f;
		if (nn < 0x10)
			nn = 0x20;
		else
			nn = (*n & ~0x0f) << 1;
		char *p = REALLOC(*buf, nn);
		*cp = p + (*cp - *buf);
		*buf = p;
		*n = nn;
	}
	*(*cp)++ = ch;
}


__thread struct ectlfr_stk ectlfr_stk[1] = 
		{SLIST_HEAD_INITIALIZER(ectlfr_stk[0])};

__thread struct ectlno_stk ectlno_stk[1] = 
		{SLIST_HEAD_INITIALIZER(ectlno_stk[0])};
__thread char ectlno_msgbuf[MAX_ECTLNO_MSGBUF] = "", *ectlno_msgcurptr = NULL, 
		*ectlno_msginuseptr = NULL;

static
int
ectlno_fread(void *cookie, char *buf, int size)
{
        int n = ectlno_msginuseptr - ectlno_msgcurptr;
        if (n < size)
                size = n;
        memmove(buf, ectlno_message, size);
        ectlno_msgcurptr += size;
        return size;
}
static
int
ectlno_fwrite(void *cookie, const char *buf, int size)
{
	int n = ectlno_msgendptr - ectlno_msgcurptr - 1;
	if (size > n)
		size = n;
	memmove(ectlno_msgcurptr, buf, size);
	ectlno_msgcurptr += size;
	*ectlno_msgcurptr = '\0';
	if (ectlno_msgcurptr > ectlno_msginuseptr)
		ectlno_msginuseptr = ectlno_msgcurptr;
	return size;
}
static
fpos_t
ectlno_fseek(void *cookie, fpos_t offset, int whence)
{
        ssize_t fpos;

        fpos = (ssize_t)offset;
        switch (whence) {
                case SEEK_SET:
                        break;
                case SEEK_END:
                        fpos += ectlno_msginuseptr - ectlno_message;
                        break;
                case SEEK_CUR:
                        fpos += ectlno_msgcurptr - ectlno_message;
                        break;
                default:
                        goto L_EINVAL;
        }
        if (fpos < 0 || fpos > ectlno_msginuseptr - ectlno_message)
                goto L_EINVAL;
        ectlno_msgcurptr += fpos;
        return (fpos_t)fpos;

L_EINVAL:
        errno = EINVAL;
        return -1;
}

FILE *
ectlno_fopen()
{
	return funopen(NULL, ectlno_fread, ectlno_fwrite, ectlno_fseek, NULL);
}

