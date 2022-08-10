/* $Id: core.h,v 1.30 2021/05/18 07:47:36 swp Exp $ */
#ifndef __foo_h__
#define __foo_h__

#include <sys/cdefs.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <setjmp.h>
#include <errno.h>
#include <ctype.h>
#include <wchar.h>
#include <string.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <assert.h>

typedef struct error_defn *error_t;
struct error_type {
	const char *(*get_error_desc)(error_t);		/* статическое описание ошибки */
	const char *(*get_error_origname)(error_t);	/* если ошибка приходит из другой системы, то
							 * это её оригинальное имя. например у posix
							 * ошибок, это оригинальные имена макросов - 
							 * EINVAL, EAGAIN и т.д. */
};
struct error_defn {
	const char *name;				/* название ошибки, совпадает с именем переменной.
							 * например: E_POSIX_EINVAL */
	const struct error_type *type;			/* указатель на структуру операций с этим видом
							 * ошибок */
	union {
		const char *cstr;			/* поле статического описания ошибки */
		const int code;				/* поле кода ошибки (например для posix) */
		const char sbuf[0];			/* поле для хранения строки-идентификатора для
							 * динамической (external) ошибки */
	};
};

#define DECL_ERROR(e)		extern struct error_defn e[1];

extern const struct error_type error_type[1];
extern const struct error_type error_type_posix[1];
extern const struct error_type error_type_external[1];	/* тип динамических внешних ошибок */

#define	DEFN_ERROR(e, s)	struct error_defn e[1] = {{ .name = #e, .type = error_type, .cstr = s }};
#define	DEFN_POSIX_ERROR(e, c)	struct error_defn e[1] = {{ .name = #e, .type = error_type_posix, .code = c }};

static inline const char *error_name(error_t e) { return e->name; }
static inline const char *error_desc(error_t e) { return e->type->get_error_desc(e); }
static inline const char *error_origname(error_t e) { return e->type->get_error_origname(e); }

extern error_t (*get_error_by_name)(const char *error_name);
extern error_t (*get_error_by_origname)(const char *error_origname);

__BEGIN_DECLS
error_t		get_external_error(const char *);
__END_DECLS

DECL_ERROR(E_NOERROR)
DECL_ERROR(E_GENERIC)
DECL_ERROR(E_HOSTUNKNOWN)
DECL_ERROR(E_NOTFOUND)
DECL_ERROR(E_SYNTAX)

DECL_ERROR(E_POSIX_EPERM)
DECL_ERROR(E_POSIX_ENOENT)
DECL_ERROR(E_POSIX_ESRCH)
DECL_ERROR(E_POSIX_EINTR)
DECL_ERROR(E_POSIX_EIO)
DECL_ERROR(E_POSIX_ENXIO)
DECL_ERROR(E_POSIX_E2BIG)
DECL_ERROR(E_POSIX_ENOEXEC)
DECL_ERROR(E_POSIX_EBADF)
DECL_ERROR(E_POSIX_ECHILD)
DECL_ERROR(E_POSIX_EDEADLK)
DECL_ERROR(E_POSIX_ENOMEM)
DECL_ERROR(E_POSIX_EACCES)
DECL_ERROR(E_POSIX_EFAULT)
DECL_ERROR(E_POSIX_ENOTBLK)
DECL_ERROR(E_POSIX_EBUSY)
DECL_ERROR(E_POSIX_EEXIST)
DECL_ERROR(E_POSIX_EXDEV)
DECL_ERROR(E_POSIX_ENODEV)
DECL_ERROR(E_POSIX_ENOTDIR)
DECL_ERROR(E_POSIX_EISDIR)
DECL_ERROR(E_POSIX_EINVAL)
DECL_ERROR(E_POSIX_ENFILE)
DECL_ERROR(E_POSIX_EMFILE)
DECL_ERROR(E_POSIX_ENOTTY)
DECL_ERROR(E_POSIX_ETXTBSY)
DECL_ERROR(E_POSIX_EFBIG)
DECL_ERROR(E_POSIX_ENOSPC)
DECL_ERROR(E_POSIX_ESPIPE)
DECL_ERROR(E_POSIX_EROFS)
DECL_ERROR(E_POSIX_EMLINK)
DECL_ERROR(E_POSIX_EPIPE)
DECL_ERROR(E_POSIX_EDOM)
DECL_ERROR(E_POSIX_ERANGE)
DECL_ERROR(E_POSIX_EAGAIN)
DECL_ERROR(E_POSIX_EINPROGRESS)
DECL_ERROR(E_POSIX_EALREADY)
DECL_ERROR(E_POSIX_ENOTSOCK)
DECL_ERROR(E_POSIX_EDESTADDRREQ)
DECL_ERROR(E_POSIX_EMSGSIZE)
DECL_ERROR(E_POSIX_EPROTOTYPE)
DECL_ERROR(E_POSIX_ENOPROTOOPT)
DECL_ERROR(E_POSIX_EPROTONOSUPPORT)
DECL_ERROR(E_POSIX_ESOCKTNOSUPPORT)
DECL_ERROR(E_POSIX_EOPNOTSUPP)
DECL_ERROR(E_POSIX_EPFNOSUPPORT)
DECL_ERROR(E_POSIX_EAFNOSUPPORT)
DECL_ERROR(E_POSIX_EADDRINUSE)
DECL_ERROR(E_POSIX_EADDRNOTAVAIL)
DECL_ERROR(E_POSIX_ENETDOWN)
DECL_ERROR(E_POSIX_ENETUNREACH)
DECL_ERROR(E_POSIX_ENETRESET)
DECL_ERROR(E_POSIX_ECONNABORTED)
DECL_ERROR(E_POSIX_ECONNRESET)
DECL_ERROR(E_POSIX_ENOBUFS)
DECL_ERROR(E_POSIX_EISCONN)
DECL_ERROR(E_POSIX_ENOTCONN)
DECL_ERROR(E_POSIX_ESHUTDOWN)
DECL_ERROR(E_POSIX_ETOOMANYREFS)
DECL_ERROR(E_POSIX_ETIMEDOUT)
DECL_ERROR(E_POSIX_ECONNREFUSED)
DECL_ERROR(E_POSIX_ELOOP)
DECL_ERROR(E_POSIX_ENAMETOOLONG)
DECL_ERROR(E_POSIX_EHOSTDOWN)
DECL_ERROR(E_POSIX_EHOSTUNREACH)
DECL_ERROR(E_POSIX_ENOTEMPTY)
DECL_ERROR(E_POSIX_EPROCLIM)
DECL_ERROR(E_POSIX_EUSERS)
DECL_ERROR(E_POSIX_EDQUOT)
DECL_ERROR(E_POSIX_ESTALE)
DECL_ERROR(E_POSIX_EREMOTE)
DECL_ERROR(E_POSIX_EBADRPC)
DECL_ERROR(E_POSIX_ERPCMISMATCH)
DECL_ERROR(E_POSIX_EPROGUNAVAIL)
DECL_ERROR(E_POSIX_EPROGMISMATCH)
DECL_ERROR(E_POSIX_EPROCUNAVAIL)
DECL_ERROR(E_POSIX_ENOLCK)
DECL_ERROR(E_POSIX_ENOSYS)
DECL_ERROR(E_POSIX_EFTYPE)
DECL_ERROR(E_POSIX_EAUTH)
DECL_ERROR(E_POSIX_ENEEDAUTH)
DECL_ERROR(E_POSIX_EIDRM)
DECL_ERROR(E_POSIX_ENOMSG)
DECL_ERROR(E_POSIX_EOVERFLOW)
DECL_ERROR(E_POSIX_ECANCELED)
DECL_ERROR(E_POSIX_EILSEQ)
DECL_ERROR(E_POSIX_ENOATTR)
DECL_ERROR(E_POSIX_EDOOFUS)
DECL_ERROR(E_POSIX_EBADMSG)
DECL_ERROR(E_POSIX_EMULTIHOP)
DECL_ERROR(E_POSIX_ENOLINK)
DECL_ERROR(E_POSIX_EPROTO)
DECL_ERROR(E_POSIX_ENOTCAPABLE)
DECL_ERROR(E_POSIX_ECAPMODE)
DECL_ERROR(E_POSIX_ENOTRECOVERABLE)
DECL_ERROR(E_POSIX_EOWNERDEAD)

__BEGIN_DECLS
error_t		posix_name_to_error(const char *);
error_t		posix_code_to_error(int);
__END_DECLS
#define		errno_to_error		posix_code_to_error


/* отступ, при выводе полей структур (смещение на уровень вложенности) */
#define DUMP_OFFSET_STEP	2

#define CONCAT(x, y)		__CONCAT(x, y)
#define AUTONAME		CONCAT(_autoname_, __COUNTER__)

typedef void free_t(void *);
typedef int cmp_t(const void *, const void *);

typedef void (*syslogproc_t)(int, const char *, ...);
extern syslogproc_t syslogproc;

#define LOG			syslogproc

#define PLOG(fmt, ...)          LOG(LOG_EMERG,   fmt, ## __VA_ARGS__)
#define ALOG(fmt, ...)          LOG(LOG_ALERT,   fmt, ## __VA_ARGS__)
#define CLOG(fmt, ...)          LOG(LOG_CRIT,    fmt, ## __VA_ARGS__)
#define ELOG(fmt, ...)          LOG(LOG_ERR,     fmt, ## __VA_ARGS__)
#define WLOG(fmt, ...)          LOG(LOG_WARNING, fmt, ## __VA_ARGS__)
#define NLOG(fmt, ...)          LOG(LOG_NOTICE,  fmt, ## __VA_ARGS__)
#define ILOG(fmt, ...)          LOG(LOG_INFO,    fmt, ## __VA_ARGS__)
#define DLOG(fmt, ...)          LOG(LOG_DEBUG,   fmt, ## __VA_ARGS__)

__BEGIN_DECLS
void		log_buffer(int prio, char *buf);
__END_DECLS

#define LOG_BUFFER		log_buffer
#define PLOG_BUFFER(buf)	LOG_BUFFER(LOG_EMERG,   buf)
#define ALOG_BUFFER(buf)	LOG_BUFFER(LOG_ALERT,   buf)
#define CLOG_BUFFER(buf)	LOG_BUFFER(LOG_CRIT,    buf)
#define ELOG_BUFFER(buf)	LOG_BUFFER(LOG_ERR,     buf)
#define WLOG_BUFFER(buf)	LOG_BUFFER(LOG_WARNING, buf)
#define NLOG_BUFFER(buf)	LOG_BUFFER(LOG_NOTICE,  buf)
#define ILOG_BUFFER(buf)	LOG_BUFFER(LOG_INFO,    buf)
#define DLOG_BUFFER(buf)	LOG_BUFFER(LOG_DEBUG,   buf)

/* objptr = OBJ_ATTACH(objaddr, nref);
 *
 * OBJ_DETACH(objaddr, nref) {
 *	obj_fini(objaddr);
 *	free(objaddr);
 * }
 */
#define __OBJ_ATTACH(objaddr, ref, _objaddr) ({		\
                __auto_type _objaddr = (objaddr);	\
                _objaddr->ref++;			\
                _objaddr;				\
        })
#define OBJ_ATTACH(obj, ref)    __OBJ_ATTACH(obj, ref, AUTONAME)

#define OBJ_DETACH(objaddr, ref)			\
                if ((objaddr)->ref > 1)			\
                        (objaddr)->ref--;		\
                else

/* http://fdiv.net/2015/10/08/emulating-defer-c-clang-or-gccblocks
 *
 * static inline
 * void
 * cleanup_ptr(void **pptr)
 * {
 *	if (*pptr)
 *		free(*pptr);
 * }
 *
 * int
 * main()
 * {
 *	char *p CLEANUP(cleanup_ptr) = malloc(N);
 *	return EXIT_SUCCESS;
 * }
 */
#define CLEANUP(f)		__attribute__((__cleanup__(f)))

static inline
void 
cleanup_ptr(void **pptr)
{
	if (*pptr)
		free(*pptr);
}
static inline
void 
cleanup_FILE(FILE **pfp)
{
	if (*pfp)
		fclose(*pfp);
}

struct ectlfr {
	jmp_buf env;
	void *jaddr;
	SLIST_ENTRY(ectlfr) ent;
};
extern __thread SLIST_HEAD(ectlfr_stk, ectlfr) ectlfr_stk[1];

#ifndef DEBUG_ECTLFR
#define ectlfr_begin(fr, L) do {				\
		(fr)->jaddr = &&L;				\
		SLIST_INSERT_HEAD(ectlfr_stk, (fr), ent);	\
		if (setjmp((fr)->env))				\
			goto *(fr)->jaddr;			\
	} while (0)
#define	ectlfr_end(fr) do { \
		SLIST_REMOVE_HEAD(ectlfr_stk, ent); \
	} while (0)
#else
#define ectlfr_begin(fr, L) do {				\
		(fr)->jaddr = &&L;				\
printf("\n%s(),%d: (1) ectlfr_begin(%p): ectlfr_stk -> %p\n", __func__, __LINE__, fr, SLIST_FIRST(ectlfr_stk)); \
		SLIST_INSERT_HEAD(ectlfr_stk, (fr), ent);	\
printf("\n%s(),%d: (2) ectlfr_begin(%p): ectlfr_stk -> %p\n", __func__, __LINE__, fr, SLIST_FIRST(ectlfr_stk)); \
		if (setjmp((fr)->env))				\
			goto *(fr)->jaddr;			\
	} while (0)
#define	ectlfr_end(fr) do { \
printf("\n%s(),%d: (1) ectlfr_end(%p): ectlfr_stk -> %p\n", __func__, __LINE__, fr, SLIST_FIRST(ectlfr_stk)); \
		SLIST_REMOVE_HEAD(ectlfr_stk, ent); \
printf("\n%s(),%d: (2) ectlfr_end(%p): ectlfr_stk -> %p\n", __func__, __LINE__, fr, SLIST_FIRST(ectlfr_stk)); \
	} while (0)
#endif

#define	ectlfr_goto(fr) \
		goto *(fr)->jaddr

#define	ectlfr_ontrap(fr, L) \
		(fr)->jaddr = &&L

#define ectlfr_trap() \
		longjmp(SLIST_FIRST(ectlfr_stk)->env, 1)

struct ectlno {
	error_t error;
        char *bptr;
        SLIST_ENTRY(ectlno) ent;
};
extern __thread SLIST_HEAD(ectlno_stk, ectlno) ectlno_stk[1];

/* [!] при больших значениях MAX_ECTLNO_MSGBUF происходит нарушение сегментации.
 * если убрать json_parser.y, или собирать без -lpthread, то проблема не возникает...
 */
#define	MAX_ECTLNO_MSGBUF 1000
extern __thread char ectlno_msgbuf[MAX_ECTLNO_MSGBUF], *ectlno_msgcurptr,
		*ectlno_msginuseptr;

#define	ectlno_msgendptr	(ectlno_msgbuf + sizeof ectlno_msgbuf)

#define	ectlno_error		(SLIST_FIRST(ectlno_stk)->error)
#define	ectlno_message		(SLIST_FIRST(ectlno_stk)->bptr)
#define	ectlno_iserror()	(ectlno_error != NULL && ectlno_error != E_NOERROR)

#define	ectlno_begin_(ctx, _ctx) do {					\
		struct ectlno *_ctx = (ctx);				\
		_ctx->error = NULL;					\
		if (!ectlno_msgcurptr)					\
			ectlno_msgcurptr = ectlno_msginuseptr =		\
				ectlno_msgbuf;				\
		_ctx->bptr = ectlno_msgcurptr;				\
		SLIST_INSERT_HEAD(ectlno_stk, _ctx, ent);		\
	} while(0)
#define ectlno_begin(ctx)	ectlno_begin_(ctx, AUTONAME)

#if defined(NDEBUG)
#define	ectlno_end_(ctx, _ctx) do {					\
		SLIST_REMOVE_HEAD(ectlno_stk, ent);			\
		if (SLIST_EMPTY(ectlno_stk)) {				\
			ectlno_msgcurptr = ectlno_msginuseptr =		\
				ectlno_msgbuf;				\
			ectlno_msgbuf[0] = '\0';			\
		}							\
	} while (0)
#else
#define	ectlno_end_(ctx, _ctx) do {					\
		struct ectlno *_ctx = (ctx);				\
		assert(_ctx == SLIST_FIRST(ectlno_stk));		\
		SLIST_REMOVE_HEAD(ectlno_stk, ent);			\
		if (SLIST_EMPTY(ectlno_stk)) {				\
			ectlno_msgcurptr = ectlno_msginuseptr =		\
				ectlno_msgbuf;				\
			ectlno_msgbuf[0] = '\0';			\
		}							\
	} while (0)
#endif
#define	ectlno_end(ctx)		ectlno_end_(ctx, AUTONAME)

#define __ectlno_seterror(ctx, e)	({ (ctx)->error = (e); })
#define ectlno_seterror(e)		__ectlno_seterror(SLIST_FIRST(ectlno_stk), e)
#define ectlno_setposixerror(erno)	ectlno_seterror(errno_to_error(erno))

#define	__ectlno_setparenterror(ctx, _eptr) do {			\
		__auto_type _eptr = SLIST_NEXT((ctx), ent);		\
		if (_eptr)						\
			_eptr->error = (ctx)->error;			\
	} while (0)
#define	ectlno_setparenterror(ctx)					\
		__ectlno_setparenterror(ctx, AUTONAME)

#define ectlno_clearcode()	ectlno_seterror(NULL)

#define ectlno_clearmessage() do {					\
		ectlno_msgcurptr = ectlno_msginuseptr =			\
			SLIST_FIRST(ectlno_stk)->bptr;			\
		ectlno_msgcurptr[0] = '\0';				\
	} while (0)

#define	ectlno_clearerror() do {					\
		ectlno_clearcode();					\
		ectlno_clearmessage();					\
	} while (0)

#define	ectlno_printf(fmt, ...) do {					\
		ectlno_msgcurptr += snprintf(ectlno_msgcurptr,		\
				ectlno_msgendptr - ectlno_msgcurptr,	\
					fmt, ##__VA_ARGS__);		\
		if (ectlno_msgcurptr > ectlno_msgendptr - 1)		\
			ectlno_msgcurptr = ectlno_msgendptr - 1;	\
		if (ectlno_msginuseptr < ectlno_msgcurptr)		\
			ectlno_msginuseptr = ectlno_msgcurptr;		\
	} while (0)

#define ectlno_log() \
		ELOG_BUFFER(SLIST_FIRST(ectlno_stk)->bptr)


#define __ECTL_CALL_NO_EXCEPTIONS(_fr, _ex, L_0, L_1, ...) do {		\
		__label__ L_0, L_1;					\
		struct ectlfr _fr[1];					\
		struct ectlno _ex[1];					\
									\
		ectlfr_begin(_fr, L_1);					\
		ectlno_begin(_ex);					\
		do { __VA_ARGS__; } while (0);				\
		goto L_0;						\
									\
	L_1:	ectlno_log();						\
		ectlno_clearmessage();					\
	L_0:	ectlno_end(_ex);					\
		ectlfr_end(_fr);					\
	} while (0)
#define	ECTL_CALL_NO_EXCEPTIONS(...)					\
		__ECTL_CALL_NO_EXCEPTIONS(AUTONAME, AUTONAME, AUTONAME,	\
				AUTONAME, __VA_ARGS__)
/* старое название */
#define ECTL_NO_EXCEPTIONS	ECTL_CALL_NO_EXCEPTIONS

/* макрос подобен ECTL_CALL_NO_EXCEPTIONS(), немного легче, но применим 
 * только в функциях, у которых есть свой собственный struct ectlfr.
 */
#define __ectlfr_call_no_exceptions(fr, _ex, _jaddr, L_0, L_1, ...) do {\
		__label__ L_0, L_1;					\
		struct ectlno _ex[1];					\
		__auto_type _jaddr = (fr)->jaddr;			\
		(fr)->jaddr = &&L_1;					\
		ectlno_begin(_ex);					\
		do { __VA_ARGS__; } while (0);				\
		goto L_0;						\
	L_1:	ectlno_log();						\
		ectlno_clearmessage();					\
	L_0:	ectlno_end(_ex);					\
		(fr)->jaddr = _jaddr;					\
	} while (0)
#define	ectlfr_call_no_exceptions(fr, ...)				\
		__ectlfr_call_no_exceptions(fr, AUTONAME, AUTONAME,	\
			AUTONAME, AUTONAME, __VA_ARGS__)

/* макрос ловит trap (т.е. ectlfr_trap()) и в случае, если он был, возвращает
 * отличное от 0 число. применим только в функциях с собственным struct ectlfr.
 */
#define __ectlfr_catch(fr, _trap, _jaddr, L_0, ...) ({			\
		__label__ L_0;						\
		__auto_type _jaddr = (fr)->jaddr;			\
		volatile int _trap = 1;					\
									\
		(fr)->jaddr = &&L_0;					\
		do {__VA_ARGS__;} while(0);				\
		_trap = 0;						\
	L_0:	(fr)->jaddr = _jaddr;					\
		_trap;							\
	})
#define	ectlfr_catch(fr, ...)						\
		__ectlfr_catch(fr, AUTONAME, AUTONAME,			\
			AUTONAME, __VA_ARGS__)

__BEGIN_DECLS
FILE *	ectlno_fopen();
__END_DECLS

#define ECTL_PREPARE_TRAP(e, fmt, ...) do {				\
		ectlno_seterror(e);					\
		ectlno_printf("%s(),%d: {%s%s} " fmt,			\
			__func__, __LINE__,				\
			error_name(ectlno_error) ? "" : "*",		\
			error_name(ectlno_error) ?:			\
				error_origname(ectlno_error),		\
			## __VA_ARGS__);				\
	} while (0)
#define ECTL_TRAP(e, fmt, ...) do {					\
		ECTL_PREPARE_TRAP(e, fmt, ##__VA_ARGS__);		\
		ectlfr_trap();						\
	} while (0)
#define ECTL_PREPARE_PTRAP(pe, fmt, ...)				\
		ECTL_PREPARE_TRAP(errno_to_error(pe), fmt, ##__VA_ARGS__)
#define ECTL_PTRAP(pe, fmt, ...) \
		ECTL_TRAP(errno_to_error(pe), fmt, ##__VA_ARGS__)
#define ECTL_PREPARE_TRAP_SAFE(e, fmt, ...) do {			\
		ectlno_seterror(e);					\
		ectlno_printf("%s(),%d: {%s%s} ",			\
			__func__, __LINE__,				\
			error_name(ectlno_error) ? "" : "*",		\
			error_name(ectlno_error) ?:			\
				error_origname(ectlno_error));		\
		ectlno_printf(fmt, ## __VA_ARGS__);			\
	} while (0)
#define ECTL_TRAP_SAFE(e, fmt, ...) do {				\
		ECTL_PREPARE_TRAP_SAFE(e, fmt, ##__VA_ARGS__);		\
		ectlfr_trap();						\
	} while (0)
#define ECTL_PTRAP_SAFE(pe, fmt, ...) \
		ECTL_TRAP_SAFE(errno_to_error(pe), fmt, ##__VA_ARGS__)

#define __PTHREAD_CALL(_errno, proc, ...) do {				\
		int _errno = proc(__VA_ARGS__);				\
		if (_errno) {						\
			ectlno_setposixerror(_errno);			\
			ectlno_printf("%s(),%d: {%s} %s.\n",		\
				#proc, __LINE__,			\
				error_name(ectlno_error),		\
				strerror(_errno));			\
			ectlfr_trap();					\
		}							\
	} while (0)
#define PTHREAD_CALL(proc, ...) \
		__PTHREAD_CALL(AUTONAME, proc, ##__VA_ARGS__)

#define PTHREAD_SPIN_INIT(lock, pshared) \
		PTHREAD_CALL(pthread_spin_init, lock, pshared)
#define PTHREAD_SPIN_DESTROY(lock) \
		PTHREAD_CALL(pthread_spin_destroy, lock)
#define PTHREAD_SPIN_LOCK(lock) \
		PTHREAD_CALL(pthread_spin_lock, lock)
#define PTHREAD_SPIN_UNLOCK(lock) \
		PTHREAD_CALL(pthread_spin_unlock, lock)
#define	PTHREAD_SPIN_TRYLOCK(lock) \
		PTHREAD_CALL(pthread_spin_trylock, lock)

#define PTHREAD_MUTEXATTR_INIT(mtxattr)	\
		PTHREAD_CALL(pthread_mutexattr_init, mtxattr)
#define PTHREAD_MUTEXATTR_DESTROY(mtxattr) \
		PTHREAD_CALL(pthread_mutexattr_destroy, mtxattr)
#define PTHREAD_MUTEXATTR_SETPRIOCEILING(mtxattr, prio)	\
		PTHREAD_CALL(pthread_mutexattr_setprioceiling, mtxattr, prio)
#define PTHREAD_MUTEXATTR_GETPRIOCEILING(mtxattr, prio)	\
		PTHREAD_CALL(pthread_mutexattr_getprioceiling, mtxattr, prio)
#define PTHREAD_MUTEXATTR_SETPROTOCOL(mtxattr, proto) \
		PTHREAD_CALL(pthread_mutexattr_setprotocol, mtxattr, proto)
#define PTHREAD_MUTEXATTR_GETPROTOCOL(mtxattr, proto) \
		PTHREAD_CALL(pthread_mutexattr_getprotocol, mtxattr, proto)
#define PTHREAD_MUTEXATTR_SETTYPE(mtxattr, type) \
		PTHREAD_CALL(pthread_mutexattr_settype, mtxattr, type)
#define PTHREAD_MUTEXATTR_GETTYPE(mtxattr, type) \
		PTHREAD_CALL(pthread_mutexattr_gettype, mtxattr, type)

#define PTHREAD_MUTEX_INIT(pmtx, pattr)	\
		PTHREAD_CALL(pthread_mutex_init, (pmtx), (pattr))
#define PTHREAD_MUTEX_DESTROY(pmtx) \
		PTHREAD_CALL(pthread_mutex_destroy, pmtx)
#define	PTHREAD_MUTEX_LOCK(pmtx) \
		PTHREAD_CALL(pthread_mutex_lock, pmtx)
#define	PTHREAD_MUTEX_UNLOCK(pmtx) \
		PTHREAD_CALL(pthread_mutex_unlock, pmtx)
#define	PTHREAD_MUTEX_TRYLOCK(pmtx) \
		PTHREAD_CALL(pthread_mutex_trylock, pmtx)

#define PTHREAD_CONDATTR_INIT(condattr)	\
		PTHREAD_CALL(pthread_condattr_init, condattr)
#define PTHREAD_CONDATTR_DESTROY(condattr) \
		PTHREAD_CALL(pthread_condattr_destroy, condattr)

#define PTHREAD_COND_INIT(pcond, pattr)	\
		PTHREAD_CALL(pthread_cond_init, pcond, pattr)
#define PTHREAD_COND_DESTROY(pcond) \
		PTHREAD_CALL(pthread_cond_destroy, pcond)
#define	PTHREAD_COND_WAIT(pcond, pmtx) \
		PTHREAD_CALL(pthread_cond_wait, pcond, pmtx)
#define	PTHREAD_COND_TIMEDWAIT(pcond, pmtx, ts) \
		PTHREAD_CALL(pthread_cond_timedwait, pcond, pmtx)

#define	PTHREAD_COND_BROADCAST(pcond) \
		PTHREAD_CALL(pthread_cond_broadcast, pcond)
#define PTHREAD_COND_SIGNAL(pcond) \
		PTHREAD_CALL(pthread_cond_signal, pcond)

#define PTHREAD_RWLOCK_INIT(prwlock, pattr) \
		PTHREAD_CALL(pthread_rwlock_init, prwlock, pattr)
#define PTHREAD_RWLOCK_DESTROY(prwlock) \
		PTHREAD_CALL(pthread_rwlock_destroy, prwlock)
#define PTHREAD_RWLOCK_RDLOCK(prwlock) \
		PTHREAD_CALL(pthread_rwlock_rdlock, prwlock)
#define PTHREAD_RWLOCK_WRLOCK(prwlock) \
		PTHREAD_CALL(pthread_rwlock_wrlock, prwlock)
#define PTHREAD_RWLOCK_UNLOCK(prwlock) \
		PTHREAD_CALL(pthread_rwlock_unlock, prwlock)

#define PTHREAD_ATTR_INIT(pattr) \
		PTHREAD_CALL(pthread_attr_init, pattr)
#define PTHREAD_ATTR_DESTROY(pattr) \
		PTHREAD_CALL(pthread_attr_destroy, pattr)
#define	PTHREAD_ATTR_SETDETACHSTATE(pattr, detachstate) \
		PTHREAD_CALL(pthread_attr_setdetachstate, pattr, detachstate)
#define	PTHREAD_ATTR_GETDETACHSTATE(pattr, pdetachstate) \
		PTHREAD_CALL(pthread_attr_getdetachstate, pattr, pdetachstate)
#define	PTHREAD_CREATE(pthr, pattr, start_routine, arg) \
		PTHREAD_CALL(pthread_create, pthr, pattr, start_routine, arg)
#define PTHREAD_JOIN(tid, parg) \
		PTHREAD_CALL(pthread_join, tid, parg)
#define PTHREAD_EXIT(pvalue) \
		({ pthread_exit(pvalue); 0; })
#define	PTHREAD_SELF() \
		pthread_self()
#define	PTHREAD_EQUAL(t1, t2) \
		pthread_equal(t1, t2)

#define	PTHREAD_KEY_CREATE(pkey, destructor) \
		PTHREAD_CALL(pthread_key_create, pkey, destructor)
#define	PTHREAD_KEY_DELETE(pkey) \
		PTHREAD_CALL(pthread_key_delete, pkey)
#define	PTHREAD_GETSPECIFIC(pkey) \
		pthread_getspecific(pkey)
#define PTHREAD_SETSPECIFIC(pkey, value) \
		PTHREAD_CALL(pthread_setspecific, pkey, value)

#define	PTHREAD_ONCE(once, oncefunc) \
		PTHREAD_CALL(pthread_once, once, oncefunc)

#define __FIND_HI_BIT1(n, _n, _b, _m, _x, _w) ({		\
		__auto_type _n = (n);				\
		int _b = -1;					\
		__typeof__(_n) _m, _x;				\
		unsigned char _w;				\
								\
		if (_n)	{					\
			_b = 0;					\
			_w = 4 * sizeof(_n);			\
			_m = ~(((__typeof__(_n))-1) << _w);	\
			do {					\
				_x = (_n >> _w) & _m;		\
				if (_x) {			\
					_b += _w;		\
					_n = _x;		\
				} else				\
					_n &= _m;		\
				_w >>= 1;			\
				if (!_w)			\
					break;			\
				_m >>= _w;			\
			} while (1);				\
		}						\
		_b;						\
	})
#define FIND_HI_BIT1(n)						\
		__FIND_HI_BIT1(n, AUTONAME, AUTONAME, AUTONAME, \
				AUTONAME, AUTONAME)

static inline
size_t
ceilpow2(size_t n)
{
        int i;

        switch (n) {
		case 0:	break;
		case 1:	n = 2;
			break;
		default:
			i = __builtin_choose_expr(
				__builtin_types_compatible_p(size_t, unsigned int),
				__builtin_clz(n-1),
				__builtin_choose_expr(
					__builtin_types_compatible_p(size_t, unsigned long),
					__builtin_clzl(n-1),
					__builtin_choose_expr(
						__builtin_types_compatible_p(size_t, unsigned long long),
						__builtin_clzll(n-1), 
						(8 * sizeof(size_t) - 1) - FIND_HI_BIT1(n-1)
					)
				)
			);
			n = (size_t)-1;
			if (i)
				n = (n >> i) + 1;
			break;
        }
        return n;
}

#define __MALLOC(n, n_, p_, e_) ({					\
		size_t n_ = (n);					\
		void *p_ = malloc(n_);					\
		if (!p_) {						\
			__auto_type e_ = errno;				\
			ECTL_PTRAP(e_, "malloc(%zu): %s.\n",		\
				n_, strerror(e_));			\
		}							\
		p_;							\
	})
#define	MALLOC(n)	__MALLOC(n, AUTONAME, AUTONAME, AUTONAME)

#define __REALLOC(p, n, p_, n_, e_) ({					\
		size_t n_ = (n);					\
		void *p_ = (p);						\
									\
		p_ = realloc(p_, n_);					\
		if (!p_) {						\
			__auto_type e_ = errno;				\
			ECTL_PTRAP(e_, "realloc(%p,%zu): %s.\n",	\
				p_, n_, strerror(e_));			\
		}							\
		p_;							\
	})
#define REALLOC(p, n)	__REALLOC(p, n, AUTONAME, AUTONAME, AUTONAME)

#define	__STRDUP(s, s_, p_, e_) ({					\
		char *s_ = (s);						\
		char *p_;						\
									\
		p_ = strdup(s_);					\
		if (!p_) {						\
			__auto_type e_ = errno;				\
			ECTL_PTRAP(e_, "strdup([%zu]%p): %s.\n",	\
				strlen(s_), s_, strerror(e_));		\
		}							\
		p_;							\
	})
#define STRDUP(s)	__STRDUP(s, AUTONAME, AUTONAME, AUTONAME)

#define	__WCSDUP(ws, ws_, p_, e_) ({					\
		wchar_t *ws_ = (ws), *p_;				\
									\
		p_ = wcsdup(ws_);					\
		if (!p_) {						\
			__auto_type e_ = errno;				\
			ECTL_PTRAP(e_, "wcsdup([%zu]%p): %s.\n",	\
				wcslen(ws_), ws_, strerror(e_));	\
		}							\
		p_;							\
	})
#define WCSDUP(ws)	__WCSDUP(ws, AUTONAME, AUTONAME, AUTONAME)

#define __MEMDUP(s, n, s_, n_, p_, e_) ({				\
		void *s_ = (s), *p_;					\
		size_t n_ = (n);					\
									\
		p_ = malloc(n_);					\
		if (!p_) {						\
			__auto_type e_ = errno;				\
			ECTL_PTRAP(e_, "memdup(%p,%zu): %s.\n",		\
				s_, n_, strerror(e_));			\
		}							\
		memcpy(p_, s_, n_);					\
		p_;							\
	})
#define MEMDUP(s, n)	__MEMDUP(s, n, AUTONAME, AUTONAME, AUTONAME, AUTONAME)

__BEGIN_DECLS
void		buf_addc(int ch, char **cp, char **buf, size_t *n);
__END_DECLS

struct zma;

__BEGIN_DECLS
struct zma *	zma_create(int nelb, int elsz);
struct zma *	zma_attach(struct zma *);
void		zma_detach(struct zma *);
void *		zma_alloc(struct zma *);
void		zma_free(struct zma *, void *);
__END_DECLS

__BEGIN_DECLS
size_t		mbs_nchars(const char *mbs);
wchar_t *	mbs2wcs_ndup(const char *mbs, int n);
char *		wcs2mbs_ndup(const wchar_t *ws, int n);
__END_DECLS

static inline
wchar_t *	mbs2wcs_dup(const char *mbs)
{
        return mbs2wcs_ndup(mbs, mbs_nchars(mbs));
}
static inline
char *		wcs2mbs_dup(const wchar_t *wcs)
{
        return wcs2mbs_ndup(wcs, wcslen(wcs));
}

__BEGIN_DECLS
void		colputs(const char **, size_t);
__END_DECLS

#define WCSTR_MIN_NCHARS	8

typedef struct wcstr {
	int		nref;
	size_t		size;	/* amount of allocated wide chars */
	size_t		length;	/* current length of string */
	wchar_t *	wcbuf;
} wcstr_t;

__BEGIN_DECLS
wcstr_t *	wcstr_create(const wchar_t *wcs, size_t len, size_t size);
wcstr_t *	wcstr_create_mbs(const char *mbs, size_t len, size_t size);
void		wcstr_append(wcstr_t *, wchar_t);
__END_DECLS

#define	wcstr_getsize(s)	((s)->size)
#define	wcstr_getlength(s)	((s)->length)
#define	wcstr_getwcs(s)		((s)->wcbuf)

static inline
wcstr_t *
wcstr_attach(wcstr_t *s)
{
	return OBJ_ATTACH(s, nref);
}
static inline
void
wcstr_detach(wcstr_t *s)
{
	OBJ_DETACH(s, nref) {
		if (s->wcbuf)
			free(s->wcbuf);
		free(s);
	}
}

static inline
wcstr_t *
wcstr_dup(wcstr_t *s)
{
	return wcstr_create(s->wcbuf, s->length, s->size);
}

static inline
void
wcstr_truncate(wcstr_t *s, size_t len)
{
	if (s->length > len) {
		s->length = len;
		s->wcbuf[len] = L'\0';
	}
}

static inline
FILE *		fopen_wcstr(wcstr_t *s)
{
        FILE *fp = open_wmemstream(&s->wcbuf, &s->size);
        if (!fp)
		ECTL_PTRAP(errno, "open_wmemstream(): %s.\n", strerror(errno));
        return fp;
}

struct rbglue {
        RB_ENTRY(rbglue) ent;
        struct rbtree *rbtree;
        void *data;
};
RB_HEAD(rbtreehead, rbglue);
struct rbtree {
        struct rbtreehead tree[1];
        int (*cmp)(void *, void *);
};
__BEGIN_DECLS
int rbglue_cmp(struct rbglue *a, struct rbglue *b);
RB_PROTOTYPE(rbtreehead, rbglue, ent, rbglue_cmp);
__END_DECLS

#define RBTREE_INITIALIZER(t, dcmp)	{ .tree = { [0] = RB_INITIALIZER((t)->tree) }, .cmp = (dcmp) }

#define DCMP_CAST(fn)		((int (*)(void *, void *))(fn))
#define DFREE_CAST(fn)		((void (*)(void *))(fn))
#define DDUP_CAST(fn)		((void *(*)(void *))(fn))

#define RBTREE_DCMP_CAST(fn)	DCMP_CAST(fn)
#define RBTREE_DFREE_CAST(fn)	DFREE_CAST(fn)
#define RBTREE_DDUP_CAST(fn)	DDUP_CAST(fn)

__BEGIN_DECLS
static inline struct rbtree *	rbtree_init(struct rbtree *, int (*dcmp)(void *, void *));
static inline void		rbtree_fini(struct rbtree *, void (*dfree)(void *));
static inline struct rbtree *	rbtree_create(int (*dcmp)(void *, void *));
static inline void		rbtree_destroy(struct rbtree *, void (*dfree)(void *));
	      void		rbtree_clear(struct rbtree *, void (*dfree)(void *));
	      struct rbtree *	rbtree_dup(struct rbtree *src, void *(*ddup)(void *), void (*dfree)(void *));
static inline struct rbglue *	rbtree_find(struct rbtree *, void *);
static inline struct rbglue *	rbtree_nfind(struct rbtree *, void *);

static inline struct rbglue *	rbtree_root(struct rbtree *);
static inline int		rbtree_empty(struct rbtree *);
static inline struct rbglue *	rbtree_min(struct rbtree *);
static inline struct rbglue *	rbtree_max(struct rbtree *);
static inline struct rbglue *	rbtree_insert(struct rbtree *, void *, struct rbglue **);
	      void		rbtree_remove(struct rbglue *, void (*dfree)(void *));

static inline struct rbglue *	rbglue_next(struct rbglue *);
static inline struct rbglue *	rbglue_prev(struct rbglue *);
static inline struct rbglue *	rbglue_left(struct rbglue *);
static inline struct rbglue *	rbglue_right(struct rbglue *);
static inline struct rbglue *	rbglue_parent(struct rbglue *);
static inline void *		rbglue_dptr(struct rbglue *);
__END_DECLS

#define RBTREE_FOREACH(g, t) \
                for (g = rbtree_min(t); g; g = rbglue_next(g))
#define RBTREE_FOREACH_REVERSE(g, t) \
                for (g = rbtree_max(t); g; g = rbglue_prev(g))

__BEGIN_DECLS
static inline 
struct rbtree *
rbtree_create(int (*dcmp)(void *, void *))
{
        return rbtree_init(MALLOC(sizeof(struct rbtree)), dcmp);
}

static inline 
void
rbtree_destroy(struct rbtree *t, void (*dfree)(void *))
{
        rbtree_fini(t, dfree);
        free(t);
}

static inline 
struct rbtree *
rbtree_init(struct rbtree *t, int (*dcmp)(void *, void *))
{
        RB_INIT(t->tree);
        t->cmp = dcmp;
        return t;
}

static inline 
void
rbtree_fini(struct rbtree *t, void (*dfree)(void *))
{
        rbtree_clear(t, dfree);
}

static inline 
struct rbglue *
rbtree_find(struct rbtree *tree, void *data)
{
        struct rbglue find, *res;

        find.rbtree = tree;
        find.data = data;
        res = RB_FIND(rbtreehead, tree->tree, &find);
        return res;
}

static inline 
struct rbglue *
rbtree_nfind(struct rbtree *tree, void *data)
{
        struct rbglue find, *res;

        find.rbtree = tree;
        find.data = data;
        res = RB_NFIND(rbtreehead, tree->tree, &find);
        return res;
}
 
static inline 
struct rbglue *
rbtree_root(struct rbtree *tree)
{
        return RB_ROOT(tree->tree);
}

static inline 
int
rbtree_empty(struct rbtree *tree)
{
        return RB_EMPTY(tree->tree);
}

static inline 
struct rbglue *
rbtree_min(struct rbtree *tree)
{
        return RB_MIN(rbtreehead, tree->tree);
}

static inline 
struct rbglue *
rbtree_max(struct rbtree *tree)
{
        return RB_MAX(rbtreehead, tree->tree);
}
 
static inline 
struct rbglue *
rbglue_next(struct rbglue *p)
{
        return RB_NEXT(rbtreehead, p->rbtree->rbtree, p);
}

static inline 
struct rbglue *
rbglue_prev(struct rbglue *p)
{
        return RB_PREV(rbtreehead, p->rbtree->rbtree, p);
}

static inline 
struct rbglue *
rbglue_left(struct rbglue *p)
{
        return RB_LEFT(p, ent);
}

static inline 
struct rbglue *
rbglue_right(struct rbglue *p)
{
        return RB_RIGHT(p, ent);
}

static inline 
struct rbglue *
rbglue_parent(struct rbglue *p)
{
        return RB_PARENT(p, ent);
}
 
static inline
struct rbglue *
rbtree_insert(struct rbtree *tree, void *data, struct rbglue **colg)
{
        struct rbglue *g, *c;

        g = MALLOC(sizeof(struct rbglue));
        g->rbtree = tree;
        g->data = data;
        c = RB_INSERT(rbtreehead, tree->tree, g);
        if (c) {
                free(g);
                g = NULL;
        }
        if (colg)
                *colg = c;
        return g;
}

static inline 
void *
rbglue_dptr(struct rbglue *glue)
{
        return (void *)glue->data;
}
__END_DECLS

#define	__XDC2NUM(c, _c) ({ __auto_type _c = (c); isdigit(_c) ? _c - '0' : tolower(_c) - 'a' + 10; })
#define XDC2NUM(c) __XDC2NUM(c, AUTONAME)

#endif

