#include <foo.h>

#ifndef lint
static const char rcsid[] =
        "$Id: error.c,v 1.8 2021/05/18 07:47:33 swp Exp $";
#endif

static
const char *
get_error_desc(struct error_defn *e)
{
	return e->cstr;
}
static
const char *
get_error_origname(struct error_defn *e)
{
	return error_name(e);
}
const struct error_type error_type[1] = {{ 
	.get_error_desc = get_error_desc,
	.get_error_origname = get_error_origname
}};

static
const char *
get_error_posix_desc(struct error_defn *e)
{
	return strerror(e->code);
}
static
const char *
get_error_posix_origname(struct error_defn *e)
{
	return e->name + sizeof "E_POSIX_" - 1;
}
const struct error_type error_type_posix[1] = {{ 
	.get_error_desc = get_error_posix_desc,
	.get_error_origname = get_error_posix_origname
}};


/* EXTERNAL ERRORS 
 */
static
const char *
get_external_error_origname(error_t e)
{
	return e->sbuf;
}
const struct error_type error_type_external[1] = {{
	.get_error_desc = get_external_error_origname,
	.get_error_origname = get_external_error_origname
}};
static
int
compare_external_errors(struct error_defn *a, struct error_defn *b)
{
	return strcmp(a->type->get_error_origname(a), b->type->get_error_origname(b));
}
static pthread_rwlock_t external_errors_rwlock[1] = { PTHREAD_RWLOCK_INITIALIZER };
static struct rbtree external_errors[1] = {
	RBTREE_INITIALIZER(external_errors, RBTREE_DCMP_CAST(compare_external_errors)) 
};

error_t
get_external_error(const char *s)
{
	struct ectlfr fr[1];
	struct rbglue *g, *cg;
	char ebuf[__offsetof(struct error_defn, sbuf) + strlen(s) + 1];
	struct error_defn *volatile e = (struct error_defn *)ebuf;

	e->name = NULL;
	e->type = error_type_external;
	strcpy((char *)e->sbuf, s);

	PTHREAD_RWLOCK_RDLOCK(external_errors_rwlock);
	g = rbtree_find(external_errors, e);
	pthread_rwlock_unlock(external_errors_rwlock);

	if (!g) {
		e = MALLOC(sizeof ebuf);
		memcpy(e, ebuf, sizeof ebuf);
		ectlfr_begin(fr, L_1);
		PTHREAD_RWLOCK_WRLOCK(external_errors_rwlock);
		ectlfr_ontrap(fr, L_2);
		g = rbtree_insert(external_errors, e, &cg);
		ectlfr_end(fr);
		pthread_rwlock_unlock(external_errors_rwlock);

		if (!g) {
			free(e);
			assert(cg);
			g = cg;
		}
	}
	return (error_t)rbglue_dptr(g);

L_2:	pthread_rwlock_unlock(external_errors_rwlock);
L_1:	free(e);
	ectlfr_end(fr);
	ectlfr_trap();
}


DEFN_ERROR(E_NOERROR, "No error.")
DEFN_ERROR(E_GENERIC, "Generic error.")
DEFN_ERROR(E_HOSTUNKNOWN, "Host unknown.")
DEFN_ERROR(E_NOTFOUND, "Not found.")
DEFN_ERROR(E_SYNTAX, "Syntax error.")

DEFN_POSIX_ERROR(E_POSIX_EPERM, EPERM)                       /*   1 */
DEFN_POSIX_ERROR(E_POSIX_ENOENT, ENOENT)                     /*   2 */
DEFN_POSIX_ERROR(E_POSIX_ESRCH, ESRCH)                       /*   3 */
DEFN_POSIX_ERROR(E_POSIX_EINTR, EINTR)                       /*   4 */
DEFN_POSIX_ERROR(E_POSIX_EIO, EIO)                           /*   5 */
DEFN_POSIX_ERROR(E_POSIX_ENXIO, ENXIO)                       /*   6 */
DEFN_POSIX_ERROR(E_POSIX_E2BIG, E2BIG)                       /*   7 */
DEFN_POSIX_ERROR(E_POSIX_ENOEXEC, ENOEXEC)                   /*   8 */
DEFN_POSIX_ERROR(E_POSIX_EBADF, EBADF)                       /*   9 */
DEFN_POSIX_ERROR(E_POSIX_ECHILD, ECHILD)                     /*  10 */
DEFN_POSIX_ERROR(E_POSIX_EDEADLK, EDEADLK)                   /*  11 */
DEFN_POSIX_ERROR(E_POSIX_ENOMEM, ENOMEM)                     /*  12 */
DEFN_POSIX_ERROR(E_POSIX_EACCES, EACCES)                     /*  13 */
DEFN_POSIX_ERROR(E_POSIX_EFAULT, EFAULT)                     /*  14 */
DEFN_POSIX_ERROR(E_POSIX_ENOTBLK, ENOTBLK)                   /*  15 */
DEFN_POSIX_ERROR(E_POSIX_EBUSY, EBUSY)                       /*  16 */
DEFN_POSIX_ERROR(E_POSIX_EEXIST, EEXIST)                     /*  17 */
DEFN_POSIX_ERROR(E_POSIX_EXDEV, EXDEV)                       /*  18 */
DEFN_POSIX_ERROR(E_POSIX_ENODEV, ENODEV)                     /*  19 */
DEFN_POSIX_ERROR(E_POSIX_ENOTDIR, ENOTDIR)                   /*  20 */
DEFN_POSIX_ERROR(E_POSIX_EISDIR, EISDIR)                     /*  21 */
DEFN_POSIX_ERROR(E_POSIX_EINVAL, EINVAL)                     /*  22 */
DEFN_POSIX_ERROR(E_POSIX_ENFILE, ENFILE)                     /*  23 */
DEFN_POSIX_ERROR(E_POSIX_EMFILE, EMFILE)                     /*  24 */
DEFN_POSIX_ERROR(E_POSIX_ENOTTY, ENOTTY)                     /*  25 */
DEFN_POSIX_ERROR(E_POSIX_ETXTBSY, ETXTBSY)                   /*  26 */
DEFN_POSIX_ERROR(E_POSIX_EFBIG, EFBIG)                       /*  27 */
DEFN_POSIX_ERROR(E_POSIX_ENOSPC, ENOSPC)                     /*  28 */
DEFN_POSIX_ERROR(E_POSIX_ESPIPE, ESPIPE)                     /*  29 */
DEFN_POSIX_ERROR(E_POSIX_EROFS, EROFS)                       /*  30 */
DEFN_POSIX_ERROR(E_POSIX_EMLINK, EMLINK)                     /*  31 */
DEFN_POSIX_ERROR(E_POSIX_EPIPE, EPIPE)                       /*  32 */
DEFN_POSIX_ERROR(E_POSIX_EDOM, EDOM)                         /*  33 */
DEFN_POSIX_ERROR(E_POSIX_ERANGE, ERANGE)                     /*  34 */
DEFN_POSIX_ERROR(E_POSIX_EAGAIN, EAGAIN)                     /*  35 */
DEFN_POSIX_ERROR(E_POSIX_EINPROGRESS, EINPROGRESS)           /*  36 */
DEFN_POSIX_ERROR(E_POSIX_EALREADY, EALREADY)                 /*  37 */
DEFN_POSIX_ERROR(E_POSIX_ENOTSOCK, ENOTSOCK)                 /*  38 */
DEFN_POSIX_ERROR(E_POSIX_EDESTADDRREQ, EDESTADDRREQ)         /*  39 */
DEFN_POSIX_ERROR(E_POSIX_EMSGSIZE, EMSGSIZE)                 /*  40 */
DEFN_POSIX_ERROR(E_POSIX_EPROTOTYPE, EPROTOTYPE)             /*  41 */
DEFN_POSIX_ERROR(E_POSIX_ENOPROTOOPT, ENOPROTOOPT)           /*  42 */
DEFN_POSIX_ERROR(E_POSIX_EPROTONOSUPPORT, EPROTONOSUPPORT)   /*  43 */
DEFN_POSIX_ERROR(E_POSIX_ESOCKTNOSUPPORT, ESOCKTNOSUPPORT)   /*  44 */
DEFN_POSIX_ERROR(E_POSIX_EOPNOTSUPP, EOPNOTSUPP)             /*  45 */
DEFN_POSIX_ERROR(E_POSIX_EPFNOSUPPORT, EPFNOSUPPORT)         /*  46 */
DEFN_POSIX_ERROR(E_POSIX_EAFNOSUPPORT, EAFNOSUPPORT)         /*  47 */
DEFN_POSIX_ERROR(E_POSIX_EADDRINUSE, EADDRINUSE)             /*  48 */
DEFN_POSIX_ERROR(E_POSIX_EADDRNOTAVAIL, EADDRNOTAVAIL)       /*  49 */
DEFN_POSIX_ERROR(E_POSIX_ENETDOWN, ENETDOWN)                 /*  50 */
DEFN_POSIX_ERROR(E_POSIX_ENETUNREACH, ENETUNREACH)           /*  51 */
DEFN_POSIX_ERROR(E_POSIX_ENETRESET, ENETRESET)               /*  52 */
DEFN_POSIX_ERROR(E_POSIX_ECONNABORTED, ECONNABORTED)         /*  53 */
DEFN_POSIX_ERROR(E_POSIX_ECONNRESET, ECONNRESET)             /*  54 */
DEFN_POSIX_ERROR(E_POSIX_ENOBUFS, ENOBUFS)                   /*  55 */
DEFN_POSIX_ERROR(E_POSIX_EISCONN, EISCONN)                   /*  56 */
DEFN_POSIX_ERROR(E_POSIX_ENOTCONN, ENOTCONN)                 /*  57 */
DEFN_POSIX_ERROR(E_POSIX_ESHUTDOWN, ESHUTDOWN)               /*  58 */
DEFN_POSIX_ERROR(E_POSIX_ETOOMANYREFS, ETOOMANYREFS)         /*  59 */
DEFN_POSIX_ERROR(E_POSIX_ETIMEDOUT, ETIMEDOUT)               /*  60 */
DEFN_POSIX_ERROR(E_POSIX_ECONNREFUSED, ECONNREFUSED)         /*  61 */
DEFN_POSIX_ERROR(E_POSIX_ELOOP, ELOOP)                       /*  62 */
DEFN_POSIX_ERROR(E_POSIX_ENAMETOOLONG, ENAMETOOLONG)         /*  63 */
DEFN_POSIX_ERROR(E_POSIX_EHOSTDOWN, EHOSTDOWN)               /*  64 */
DEFN_POSIX_ERROR(E_POSIX_EHOSTUNREACH, EHOSTUNREACH)         /*  65 */
DEFN_POSIX_ERROR(E_POSIX_ENOTEMPTY, ENOTEMPTY)               /*  66 */
DEFN_POSIX_ERROR(E_POSIX_EPROCLIM, EPROCLIM)                 /*  67 */
DEFN_POSIX_ERROR(E_POSIX_EUSERS, EUSERS)                     /*  68 */
DEFN_POSIX_ERROR(E_POSIX_EDQUOT, EDQUOT)                     /*  69 */
DEFN_POSIX_ERROR(E_POSIX_ESTALE, ESTALE)                     /*  70 */
DEFN_POSIX_ERROR(E_POSIX_EREMOTE, EREMOTE)                   /*  71 */
DEFN_POSIX_ERROR(E_POSIX_EBADRPC, EBADRPC)                   /*  72 */
DEFN_POSIX_ERROR(E_POSIX_ERPCMISMATCH, ERPCMISMATCH)         /*  73 */
DEFN_POSIX_ERROR(E_POSIX_EPROGUNAVAIL, EPROGUNAVAIL)         /*  74 */
DEFN_POSIX_ERROR(E_POSIX_EPROGMISMATCH, EPROGMISMATCH)       /*  75 */
DEFN_POSIX_ERROR(E_POSIX_EPROCUNAVAIL, EPROCUNAVAIL)         /*  76 */
DEFN_POSIX_ERROR(E_POSIX_ENOLCK, ENOLCK)                     /*  77 */
DEFN_POSIX_ERROR(E_POSIX_ENOSYS, ENOSYS)                     /*  78 */
DEFN_POSIX_ERROR(E_POSIX_EFTYPE, EFTYPE)                     /*  79 */
DEFN_POSIX_ERROR(E_POSIX_EAUTH, EAUTH)                       /*  80 */
DEFN_POSIX_ERROR(E_POSIX_ENEEDAUTH, ENEEDAUTH)               /*  81 */
DEFN_POSIX_ERROR(E_POSIX_EIDRM, EIDRM)                       /*  82 */
DEFN_POSIX_ERROR(E_POSIX_ENOMSG, ENOMSG)                     /*  83 */
DEFN_POSIX_ERROR(E_POSIX_EOVERFLOW, EOVERFLOW)               /*  84 */
DEFN_POSIX_ERROR(E_POSIX_ECANCELED, ECANCELED)               /*  85 */
DEFN_POSIX_ERROR(E_POSIX_EILSEQ, EILSEQ)                     /*  86 */
DEFN_POSIX_ERROR(E_POSIX_ENOATTR, ENOATTR)                   /*  87 */
DEFN_POSIX_ERROR(E_POSIX_EDOOFUS, EDOOFUS)                   /*  88 */
DEFN_POSIX_ERROR(E_POSIX_EBADMSG, EBADMSG)                   /*  89 */
DEFN_POSIX_ERROR(E_POSIX_EMULTIHOP, EMULTIHOP)               /*  90 */
DEFN_POSIX_ERROR(E_POSIX_ENOLINK, ENOLINK)                   /*  91 */
DEFN_POSIX_ERROR(E_POSIX_EPROTO, EPROTO)                     /*  92 */
DEFN_POSIX_ERROR(E_POSIX_ENOTCAPABLE, ENOTCAPABLE)           /*  93 */
DEFN_POSIX_ERROR(E_POSIX_ECAPMODE, ECAPMODE)                 /*  94 */
DEFN_POSIX_ERROR(E_POSIX_ENOTRECOVERABLE, ENOTRECOVERABLE)   /*  95 */
DEFN_POSIX_ERROR(E_POSIX_EOWNERDEAD, EOWNERDEAD)             /*  96 */

static const error_t errors_ordered_by_posix_code[] = {
	[1] = E_POSIX_EPERM,
	[2] = E_POSIX_ENOENT,
	[3] = E_POSIX_ESRCH,
	[4] = E_POSIX_EINTR,
	[5] = E_POSIX_EIO,
	[6] = E_POSIX_ENXIO,
	[7] = E_POSIX_E2BIG,
	[8] = E_POSIX_ENOEXEC,
	[9] = E_POSIX_EBADF,
	[10] = E_POSIX_ECHILD,
	[11] = E_POSIX_EDEADLK,
	[12] = E_POSIX_ENOMEM,
	[13] = E_POSIX_EACCES,
	[14] = E_POSIX_EFAULT,
	[15] = E_POSIX_ENOTBLK,
	[16] = E_POSIX_EBUSY,
	[17] = E_POSIX_EEXIST,
	[18] = E_POSIX_EXDEV,
	[19] = E_POSIX_ENODEV,
	[20] = E_POSIX_ENOTDIR,
	[21] = E_POSIX_EISDIR,
	[22] = E_POSIX_EINVAL,
	[23] = E_POSIX_ENFILE,
	[24] = E_POSIX_EMFILE,
	[25] = E_POSIX_ENOTTY,
	[26] = E_POSIX_ETXTBSY,
	[27] = E_POSIX_EFBIG,
	[28] = E_POSIX_ENOSPC,
	[29] = E_POSIX_ESPIPE,
	[30] = E_POSIX_EROFS,
	[31] = E_POSIX_EMLINK,
	[32] = E_POSIX_EPIPE,
	[33] = E_POSIX_EDOM,
	[34] = E_POSIX_ERANGE,
	[35] = E_POSIX_EAGAIN,
	[36] = E_POSIX_EINPROGRESS,
	[37] = E_POSIX_EALREADY,
	[38] = E_POSIX_ENOTSOCK,
	[39] = E_POSIX_EDESTADDRREQ,
	[40] = E_POSIX_EMSGSIZE,
	[41] = E_POSIX_EPROTOTYPE,
	[42] = E_POSIX_ENOPROTOOPT,
	[43] = E_POSIX_EPROTONOSUPPORT,
	[44] = E_POSIX_ESOCKTNOSUPPORT,
	[45] = E_POSIX_EOPNOTSUPP,
	[46] = E_POSIX_EPFNOSUPPORT,
	[47] = E_POSIX_EAFNOSUPPORT,
	[48] = E_POSIX_EADDRINUSE,
	[49] = E_POSIX_EADDRNOTAVAIL,
	[50] = E_POSIX_ENETDOWN,
	[51] = E_POSIX_ENETUNREACH,
	[52] = E_POSIX_ENETRESET,
	[53] = E_POSIX_ECONNABORTED,
	[54] = E_POSIX_ECONNRESET,
	[55] = E_POSIX_ENOBUFS,
	[56] = E_POSIX_EISCONN,
	[57] = E_POSIX_ENOTCONN,
	[58] = E_POSIX_ESHUTDOWN,
	[59] = E_POSIX_ETOOMANYREFS,
	[60] = E_POSIX_ETIMEDOUT,
	[61] = E_POSIX_ECONNREFUSED,
	[62] = E_POSIX_ELOOP,
	[63] = E_POSIX_ENAMETOOLONG,
	[64] = E_POSIX_EHOSTDOWN,
	[65] = E_POSIX_EHOSTUNREACH,
	[66] = E_POSIX_ENOTEMPTY,
	[67] = E_POSIX_EPROCLIM,
	[68] = E_POSIX_EUSERS,
	[69] = E_POSIX_EDQUOT,
	[70] = E_POSIX_ESTALE,
	[71] = E_POSIX_EREMOTE,
	[72] = E_POSIX_EBADRPC,
	[73] = E_POSIX_ERPCMISMATCH,
	[74] = E_POSIX_EPROGUNAVAIL,
	[75] = E_POSIX_EPROGMISMATCH,
	[76] = E_POSIX_EPROCUNAVAIL,
	[77] = E_POSIX_ENOLCK,
	[78] = E_POSIX_ENOSYS,
	[79] = E_POSIX_EFTYPE,
	[80] = E_POSIX_EAUTH,
	[81] = E_POSIX_ENEEDAUTH,
	[82] = E_POSIX_EIDRM,
	[83] = E_POSIX_ENOMSG,
	[84] = E_POSIX_EOVERFLOW,
	[85] = E_POSIX_ECANCELED,
	[86] = E_POSIX_EILSEQ,
	[87] = E_POSIX_ENOATTR,
	[88] = E_POSIX_EDOOFUS,
	[89] = E_POSIX_EBADMSG,
	[90] = E_POSIX_EMULTIHOP,
	[91] = E_POSIX_ENOLINK,
	[92] = E_POSIX_EPROTO,
	[93] = E_POSIX_ENOTCAPABLE,
	[94] = E_POSIX_ECAPMODE,
	[95] = E_POSIX_ENOTRECOVERABLE,
	[96] = E_POSIX_EOWNERDEAD
};

static const error_t errors_ordered_by_posix_name[] = {
	/*  7 */ E_POSIX_E2BIG,
	/* 13 */ E_POSIX_EACCES,
	/* 48 */ E_POSIX_EADDRINUSE,
	/* 49 */ E_POSIX_EADDRNOTAVAIL,
	/* 47 */ E_POSIX_EAFNOSUPPORT,
	/* 35 */ E_POSIX_EAGAIN,
	/* 37 */ E_POSIX_EALREADY,
	/* 80 */ E_POSIX_EAUTH,
	/*  9 */ E_POSIX_EBADF,
	/* 89 */ E_POSIX_EBADMSG,
	/* 72 */ E_POSIX_EBADRPC,
	/* 16 */ E_POSIX_EBUSY,
	/* 85 */ E_POSIX_ECANCELED,
	/* 94 */ E_POSIX_ECAPMODE,
	/* 10 */ E_POSIX_ECHILD,
	/* 53 */ E_POSIX_ECONNABORTED,
	/* 61 */ E_POSIX_ECONNREFUSED,
	/* 54 */ E_POSIX_ECONNRESET,
	/* 11 */ E_POSIX_EDEADLK,
	/* 39 */ E_POSIX_EDESTADDRREQ,
	/* 33 */ E_POSIX_EDOM,
	/* 88 */ E_POSIX_EDOOFUS,
	/* 69 */ E_POSIX_EDQUOT,
	/* 17 */ E_POSIX_EEXIST,
	/* 14 */ E_POSIX_EFAULT,
	/* 27 */ E_POSIX_EFBIG,
	/* 79 */ E_POSIX_EFTYPE,
	/* 64 */ E_POSIX_EHOSTDOWN,
	/* 65 */ E_POSIX_EHOSTUNREACH,
	/* 82 */ E_POSIX_EIDRM,
	/* 86 */ E_POSIX_EILSEQ,
	/* 36 */ E_POSIX_EINPROGRESS,
	/*  4 */ E_POSIX_EINTR,
	/* 22 */ E_POSIX_EINVAL,
	/*  5 */ E_POSIX_EIO,
	/* 56 */ E_POSIX_EISCONN,
	/* 21 */ E_POSIX_EISDIR,
	/* 62 */ E_POSIX_ELOOP,
	/* 24 */ E_POSIX_EMFILE,
	/* 31 */ E_POSIX_EMLINK,
	/* 40 */ E_POSIX_EMSGSIZE,
	/* 90 */ E_POSIX_EMULTIHOP,
	/* 63 */ E_POSIX_ENAMETOOLONG,
	/* 81 */ E_POSIX_ENEEDAUTH,
	/* 50 */ E_POSIX_ENETDOWN,
	/* 52 */ E_POSIX_ENETRESET,
	/* 51 */ E_POSIX_ENETUNREACH,
	/* 23 */ E_POSIX_ENFILE,
	/* 87 */ E_POSIX_ENOATTR,
	/* 55 */ E_POSIX_ENOBUFS,
	/* 19 */ E_POSIX_ENODEV,
	/*  2 */ E_POSIX_ENOENT,
	/*  8 */ E_POSIX_ENOEXEC,
	/* 77 */ E_POSIX_ENOLCK,
	/* 91 */ E_POSIX_ENOLINK,
	/* 12 */ E_POSIX_ENOMEM,
	/* 83 */ E_POSIX_ENOMSG,
	/* 42 */ E_POSIX_ENOPROTOOPT,
	/* 28 */ E_POSIX_ENOSPC,
	/* 78 */ E_POSIX_ENOSYS,
	/* 15 */ E_POSIX_ENOTBLK,
	/* 93 */ E_POSIX_ENOTCAPABLE,
	/* 57 */ E_POSIX_ENOTCONN,
	/* 20 */ E_POSIX_ENOTDIR,
	/* 66 */ E_POSIX_ENOTEMPTY,
	/* 95 */ E_POSIX_ENOTRECOVERABLE,
	/* 38 */ E_POSIX_ENOTSOCK,
	/* 25 */ E_POSIX_ENOTTY,
	/*  6 */ E_POSIX_ENXIO,
	/* 45 */ E_POSIX_EOPNOTSUPP,
	/* 84 */ E_POSIX_EOVERFLOW,
	/* 96 */ E_POSIX_EOWNERDEAD,
	/*  1 */ E_POSIX_EPERM,
	/* 46 */ E_POSIX_EPFNOSUPPORT,
	/* 32 */ E_POSIX_EPIPE,
	/* 67 */ E_POSIX_EPROCLIM,
	/* 76 */ E_POSIX_EPROCUNAVAIL,
	/* 75 */ E_POSIX_EPROGMISMATCH,
	/* 74 */ E_POSIX_EPROGUNAVAIL,
	/* 92 */ E_POSIX_EPROTO,
	/* 43 */ E_POSIX_EPROTONOSUPPORT,
	/* 41 */ E_POSIX_EPROTOTYPE,
	/* 34 */ E_POSIX_ERANGE,
	/* 71 */ E_POSIX_EREMOTE,
	/* 30 */ E_POSIX_EROFS,
	/* 73 */ E_POSIX_ERPCMISMATCH,
	/* 58 */ E_POSIX_ESHUTDOWN,
	/* 44 */ E_POSIX_ESOCKTNOSUPPORT,
	/* 29 */ E_POSIX_ESPIPE,
	/*  3 */ E_POSIX_ESRCH,
	/* 70 */ E_POSIX_ESTALE,
	/* 60 */ E_POSIX_ETIMEDOUT,
	/* 59 */ E_POSIX_ETOOMANYREFS,
	/* 26 */ E_POSIX_ETXTBSY,
	/* 68 */ E_POSIX_EUSERS,
	/* 18 */ E_POSIX_EXDEV
};

static
int
cmp_origname(const error_t *a, const error_t *b)
{
	return strcmp(error_origname(*a), error_origname(*b));
}
static 
const char *
get_error_fake_origname(error_t e) 
{ 
	return e->name; 
}
static const struct error_type error_type_fake = { 
	.get_error_desc = NULL, 
	.get_error_origname = get_error_fake_origname 
};
error_t
posix_name_to_error(const char *s)
{
	struct error_defn fake_e[1] = {{ .name = s, .type = &error_type_fake }}, *fake_e_ptr = fake_e;
	error_t *p = bsearch(&fake_e_ptr, errors_ordered_by_posix_name, 
			sizeof errors_ordered_by_posix_name / sizeof(error_t), 
			sizeof(error_t), (int (*)(const void *, const void *))cmp_origname);
	return p ? *p : NULL;
}

static 
error_t 
core_get_error_by_name(const char *s)
{
	error_t e;

	e = NULL;
	if (!strncmp("E_POSIX_", s, sizeof "E_POSIX_" - 1))
		e = posix_name_to_error(s + (sizeof "E_POSIX_" - 1));
	else if (!strcmp("E_NOERROR", s))
		e = E_NOERROR;
	else if (!strcmp("E_GENERIC", s))
		e = E_GENERIC;
	else if (!strcmp("E_HOSTUNKNOWN", s))
		e = E_HOSTUNKNOWN;
	else if (!strcmp("E_NOTFOUND", s))
		e = E_NOTFOUND;
	return e;
}
error_t (*get_error_by_name)(const char *error_name) = core_get_error_by_name;

static 
error_t 
core_get_error_by_origname(const char *s)
{
	error_t e;

	e = posix_name_to_error(s);
	if (!e) {
		if (!strcmp("E_NOERROR", s))
			e = E_NOERROR;
		else if (!strcmp("E_GENERIC", s))
			e = E_GENERIC;
		else if (!strcmp("E_HOSTUNKNOWN", s))
			e = E_HOSTUNKNOWN;
		else if (!strcmp("E_NOTFOUND", s))
			e = E_NOTFOUND;
		else
			e = NULL;
	}
	return e;
}
error_t (*get_error_by_origname)(const char *error_name) = core_get_error_by_origname;

error_t
posix_code_to_error(int erno)
{
	error_t e = NULL;
	if (!erno)
		e = E_NOERROR;
	else if (erno > 0 && erno < sizeof errors_ordered_by_posix_code/sizeof(error_t))
		e = errors_ordered_by_posix_code[erno];
	return e;
}

static
void __attribute__((__constructor__))
init()
{
}
static
void __attribute__((__destructor__))
fini()
{
	rbtree_fini(external_errors, RBTREE_DFREE_CAST(free));
	pthread_rwlock_destroy(external_errors_rwlock);
}

