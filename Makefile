PROG=	dpinger
MAN=

BINDIR=	${PREFIX}/bin
WARNS=	2

LDADD=	-lpthread

.include <bsd.prog.mk>
