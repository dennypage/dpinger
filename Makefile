PROG=	dpinger
MAN=

BINDIR=	${PREFIX}/bin
WARNS=	6

CFLAGS=	-g
LDADD=	-lpthread

.include <bsd.prog.mk>
