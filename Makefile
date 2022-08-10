PROG= dhcpdump
SRCS= foo.c error.c rbtree.c ip.c ipmap.c dhcp.c dhcpdump.c
OBJS= $(SRCS:.c=.o)
DESTDIR= /usr/local
DESTBINDIR= $(DESTDIR)/bin
CFLAGS= -march=native -O2 -pipe -D_GNU_SOURCE -Wno-address-of-packed-member
CPPFLAGS= -DNDEBUG -I. -I/usr/include
LDFLAGS= -L/usr/lib -L/usr/local/lib
LDLIBS= -lpcap -lpthread -lm
.PHONY: all clean cleandepend depend install
all: $(PROG)
$(PROG): $(OBJS)
clean: ; @for f in $(OBJS) $(PROG); do unlink $$f; done
depend: ; $(CC) -M $(CPPFLAGS) $(SRCS) > .depend
%.o: %.c ; $(COMPILE.c) $(OUTPUT_OPTION) $<
