CFLAGS = -I/usr/local/include -Wall -Werror -g -O2 -fno-strict-aliasing -Wpointer-sign
LDFLAGS = -L/usr/local/lib
LIBS = -lev
SRCS = mxtarpit.c
OBJS = $(SRCS:c=o)

mxtarpit: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

linux:
	$(MAKE) mxtarpit "LIBS=$(LIBS) -lresolv"

tags:
	ctags $(SRCS)

clean:
	rm -f mxtarpit $(OBJS)
