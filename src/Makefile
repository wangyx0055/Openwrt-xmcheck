CHECK_OBJS = dhcpc.o clientpacket.o script.o clientsocket.o arpping.o \
		 options.o socket.o packet.o pidfile.o common.o signalpipe.o \
		pppoe_main.o xmcheck.o
CHECK_SRCS=$(CHECK_OBJS:.o=.c)
CHECK_NAME=xmcheck
$(CHECK_NAME):$(CHECK_OBJS)
	$(CC) -o $@ $^ $(LDCFLAGS) -DDEBUG_DISABLE

clean:
	rm -f *.o $(CHECK_NAME) 
