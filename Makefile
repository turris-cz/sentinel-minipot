
all: main.c telnet.o zmq_log.o
	$(CC) -std=gnu99 -Wall $(CFLAGS) $(LDFLAGS) main.c telnet.o zmq_log.o -lczmq -levent -o sentinel-minipot

%.o: %.c
	$(CC) -std=gnu99 -Wall $(CFLAGS) $(LDFLAGS) -c $< -o $@

clean:
	rm -f sentinel-minipot *.o

