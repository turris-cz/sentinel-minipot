all: main.c telnet.o zmq_log.o
	$(CC) main.c telnet.o zmq_log.o -lczmq -levent -o sentinel-minipot

%.o: %.c
	$(CC) -c $< -o $@

clean:
	rm -f sentinel-minipot *.o

