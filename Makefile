
all: main.c telnet.o zmq_log.o
	$(CC) -std=c99 main.c telnet.o zmq_log.o -lczmq -levent -o sentinel-minipot

%.o: %.c
	$(CC) -std=c99 -c $< -o $@

clean:
	rm -f sentinel-minipot *.o

