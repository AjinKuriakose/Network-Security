all: clean pbproxy

pbproxy: pbproxy.c
	gcc -g pbproxy.c -o pbproxy -lcrypto

clean:
	rm -f *~ *.o *.out

