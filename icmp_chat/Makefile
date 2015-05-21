FLAGS      = -O2 -std=c++11
LIBS       = -lboost_program_options -lpcap -lpthread

all: libnet main

libnet:
	gcc -c -O2 -Wall -Werror -fpic net.c
	gcc -shared -o libnet.so net.o

main:
	g++ main.cc -L. $(FLAGS) -o main -lnet $(LIBS)

clean:
	rm -f main *.o *.so
