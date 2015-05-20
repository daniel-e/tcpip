all: tcpsyn

tcpsyn: tcpsyn.cc
	g++ -O2 tcpsyn.cc -std=c++11 -o tcpsyn

clean:
	rm -f tcpsyn
