all: tcpsyn

syn_tcp: syn_tcp.cc
	g++ -O2 tcpsyn.cc -std=c++11 -o tcpsyn

