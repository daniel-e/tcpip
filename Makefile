all: tcpsyn tcpsyn_srv tcpsyn_cli

tcpsyn: tcpsyn.cc
	g++ -O2 tcpsyn.cc -std=c++11 -o tcpsyn

tcpsyn_srv: tcpsyn_srv.cc
	g++ -O2 -std=c++11 tcpsyn_srv.cc -o tcpsyn_srv -lboost_program_options

tcpsyn_cli: tcpsyn_cli.cc
	g++ -O2 -std=c++11 tcpsyn_cli.cc -o tcpsyn_cli -lpcap -lboost_program_options

clean:
	rm -f tcpsyn tcpsyn_srv tcpsyn_cli
