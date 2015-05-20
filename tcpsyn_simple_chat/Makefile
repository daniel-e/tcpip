FLAGS = -O2 -std=c++11
LIBS  = -lboost_program_options

all: tcpsyn_srv tcpsyn_cli

tcpsyn_srv: tcpsyn_srv.cc
	g++ $(FLAGS) tcpsyn_srv.cc -o tcpsyn_srv $(LIBS) -lpcap

tcpsyn_cli: tcpsyn_cli.cc
	g++ $(FLAGS) tcpsyn_cli.cc -o tcpsyn_cli $(LIBS)

clean:
	rm -f tcpsyn_srv tcpsyn_cli
