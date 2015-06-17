FLAGS = -O2 -std=c++11 -g
LIBS  = -lboost_program_options
all: ipudp

ipudp: ipudp.cc
	g++ $(FLAGS) ipudp.cc -o ipudp $(LIBS)

clean:
	rm -f ipudp
