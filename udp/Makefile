FLAGS = -O2 -std=c++11 -g
LIBS  = -lboost_program_options
all: udp

udp: udp.cc
	g++ $(FLAGS) udp.cc -o udp $(LIBS)

clean:
	rm -f udp
