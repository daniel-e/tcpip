FLAGS = -O2 -std=c++11
LIBS  = -lboost_program_options
all: icmp

icmp: icmp.cc
	g++ $(FLAGS) icmp.cc -o icmp $(LIBS)

clean:
	rm -f icmp
