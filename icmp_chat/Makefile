FLAGS      = -O2 -std=c++11
LIBS       = -lboost_program_options -lpcap -lpthread
SOURCES    = main.cc net.cc
OBJECTS    = $(SOURCES:.cc=.o)
EXECUTABLE = main

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	g++ $(FLAGS) $(OBJECTS) -o $@ $(LIBS)

.cc.o:
	g++ -c $(FLAGS) $< -o $@

clean:
	rm -f main *.o
