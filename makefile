LDLIBS=-lpcap -lpthread

all: signal-strength

signal-strength: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o

clean:
	rm -f signal-strength *.o
