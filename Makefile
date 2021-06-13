BINFILE=arpmon
JSONC=$(shell pkg-config --cflags --libs json-c)

all:
	gcc *.c -o $(BINFILE) --std=c11 -lpcap $(JSONC)

clean:
	rm -f $(BINFILE) -vv
