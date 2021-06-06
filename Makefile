BINFILE=arpmon

all:
	gcc *.c -o $(BINFILE) --std=c11 -lpcap

clean:
	rm -f $(BINFILE) -vv
