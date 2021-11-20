BINFILE=arpmon
JSONC=$(shell pkg-config --cflags --libs json-c)

.PHONY: install

all:
	gcc *.c -o $(BINFILE) --std=c11 -lpcap $(JSONC)

install:
	python3 install.py

clean:
	rm -f $(BINFILE) -vv
