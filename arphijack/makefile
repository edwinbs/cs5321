CC      = g++
CFLAGS  = -O3
LDFLAGS = -l pcap

all: arphijack

arphijack: arphijack.o
	$(CC) $(LDFLAGS) -o $@ $^
	
arphijack.o: arphijack.cc
	$(CC) $(CFLAGS) -c -o $@ $<
	
clean:
	rm -f arphijack arphijack.o
	
.PHONY: clean
