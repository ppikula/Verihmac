CC = gcc 
CFLAGS = -Wall
LDFLAGS = -lcrypto

verihmac-sign: verihmac-sign.o

install: verihmac-sign
	cp verihmac-sign /usr/bin/verihmac-sign
	
clean:
	rm -f verihmac-sign.o verihmac-sign