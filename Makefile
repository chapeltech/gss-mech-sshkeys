CFLAGS  = -Wall -g -fPIC -I. -I/usr/include/heimdal  -I/var/tmp/openssh-install/include -I/u/elric/tree/libssh2/src 
CFLAGS += -Wno-unused-label
LDFLAGS = -shared -L/var/tmp/openssh-install/lib 
LDADD   = -Wl,-rpath=/var/tmp/openssh-install/lib -lssh2 -lcrypto
TARGET  = sshkey.so

SRCS=sshkey.c asn1_sshkey.c curve25519-donna.c cfx.c sequence.c

all: $(TARGET)

%.c: %.x
	cp $< $@

%.h: %.hx
	cp $< $@

asn1_sshkey.x sshkey-priv.hx sshkey.hx sshkey_files: sshkey.asn1
	touch asn1-template.h
	asn1_compile --one-code-file sshkey.asn1

$(TARGET): sshkey.c asn1_sshkey.c sshkey-priv.h sshkey.h
	$(CC) -g -O0 $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRCS) $(LDADD)

clean:
	rm -f $(TARGET)
	rm -f asn1_sshkey.[cx]
	rm -f asn1-template.h
	rm -f sshkey-priv.h
	rm -f sshkey-priv.hx
	rm -f sshkey.hx
	rm -f sshkey_files

