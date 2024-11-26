CFLAGS = -Wall -fPIC -I/usr/include/heimdal  -I/var/tmp/openssh-install/include -I/u/elric/tree/libssh2/src 
LDFLAGS = -shared -L/var/tmp/openssh-install/lib 
TARGET = sshkey.so



all: $(TARGET)

$(TARGET): sshkey.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) sshkey.c -Wl,-rpath=/var/tmp/openssh-install/lib -lssh2 -lcrypto

clean:
	rm -f $(TARGET)
