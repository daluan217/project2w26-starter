CC=gcc
OPENSSL_PREFIX := /opt/homebrew/opt/openssl
CFLAGS=-Wall -Wextra -std=gnu17 -I$(OPENSSL_PREFIX)/include
LDFLAGS=-L$(OPENSSL_PREFIX)/lib
LDLIBS=-lcrypto

DEPS=io.o libsecurity.o security.o

all: server client gen_cert

server: server.o $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

client: client.o $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

gen_cert: gen_cert.o $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	@find . -type f \
		! -name "*.c" \
		! -name "*.h" \
		! -name "*.cpp" \
		! -name "*.hpp" \
		! -name "Makefile" \
		! -name "README.md" -delete
	@find . -type d \( ! -name "." \) -exec rm -rf {} +
