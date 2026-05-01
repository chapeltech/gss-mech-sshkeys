CARGO ?= cargo
RUSTUP_HOME ?= $(CURDIR)/.rustup
CARGO_HOME ?= $(CURDIR)/.cargo
TARGET = sshkey.so
RUST_LIB = target/release/libgss_sshkey.so

export RUSTUP_HOME
export CARGO_HOME

all: $(TARGET)

.PHONY: clean test test-gss-token test-rust

test: test-rust test-gss-token

test-rust:
	$(CARGO) test

test-gss-token: $(TARGET)
	tests/gss-token/run.sh

$(TARGET): Cargo.toml build.rs src/lib.rs sshkey.asn1
	$(CARGO) build --release
	cp $(RUST_LIB) $(TARGET)

clean:
	if command -v $(CARGO) >/dev/null 2>&1; then $(CARGO) clean; fi
	rm -f $(TARGET)
	rm -f asn1_sshkey.[cx]
	rm -f asn1-template.h
	rm -f sshkey-priv.h
	rm -f sshkey-priv.hx
	rm -f sshkey.h
	rm -f sshkey.hx
	rm -f sshkey_files
