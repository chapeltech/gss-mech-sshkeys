CARGO ?= cargo
CC ?= cc
CARGO_TARGET_DIR ?= target
TARGET = sshkey.so
RUST_LIB = $(CARGO_TARGET_DIR)/release/libgss_sshkey.so
VERSION ?= 0.1.0-alpha.1
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
SYSCONFDIR ?= $(PREFIX)/etc
DOCDIR ?= $(PREFIX)/share/doc/gss-sshkey
GSS_MECH_DIR ?= $(SYSCONFDIR)/gss/mech.d
GSS_MECH_LIBDIR ?= $(LIBDIR)/gss
GSS_MECH_LIB = $(GSS_MECH_LIBDIR)/$(TARGET)
GSS_MECH_CONFIG = $(GSS_MECH_DIR)/sshkey.conf
GSS_SSHKEY_HEADER = $(INCLUDEDIR)/gss_sshkey.h
GSS_SSHKEY_LICENSE = $(DOCDIR)/COPYING
GSS_SSHKEY_RELEASE_NOTES = $(DOCDIR)/RELEASE-NOTES.md
GSS_MECH_CONFIG_FORMAT ?= heimdal
MECH_NAME ?= sshkey
MECH_OID ?= 1.3.6.1.4.1.99999.1
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 755
INSTALL_DATA ?= $(INSTALL) -m 644
TAR ?= tar
PKGDIR ?= dist
PACKAGE ?= $(PKGDIR)/gss-sshkey-$(VERSION)-$(GSS_MECH_CONFIG_FORMAT).tar.gz
SOURCE_PACKAGE ?= $(PKGDIR)/gss-sshkey-$(VERSION)-source.tar.gz
SOURCE_RELEASE = gss-sshkey-$(VERSION)-source

GSS_MECH_BUILDER_SOURCES = \
    ../gss-mech-builder/Cargo.toml \
    $(wildcard ../gss-mech-builder/src/*.rs)
SSH_CONFIG_SOURCES = \
    ../ssh-config/Cargo.toml \
    $(wildcard ../ssh-config/src/*.rs)
SOURCE_ROOT_FILES = \
    .gitignore ARCHITECTURE.md BACKLOG.md Cargo.lock Cargo.toml COPYING \
    Makefile README.md RELEASE-NOTES.md REQUIREMENTS.md SECURITY-REVIEW.md \
    TODO.md build.rs draft-dowdeswell-kitten-gss-sshkey-00.xml \
    rustfmt.toml sshkey.asn1
SOURCE_ROOT_DIRS = docs include src tests
SOURCE_GSS_MECH_BUILDER_FILES = \
    ../gss-mech-builder/.gitignore ../gss-mech-builder/Cargo.lock \
    ../gss-mech-builder/Cargo.toml ../gss-mech-builder/COPYING \
    ../gss-mech-builder/Makefile ../gss-mech-builder/README.md
SOURCE_GSS_MECH_BUILDER_DIRS = \
    ../gss-mech-builder/benches ../gss-mech-builder/src \
    ../gss-mech-builder/tests
SOURCE_RFC4121_FILES = \
    ../rfc4121/.gitignore ../rfc4121/Cargo.lock ../rfc4121/Cargo.toml \
    ../rfc4121/COPYING ../rfc4121/Makefile ../rfc4121/README.md
SOURCE_RFC4121_DIRS = ../rfc4121/benches ../rfc4121/src ../rfc4121/tests
SOURCE_RFC4121_FUZZ_FILES = \
    ../rfc4121/fuzz/Cargo.lock ../rfc4121/fuzz/Cargo.toml
SOURCE_RFC4121_FUZZ_TARGETS = ../rfc4121/fuzz/fuzz_targets
SOURCE_SSH_CONFIG_FILES = \
    ../ssh-config/.gitignore ../ssh-config/Cargo.toml ../ssh-config/COPYING \
    ../ssh-config/README.md ../ssh-config/rustfmt.toml
SOURCE_SSH_CONFIG_DIRS = ../ssh-config/src

export CARGO_TARGET_DIR

all: $(TARGET)

.PHONY: all clean force install package release-alpha source-package test \
    test-alpha \
    test-context-helper test-gss-token test-install test-openssh-live \
    test-package test-rust test-source-package uninstall

force:

test: test-rust test-context-helper test-install test-package \
    test-source-package test-gss-token

test-alpha: test-rust test-context-helper test-install test-package \
    test-source-package $(TARGET)
	REQUIRE_GSS_LOADERS=1 REQUIRE_SSH_AGENT=1 tests/gss-token/run.sh

test-rust:
	$(CARGO) test --offline
	$(CARGO) test --offline --manifest-path ../rfc4121/Cargo.toml
	$(CARGO) test --offline \
	    --manifest-path ../gss-mech-builder/Cargo.toml \
	    --features test-harness
	$(CARGO) test --offline --manifest-path ../ssh-config/Cargo.toml

test-context-helper:
	set -eu; \
	obj=$$(mktemp "$${TMPDIR:-/tmp}/gss-sshkey-header.XXXXXX.o"); \
	trap 'rm -f "$$obj"' EXIT; \
	$(CC) -Wall -Wextra -Werror -Iinclude \
	    -c tests/context-helper/header-smoke.c -o "$$obj"

test-gss-token: $(TARGET)
	tests/gss-token/run.sh

test-openssh-live: $(TARGET)
	tests/openssh-live/run.sh

test-install: $(TARGET)
	set -eu; \
	stage=$$(mktemp -d); \
	trap 'rm -rf "$$stage"' EXIT; \
	$(MAKE) --no-print-directory install \
	    DESTDIR="$$stage/heimdal" PREFIX=/usr LIBDIR=/usr/lib \
	    INCLUDEDIR=/usr/include SYSCONFDIR=/etc \
	    GSS_MECH_DIR=/etc/gss/mech.d \
	    GSS_MECH_LIBDIR=/usr/lib/gss >/dev/null; \
	test -x "$$stage/heimdal/usr/lib/gss/sshkey.so"; \
	test -r "$$stage/heimdal/usr/include/gss_sshkey.h"; \
	test -r "$$stage/heimdal/usr/share/doc/gss-sshkey/COPYING"; \
	test -r \
	    "$$stage/heimdal/usr/share/doc/gss-sshkey/RELEASE-NOTES.md"; \
	printf '%s %s %s -\n' "$(MECH_NAME)" "$(MECH_OID)" \
	    "/usr/lib/gss/sshkey.so" \
	    | cmp - "$$stage/heimdal/etc/gss/mech.d/sshkey.conf"; \
	$(MAKE) --no-print-directory install \
	    DESTDIR="$$stage/mit" PREFIX=/usr LIBDIR=/usr/lib \
	    INCLUDEDIR=/usr/include SYSCONFDIR=/etc \
	    GSS_MECH_DIR=/etc/gss/mech.d \
	    GSS_MECH_LIBDIR=/usr/lib/gss \
	    GSS_MECH_CONFIG_FORMAT=mit >/dev/null; \
	test -x "$$stage/mit/usr/lib/gss/sshkey.so"; \
	test -r "$$stage/mit/usr/include/gss_sshkey.h"; \
	test -r "$$stage/mit/usr/share/doc/gss-sshkey/COPYING"; \
	test -r "$$stage/mit/usr/share/doc/gss-sshkey/RELEASE-NOTES.md"; \
	printf '%s %s %s\n' "$(MECH_NAME)" "$(MECH_OID)" \
	    "/usr/lib/gss/sshkey.so" \
	    | cmp - "$$stage/mit/etc/gss/mech.d/sshkey.conf"

test-package: $(TARGET)
	set -eu; \
	for format in heimdal mit; do \
	    stage=$$(mktemp -d); \
	    trap 'rm -rf "$$stage"' EXIT HUP INT TERM; \
	    $(MAKE) --no-print-directory package \
	        PKGDIR="$$stage/dist" \
	        PACKAGE="$$stage/dist/test.tar.gz" \
	        PREFIX=/usr LIBDIR=/usr/lib INCLUDEDIR=/usr/include \
	        SYSCONFDIR=/etc DOCDIR=/usr/share/doc/gss-sshkey \
	        GSS_MECH_DIR=/etc/gss/mech.d \
	        GSS_MECH_LIBDIR=/usr/lib/gss \
	        GSS_MECH_CONFIG_FORMAT="$$format" >/dev/null; \
	    test -s "$$stage/dist/test.tar.gz"; \
	    mkdir "$$stage/out"; \
	    $(TAR) -xzf "$$stage/dist/test.tar.gz" -C "$$stage/out"; \
	    find "$$stage/out" -type f -printf '%P\n' \
	        | LC_ALL=C sort > "$$stage/actual"; \
	    printf '%s\n' \
	        etc/gss/mech.d/sshkey.conf \
	        usr/include/gss_sshkey.h \
	        usr/lib/gss/sshkey.so \
	        usr/share/doc/gss-sshkey/COPYING \
	        usr/share/doc/gss-sshkey/RELEASE-NOTES.md \
	        > "$$stage/expected"; \
	    cmp "$$stage/expected" "$$stage/actual"; \
	    test -x "$$stage/out/usr/lib/gss/sshkey.so"; \
	    rm -rf "$$stage"; \
	    trap - EXIT HUP INT TERM; \
	done

test-source-package:
	set -eu; \
	stage=$$(mktemp -d); \
	trap 'rm -rf "$$stage"' EXIT HUP INT TERM; \
	$(MAKE) --no-print-directory source-package \
	    PKGDIR="$$stage/dist" \
	    SOURCE_PACKAGE="$$stage/dist/source.tar.gz" >/dev/null; \
	test -s "$$stage/dist/source.tar.gz"; \
	mkdir "$$stage/out"; \
	$(TAR) -xzf "$$stage/dist/source.tar.gz" -C "$$stage/out"; \
	release="$$stage/out/$(SOURCE_RELEASE)"; \
	test -r "$$release/SOURCE-MANIFEST.txt"; \
	test -r "$$release/gss-sshkey/COPYING"; \
	test -r "$$release/ssh-config/COPYING"; \
	test -r "$$release/gss-mech-builder/COPYING"; \
	test -r "$$release/rfc4121/COPYING"; \
	if find "$$release" \( -name .git -o -name target -o -name dist \
	    -o -name .cargo -o -name .rustup -o -name .codex \
	    -o -name '*.so' \) -print -quit | grep -q .; then \
	    echo "source package contains build, cache, or VCS material" >&2; \
	    exit 1; \
	fi; \
	(cd "$$release" && find . -type f \
	    ! -name SOURCE-MANIFEST.txt -print | LC_ALL=C sort) \
	    | cmp - "$$release/SOURCE-MANIFEST.txt"; \
	(cd "$$release/gss-sshkey" && \
	    CARGO_TARGET_DIR="$$stage/source-target" \
	        $(CARGO) check --locked --offline >/dev/null)

$(TARGET): force Cargo.toml Cargo.lock build.rs include/gss_sshkey.h \
    src/host_trust.rs src/lib.rs src/sshfp.rs sshkey.asn1 \
    $(GSS_MECH_BUILDER_SOURCES) $(SSH_CONFIG_SOURCES)
	$(CARGO) build --release
	cp $(RUST_LIB) $(TARGET)

install: $(TARGET)
	$(INSTALL) -d "$(DESTDIR)$(GSS_MECH_LIBDIR)"
	$(INSTALL_PROGRAM) "$(TARGET)" "$(DESTDIR)$(GSS_MECH_LIB)"
	$(INSTALL) -d "$(DESTDIR)$(INCLUDEDIR)"
	$(INSTALL_DATA) "include/gss_sshkey.h" \
	    "$(DESTDIR)$(GSS_SSHKEY_HEADER)"
	$(INSTALL) -d "$(DESTDIR)$(DOCDIR)"
	$(INSTALL_DATA) "COPYING" "$(DESTDIR)$(GSS_SSHKEY_LICENSE)"
	$(INSTALL_DATA) "RELEASE-NOTES.md" \
	    "$(DESTDIR)$(GSS_SSHKEY_RELEASE_NOTES)"
	$(INSTALL) -d "$(DESTDIR)$(GSS_MECH_DIR)"
	if [ "$(GSS_MECH_CONFIG_FORMAT)" = mit ]; then \
	    printf '%s %s %s\n' "$(MECH_NAME)" "$(MECH_OID)" \
	        "$(GSS_MECH_LIB)" \
	        > "$(DESTDIR)$(GSS_MECH_CONFIG)"; \
	else \
	    printf '%s %s %s -\n' "$(MECH_NAME)" "$(MECH_OID)" \
	        "$(GSS_MECH_LIB)" > "$(DESTDIR)$(GSS_MECH_CONFIG)"; \
	fi
	chmod 644 "$(DESTDIR)$(GSS_MECH_CONFIG)"

package: $(TARGET)
	set -eu; \
	stage=$$(mktemp -d); \
	trap 'rm -rf "$$stage"' EXIT; \
	$(MAKE) --no-print-directory install DESTDIR="$$stage" \
	    PREFIX="$(PREFIX)" LIBDIR="$(LIBDIR)" \
	    INCLUDEDIR="$(INCLUDEDIR)" SYSCONFDIR="$(SYSCONFDIR)" \
	    DOCDIR="$(DOCDIR)" \
	    GSS_MECH_DIR="$(GSS_MECH_DIR)" \
	    GSS_MECH_LIBDIR="$(GSS_MECH_LIBDIR)" \
	    GSS_MECH_CONFIG="$(GSS_MECH_CONFIG)" \
	    GSS_SSHKEY_HEADER="$(GSS_SSHKEY_HEADER)" \
	    GSS_SSHKEY_LICENSE="$(GSS_SSHKEY_LICENSE)" \
	    GSS_SSHKEY_RELEASE_NOTES="$(GSS_SSHKEY_RELEASE_NOTES)" \
	    GSS_MECH_CONFIG_FORMAT="$(GSS_MECH_CONFIG_FORMAT)" \
	    MECH_NAME="$(MECH_NAME)" MECH_OID="$(MECH_OID)" >/dev/null; \
	$(INSTALL) -d "$(PKGDIR)"; \
	$(TAR) -C "$$stage" -czf "$(PACKAGE)" .

source-package:
	set -eu; \
	stage=$$(mktemp -d); \
	trap 'rm -rf "$$stage"' EXIT HUP INT TERM; \
	release="$$stage/$(SOURCE_RELEASE)"; \
	$(INSTALL) -d "$$release/gss-sshkey" \
	    "$$release/gss-mech-builder" "$$release/rfc4121" \
	    "$$release/rfc4121/fuzz" "$$release/ssh-config"; \
	cp -a $(SOURCE_ROOT_FILES) $(SOURCE_ROOT_DIRS) \
	    "$$release/gss-sshkey/"; \
	cp -a $(SOURCE_GSS_MECH_BUILDER_FILES) \
	    $(SOURCE_GSS_MECH_BUILDER_DIRS) \
	    "$$release/gss-mech-builder/"; \
	cp -a $(SOURCE_RFC4121_FILES) $(SOURCE_RFC4121_DIRS) \
	    "$$release/rfc4121/"; \
	cp -a $(SOURCE_RFC4121_FUZZ_FILES) \
	    $(SOURCE_RFC4121_FUZZ_TARGETS) "$$release/rfc4121/fuzz/"; \
	cp -a $(SOURCE_SSH_CONFIG_FILES) $(SOURCE_SSH_CONFIG_DIRS) \
	    "$$release/ssh-config/"; \
	(cd "$$release" && find . -type f -print | LC_ALL=C sort) \
	    > "$$stage/SOURCE-MANIFEST.txt"; \
	mv "$$stage/SOURCE-MANIFEST.txt" "$$release/SOURCE-MANIFEST.txt"; \
	$(INSTALL) -d "$(PKGDIR)"; \
	$(TAR) -C "$$stage" -czf "$(SOURCE_PACKAGE)" \
	    "$(SOURCE_RELEASE)"

release-alpha: test-alpha
	$(MAKE) --no-print-directory source-package
	$(MAKE) --no-print-directory package GSS_MECH_CONFIG_FORMAT=heimdal
	$(MAKE) --no-print-directory package GSS_MECH_CONFIG_FORMAT=mit

uninstall:
	rm -f "$(DESTDIR)$(GSS_MECH_CONFIG)"
	rm -f "$(DESTDIR)$(GSS_MECH_LIB)"
	rm -f "$(DESTDIR)$(GSS_SSHKEY_HEADER)"
	rm -f "$(DESTDIR)$(GSS_SSHKEY_LICENSE)"
	rm -f "$(DESTDIR)$(GSS_SSHKEY_RELEASE_NOTES)"

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
