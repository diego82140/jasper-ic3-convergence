SHELL := /bin/bash
CC ?= gcc
PYTHON ?= python3
OUT := $(abspath ../rebuilt)
GUM := $(abspath ../third_party/frida-gum)
CFLAGS ?= -O2 -g
# Optional PRODUCER sysroot; never required by the prebuilt customer launcher.
COMPAT_LIB ?=
ifeq ($(strip $(COMPAT_LIB)),)
  LIBC_LINK := -ldl -lrt -pthread
else
  LIBC_LINK := -Wl,--no-as-needed $(COMPAT_LIB)/libdl.so.2 $(COMPAT_LIB)/librt.so.1 $(COMPAT_LIB)/libpthread.so.0 -Wl,--as-needed
endif
PORTABLE_IMAGE := quay.io/pypa/manylinux2014_x86_64@sha256:2fa5f99f660f115f547d96b4edcadfc19f77a6de8807734bf0fc4924f81be01a
.PHONY: all library launcher portable-library test inspect
all: library
$(OUT):
	mkdir -p "$(OUT)"
library: $(OUT)/libjipstats.so
$(OUT)/libjipstats.so: src/events.c src/launchpropagate.c src/compat.c src/compat.h src/sha256.h src/details.h src/semantics.h src/parity.h src/activations.h $(GUM)/frida-gum.h $(GUM)/libfrida-gum.a | $(OUT)
	$(CC) -D_GNU_SOURCE -std=gnu11 $(CFLAGS) -shared -fPIC -fvisibility=hidden -Wall -Wextra \
	  -Wl,--exclude-libs,ALL -I"$(GUM)" -include src/compat.h \
	  src/events.c src/launchpropagate.c src/compat.c "$(GUM)/libfrida-gum.a" -Wl,--wrap=stat64 \
	  $(LIBC_LINK) -lresolv -lm -lz -o "$@"
# After make library, install ../rebuilt/libjipstats.so as ../libjipstats.so.
# Recompile ONLY the two extension-owned modules, retain portable bundled runtime.
# Work in an idle local package copy; do not overwrite a mapped library.
# Requires producer Python 3.13 (matching the packaged runtime) and objcopy.
launcher: library
	cp "$(OUT)/libjipstats.so" ../libjipstats.so.new
	mv ../libjipstats.so.new ../libjipstats.so
	$(PYTHON) sync_analysis.py
	$(PYTHON) sync_atlas_names.py
	$(PYTHON) embed_release.py ..
	$(PYTHON) repack_events.py ../jipstats jipstats.py prepare.py "$(OUT)/jipstats"
# Optional producer target, requiring Docker and access to the pinned build image.
# Not executed in this delivery environment; the same old-glibc ABI was tested
# through the supplied compatibility runtime. No Jasper source enters the build.
portable-library:
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp \
	  -v "$(abspath ..):/pkg" -w /pkg/source "$(PORTABLE_IMAGE)" make library
# Fresh no-marker fixture, generated profile and wrapper regression. NOT Jasper.
test: library
	JIPSTATS_TEST_BUILD="$(OUT)" $(PYTHON) tests/run_fixture_tests.py
inspect: library
	readelf -d "$(OUT)/libjipstats.so"
	readelf -V "$(OUT)/libjipstats.so"

.PHONY: release-adapter
# Producer-only regeneration from the exact user worker; no source tree needed.
release-adapter:
	@test -n "$(WORKER)" || { echo 'Use make release-adapter WORKER=/path/to/jg_proof'; exit 2; }
	$(PYTHON) release_adapters/build_b5006df1.py "$(WORKER)" --output ../profiles

.PHONY: worker-protocol-test live-tests
# Optional producer regression. Do not confuse native worker jobs with frontend prove.
worker-protocol-test:
	@test -n "$(WORKER)" -a -n "$(RUNTIME)" -a -n "$(RESULTS)" || { echo 'Set WORKER, RUNTIME and a new RESULTS directory'; exit 2; }
	$(PYTHON) tests/worker_protocol/run.py --worker "$(WORKER)" --runtime "$(RUNTIME)" --package .. --output "$(RESULTS)"
live-tests:
	JIPSTATS_LIVE_TEST_PACKAGE="$(abspath ..)" JIPSTATS_LIVE_TEST_TARGET="$(WORKER)" $(PYTHON) tests/live_tests.py

.PHONY: release mathematical-tests semantic-tests
release: launcher
	cp "$(OUT)/jipstats" ../jipstats.new
	mv ../jipstats.new ../jipstats
mathematical-tests:
	$(PYTHON) tests/test_induction_contract.py --output "$(OUT)/MATHEMATICAL-TESTS.json"
semantic-tests:
	@test -n "$(CAPTURE)" -a -n "$(MANIFEST)" -a -n "$(RESULTS)" || { echo 'Set CAPTURE, MANIFEST and RESULTS'; exit 2; }
	$(PYTHON) tests/test_semantic_analysis.py "$(CAPTURE)" "$(MANIFEST)" --output "$(RESULTS)"

.PHONY: parity-test parity-consumer-test
# Producer-only differential certificate; customer launch needs only the package.
parity-test:
	@test -n "$(WORKER)" -a -n "$(RUNTIME)" -a -n "$(RESULTS)" || { echo 'Set WORKER, RUNTIME and a new RESULTS'; exit 2; }
	$(PYTHON) tests/parity/suite.py --worker "$(WORKER)" --runtime "$(RUNTIME)" --package .. --output "$(RESULTS)"
parity-consumer-test:
	@test -n "$(SUITE)" -a -n "$(RESULTS)" || { echo 'Set SUITE to a completed parity-test and a new RESULTS'; exit 2; }
	$(PYTHON) tests/parity/test_parity_consumer.py --suite "$(SUITE)" --output "$(RESULTS)"
