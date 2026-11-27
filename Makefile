XU ?= xu
XU_STDLIB_ROOT ?= $(if $(wildcard ../xu/src/runtime/core),../xu/src,$(HOME)/.xu/src)
OUT ?= build/fatext

.PHONY: build test test-unit test-p2p clean

build:
	@mkdir -p build
	python3 scripts/sync_version.py
	XU_STDLIB_ROOT=$(XU_STDLIB_ROOT) $(XU) build src -o $(OUT)
	@if [ "$$(uname -s)" = "Darwin" ]; then codesign -fs - $(OUT); fi

test-p2p: build
	python3 scripts/test_p2p.py

test-unit: build
	python3 scripts/test_cli.py --suite-b-only
	python3 scripts/test_p2p.py

test: build
	python3 scripts/test_cli.py
	python3 scripts/test_p2p.py

clean:
	rm -rf build/
