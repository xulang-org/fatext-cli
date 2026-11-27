XU ?= xu
XU_STDLIB_ROOT ?= $(if $(wildcard ../xu/src/runtime/core),../xu/src,$(HOME)/.xu/src)
OUT ?= build/fatext

.PHONY: build test test-unit clean

build:
	@mkdir -p build
	python3 scripts/sync_version.py
	XU_STDLIB_ROOT=$(XU_STDLIB_ROOT) $(XU) build src -o $(OUT)
	@if [ "$$(uname -s)" = "Darwin" ]; then codesign -fs - $(OUT); fi

test-unit: build
	python3 scripts/test_cli.py --suite-b-only

test: build
	python3 scripts/test_cli.py

clean:
	rm -rf build/
