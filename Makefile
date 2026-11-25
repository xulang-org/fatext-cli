XU ?= xu
XU_STDLIB_ROOT ?= ../xu/src
OUT ?= build/fatext

.PHONY: build test clean

build:
	@mkdir -p build
	python3 scripts/sync_version.py
	XU_STDLIB_ROOT=$(XU_STDLIB_ROOT) $(XU) build src -o $(OUT)
	@if [ "$$(uname -s)" = "Darwin" ]; then codesign -fs - $(OUT); fi

test: build
	python3 scripts/test_cli.py

clean:
	rm -rf build/
