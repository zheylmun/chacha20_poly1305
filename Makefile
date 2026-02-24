BUILD_DIR   = build
DEBUG_DIR   = build-debug

.PHONY: all build debug test test-debug clean

all: build

build:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR)

debug:
	cmake -B $(DEBUG_DIR) -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(DEBUG_DIR)

test: build
	cd $(BUILD_DIR) && ctest --output-on-failure

test-debug: debug
	cd $(DEBUG_DIR) && ctest --output-on-failure

clean:
	rm -rf $(BUILD_DIR) $(DEBUG_DIR)
