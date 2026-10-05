CC := gcc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror
SRC_DIR := src
TOOL_TARGET := resource-tool
GUI_TARGET := visual-window-app
CORE_SOURCES := $(SRC_DIR)/resource_paths.c $(SRC_DIR)/sha256.c $(SRC_DIR)/resource_pkg.c $(SRC_DIR)/http_client.c $(SRC_DIR)/resource_client.c
GUI_SOURCES := $(SRC_DIR)/main.c $(SRC_DIR)/window.c $(SRC_DIR)/renderer.c

SDL_AVAILABLE := $(shell command -v sdl2-config >/dev/null 2>&1 && echo yes)

.PHONY: all tool app clean run test

all: tool
ifeq ($(SDL_AVAILABLE),yes)
all: app
endif

tool: $(TOOL_TARGET)

app: $(GUI_TARGET)

$(TOOL_TARGET): $(SRC_DIR)/resource_tool.c $(CORE_SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ 

ifeq ($(SDL_AVAILABLE),yes)
$(GUI_TARGET): $(GUI_SOURCES) $(SRC_DIR)/resource_paths.c $(SRC_DIR)/sha256.c $(SRC_DIR)/resource_pkg.c $(SRC_DIR)/http_client.c $(SRC_DIR)/resource_client.c
	$(CC) $(CFLAGS) $(shell sdl2-config --cflags) $^ -o $@ $(shell sdl2-config --libs) -lSDL2_image 
else
$(GUI_TARGET):
	@echo "SDL development files are unavailable; 'resource-tool' was built. In Docker run 'make app' after installing libsdl2-dev/libsdl2-image-dev."
	@exit 2
endif

run: app
	./$(GUI_TARGET)

test: tool
	./test/integration_test.sh

clean:
	rm -f $(TOOL_TARGET) $(GUI_TARGET)
