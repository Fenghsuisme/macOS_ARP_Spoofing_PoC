CC = gcc


ifneq ($(wildcard /opt/homebrew/include),)
    INC_PATH = -I/opt/homebrew/include
    LIB_PATH = -L/opt/homebrew/lib
else
    INC_PATH = -I/usr/local/include
    LIB_PATH = -L/usr/local/lib
endif

CFLAGS = -Wall -g -pthread -Iheaders $(INC_PATH)
LDFLAGS = $(LIB_PATH) -lpcap

SRC_DIR = src
OBJ_DIR = build
BIN = mac_mitm

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN) passwords.txt raw_traffic.log

.PHONY: all clean