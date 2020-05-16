CC = cl
CFLAGS = /nologo /EHsc /W3 /DDEBUG -Ihttp-parser /Iwin /I.
OBJ_DIR = ./obj
SRC_DIR = ./win
DEPENDENCY = ./http-parser
MKDIR = mkdir

all: build

.PHONY: directories
directories: $(OBJ_DIR)

.PHONY: build
build: directories aws.obj $(OBJ_DIR)/sock_util.obj $(OBJ_DIR)/http_parser.obj
	link /out:aws.exe aws.obj $(OBJ_DIR)/sock_util.obj $(OBJ_DIR)/http_parser.obj wsock32.lib ws2_32.lib

$(OBJ_DIR):
	$(MKDIR) obj

aws.obj: $(SRC_DIR)/aws.c aws.h
	$(CC) $(CFLAGS) /Foaws.obj /c $(SRC_DIR)/aws.c

$(OBJ_DIR)/sock_util.obj: $(SRC_DIR)/sock_util.c $(SRC_DIR)/sock_util.h
	$(CC) /Fo$(OBJ_DIR)/sock_util.obj /c $(SRC_DIR)/sock_util.c

$(OBJ_DIR)/http_parser.obj: $(DEPENDENCY)/http_parser.c $(DEPENDENCY)/http_parser.h
	$(CC) /Fo$(OBJ_DIR)/http_parser.obj /TP /c $(DEPENDENCY)/http_parser.c

.PHONY: clean
clean:
	rmdir "obj" /S /Q
	del aws.exe aws.obj
