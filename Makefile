
 #   Slhasher - a command-line tool to compute hashes
 #
 #   Copyright (C) 2025  absoluteseeker  absoluteseeker@proton.me
 #
 #   Slhasher is free software: you can redistribute it and/or modify
 #   it under the terms of the GNU General Public License as published by
 #   the Free Software Foundation, either version 3 of the License, or
 #   (at your option) any later version.
 #
 #   Slhasher is distributed in the hope that it will be useful,
 #   but WITHOUT ANY WARRANTY; without even the implied warranty of
 #   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 #   GNU General Public License for more details.
 #
 #   You should have received a copy of the GNU General Public License
 #   along with Slhasher.  If not, see <https://www.gnu.org/licenses/>.
 


PROJECT := slhasher

CC ?= cc

CFLAGS := -Wall -Werror -Wextra -O3 -march=native -g

LDFLAGS :=

BUILD_DIR := build

SRC_DIR := src

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
	INST_DIR ?= /usr/local/bin
endif

ifeq ($(UNAME_S),Darwin)
        INST_DIR ?= /usr/local/bin
endif

ifeq ($(OS),Windows_NT)
	INST_DIR ?= C:/ProgramFiles
endif


SRCS := $(wildcard $(SRC_DIR)/*.c)

OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)


all: $(BUILD_DIR)/$(PROJECT)

$(BUILD_DIR)/$(PROJECT): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

install: $(BUILD_DIR)/$(PROJECT)
	install -d $(INST_DIR)
	install $(BUILD_DIR)/$(PROJECT) $(INST_DIR)


uninstall:
	rm -f $(INST_DIR)/$(PROJECT)

.PHONY: clean make install uninstall
