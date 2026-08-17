CXX = clang++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS = -F/Applications/Xcode.app/Contents/SharedFrameworks -framework LLDB -framework Foundation -Wl,-rpath,/Applications/Xcode.app/Contents/SharedFrameworks

SDK ?= $(shell xcrun --show-sdk-path 2>/dev/null)
ifeq ($(SDK),)
    $(error Could not find macOS SDK. Install Xcode Command Line Tools.)
endif

LLDB_INC ?= /opt/homebrew/Cellar/llvm/22.1.8/include
ifeq ($(wildcard $(LLDB_INC)/lldb/API/LLDB.h),)
    $(error Could not find LLDB headers. Set LLDB_INC to the directory containing lldb/API/LLDB.h)
endif

CXXFLAGS += -isysroot $(SDK) -I$(LLDB_INC)

SRCS = src/amfidont.c src/config_store.c src/bypass_runtime.c src/daemon_runtime.c
OBJS = $(SRCS:.c=.o)
TARGET = amfidont

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CXX) $(CXXFLAGS) -x c++ -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
