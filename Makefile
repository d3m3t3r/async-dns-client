# Makefile

CXXFLAGS = -std=c++17 -g -O0 -Wall -I$(HOME)/ws/common/include
LDFLAGS  =
LDLIBS   = -L$(HOME)/ws/common/lib -pthread -lresolv

SRCS     = async-dns-client.cpp main.cpp
EXE      = adc

.PHONY: all
all: $(EXE)

.PHONY: clean
clean:
	$(RM) $(EXE) $(SRCS:.cpp=.o)

$(EXE): $(SRCS:.cpp=.o)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)
