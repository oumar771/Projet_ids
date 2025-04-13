CXX = g++
CXXFLAGS = -std=c++14 -Wall `pkg-config --cflags gtk+-3.0` -Iinclude
LDFLAGS = `pkg-config --libs gtk+-3.0` -ltins -pthread

SRC = src/capture.cpp src/gui.cpp src/main.cpp
OBJ = $(SRC:.cpp=.o)
BIN = build/nids

all: $(BIN)

$(BIN): $(OBJ)
	@mkdir -p build
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)
