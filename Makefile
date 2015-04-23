CC=g++
CPFLAGS=-g
LDFLAGS= -pthread -lpcap

SRC= portScanner.cpp ps_helper.cpp ps_lib.cpp ps_pcap.cpp ps_setup.cpp
OBJ=$(SRC:.cpp=.o)
BIN=portScanner

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.cpp
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
