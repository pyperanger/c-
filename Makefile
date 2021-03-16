CC=g++
PROJ=r00tquit
CFLAGS=-static -O2
OBJ = main.o src/rootkit_pid.o

%.o: %.c 
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROJ): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clear:
	rm $(OBJ) $(PROJ)
