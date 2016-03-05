#Amit Bapat

CFLAGS = -g -Wall -Werror
LIBS = -lpcap
CC = gcc
OBJ = mydump.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

mydump: $(OBJ)
	$(CC) -o $@ $^  $(CFLAGS) $(LIBS)

clean:
	rm -f *~ *.o mydump