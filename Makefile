#Amit Bapat

CFLAGS = -g -Wall -Werror -Wno-pointer-sign
LIBS = -lpcap
CC = gcc
OBJ = mydump.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

mydump: $(OBJ)
	$(CC) -o $@ $^  $(CFLAGS) $(LIBS)

clean:
	rm -f *~ *.o mydump