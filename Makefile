CFLAGS=-Wall -Wextra -std=c2x
LIBS=-L./libbcrypt -l:./bcrypt.a

zort: zort.c
	cc $(CFLAGS) -o zort zort.c $(LIBS)
