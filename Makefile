CFLAGS=-Wall -Wextra -std=c2x -DUSE_MEOW_HASH -O3 -mavx -maes
LIBS=-L./libbcrypt -l:./bcrypt.a

zort: zort.c
	cc $(CFLAGS) -o zort zort.c $(LIBS)
