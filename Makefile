CFLAGS=-Wall -Wextra -std=c2x -DUSE_MEOW_HASH -ggdb -mavx -maes
LIBS=-L./libbcrypt -l:./bcrypt.a -lc

zort: zort.c
	cc $(CFLAGS) -o zort zort.c $(LIBS)
