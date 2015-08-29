libtnacl.a: tweetnacl.o randombytes.o
	ar rcs libtnacl.a tweetnacl.o randombytes.o

tweetnacl.o: tweetnacl.c tweetnacl.h
	gcc -c tweetnacl.c -o tweetnacl.o

randombytes.o: randombytes.c
	gcc -c randombytes.c -o randombytes.o

PHONY: clean

clean:
	rm -f *.o *.a
