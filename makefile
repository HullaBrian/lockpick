pick : main.o hash.o
	gcc -Wall out/hash.o out/main.o -o pick -lcrypto -lssl

main.o : src/main.c src/hash.h
	mkdir out -p
	gcc -Wall -c src/main.c -o out/main.o -lcrypto -lssl

hash.o : src/hash.c src/hash.h
	gcc -Wall -c src/hash.c -o out/hash.o -lcrypto -lssl

clean:
	rm out/*