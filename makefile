pick : main.o
	gcc out/main.o -o out/pick

main.o : src/main.c
	gcc -Wall -c src/main.c -o out/main.o

clean:
	rm out/*