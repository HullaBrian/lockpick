pick : main.o
	gcc out/main.o -o pick

main.o : src/main.c
	mkdir out -p
	gcc -Wall -c src/main.c -o out/main.o

clean:
	rm out/*