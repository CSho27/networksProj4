all: proj4.o
	gcc -o proj4 proj4.o -lm

proj4.o: proj4.c
	gcc -Wall -Werror -g -c proj4.c  -lm
	
clean:
	rm -f *.o
	rm -f proj4