all:
		gcc -o serverM serverM.c
		gcc -o serverA serverA.c
		gcc -o serverB serverB.c
		gcc -o client client.c

clean:
		rm -f serverM
		rm -f serverA
		rm -f serverB
		rm -f client