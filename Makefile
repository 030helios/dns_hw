all:
	gcc -o dns_attack main.c dns.c
clean:
	rm -f dns_attack
