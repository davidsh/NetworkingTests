all: gssapitests

gssapitests: main.o helpers.o ntlmtest.o spnegotest.o client.o
	gcc -g -o gssapitests main.o helpers.o ntlmtest.o spnegotest.o client.o -lgssapi_krb5

main.o: main.c
	gcc -g -c main.c

helpers.o: helpers.c
	gcc -g -c helpers.c

ntlmtest.o: ntlmtest.c
	gcc -g -c ntlmtest.c

spnegotest.o: spnegotest.c
	gcc -g -c spnegotest.c

client.o: client.c
	gcc -g -c client.c

clean:
	rm main.o helpers.o ntlmtest.o spnegotest.o client.o gssapitests
