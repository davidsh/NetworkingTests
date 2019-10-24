all: spncheck.exe

spncheck.exe: main.o
	gcc -g -o spncheck main.o -lgssapi_krb5

main.o: main.c
	gcc -g -c main.c
     
clean:
	rm main.o spncheck
