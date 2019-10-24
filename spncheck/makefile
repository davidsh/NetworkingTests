all: spncheck.exe

spncheck.exe: main.o
	gcc -o spncheck main.o -lgssapi_krb5

main.o: main.c
	gcc -c main.c
     
clean:
	rm main.o spncheck
