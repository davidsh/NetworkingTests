OBJDIR=obj
BINDIR=bin

all: $(BINDIR)/gssapitests

$(BINDIR)/gssapitests: $(OBJDIR)/main.o $(OBJDIR)/helpers.o $(OBJDIR)/ntlmtest.o $(OBJDIR)/spnegotest.o $(OBJDIR)/client.o
	mkdir -p bin
	gcc -g -o $(BINDIR)/gssapitests $(OBJDIR)/main.o $(OBJDIR)/helpers.o $(OBJDIR)/ntlmtest.o $(OBJDIR)/spnegotest.o $(OBJDIR)/client.o -lgssapi_krb5

$(OBJDIR)/main.o: main.c
	mkdir -p obj
	gcc -g -c main.c -o $(OBJDIR)/main.o

$(OBJDIR)/helpers.o: helpers.c
	mkdir -p obj
	gcc -g -c helpers.c -o $(OBJDIR)/helpers.o

$(OBJDIR)/ntlmtest.o: ntlmtest.c
	mkdir -p obj
	gcc -g -c ntlmtest.c -o $(OBJDIR)/ntlmtest.o

$(OBJDIR)/spnegotest.o: spnegotest.c
	mkdir -p obj
	gcc -g -c spnegotest.c -o $(OBJDIR)/spnegotest.o

$(OBJDIR)/client.o: client.c
	mkdir -p obj
	gcc -g -c client.c -o $(OBJDIR)/client.o

clean:
	rm -rf $(BINDIR) $(OBJDIR)
