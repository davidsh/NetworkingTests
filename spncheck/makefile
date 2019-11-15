OBJDIR=obj
BINDIR=bin

all: $(BINDIR)/spncheck.exe

$(BINDIR)/spncheck.exe: $(OBJDIR)/main.o
	mkdir -p $(BINDIR)
	gcc -g -o $(BINDIR)/spncheck $(OBJDIR)/main.o -lgssapi_krb5

$(OBJDIR)/main.o: main.c
	mkdir -p $(OBJDIR)
	gcc -g -c main.c -o $(OBJDIR)/main.o
     
clean:
	rm -rf $(BINDIR) $(OBJDIR)
