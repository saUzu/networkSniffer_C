CC      =       gcc
CFLAGS  =       -Wall -std=c17 -I./include/
LINKER  =       gcc -o
LFLAGS  =       -Wall -static -L./lib/x64

SRCDIR  =       kaynak
INCDIR  =       include
OBJDIR  =       nesne
BINDIR  =       bin

LIBDIR  =       ./lib/x64 
LIBFLAG =       -l wpcap -l Packet -l Ws2_32

SOURCES         :=      $(wildcard $(SRCDIR)/*.c)
INCLUDES        :=      $(wildcard $(INCDIR)/*.h)
OBJECTS         :=      $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
rm              =       rm -f

$(BINDIR)/ana: $(OBJECTS)
	@$(LINKER) $@ $(LFLAGS) -L$(LIBDIR) $(OBJECTS) $(LIBFLAG) 
	@echo "Baglanma basarili!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo $<" basarili bir sekilde compile edildi."

.PHONY: clean
clean:
	@$(rm) $(OBJECTS)
	@echo "Temizlik tamamlandi"

.PHONY: remove
remove: clean
	@$(rm) $(BINDIR)
	@echo "Exeler Silindi"