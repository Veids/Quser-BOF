BOF_Function := quser
CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
CC_x86 := i686-w64-mingw32-gcc
OPTIONS := -Wall

all:
	$(CC_x64) -o $(BOF_Function).x64.o -c $(BOF_Function).c $(OPTIONS)
	$(STRIP_x64) --strip-unneeded $(BOF_Function).x64.o

	$(CC_x86) -o $(BOF_Function).x86.o -c $(BOF_Function).c $(OPTIONS)

clean:
	rm $(BOF_Function).o
