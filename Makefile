kaslr:
	gcc leak.c -o leak -static -Wno-format -lpthread -lkeyutils
