all:
	gcc main.c -O2 -o verifier

clean:
	del verifier.exe
