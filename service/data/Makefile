all: decode.so

decode.so: decode.c
	clang -target bpf -Wall -O2 -fno-builtin -fPIC -c decode.c -o decode.o
	ld.lld -z notext -shared --Bdynamic -o decode.so decode.o
	rm -f decode.o
