

CC = riscv64-unknown-elf-gcc
AR = riscv64-unknown-elf-ar
LD = riscv64-unknown-elf-ld

CKBLIBC ?= /home/gmssl/ckb/ckb-c-stdlib-master/libc
CKBVM ?= /home/gmssl/ckb/ckb-vm-test-suite/binary/target/release/asm64
CFLAGS	?= 
WARNING_CFLAGS ?=  -Wall -Wextra
LDFLAGS ?= 

LOCAL_CFLAGS = $(WARNING_CFLAGS) -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

.SILENT:

.PHONY: all clean all

all: sm3
	echo "Build sm3 done!"

# add --verbose to dump more information
sm3: sm3.c 
	echo "RISCV ${CFLAGS} $(LDFLAGS) $^"
	$(CC) ${CFLAGS} ${LOCAL_CFLAGS} $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $^

run: sm3
	echo running $(CKBVM) sm3
	$(CKBVM) sm3
	echo "Done. There should be no output(return 0)."

fail: sm3
	echo running $(CKBVM) sm3
	echo "There will be output like this: Ok(1)"
	$(CKBVM) sm3 hello,World! 5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF482546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE48206DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C73D1EE248819479574028389376BD7F9FB4F5C9B || echo "Failed as expected."

dis:
	echo "Disasemble rsa_verify_no_fs to dis.txg"
	riscv64-unknown-elf-objdump -d rsa_verify_no_fs > dis.txt
	echo "done"

clean:
	rm -f rsa_verify_no_fs
	rm -f *.o
