ARCH := $(shell uname -m | sed 's/^i[3-6]86.*/i386/;s/^arm.*/arm/')
FLAGS_x86_64 :=
FLAGS_i386 := -m32 -fno-PIE -Wl,-no-pie
FLAGS_aarch64 := -fno-PIE -Wl,-no-pie
FLAGS_arm := -fno-PIE -Wl,-no-pie
all: safeexec
safeexec: test.c safeexec.c safeexec.h safeexec.ld
	gcc $(FLAGS_$(ARCH)) -Wall -Werror -g -O2 -fno-jump-tables -fno-builtin -o safeexec test.c safeexec.c -Wl,-T,safeexec.ld

clean:
	rm -f safeexec
