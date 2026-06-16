CC = gcc
CFLAGS_COMMON = -m32 -fno-stack-protector -no-pie -ggdb -O0 -Wno-format-security
LDFLAGS_COMMON = -m32 -no-pie -Wl,-z,execstack

.PHONY: all clean level0 level1 level2 level3 level4

all: level0 level1 level2 level3 level4

level0: level0/format0
level1: level1/format1
level2: level2/format2
level3: level3/format3
level4: level4/format4

level0/format0: level0/format0.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $<

level1/format1: level1/format1.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $<

level2/format2: level2/format2.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $<

level3/format3: level3/format3.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $<

level4/format4: level4/format4.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $<

level4/format4_hard: level4/format4.c
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -D_FORTIFY_SOURCE=2 -O2 -o $@ $<

clean:
	rm -f level0/format0 level1/format1 level2/format2 level3/format3 level4/format4 level4/format4_hard
