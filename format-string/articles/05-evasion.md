# 05 - Evasion

**Author**: Kenshin Himura

## Pendahuluan

Setelah exploit bekerja di lingkungan lab, tantangan berikutnya:
membuatnya bekerja di lingkungan yang dilindungi. Bab ini membahas
teknik menyembunyikan payload, menghindari deteksi, dan mem-bypass
proteksi runtime.

## Payload Obfuscation

### Encoding Address

Address dalam payload harus dihindari dari karakter yang difilter.
Karakter problematik:

| Byte | Masalah |
|------|---------|
| `\x00` | Null byte - memutus string |
| `\x0a` | Newline - `fgets()` berhenti |
| `\x0d` | Carriage return |
| `\x20` | Space - parser command line |
| `\x25` | `%` - konflik format specifier |

Strategi:

- Gunakan `%hn` (2 byte) atau `%hhn` (1 byte) untuk menghindari
  null byte di address 64-bit upper word
- Tempatkan address di akhir payload (setelah null byte, jika
  protocol mengizinkan)
- Encode address dengan XOR atau ROT: payload decode dulu di stack,
  tidak praktis untuk format string

### Padding Random

Tambahkan karakter acak di antara format specifier:

```
Payload: [addr] %100x%7$n %50x%8$n
Menjadi: [addr] %*100$c%100x%7$n %*101$c%50x%8$n
```

`%*100$c` menggunakan dynamic width dari argumen ke-100. Nilainya
tidak deterministik, menyulitkan signature-based detection.

### Split Output

```python
# Daripada %100x (100 karakter padding)
# Gunakan: %c%c%c... (100 kali %c)
# Atau: %10x%10x%10x... (10 kali %10x)
```

Output terlihat berbeda tapi total karakter sama.

## Evasion Filter dan Firewall

### URI Encoding

Jika payload dikirim lewat HTTP:

```
\x41 -> %41
\xe8 -> %E8
```

Semua byte non-printable di-encode sebagai `%XX`.

### Multi-Stage

Pisahkan leak dan write ke koneksi terpisah:

```
Stage 1: Kirim payload leak (hanya %p) -> dapatkan address
Stage 2: Kirim payload write (dengan %n) -> timpa memory
```

Payload stage 1 tidak mengandung `%n` sehingga tidak terdeteksi filter
yang mencari `%n` pattern.

### Timing-Based

Tambahkan delay untuk menghindari rate limiting:

```
Payload: %10000000x%7$n
```

Mencetak 10 juta karakter -> delay signifikan sebelum `%n` dieksekusi.

Untuk split timing: kirim byte per byte dengan jeda.

## Bypass FORTIFY_SOURCE

### Cara Kerja FORTIFY

`FORTIFY_SOURCE=1`: compile-time check, mendeteksi `%n` di format
string literal.

`FORTIFY_SOURCE=2`: runtime check via `__printf_chk()`. Memeriksa
apakah format string berada di segment writable. Jika ya dan
mengandung `%n` -> `SIGABRT`.

Pesan error: `*** %n in writable segment detected ***`

### Teknik Bypass

#### Nargs Overflow (CVE-2012-0864)

Hanya bekerja di glibc < 2.15. FORTIFY melacak jumlah `%` specifier
dengan counter `nargs`. Jika `nargs` overflow (wrap ke 0 atau nilai
kecil), pengecekan lolos.

Payload: `%20$08n %*482$ %*2850$ %1073741824$`

- `%*482$` dan `%*2850$`: dynamic width, menaikkan counter nargs
- `%1073741824$`: argument position besar, mendorong nargs melewati
  INT_MAX -> overflow -> wrap ke 0
- `%20$08n`: write ke argumen 20, tidak terdeteksi karena nargs = 0

#### Format String di Read-Only Memory

Jika format string dapat ditempatkan di `.rodata` (bukan stack/heap),
FORTIFY tidak memblokir karena segment tersebut read-only dianggap
aman oleh checker.

#### Indirect Write

Gunakan `%s` + buffer overflow untuk menulis, bukan `%n`:

```
Step 1: sprintf(buffer, "%s%s%s...", input1, input2, ...) -> overflow
Step 2: overwritten return address -> code execution
```

Ini bukan format string write murni, tapi kombinasi format string
dengan buffer overflow.

## Anti-Debug

### Deteksi Debugger

```c
// Deteksi ptrace
if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
    // Debugger terdeteksi, ubah perilaku
    printf("OK\n");  // bukan format string bug
} else {
    printf(user_input);  // baru rentan
}
```

### Polymorphic Payload

Payload berubah-ubah setiap kali dikirim:

```python
# Pilih offset random untuk padding
pad1 = random.randint(100, 65535)
pad2 = target_value - pad1 - 8
payload = p32(addr1) + p32(addr2) + f'%{pad1}x%7$hn%{pad2}x%8$hn'.encode()
```

Output berbeda setiap kali -> sulit dideteksi signature.

## Ringkasan

- Hindari karakter terlarang: null, newline, `%`
- Split payload ke multi-stage: leak dulu, write kemudian
- FORTIFY bypass (glibc < 2.15): nargs overflow lewat `%*N$`
- Polymorphic payload untuk hindari signature detection
