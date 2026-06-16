# 02 - Debugging dan Menemukan Format String Bug

**Author**: Kenshin Himura

## Pendahuluan

Menemukan format string bug bisa dilakukan lewat static analysis
(memeriksa source code), dynamic analysis (menjalankan program dengan
input crafted), atau kombinasi keduanya. Bab ini membahas tools dan
teknik untuk mendeteksi bug sebelum dieksploitasi.

## Pola Vulnerable

Pola yang harus dicari:

```c
// Format string berasal dari input user
printf(argv[1]);
printf(getenv("USER"));
fprintf(stderr, user_buffer);
syslog(LOG_DEBUG, packet_data);
err(1, "error: %s", user_input);  // %s aman, format literal

// Yang ini RENTAN:
printf(user_input);
```

Aturan: setiap pemanggilan `printf`-family yang argumen pertamanya
bukan string literal patut dicurigai.

## Static Analysis

### Grep Manual

Cara paling sederhana: grep source code untuk pola pemanggilan:

```bash
grep -rn 'printf(' --include='*.c' . | grep -v '"%'
grep -rn 'fprintf(' --include='*.c' . | grep -v '"%'
grep -rn 'syslog(' --include='*.c' . | grep -v '"%'
```

`grep -v '"%'` membuang pemanggilan yang menggunakan format string
literal (dimulai dengan `"`). Sisanya adalah kandidat rentan.

### Compiler Warning

GCC punya flag khusus untuk mendeteksi format string non-literal:

```bash
gcc -Wall -Wextra -Wformat-security -Wformat=2 program.c
```

Flag `-Wformat-security` memperingatkan saat format string bukan
literal. Flag `-Wformat=2` lebih agresif, termasuk memeriksa
`printf(fmt)` dengan satu argumen.

### SAST Tools

Tool Static Application Security Testing:

- **Semgrep**: pattern matching untuk code. Bisa menulis rule custom
  untuk mendeteksi `printf(user_input)`.

  ```yaml
  rules:
    - id: format-string-bug
      pattern: printf($X)
      message: "Potential format string vulnerability"
  ```

- **CodeQL**: query language untuk analisis code. Bisa melacak data
  flow dari input user ke format string argument.

- **Flawfinder** / **Splint**: tool lama untuk C static analysis,
  punya aturan built-in untuk format string.

### Binary Analysis

Menganalisis binary yang sudah di-compile:

```bash
# Cari referensi ke printf@plt
objdump -d binary | grep 'printf@plt'

# Lihat relokasi GOT
readelf -r binary | grep printf

# Cari string format non-literal di .rodata
strings binary | grep '%'
```

## Dynamic Analysis

### Fuzzing

Kirim input acak yang mengandung format specifier dan lihat apakah
program crash atau menghasilkan output tidak normal.

```bash
# Dengan AFL++
afl-fuzz -i inputs -o outputs ./program

# Input seed: file berisi %n%n%n%n%n
```

Jika program crash dengan SIGSEGV saat menerima `%n`, kemungkinan
besar ada format string bug.

### AddressSanitizer (ASAN)

Compile program dengan ASAN untuk mendeteksi memory corruption:

```bash
gcc -fsanitize=address -g program.c -o program
echo '%n%n%n%n' | ./program
```

ASAN akan melaporkan saat `%n` mencoba menulis ke alamat invalid.

### Dynamic Binary Instrumentation

Tools seperti **PIN** atau **DynamoRIO** bisa digunakan untuk
memantau pemanggilan `printf` dan mendeteksi format string yang
mencurigakan saat runtime.

## Debugging dengan GDB

### Setup

GDB dengan GEF atau Pwndbg memberikan tampilan stack yang lebih baik:

```bash
# Install GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Atau Pwndbg
pip3 install pwndbg
```

### Mencari Offset

Cara standar mencari offset format string:

```
(gdb) b printf
(gdb) r <<< 'AAAA.%p.%p.%p.%p.%p.%p.%p.%p'
(gdb) c
```

Lihat output - cari `0x41414141`. Posisinya (ke-N dalam output) adalah
offset format string.

Atau dengan positional argument:

```
(gdb) r <<< 'AAAA%1$p'
(gdb) r <<< 'AAAA%2$p'
...
```

### Inspeksi Stack

```
(gdb) x/40x $esp      # dump 40 dword dari stack pointer
(gdb) telescope $esp 20  # GEF: tampilan lebih rapi
(gdb) info frame      # informasi stack frame
```

### Trace Format String

```
(gdb) b *printf@plt
(gdb) r
(gdb) ni              # next instruction - trace satu per satu
(gdb) x/s $eax        # lihat format string yang sedang diproses
```

## Tools

| Tool | Fungsi |
|------|--------|
| GDB + GEF/Pwndbg | Debugging, inspeksi stack |
| AFL++ | Fuzzing untuk temukan crash |
| Semgrep / CodeQL | Static analysis |
| checksec | Cek proteksi binary |
| pwntools | Exploit development |
| libformatstr | Format string helper |

## Ringkasan

- Static analysis: grep + compiler warning + SAST untuk temukan pola
  `printf(user_input)` di source code
- Dynamic analysis: fuzzing dengan `%n` payload untuk konfirmasi bug
- GDB: cari offset dengan `AAAA%p` chain atau positional `%N$p`
- Offset yang ditemukan dipakai di tahap exploit: `%N$s` untuk baca,
  `%N$n` untuk tulis
