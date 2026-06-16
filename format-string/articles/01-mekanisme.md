# 01 - Mekanisme Format String

**Author**: Kenshin Himura

## Pendahuluan

Format string bug terjadi ketika program memanggil fungsi dari keluarga
`printf` dengan format string yang bisa dikontrol user. Bug ini
memungkinkan penyerang membaca dan menulis memory secara arbitrary.

Bab ini membahas cara kerja internal fungsi `printf`-family, layout
stack saat pemanggilan, dan mengapa format specifier `%n` berbahaya.

## Keluarga printf

Fungsi yang rentan terhadap format string bug:

| Fungsi | Deskripsi |
|--------|-----------|
| `printf` | Output ke stdout |
| `fprintf` | Output ke file stream |
| `sprintf` | Output ke string buffer |
| `snprintf` | Output ke string buffer dengan batas |
| `vprintf` | Varargs version dari printf |
| `syslog` | Output ke system log |
| `err` / `warn` | Output ke stderr dengan error info |

Pola rentan:

```c
printf(user_input);          // user_input jadi format string
fprintf(fp, user_input);     // user_input jadi format string
syslog(LOG_ERR, user_input); // user_input jadi format string
```

Pola aman:

```c
printf("%s", user_input);
fprintf(fp, "%s", user_input);
syslog(LOG_ERR, "%s", user_input);
```

## Variadic Function

`printf` termasuk variadic function - fungsi dengan jumlah argumen
tidak tetap. Prototipe-nya:

```c
int printf(const char *format, ...);
```

Parameter `...` (ellipsis) berarti fungsi bisa menerima argumen
tambahan dalam jumlah berapa pun. Kompiler C tidak melakukan type
checking pada argumen variadic - fungsi membaca argumen berdasarkan
format specifier di string pertama.

Saat `printf` dipanggil:

```c
printf("%d + %d = %d", 2, 3, 5);
```

Fungsi membaca format string `"%d + %d = %d"` dan mengkonsumsi 3
argumen integer dari stack (x86) atau register+stack (x64). Jika format
string meminta lebih banyak argumen daripada yang diberikan, `printf`
tetap membaca dari stack - membaca nilai apa pun yang ada di sana.

## Format Specifier

Anatomi format specifier:

```
%[parameter][flags][width][.precision][length]specifier
```

### Specifier

| Specifier | Output |
|-----------|--------|
| `%d` | Signed decimal integer |
| `%u` | Unsigned decimal integer |
| `%x` | Hexadecimal lowercase |
| `%p` | Pointer address |
| `%s` | String (null-terminated) |
| `%c` | Character |
| `%n` | **Write** - jumlah karakter yang sudah di-print |
| `%hn` | Write 2 byte (half-word) |
| `%hhn` | Write 1 byte |

### Parameter (Positional)

`%7$x` mengakses argumen ke-7, bukan argumen ke-7 dari kiri. Ini
memungkinkan akses ke posisi stack mana pun.

### Width

`%100x` mencetak integer dengan minimal lebar 100 karakter (dipadding
spasi). Digunakan dalam exploit untuk mengontrol jumlah karakter yang
sudah di-print sebelum `%n`.

### Length

`%hn` menulis short (2 byte). `%hhn` menulis char (1 byte). `%n`
menulis int (4 byte di x86, 4 atau 8 di x64 tergantung ABI).

## Stack Layout x86 (cdecl)

Pada arsitektur x86 dengan calling convention cdecl:

```
Alamat rendah
+------------------+
| local variables  |  <- ESP (stack pointer)
+------------------+
| saved EBP        |
+------------------+
| return address   |
+------------------+
| arg 1 (format)   |
+------------------+
| arg 2            |
+------------------+
| arg 3            |
+------------------+
| ...              |
Alamat tinggi
```

Argumen fungsi di-push ke stack dari kanan ke kiri. Saat `printf(fmt,
a, b, c)` dipanggil, stack berisi (dari atas ke bawah): `c`, `b`, `a`,
`fmt`, return address.

Saat format string di-parse, `printf` membaca argumen mulai dari
posisi setelah format string pointer. Jika format string meminta 10
argumen tapi hanya 3 yang diberikan, 7 slot berikutnya berisi data
apa pun yang ada di stack: local variable, saved EBP, return address,
pointer ke heap, dll.

## Stack Layout x64 (System V AMD64)

Pada x64, 6 argumen pertama dilewatkan via register: `rdi`, `rsi`,
`rdx`, `rcx`, `r8`, `r9`. Argumen ke-7 dst ada di stack.

Dampaknya: format string di x64 membaca register dulu, baru stack.
Offset ke input user berbeda dengan x86. Address dengan null byte
(umum di x64) harus ditaruh di akhir payload karena `printf` berhenti
di null byte.

## Mengapa %n Berbahaya

`%n` bukan membaca - ia menulis. Specifier ini menulis jumlah karakter
yang sudah di-print ke alamat yang ditunjuk oleh argumen terkait.

```c
int count = 0;
printf("hello%n", &count);
// count sekarang = 5
```

Dalam exploit: penyerang menaruh alamat target di stack (lewat input),
lalu menggunakan `%n` untuk menulis ke alamat tersebut. Jumlah
karakter yang di-print dikontrol lewat width modifier.

```c
// Input user: "\x40\xc0\x04\x08%64x%7$n"
// Menulis nilai 68 (4 + 64) ke alamat 0x0804c040
```

## Memory Layout: GOT, PLT, dan Segment

### GOT (Global Offset Table)

Tabel pointer di memory yang menyimpan alamat fungsi library yang
sudah di-resolve. Saat program memanggil `printf()`, sebenarnya ia
memanggil stub di PLT yang melompat ke GOT entry.

### PLT (Procedure Linkage Table)

Stub kecil untuk setiap fungsi eksternal. Saat pertama kali dipanggil,
PLT memicu dynamic linker untuk resolve alamat. Setelah resolve,
PLT langsung melompat ke GOT entry yang sudah terisi.

### Segment Memory

| Segment | Isi | Writable |
|---------|-----|----------|
| .text | Kode program | Tidak |
| .data | Global variable terinisialisasi | Ya |
| .bss | Global variable tidak terinisialisasi | Ya |
| .got | GOT entries | Tergantung RELRO |
| .got.plt | PLT GOT entries | Partial RELRO: ya |
| .fini_array | Destructor array | Ya (jika tidak Full RELRO) |

### Proteksi Binary

| Proteksi | Efek pada Format String |
|----------|------------------------|
| ASLR | Address acak - perlu leak dulu |
| PIE | Binary base acak - perlu leak |
| NX | Stack/heap tidak executable - perlu ROP |
| Stack Canary | Deteksi buffer overflow |
| Partial RELRO | .got.plt writable - bisa GOT overwrite |
| Full RELRO | .got.plt read-only - harus cari target lain |
| FORTIFY_SOURCE | Runtime check %n di format string literal |

## Ringkasan

- `printf` membaca argumen dari stack tanpa batas - input user sebagai
  format string memberi akses baca/tulis ke memory proses
- `%n` mengubah bug dari information leak menjadi arbitrary write
- Layout stack dan calling convention menentukan posisi argumen
- GOT dan PLT adalah target klasik untuk redirect execution
- Proteksi binary (ASLR, PIE, RELRO, FORTIFY) menentukan strategi
  exploit
