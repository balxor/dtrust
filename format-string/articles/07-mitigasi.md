# 07 - Mitigasi dan Defense

**Author**: Kenshin Himura

## Pendahuluan

Bab ini membahas cara mencegah format string bug dari sisi developer
(secure coding), compiler (hardening flags), dan sistem operasi
(runtime protection).

## Compiler Hardening

### Warning Flags

Compile dengan warning maksimal:

```bash
gcc -Wall -Wextra -Wformat-security -Wformat=2 -Werror program.c
```

`-Werror` mengubah warning jadi error -> build gagal jika ada format
string non-literal.

### FORTIFY_SOURCE

```bash
gcc -D_FORTIFY_SOURCE=2 -O2 program.c
```

Efek pada glibc >= 2.15:

- `FORTIFY_SOURCE=1`: compile-time check, mendeteksi `%n` di format
  string literal. Menambahkan check bounds pada `sprintf`, `strcpy`, dll.
- `FORTIFY_SOURCE=2`: runtime check via `__printf_chk()`. Mendeteksi
  `%n` di format string di writable memory dan memanggil `abort()`.

Output saat terdeteksi: `*** %n in writable segment detected ***`

### Stack Protector

```bash
gcc -fstack-protector-strong program.c
```

Menambahkan canary di antara local variable dan return address.
Jika canary berubah, program `abort()`. Tidak langsung mencegah
format string, tapi membatasi dampak buffer overflow companion.

### PIE dan RELRO

```bash
gcc -pie -fPIE -Wl,-z,relro,-z,now program.c
```

- `-pie -fPIE`: binary base acak (ASLR) -> penyerang harus leak dulu
- `-Wl,-z,relro,-z,now`: Full RELRO -> GOT read-only -> tidak bisa
  GOT overwrite. Target alternatif (`.fini_array`) juga ikut read-only.

### Non-Executable Stack

```bash
gcc -z noexecstack program.c
```

Mencegah eksekusi kode di stack/heap. Shellcode tidak bisa langsung
dijalankan, harus pakai ROP.

## Secure Coding

### Aturan Wajib

Format string argumen pertama HARUS string literal:

```c
// BENAR
printf("%s", user_input);
fprintf(stderr, "Error: %s\n", user_input);
snprintf(buf, sizeof(buf), "%s", user_input);
syslog(LOG_ERR, "%s", user_input);

// SALAH
printf(user_input);
fprintf(stderr, user_input);
snprintf(buf, sizeof(buf), user_input);
syslog(LOG_ERR, user_input);
```

### Wrapper Aman

Buat wrapper untuk logging:

```c
void safe_log(const char *msg) {
    printf("%s", msg);  // format literal
}

// Pakai di seluruh codebase
safe_log(user_input);
```

### Static Analysis di CI/CD

Integrasikan SAST tool di pipeline:

```yaml
# .github/workflows/security.yml
- name: Semgrep scan
  run: semgrep --config=auto --error .

- name: Check compiler warnings
  run: gcc -Wformat-security -Werror -c *.c
```

## Code Review Checklist

- [ ] Setiap `printf`/`fprintf`/`sprintf`/`syslog`/`err`/`warn`
  menggunakan format string literal
- [ ] Tidak ada path di mana input user mencapai argumen pertama
  fungsi `printf`-family
- [ ] Compile dengan `-Wformat-security -Werror`, build clean
- [ ] SAST tool (Semgrep/CodeQL) tidak mendeteksi FSB
- [ ] `FORTIFY_SOURCE=2` enabled di build production
- [ ] Binary di-compile dengan PIE + Full RELRO + NX + Canary

## Runtime Protection

### Grsecurity / PaX

Kernel patch yang menambahkan proteksi:

- `PAX_DISALLOW_FORMAT_STRING`: menonaktifkan `%n` sepenuhnya di
  userspace. Program yang menggunakan `%n` akan menerima SIGKILL.

### SELinux / AppArmor

Mandatory Access Control (MAC) yang membatasi apa yang bisa dilakukan
proses meskipun sudah compromised:

- Batasi akses filesystem (tidak bisa tulis ke `/etc`, `/usr/bin`)
- Batasi syscall (tidak bisa `execve`, `ptrace`)
- Batasi network (tidak bisa bind shell)

### seccomp-bpf

Filter syscall di level process:

```c
// Izinkan hanya write dan exit
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
seccomp_load(ctx);
```

Dengan filter ini, meskipun format string exploit berhasil mendapatkan
code execution, `execve()` diblokir -> tidak bisa spawn shell.

### System-Wide ASLR

```bash
echo 2 > /proc/sys/kernel/randomize_va_space
```

Nilai 2 = full randomization (binary, stack, heap, libc, vdso).

## Perbandingan Efektivitas

| Teknik | Cegah Leak | Cegah Write | Cegah Execute |
|--------|:---------:|:----------:|:------------:|
| `-Wformat-security` | - | - | - (hanya warning) |
| FORTIFY_SOURCE=2 | - | Ya (runtime) | - |
| PIE | Mempersulit | Mempersulit | - |
| Full RELRO | - | Ya (GOT) | - |
| NX | - | - | Ya |
| Stack Canary | - | - | - (deteksi overflow) |
| seccomp | - | - | Ya (syscall filter) |
| Grsecurity | - | Ya | Ya |

## Ringkasan

- Developer: selalu pakai format string literal, jangan pernah
  `printf(input_user)`
- Compiler: `-Wformat-security -Werror -D_FORTIFY_SOURCE=2 -pie -fPIE
  -Wl,-z,relro,-z,now -fstack-protector-strong`
- Runtime: ASLR + SELinux/AppArmor + seccomp
- Defense in depth: gabungkan semua lapisan
