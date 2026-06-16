# Silabus: Format String Vulnerability - Debugging hingga Post-Exploitation
**Author**: Kenshin Himura

**Target audience**: Pentester, Security Researcher, Red Teamer  
**Level**: Intermediate -> Advanced  
**Durasi**: 5-8 hari (intensif) atau 2-3 minggu (modular)  
**Lab utama**: Protostar-style custom lab (format0-format4) + real-world CVE  

---

## STRUCTURE OVERVIEW

```
[1] MEKANISME     -> cara kerja printf-family, stack layout, variadic function
[2] DEBUGGING     -> temukan bug via static + dynamic analysis, fuzzing, GDB
[3] RECON         -> leak memory, map address space, enumerate proteksi
[4] EXPLOITATION  -> arbitrary write (%n, %hn, %hhn), GOT overwrite, ROP chain
[5] EVASION       -> bypass FORTIFY_SOURCE, payload obfuscation, IDS evasion
[6] POST-EXPLOIT  -> privilege escalation, persistence, pivoting pasca-format-string
[7] MITIGATION    -> compiler hardening, secure coding, code review checklist
[8] REAL CVEs     -> studi kasus CVE nyata, full exploit chain
```

---

## [1] MEKANISME & TEORI

### 1.1 Cara Kerja `printf`-family
- `printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `vsnprintf`
- Variadic function: argumen diparsing tanpa type checking
- Format specifier lengkap: `%d`, `%u`, `%x`, `%p`, `%s`, `%c`, `%f`, `%n`, `%hn`, `%hhn`, `%ln`
- `%n` menulis jumlah karakter yang sudah di-print ke memory - tidak membaca argumen seperti specifier lain

### 1.2 Stack Layout Saat `printf` Dipanggil
- Calling convention x86 (cdecl): argumen di-push ke stack dari kanan ke kiri
- Calling convention x64 (System V AMD64): 6 argumen pertama via register (rdi, rsi, rdx, rcx, r8, r9), sisanya di stack
- Dampak calling convention terhadap format string exploitation
- Visualisasi stack frame `printf(format_string, arg1, arg2, ...)`

### 1.3 Format Specifier Deep Dive
```
%[parameter][flags][width][.precision][length]specifier
```
- Parameter: `%7$x` -> akses argumen ke-7
- Width: `%100x` -> padding, minimal 100 karakter
- Precision: `%.100x` -> precision untuk string/integer
- Length: `%hn` (2 byte write), `%hhn` (1 byte write), `%n` (4 byte write)

### 1.4 Memory & Assembly Refresher
- Little-endian vs big-endian
- Stack: push, pop, ebp, esp, ret addr
- GOT (Global Offset Table), PLT (Procedure Linkage Table)
- .bss, .data, .text, .fini_array
- Relro (Partial/Full), PIE, NX, Stack Canary, ASLR

**Lab**: `format0` - Identifikasi offset format string di stack  

---

## [2] DEBUGGING & FINDING BUGS

### 2.1 Pola Rentan Format String
```c
// RENTAN
printf(user_input);
fprintf(fp, user_input);
syslog(LOG_ERR, user_input);

// AMAN
printf("%s", user_input);
fprintf(fp, "%s", user_input);
syslog(LOG_ERR, "%s", user_input);
```

### 2.2 Static Analysis
- Pattern grep: `printf(`, `fprintf(`, `sprintf(` tanpa `"%s"`
- SAST tools: **Semgrep**, **CodeQL**, **Flawfinder**, **Splint**
- Compiler warning: `-Wall -Wextra -Wformat-security -Wformat=2`
- Signatures di binary: cross-reference `printf@plt` -> call site
- **Write custom CodeQL query** untuk deteksi format string bug

### 2.3 Dynamic Analysis
- Fuzzing dengan **AFL++**, **libFuzzer**, custom mutator untuk format string
- Instrumentasi binary dengan **AddressSanitizer (ASAN)** + input `%n%n%n%n`
- Crash dump analysis: SIGSEGV saat `%n` menulis ke address invalid

### 2.4 Debugging dengan GDB + GEF/Pwndbg
- Set breakpoint di `printf` dan `printf@plt`
- Inspeksi stack: `x/100x $esp`, `telescope $esp`
- Trace format string parsing: `ni` (next instruction) step-by-step
- Identifikasi offset: `AAAA%p.%p.%p.%p.%p.%p.%p`
- `%n$p` untuk precise leak

### 2.5 Tools
- **format-string-checker** (Python script - analisis otomatis)
- **libformatstr** / **fmtstr** (pwntools module)
- **libdislocator** (AFL memory allocator) untuk deteksi heap-based FSB

**Lab**: `format0` - GDB walkthrough: identifikasi offset, inspect stack  

---

## [3] RECON & ENUMERATION

### 3.1 Information Leakage Melalui Stack
- `%x` / `%p`: dump seluruh nilai di stack
- Menemukan stack cookie/canary, return address, saved EBP
- Menemukan pointer ke heap, libc, binary base
- **Leak seluruh format string memory space** dengan loop `%n$p`

### 3.2 Arbitrary Read
- Menempatkan alamat target di payload, lalu baca via `%s`
- Teknik konfirmasi: taruh `0x41414141` di stack, verifikasi bisa dibaca
- Membaca GOT entry untuk leak libc base
- Membaca environment variable, file path, credential di stack
- Membaca `/proc/self/maps` jika accessible

### 3.3 Memory Layout Mapping
- Leak binary base (PIE bypass) via saved EIP atau GOT entry
- Leak libc base via GOT entry (misal `printf@got`)
- Leak stack address via saved EBP
- Leak heap address via pointer di stack
- Hitung offset: `libc_base = leaked_printf - printf_offset_in_libc`

### 3.4 Enumerasi Proteksi
- `checksec` / `readelf -l` / `checksec.sh`
- ASLR: aktif/tidak (`/proc/sys/kernel/randomize_va_space`)
- PIE: periksa base binary (0x400000 vs acak)
- Stack Canary: cek `__stack_chk_fail` di symbol table
- NX: cek GNU_STACK header (RWE vs RW)
- RELRO: Partial vs Full

**Lab**: `format1` - Leak secret value + bypass PIE/ASLR dengan arbitrary read  
**Real CVE**: `sudo CVE-2012-0809` - Leak memory via format string di error logging  

---

## [4] EXPLOITATION

### 4.1 Arbitrary Write: `%n` Family
- `%n`:   menulis 4 byte (jumlah karakter yang sudah di-print)
- `%hn`:  menulis 2 byte (half-word)
- `%hhn`: menulis 1 byte (byte) - paling presisi
- `%ln`:  menulis 4 byte (32-bit) / 8 byte (64-bit)

### 4.2 Address Placement Strategy
- Address ditaruh di payload sendiri (paling awal payload)
- Menentukan offset ke address dengan `%p` chain
- Konfirmasi: `AAAA%7$p` -> muncul `0x41414141`

### 4.3 Teknik Single-Write
- Menimpa variable sederhana (integer, flag, boolean)
- Gunakan width modifier: `%64x%7$n` -> menulis `64` ke address
- Perhitungan: `bytes_to_print = target_value - bytes_already_printed`

### 4.4 Teknik Double-Write (`%hn` / `%hhn`)
- Untuk address 32-bit, dibutuhkan 2 × `%hn` atau 4 × `%hhn`
- **Address splitting**:
  ```
  payload = p32(target_addr)     + p32(target_addr+2)
  fmt     = "%{lower}x%offset1$hn%{upper-lower}x%offset2$hn"
  ```
- **Short write calculation**: lower 2 byte dulu, lalu upper 2 byte
- Jika upper < lower: manfaatkan integer overflow width modifier
- **4-byte full overwrite** via 4 × `%hhn` (paling presisi)

### 4.5 Target Overwrite
#### 4.5.1 GOT Overwrite (klasik)
- Ganti entry `exit@got` / `puts@got` / `printf@got` dengan `win()` / `system()`
- Perlu 2 write (`%hn`) untuk overwrite 4 byte address
- Chain: `puts@got` -> `system`, lalu panggil `puts("/bin/sh")`

#### 4.5.2 Return Address Overwrite
- Overwrite saved EIP di stack frame pemanggil
- Perlu stack leak terlebih dahulu

#### 4.5.3 .fini_array Overwrite  
- `.fini_array` -> kode yang dieksekusi saat `exit()`/return dari main
- Alamat `.fini_array` statis jika no PIE

#### 4.5.4 `__malloc_hook` / `__free_hook`
- Libc internal hook, dipanggil sebelum `malloc()`/`free()`
- Di-overwrite dengan `system()` -> setiap kali `malloc` dipanggil, eksekusi command
- Perlu libc leak terlebih dahulu

### 4.6 ROP Chain via Format String
- Menulis ROP chain ke stack return address
- Alternatif: overwrite GOT dengan gadget (misal `add rsp, X; ret` untuk pivot stack)
- stack pivot + ROP chain di heap

### 4.7 Eksploitasi di x64
- 6 argumen register -> format string membaca stack **setelah** register
- Address di payload harus di offset stack (bukan register pertama)
- Null byte di address x64 -> address harus di akhir payload
- Alternatif: partial overwrite (2 byte saja), 1/256 bruteforce ASLR

**Lab**: `format2` - Single write ke variable  
**Lab**: `format3` - Double-write `%hn` ke global variable  
**Lab**: `format4` - GOT overwrite full exploit chain: leak libc -> overwrite `exit@got` -> shell  
**Real CVE**: `wu-ftpd CVE-2000-0573` - Remote format string -> GOT overwrite -> shell  

---

## [5] EVASION

### 5.1 Payload Obfuscation
- Encoding address bytes (XOR, ROT-13) - jarang berguna karena null-byte problem
- Pad payload dengan `\x90` atau random bytes
- Gunakan `%*x$` (dynamic width) untuk generate output non-deterministik
- Split character output: `%c%c%c%c` alih-alih `%4c`

### 5.2 Evasion Terhadap Filter/Firewall
- Payload di query string, header HTTP, data POST
- URI encoding address bytes: `%41` alih-alih `\x41`
- Multi-stage: leak dulu, write kemudian (pisahkan interaksi)
- Timing-based: add `%10000000x` untuk delay / bruteforce timing

### 5.3 Bypass FORTIFY_SOURCE
- `FORTIFY_SOURCE=1`: mendeteksi `%n` di writable memory -> abort
- `FORTIFY_SOURCE=2`: strict check, tambahan batasan `%n` di `%s`
- **Bypass**: jangan gunakan `%n` di format string writable; taruh address di stack (stack variable / format string on heap)

### 5.4 Anti-Debug & Anti-Analisis
- Deteksi ptrace via `prctl(PR_SET_DUMPABLE)` atau signal handler
- Polymorphic format string payload

**Lab**: `format4` dengan `FORTIFY_SOURCE=2` diaktifkan - cari cara bypass  
**Real CVE**: `QEMU CVE-2020-14364` - format string di USB passthrough, ada FORTIFY bypass  

---

## [6] POST-EXPLOITATION

### 6.1 Privilege Escalation Pasca Format String
- **SUID binary**: exploit format string di binary SUID -> dapatkan root shell
- **Capability-aware**: exploit binary dengan `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`
- **Container escape**: format string di container runtime -> akses host filesystem
- Lingkungan terbatas: shell restricted -> escape via format string di shell built-in
- **systemd service**: format string di binary yang dijalankan service root

### 6.2 Persistence
- Modifikasi binary yang dieksekusi secara periodik (cron, service, timer)
- Overwrite `.fini_array` untuk eksekusi payload setiap binary selesai
- Tambahkan cron job via format string write ke crontab path

### 6.3 Pivoting & Lateral Movement
- Dari low-privilege shell -> discover host lain -> pivot
- Dump credentials melalui format string leak (environment, config file, memory)
- SSH key exfiltration dari memory

### 6.4 Log Cleansing
- Overwrite syslog/audit entry via file write (jika path diketahui)
- Cover tracks

**Real CVE scenarios**:
- `sudo CVE-2012-0809`: local priv esc dari user ke root
- `systemd-journald CVE-2020-1712`: local root via format string

---

## [7] MITIGASI & DEFENSE

### 7.1 Compiler Hardening
| Flag | Efek |
|------|------|
| `-Wformat-security` | Warning format string non-literal |
| `-Wformat=2` | Warning + error untuk FSB pattern |
| `-D_FORTIFY_SOURCE=2` | Runtime check %n di writable memory |
| `-fstack-protector-strong` | Stack canary |
| `-pie -fPIE` | Position-independent executable |
| `-Wl,-z,relro -Wl,-z,now` | Full RELRO |
| `-z noexecstack` | Non-executable stack |

### 7.2 Secure Coding
```c
// SELALU gunakan format string LITERAL
printf("%s", user_input);    // AMAN
syslog(level, "%s", input);  // AMAN
snprintf(buf, size, "%s", input); // AMAN

// JANGAN PERNAH
printf(input);               // RENTAN
fprintf(fp, input);          // RENTAN
err(1, input);               // RENTAN
```

### 7.3 Code Review Checklist
- [ ] Semua `printf`/`fprintf`/`sprintf`/`syslog`/`err`/`warn` sudah pakai format literal
- [ ] Tidak ada user-controlled format string
- [ ] Compiler warning `-Wformat-security` clean
- [ ] Analisis SAST tidak mendeteksi FSB
- [ ] `FORTIFY_SOURCE=2` enabled di build production

### 7.4 Runtime Protection
- **Grsecurity / PaX**: `PAX_DISALLOW_FORMAT_STRING` -> membuat `%n` tidak berfungsi
- **SELinux / AppArmor**: containment policy
- **seccomp-bpf**: filter syscall, batasi `write`/`execve`

---

## [8] STUDI KASUS REAL CVEs

| CVE | Software | Dampak | Kesulitan |
|-----|----------|--------|-----------|
| CVE-2000-0573 | wu-ftpd 2.6.0 | Remote root via `SITE EXEC` | ★★★☆ |
| CVE-2012-0809 | sudo < 1.8.4 | Local root via error logging | ★★☆☆ |
| CVE-2017-15228 | irssi < 1.0.5 | Client-side RCE via server message | ★★★☆ |
| CVE-2020-14364 | QEMU 5.1 | VM escape via USB emulation | ★★★★ |
| CVE-2020-1712 | systemd-journald | Local root | ★★★☆ |

### Walkthrough per CVE (tersedia di folder `cve/`)
1. Environment setup (Dockerfile)
2. Root cause analysis
3. Exploit step-by-step
4. Mitigation bypass analysis (FORTIFY_SOURCE bypass untuk CVE-2012-0809)

---

## LAB EXERCISE MAP

| Level | Silabus Chapter | Skill |
|-------|----------------|-------|
| `format0` | [1] Mekanisme + [2] Debugging | Leak stack, cari offset format string |
| `format1` | [3] Recon | Arbitrary read address via `%s` |
| `format2` | [4.1-4.3] Exploit | Single write `%n` ke variable |
| `format3` | [4.4] Exploit | Double-write `%hn`, precise value write |
| `format4` | [4.5-4.7] Exploit | Full chain: leak -> GOT overwrite -> shell |
| `cve-2012-0809` | [3] + [4] + [8] | Real CVE: sudo format string |
| `cve-2000-0573` | [4] + [5] + [8] | Real CVE: remote format string exploit |

---

## PREREQUISITES

### Software
- Linux VM (Ubuntu 20.04/22.04) atau WSL2
- `gcc-multilib`, `gdb`, `python3-pwntools`
- `pwntools`: `pip3 install pwntools`
- `gef` atau `pwndbg` untuk GDB
- `checksec` / `pwntools.checksec`
- Opsional: `AFL++`, `Semgrep`, `CodeQL`

### Pengetahuan Minimum
- C programming dasar
- Assembly x86/x64 dasar
- Linux binary exploitation concepts (buffer overflow basic)
- Python scripting

---

## REFERENSI

- **"Hacking: The Art of Exploitation"** - Jon Erickson (Chapter format string)
- **"The Shellcoder's Handbook"** - Chris Anley (Format string exploitation)
- **"Exploiting Format String Vulnerabilities"** - scut / team teso (2001)
- **Protostar / Phoenix** - Exploit Education (https://exploit.education)
- **pwn.college** - ASU (format string module)
- **OWASP Format String Attack** - https://owasp.org/www-community/attacks/Format_string_attack
- **Linux man page**: `man 3 printf`, `man 1 gcc`, `man 7 feature_test_macros`

---

> "The quieter you become, the more you are able to hear."
> 
> "We break things not to destroy, but to understand how they hold together."
> 
> "Format strings don't leak data -- careless programmers leak data. The
> stack remembers everything you forgot to protect."
