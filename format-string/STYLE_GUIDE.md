# Aturan Penulisan - Format String Project

**Author**: Kenshin Himura

Dokumen ini berisi aturan penulisan yang berlaku untuk seluruh file `.md`
di project ini. Wajib dipatuhi untuk menjaga konsistensi.

---

## 1. Header dan Metadata

Setiap file `.md` wajib memiliki header:

```markdown
# Judul Dokumen
**Author**: Kenshin Himura
```

Penempatan: baris pertama judul, baris kedua author.

## 2. Header File Kode

### Python
```python
#!/usr/bin/env python3
# Author: Kenshin Himura
```

### C
```c
/*
 * Author: Kenshin Himura
 */
```

## 3. Diksi Terlarang

Kata-kata berikut **tidak boleh** digunakan dalam teks naratif:

| Dilarang | Alasan |
|----------|--------|
| `fondasi`, `landasan`, `pilar` | Metafora struktural |
| `jujur`, `sejujurnya`, `terus terang` | Filler retoris |
| `sunyi`, `senyap` | Metafora keheningan |
| `utama`, `tunggal`, `mutlak`, `sempurna` | Kualifikasi berlebihan |
| `fundamental`, `esensial`, `primer` | Formal tidak perlu |
| `alih-alih` | Kuno, gunakan `dibanding` atau `sebagai pengganti` |
| `ketat` (untuk aturan/check) | Gunakan `lanjut` atau restruktur kalimat |
| `kuat` (untuk deskripsi teknis) | Hindari, gunakan deskripsi objektif |
| `berbahaya` | Gunakan `dapat dieksploitasi` |
| `target klasik`, `teknik klasik` | Gunakan `target` atau `teknik` saja |

## 4. Pengganti Kata Tidak Baku

| Hindari | Gunakan |
|---------|---------|
| `pakai` | `gunakan`, `menggunakan` |
| `bisa` | `dapat` |
| `apa pun`, `mana pun`, `berapa pun` | Frasa presisi: `tanpa batas`, `di posisi berikutnya` |

## 5. Awkward Literal Translation

Terjemahan harfiah dari idiom Inggris yang terdengar janggal:

| Hindari | Gunakan |
|---------|---------|
| `membawa` (ships with) | `menyertakan`, `hadir dengan` |
| `keluarga` (family of functions) | `printf-family` (English) |
| `pola rentan` | `pola vulnerable` atau hapus label |
| `pola aman` | `pola safe` atau hapus label |
| `alamat rendah` / `alamat tinggi` | `low address` / `high address` |

## 6. Istilah Teknis

**Jangan terjemahkan** istilah teknis. Pertahankan dalam English:

```
Benar:  attack surface, payload, threat model, pipeline, stack pointer
Salah:  permukaan serangan, muatan, model ancaman, jalur pipa
```

Berlaku juga untuk: `roadmap`, `buffer overflow`, `use-after-free`,
`race condition`, `return address`, `saved EBP`, `stack frame`,
`calling convention`, dan sejenisnya.

## 7. Karakter Terlarang

| Karakter | Kode | Pengganti |
|----------|------|-----------|
| `—` (em-dash) | U+2014 | `-` (ASCII dash) |
| `–` (en-dash) | U+2013 | `-` (ASCII dash) |
| `→` (right arrow) | U+2192 | `->` |
| `←` (left arrow) | U+2190 | `<-` |

## 8. Header Section

- Gunakan `## Referensi` (bukan `REFERENSI` caps)
- Gunakan `## Ringkasan` (bukan `Takeaways`, `Key Takeaways`)
- Format referensi seragam: `- **"Judul"** - Penulis (tahun)`
- URL ditulis lengkap, tidak dalam kurung

## 9. Struktur Kalimat

### Dilarang:

- **Negasi-afirmasi**: `"bukan X, melainkan Y"`, `"bukan membaca - ia menulis"`
  -> langsung nyatakan yang benar
- **Pengandaian**: `"bayangkan..."`, `"seolah-olah..."`
- **Scaffolding**: `"setiap fase punya..."`, `"pada bab ini akan dibahas..."`
- **Colon punchline**: kalimat yang merangkum kalimat sebelumnya dengan `:`
- **Em-dash apositif**: maksimal 1 per paragraf

### Diizinkan:

- Kalimat langsung ke isi tanpa pembuka
- Fakta dinyatakan sekali, tanpa pengulangan
- Paragraf ditutup di fakta terakhir, tanpa generalisasi

## 10. Ceklis Sebelum Commit

- [ ] Author: Kenshin Himura di setiap file `.md`, `.py`, `.c`
- [ ] Tidak ada em-dash (U+2014) atau en-dash (U+2013)
- [ ] Tidak ada unicode arrow (U+2190, U+2192)
- [ ] Tidak ada kata `pakai`, `bisa`, `utama`, `tunggal`, `alih-alih`
- [ ] Tidak ada kata `takeaway` atau `key takeaway`
- [ ] Tidak ada kata `fondasi`, `landasan`, `pilar`
- [ ] Istilah teknis dalam English
- [ ] Header referensi: `## Referensi`
- [ ] Format referensi konsisten
