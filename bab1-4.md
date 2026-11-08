# LAPORAN ANALISIS MALWARE
**Studi Kasus:** PowerShell Stealer `Z595.ps1` - C2 `185.138.88.151`

- **Analis:** urfemthings
- **Tanggal Analisis:** 8 November 2026
- **Sampel Utama:** `Z595.ps1`
- **Klasifikasi:** PowerShell Stealer / Fileless Loader

---

## 1. RINGKASAN EKSEKUTIF

Ditemukan kampanye malware aktif yang menggunakan infrastruktur Command and Control (C2) di IP `185.138.88.151`. Malware ini menggunakan rantai serangan 3 tahap berbasis PowerShell dengan teknik Fileless dan Living-off-the-Land (LOLBin) untuk menghindari deteksi antivirus.

Meskipun hanya terdeteksi oleh 1 dari 61 antivirus di VirusTotal, analisis perilaku sandbox membuktikan malware ini melakukan 71 teknik MITRE ATT&CK, melakukan Process Injection, kompilasi .NET dinamis, dan komunikasi ke server C2.

**Tingkat Bahaya:** TINGGI

## 2. INDICATORS OF COMPROMISE (IOC)

| Tipe | Nilai | Keterangan |
| :--- | :--- | :--- |
| **IP C2** | `185.138.88.151:80` | Lokasi: Amsterdam, ASN 215540 |
| **URL Tahap 1** | `http://185.138.88.151/438` | File `trungle.txt`, 50 byte, Loader |
| **URL Tahap 2** | `http://185.138.88.151/439` | File `Z595.ps1`, 471 KB, Stealer Utama |
| **URL Tahap 3** | `http://185.138.88.151/yrjs/tctc.bba` | Di-download saat eksekusi |
| **SHA256 Loader** | `eaf7114a...60076b5` | File 50 byte |
| **SHA256 Stealer** | `566a2e0f5104c7f6a7ffe7f1b896acb0013f00fee4115201436174ff71198a21` | File 471 KB |
| **MD5 Stealer** | `b40149ab606f2f4b825c291bcae0b187` | File 471 KB |
| **File Payload** | `q6ytyo0.exe` | Payload akhir (PE) |

## 3. STATIC ANALYSIS

Analisis statis dilakukan pada file `Z595.ps1`:

- **Ukuran File:** 471.37 KB (482,682 bytes)
- **Tipe File:** PowerShell Script (`.ps1`)
- **Magic:** `ASCII text, with very long lines (65536), with no line terminators`
- **First Submission VirusTotal:** 7 November 2026

File ini memiliki 1 baris super panjang tanpa pemisah baris (*line terminator*). Ini adalah ciri khas **Obfuscation**, yang bertujuan agar kode tidak dapat dibaca manusia dan sulit dideteksi oleh antivirus berbasis *signature*. Hal ini menjelaskan rendahnya tingkat deteksi (1/61).

Perbandingan ukuran membuktikan struktur *multi-stage*:
- Tahap 1: /438 (50 byte, trungle.txt) -> loader kecil
- Tahap 2: /439 (471 KB, Z595.ps1) -> stealer utama
- Tahap 3: /yrjs/tctc.bba -> file tambahan yang di-download sama Z595.ps1 pas udah jalan di sandbox

## 4. DYNAMIC / BEHAVIOUR ANALYSIS

Analisis perilaku dilakukan menggunakan sandbox (CAPE / VirusTotal Sandbox).

**Hasil Sandbox:**
- Detections: NOT FOUND (lolos signature)
- MITRE Signatures: 71 Teknik (37 MEDIUM, 30 LOW, 4 INFO)
- Sigma Rules: 1 HIGH, 2 MEDIUM, 1 LOW
- Dropped Files: 11 file (8 OTHER, 1 COFF, 1 TEXT, 1 PE_DLL)
- Network: 1 HTTP Request, 1 IP

### 4.1 Sigma Rules - Bukti Teknik Fileless

- **[HIGH] Dot net compiler compiles file from suspicious location**  
  Malware menyuruh Windows untuk meng-compile file .NET dari lokasi mencurigakan. Ini adalah teknik Living-off-the-Land.
- **[MEDIUM] Sysmon File Executable Creation Detected**  
  Malware membuat file Portable Executable (PE) baru di komputer korban.
- **[MEDIUM] Dynamic .NET Compilation Via http://Csc.EXE**  
  Malware mengeksekusi `csc.exe` untuk meng-compile kode .NET secara langsung di memory, tanpa menyentuh disk (fileless).
- **[LOW] Dynamic CSharp Compile Artefact**  
  Ditemukan file `.cmdline` sebagai jejak proses unpacking payload C#.

**Kesimpulan Teknik:** Malware menggunakan kombinasi Fileless + LOLBin + Dynamic Compilation. Ia tidak membawa virusnya sendiri, melainkan menggunakan compiler resmi Windows untuk membuat virus di dalam komputer korban.

### 4.2 File System Actions

Malware membuka lebih dari 230 file selama eksekusi, diantaranya:
- `C:\Program Files\Windows Defender\MpClient.dll`
- `C:\Program Files\Windows Defender\MpOAV.dll`
- `C:\Program Files\Windows Defender\MsMpLics.dll`
- `C:\Program Files\dotnet\`
- `C:\Program Files\nodejs\`
- `C:\Program Files (x86)\Common Files\Oracle\Java\javapath`
- `C:\Program Files\Unrar`
- `C:\ProgramData\Microsoft\MapData\...`

Pembukaan file Defender menunjukkan upaya pengecekan pertahanan (Defense Evasion). Pembukaan folder `dotnet`, `nodejs`, `Java`, `Unrar` menunjukkan upaya enumerasi tool yang dapat dimanfaatkan untuk LOLBin.

## 5. NETWORK ANALYSIS

Malware melakukan komunikasi ke C2 melalui HTTP biasa (bukan HTTPS) pada port 80:

(```)text
GET [http://185.138.88.151/yrjs/tctc.bba](http://185.138.88.151/yrjs/tctc.bba)
TCP 185.138.88.151:80)

## 6. MITRE ATT&CK MAPPING

| Taktik | Teknik | Keterangan |
| :--- | :--- | :--- |
| **Execution** (TA0002) | T1059, T1064 | Eksekusi via PowerShell / Command and Scripting Interpreter |
| **Privilege Escalation** (TA0004) | T1055 | Process Injection ke proses lain |
| **Defense Evasion** (TA0005) | T1027, T1055 | Obfuscated Files, Process Injection, Fileless |
| **Discovery** (TA0007) | T1033, T1069 | System Owner/User Discovery, Permission Groups Discovery |
| **Command and Control** | T1071 | Komunikasi HTTP ke C2 |

## 7. ALUR SERANGAN LENGKAP (KILL CHAIN)

(```)text
[1] Korban mengunduh /438 (trungle.txt - 50 byte)

        |
        v

[2] Loader mengunduh /439 (Z595.ps1 - 471 KB)

        |
        v

[3] Z595.ps1 berjalan via PowerShell, ter-obfuscate

        |
        v

[4] Menggunakan csc.exe (LOLBin) untuk compile C# di memory

        |
        v

[5] Membuat file PE / DLL baru + Process Injection

        |
        v

[6] Meng-enumerasi sistem (Defender, dotnet, nodejs, dll) + Buka 230+ file

        |
        v

[7] Mengunduh /yrjs/tctc.bba + Menjalankan q6ytyo0.exe

        |
        v

[8] Komunikasi ke C2 185.138.88.151:80 untuk exfiltrasi data.

## 8. KESIMPULAN

Malware `Z595.ps1` adalah malware kelas menengah-atas yang menggunakan teknik modern untuk menghindari deteksi. Rendahnya deteksi antivirus (1/61) bukan karena file ini aman, melainkan karena teknik *obfuscation* dan *fileless* yang digunakan.

Bukti terkuat dari analisis ini adalah konsistensi antara *Static Analysis*, *Behaviour Analysis*, dan *Network Analysis* yang semuanya mengarah ke infrastruktur yang sama.

---

## 9. REKOMENDASI MITIGASI

1. **Blokir IOC:** Blokir IP `185.138.88.151` dan semua URL terkait di *firewall* / *proxy*.
2. **Blokir LOLBin:** Batasi eksekusi `csc.exe` dan `powershell.exe` dari folder `Temp` / `AppData` via AppLocker / WDAC.
3. **EDR:** Aktifkan deteksi *Sigma Rule* untuk *Dynamic .NET Compilation*.
4. **Edukasi:** Jangan menjalankan file `.ps1` dari sumber tidak terpercaya.
5. **Hunting:** Cari file `.cmdline` dan file PE baru yang dibuat oleh `csc.exe` di *endpoint*.


