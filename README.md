# NexilisSecurityShield

Pemeriksaan kebijakan SecurityShield yang dikonfigurasi server (`get_feature_access_new`), dipisah
dari NexilisLite agar bisa dirilis sendiri lewat CocoaPods dan SPM.

## Urutan

```
APIS.connect
 ├ 1. NexilisZTA      SentinelSecurityGate.authorize   RASP, App Attest, key delivery, token
 ├ 2. SecurityShield  SecurityShield.run                kebijakan institusi (lanjut / keluar)
 └ 3. NexilisLite     Nexilis.connect                   sesi messaging
```

`Nexilis.connect` menolak bila `SentinelSecurityGate.isAuthorized` atau `SecurityShield.hasPassed`
belum terpenuhi, jadi host yang memanggilnya langsung tidak bisa melompati langkah 1 atau 2.

## API

| Simbol | Guna |
|---|---|
| `SecurityShield.run(appName:apiKey:completion:)` | jalankan rantai sekali per peluncuran; `completion(true)` di main thread |
| `SecurityShield.hasPassed` | rantai sudah lolos pada peluncuran ini |
| `SecurityShield.setUserPin(_:)` | pin pengguna untuk laporan (dipanggil NexilisLite setelah terhubung) |
| `SecurityShield.flushPendingReports()` | kirim ulang laporan yang gagal terkirim (tanpa jaringan) |
| `SecurityShield.check(appName:apiKey:)` | *deprecated* — pembungkus `run` tanpa menunggu hasil |

## Pemeriksaan

emulator · jailbreak (+ mesin native NexilisZTA) · OS usang · aplikasi kloning · hook/Frida (+ native)
· debugger (+ native) · screen casting/recording · SIM swap · geovelocity · analisis perilaku.
Overlay, call forwarding, dan multiple login tidak dapat dideteksi dari sisi iOS dan selalu bersih.

Tanpa kebijakan tersimpan (peluncuran pertama tanpa jaringan): mode 3 tidak memeriksa apa pun,
mode 1 dan 2 menjalankan emulator/jailbreak/hook/debugger dengan aksi **keluar**.

## Distribusi

- CocoaPods: `pod 'NexilisSecurityShield', '~> 6.0.7'` (dependensi hanya `NexilisZTA ~> 6.0.7`)
- SPM: `https://github.com/alqindiirsyam-es/NexilisSecurityShield.git` from `6.0.7`

## Koneksi

Semua lewat HTTPS ke `<domain>` (default `https://nexilis.io/`), di-pin lewat NexilisZTA
(`RASPGuard` + `PinSetStore`); URL non-HTTPS ditolak. Tidak ada nuSDKService.

| Endpoint | Guna | Body |
|---|---|---|
| `POST get_feature_access_new` | kebijakan | `[{app_id, apikey, f_pin?}]` |
| `POST get_app_list` | cek kloning | `{api_key, app_id, app_name, team_id}` |
| `POST data_capture` | analisis perilaku | atribut perangkat |
| `POST security_shield_logging` | laporan deteksi (sama dengan jalur HTTPS SDK Android) | atribut perangkat + `security_shield` |
