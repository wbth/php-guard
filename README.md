# PHP Guard

[![CI](https://github.com/wbth/php-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/wbth/php-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Skrip Python tunggal untuk audit kerentanan PHP di server Linux. Diunduh ke folder mana
saja di server lalu dijalankan lokal sebagai root. Tidak butuh instalasi, SSH, dashboard,
atau koneksi keluar, dan tidak ada dependensi di luar standard library.

Gunakan hanya pada server yang Anda kelola.

## Target

- CVE-2026-109618 dan CVE-2026-109619 ("PHP2Shell", unauthenticated RCE), diperbaiki
  di PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. PHP 8.1 ke bawah tidak dapat rilis resmi,
  jadi perlu backport distro atau upgrade.
- CVE-2026-115560: belum ada patch. Mitigasinya `session.upload_progress.enabled = 0`.

## Kebutuhan

Linux dengan Python 3.6+, tanpa modul tambahan. Mengenali paket PHP dari apt/dpkg,
dnf/yum, zypper, dan apk, panel cPanel/CloudLinux, mod_php, PHP-FPM, LiteSpeed,
FrankenPHP, serta PHP di dalam container. Windows tidak dicakup.

## Unduh

Tidak perlu folder khusus. Unduh ke folder aktif, misalnya home directory:

```bash
git clone https://github.com/wbth/php-guard.git
cd php-guard
```

Atau tanpa git, langsung ke folder aktif:

```bash
curl -fsSLO https://raw.githubusercontent.com/wbth/php-guard/master/php_guard.py
curl -fsSLO https://raw.githubusercontent.com/wbth/php-guard/master/php_guard.sh
```

Pengunduhan tidak butuh root; hanya menjalankan skrip yang perlu `sudo`. Pastikan
`php_guard.py` dan `php_guard.sh` berada di folder yang sama. Server tanpa akses
internet: unduh di mesin lain lalu salin via scp atau USB.

## Pemakaian

Jalankan dari folder tempat skrip diunduh:

```bash
sudo python3 php_guard.py scan                  # audit read-only, tulis laporan JSON
sudo python3 php_guard.py mitigate [--restart]  # set session.upload_progress.enabled=0
sudo python3 php_guard.py fix [--restart]       # upgrade paket PHP dari repo distro
sudo python3 php_guard.py restart               # restart php-fpm / apache / litespeed
```

Laporan JSON (`php_guard_<host>_<waktu>.json`) ditulis ke folder aktif, atau ke path
yang diberikan lewat `--out`. File laporan dibuat dengan izin 600 dan, bila dijalankan
lewat `sudo`, dimiliki user yang memanggilnya.

Kalau Python belum ada, jalankan lewat `php_guard.sh`. Ia mencari interpreter yang
cocok, dan bila tidak ada, menawarkan memasangnya setelah konfirmasi (butuh root):

```bash
sudo sh php_guard.sh scan
```

## Yang diperiksa `scan`

- Versi PHP tiap SAPI (cli, fpm, apache, lsphp, frankenphp, container) dan modul aktif.
- Verdict per instalasi, cakupan PHP 7.0 sampai terbaru: PATCHED, VULNERABLE,
  EOL_UNSUPPORTED, PATCHED_BACKPORT, UNVERIFIED, RESTART_REQUIRED. Backport distro
  dikonfirmasi dari changelog paket, bukan hanya nomor versi.
- Status kerentanan dan status kompromi dilaporkan terpisah. PATCHED tidak berarti
  host bersih dari backdoor.
- Instalasi rentan atau EOL yang masih punya worker PHP aktif ditandai lebih dulu.
- Health check lewat loopback: liveness socket PHP-FPM dan HEAD ke 127.0.0.1. Saat
  fix atau restart, kondisi sebelum dan sesudah dibandingkan; bila menurun, exit 2
  dan disarankan rollback.
- Framework dan CMS di web root umum (WordPress, Joomla, Drupal, Laravel, Symfony,
  dan lainnya) beserta versi dan status OK/OUTDATED/EOL.
- Inventaris plugin dan tema WordPress, ekstensi Joomla, serta modul dan tema Drupal
  non-core (nama dan versi). Tidak dicocokkan dengan database kerentanan; laporan
  menyarankan perintah pengeceknya (`wp plugin list`, `wpscan`, `drush pm:security`,
  `composer audit`) untuk tiap situs yang terdeteksi.
- Tanda kompromi: cron, systemd, dan authorized_keys mencurigakan, pola webshell,
  log HTTP dan auth. Baris log hanya disimpan sebagai hash, bukan isi mentah, supaya
  tidak membocorkan data. Indikator HIGH menahan `fix` dan membuat exit 2.

Sebagian opsi: `--since YYYY-MM-DD`, `--max-files N`, `--webroot DIR` (boleh diulang),
`--no-ioc`, `--no-compromise`, `--verify-packages`, `--strict-backport`,
`--out laporan.json`, `--quiet`.

## Basis data CVE (opsional)

Untuk detail CVE per versi, tarik datanya di mesin operator yang online:

```bash
python3 php_guard.py cve-update    # buat php_guard_cve.json di folder aktif
```

Salin `php_guard_cve.json` ke folder yang sama dengan `php_guard.py` di tiap server.
`scan` mencarinya di sebelah skrip, lalu di folder aktif, dan membacanya secara offline.
Tanpa file ini scan tetap jalan berdasarkan versi dan tanggal EOL. `scan` sendiri tidak
pernah menarik data dari internet.

## Uji mandiri

```bash
python3 php_guard.py selftest    # cek logika inti, tidak menyentuh sistem
```

## Exit code

`0` aman, `1` perlu tindakan (termasuk framework/CMS yang EOL atau OUTDATED), `2` indikator
kompromi HIGH, `3` error.

## Lisensi

[MIT](LICENSE) (c) 2026 wbth. Perangkat lunak disediakan apa adanya, tanpa jaminan.
