# SOC False Alarm Reduction - Kelompok 5 MIKS ITS
Final Project SOC Genap 25/26

## Anggota Kelompok
| NRP | Nama |
|-----|------|
| 5027241075 | Muhammad Farrel Rafli Al Fasya |
| 5027241106 | Mohammad Abyan Ranuaji |
| 5027241025 | Christiano Ronaldo Silalahi |
| 5027221043 | George David Nebore |
| 5027231055 | Danar Bagus Rasendriya |

---

## 1. Detail Arsitektur yang Diimplementasikan

Sistem ini terdiri dari tiga node yang berjalan di Azure Free-Tier Student:

| Node | IP | Peran |
|------|----|-------|
| wazuh-manager | 10.0.0.4 | SIEM, rule engine, integrasi AI |
| agent-web | 10.0.0.6 | Web server, target DDoS, eksekusi SOAR untuk skenario DDoS |
| agent-db | 10.0.0.7 | Database server, skenario Malware dan Social Engineering, eksekusi SOAR untuk skenario Social Engineering |

Alur kerja sistem:
1. Wazuh Agent di setiap node mengumpulkan log dan mengirim ke Wazuh Manager
2. Wazuh Manager mencocokkan log dengan rules dan menghasilkan alert
3. Model AI (`ai_predict.py`) mengklasifikasikan setiap alert sebagai TRUE_POSITIVE atau FALSE_POSITIVE
4. Active-response (`ddos-block.py`) dieksekusi secara **per-skenario, bukan global**:
   - Rule 100501 (DDoS) → dieksekusi di agent-web (host target)
   - Rule 100700/100701 (Social Engineering — SSH brute force & privilege escalation) → dieksekusi secara lokal di agent yang menghasilkan alert (agent-db)
   - Setiap keputusan dicatat ke `soar_audit.jsonl` di host yang menjalankan respons tersebut

---

## 2. Diagram Arsitektur

> <img width="1003" height="512" alt="image" src="https://github.com/user-attachments/assets/1b54a109-7537-4dbb-9e4c-e481c821dbb5" />

Alur kerja:
1. Attacker melancarkan serangan ke agent-web (DDoS) atau agent-db (Malware/Social Engineering)
2. Wazuh Agent di setiap node mengumpulkan log dan mengirim alert ke Wazuh Manager
3. AI Model (Random Forest) mengklasifikasikan setiap alert sebagai TRUE_POSITIVE atau FALSE_POSITIVE
4. Jika TRUE_POSITIVE DDoS terdeteksi, SOAR layer di agent-web memblokir IP penyerang via iptables
5. Jika TRUE_POSITIVE Social Engineering (SSH brute force) terdeteksi, SOAR layer di agent-db memblokir IP penyerang secara lokal
6. Setiap keputusan SOAR dicatat ke `soar_audit.jsonl` pada host yang mengeksekusi respons, sebagai audit trail terstruktur

---

## 3. Skenario Serangan

### 3.1 DDoS
Simulasi HTTP flood menggunakan ApacheBench dari laptop/WSL ke target agent-web:

```bash
ab -n 1000 -c 50 http://20.244.51.91/wp-login.php
```

> <img width="591" height="264" alt="Screenshot_3" src="https://github.com/user-attachments/assets/38a80de7-902a-4287-af9c-031270ebed32" />

> <img width="850" height="87" alt="Screenshot_4" src="https://github.com/user-attachments/assets/a1d746f3-8311-49f3-bbfa-8a1c1f17fb94" />

Alert rule 100501 di `alerts.json` pada wazuh-manager, menunjukkan level 15, groups `["local","syslog","ddos","attack","active_response"]`, dan `full_log` berisi `DDOS_DETECTED SRC_IP=... REQUESTS=...`. Jalankan:
> ```bash
> sudo tail -10 /var/ossec/logs/alerts/alerts.json | grep '"id":"100501"'
> ```
> **VM: wazuh-manager**

> <img width="1260" height="383" alt="image" src="https://github.com/user-attachments/assets/72127ea3-6c2b-4b7a-a72e-a4b14622af19" />

Audit trail SOAR di agent-web menunjukkan `enforcement: iptables_INPUT+FORWARD_DROP` dengan `rule_id: 100501`. Jalankan:
> ```bash
> sudo tail -5 /var/ossec/logs/soar_audit.jsonl
> ```
> **VM: agent-web**

> <img width="758" height="95" alt="image" src="https://github.com/user-attachments/assets/b00e1b3c-bc5f-45b0-9b2c-54cd13f6aa78" />

Konfirmasi iptables aktif memblokir IP penyerang di agent-web. Jalankan:
> ```bash
> sudo iptables -L INPUT -n --line-numbers
> ```
> **VM: agent-web**

> <img width="317" height="55" alt="Screenshot_2" src="https://github.com/user-attachments/assets/23840039-38fc-44e5-b06d-5e2415b4aaae" />

Konfirmasi agent-db TIDAK terpengaruh oleh blokir DDoS (membuktikan scoping per-agent berfungsi). Jalankan:
> ```bash
> sudo iptables -L INPUT -n
> ```
> **VM: agent-db**

### 3.2 Malware
Simulasi dropper malware, C2 download, dan eksekusi payload di agent-db:

```bash
sudo /usr/local/bin/simulate-malware.sh
```
**VM: agent-db**

> <img width="373" height="52" alt="Screenshot_6" src="https://github.com/user-attachments/assets/691aaa9a-430d-49a2-8296-751891bbfe09" />

Output terminal simulasi malware di agent-db.

> <img width="846" height="226" alt="Screenshot_7" src="https://github.com/user-attachments/assets/a9520d7d-fbd5-4485-b63a-b8419d9a1cff" />

Alert malware terdeteksi di Wazuh Manager (rule 100601, level 14, groups `["local","syslog","malware","attack"]`). Jalankan:
> ```bash
> sudo tail -10 /var/ossec/logs/alerts/alerts.json | grep '"id":"100601"'
> ```
> **VM: wazuh-manager**

### 3.3 Social Engineering
Simulasi SSH brute force, privilege escalation, dan eksfiltrasi data di agent-db:

```bash
sudo /usr/local/bin/simulate-soceng.sh
```
**VM: agent-db**

> <img width="366" height="49" alt="Screenshot_8" src="https://github.com/user-attachments/assets/20342c61-9f23-4bf4-b6f9-547aaf61ff3b" />

Output terminal simulasi social engineering di agent-db.

> <img width="846" height="326" alt="Screenshot_9" src="https://github.com/user-attachments/assets/7f114e08-da8d-4d9c-aa3b-47f03ec13aa4" />

Alert social engineering terdeteksi di Wazuh Manager — rule 100700 (SSH failed login), 100701 (privilege escalation), dan 100702 (phishing payload), semua dengan groups `["local","syslog","social_engineering","attack"]`. Jalankan:
> ```bash
> sudo tail -20 /var/ossec/logs/alerts/alerts.json | grep -E '"id":"(100700|100701|100702)"'
> ```
> **VM: wazuh-manager**

> <img width="1401" height="428" alt="image" src="https://github.com/user-attachments/assets/5dc9d5ec-42cc-44f2-9ab6-03c435284f98" />

Audit trail SOAR di agent-db menunjukkan blokir IP `203.0.113.x` (rule 100700). Jalankan:
> ```bash
> sudo tail -10 /var/ossec/logs/soar_audit.jsonl
> ```
> **VM: agent-db**

> <img width="631" height="154" alt="image" src="https://github.com/user-attachments/assets/51f1e66f-96ff-4d4a-8daa-f756780d592f" />

Konfirmasi iptables aktif memblokir IP di agent-db. Jalankan:
> ```bash
> sudo iptables -L INPUT -n --line-numbers
> ```
> **VM: agent-db**

> **Keterbatasan SOAR untuk Social Engineering:** Rule 100701 (privilege escalation via sudo) bersifat alert-only — log sudo tidak memiliki field source IP sehingga tidak ada target jaringan untuk diblokir. Rule 100702 (eksfiltrasi data) juga bersifat alert-only pada iterasi ini — implementasi `ddos-block.py` saat ini hanya mendukung blokir berdasarkan source IP (`-s`).

---

## 4. Penjelasan AI yang Digunakan

### Algoritma
Sistem menggunakan dua model:
- **Random Forest Classifier** : model utama untuk klasifikasi supervised
- **Isolation Forest** : baseline unsupervised untuk deteksi anomali

### Proses Training
- Data : 16.182 alert dari log Wazuh nyata di Azure (akumulasi dari seluruh skenario pengujian)
- Label : dihasilkan otomatis oleh fungsi heuristik `auto_label()` berdasarkan rule_id, firedtimes, decoder, groups, dan IP class
- Fitur : 14 sinyal behavioral (rule_id dikecualikan untuk mencegah label leakage)
- Label noise : 10% diinjeksikan saat training untuk mensimulasikan ketidakpastian anotasi
- max_depth : 8 untuk membatasi memorisasi

### Kriteria False Alarm
- FP Rule ID : 510, 503, 502, 5402, 5501, 5502, 31108
- Level < 5 dari source IP internal = FP
- firedtimes > 50 = FP (recurring benign noise)
- Decoder rootcheck dan ossec = FP secara default

### Integrasi dengan Wazuh
Model disimpan sebagai file `.pkl` dan dipanggil oleh `ai_predict.py` setiap kali ada alert masuk. Output berupa label TRUE_POSITIVE atau FALSE_POSITIVE beserta confidence score. Seluruh custom rule (100500–100702) telah diberi `<group>` tag yang sesuai (`ddos`/`malware`/`social_engineering`, `attack`) agar fitur `has_attack` dan `has_active_response` pada model AI benar-benar terisi — pada versi sebelumnya, rule custom hanya memiliki group `local,syslog` sehingga fitur tersebut selalu bernilai 0 untuk seluruh skenario serangan.

> <img width="257" height="202" alt="Screenshot_14" src="https://github.com/user-attachments/assets/61aab8d6-5376-4f73-a22e-cf9dc9dc8bdb" />

Output training pipeline `ai_false_alarm.py` di terminal.

> <img width="841" height="254" alt="Screenshot_2" src="https://github.com/user-attachments/assets/ca9c3d4d-18d0-4d48-bab8-fc28977e62e7" />

Uji klasifikasi AI pada alert nyata menggunakan `ai_predict.py`:
> ```bash
> sudo tail -n 15 /var/ossec/logs/alerts/alerts.json | sudo python3 /var/ossec/etc/ai_predict.py
> ```
> **VM: wazuh-manager**

---

## 5. Benchmark Metrik

### Random Forest - Test Set (20%)
| Metrik | Nilai |
|--------|-------|
| Precision | 0.9992 |
| Recall | 0.9655 |
| F1-Score | 0.9821 |
| ROC-AUC | 0.9949 |
| CV F1 (5-fold) | 0.9834 +/- 0.0020 |

### Isolation Forest - Baseline Unsupervised
| Metrik | Nilai |
|--------|-------|
| Precision | 0.8646 |
| Recall | 0.7332 |
| F1-Score | 0.7935 |

> <img width="267" height="394" alt="Screenshot_15" src="https://github.com/user-attachments/assets/3efaefca-843e-4baf-be8b-d05576ba8b67" />

Laporan evaluasi lengkap (`ai_model_report.txt`):
> ```bash
> sudo cat /var/ossec/logs/ai_model_report.txt
> ```
> **VM: wazuh-manager**

---

## 6. Analisis Hasil

### Reduksi False Alarm
Dari 16.182 alert yang diproses, 13.494 (83.4%) diklasifikasikan sebagai False Positive. Tanpa AI, seluruh alert ini akan masuk ke antrean analis SOC. Dengan model Random Forest, sistem mampu memfilter FP dengan precision 0.9992, artinya hampir tidak ada True Positive yang salah dibuang.

### Deteksi Ancaman
Recall 0.9655 berarti sistem berhasil mendeteksi 96.55% ancaman nyata pada held-out test set.

### Keterbatasan
Label dihasilkan secara otomatis oleh heuristik, bukan oleh analis manusia. Metrik harus diinterpretasikan sebagai upper bound, bukan ground truth independen. Evaluasi lebih akurat membutuhkan dataset berlabel manual.

### SOAR Response
Sistem terbukti merespons serangan DDoS dan Social Engineering (SSH brute force) secara otomatis dalam hitungan detik, dengan eksekusi yang di-scope ke agent yang relevan untuk masing-masing skenario. IP penyerang diblokir via iptables dan setiap keputusan dicatat dalam audit trail JSON terstruktur (`soar_audit.jsonl`) pada host yang mengeksekusi respons.

### Validitas Pengujian DDoS
Pengujian DDoS menggunakan ApacheBench (`ab -n 1000 -c 50`) dari satu sumber (single-source HTTP flood), bukan simulasi botnet terdistribusi. Hasil pengujian membuktikan deteksi dan respons berfungsi untuk pola volumetric flood dari satu IP, namun tidak merepresentasikan skenario DDoS terdistribusi dengan banyak sumber IP secara simultan.

---

## Struktur File
| File | Lokasi | Deskripsi |
|------|--------|-----------|
| `ai_false_alarm.py` | wazuh-manager | Pipeline training model AI |
| `ai_predict.py` | wazuh-manager | Inferensi AI per alert |
| `ai_model_report.txt` | wazuh-manager | Laporan evaluasi dengan metrik |
| `ddos-block.py` | agent-web **dan** agent-db | SOAR active response + audit logging (di-deploy di kedua agent untuk mendukung scoping per-skenario) |
| `ddos-detect.sh` | agent-web | Skrip deteksi DDoS |
| `local_rules.xml` | wazuh-manager | Custom detection rules |
| `local_decoder.xml` | wazuh-manager | Custom log decoder |
| `simulate-malware.sh` | agent-db | Simulasi skenario Malware |
| `simulate-soceng.sh` | agent-db | Simulasi skenario Social Engineering |
| `ossec_manager.conf` | wazuh-manager | Konfigurasi `ossec.conf`, termasuk binding active-response per-skenario |

## Cara Menjalankan

### Training Model AI (di wazuh-manager)
```bash
sudo python3 /var/ossec/etc/ai_false_alarm.py
```

### Uji Prediksi AI
```bash
sudo tail -n 15 /var/ossec/logs/alerts/alerts.json | sudo python3 /var/ossec/etc/ai_predict.py
```

### Simulasi DDoS (dari WSL/laptop)
```bash
ab -n 1000 -c 50 http://20.244.51.91/wp-login.php
```

### Simulasi Malware (di agent-db)
```bash
sudo /usr/local/bin/simulate-malware.sh
```

### Simulasi Social Engineering (di agent-db)
```bash
sudo /usr/local/bin/simulate-soceng.sh
```

### Monitor SOAR
```bash
sudo tail -f /var/ossec/logs/soar_audit.jsonl
```
**VM: agent-web (skenario DDoS) atau agent-db (skenario Social Engineering)**
