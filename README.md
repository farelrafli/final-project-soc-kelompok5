# SOC False Alarm Reduction - Kelompok 5 MIKS ITS
Final Project SOC Genap 24/25

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
| agent-web | 10.0.0.6 | Web server, target DDoS, eksekusi SOAR |
| agent-db | 10.0.0.7 | Database server, skenario Malware dan Social Engineering |

Alur kerja sistem:
1. Wazuh Agent di setiap node mengumpulkan log dan mengirim ke Wazuh Manager
2. Wazuh Manager mencocokkan log dengan rules dan menghasilkan alert
3. Model AI (ai_predict.py) mengklasifikasikan setiap alert sebagai TRUE_POSITIVE atau FALSE_POSITIVE
4. Jika alert adalah TRUE_POSITIVE DDoS, SOAR (ddos-block.py) otomatis memblokir IP penyerang via iptables dan mencatat audit trail ke soar_audit.jsonl

---

## 2. Diagram Arsitektur

<img width="986" height="587" alt="image" src="https://github.com/user-attachments/assets/a2fbbd70-ad8e-4161-9eba-b714c848c585" />

Alur kerja:
1. Attacker melancarkan serangan ke agent-web (DDoS) atau agent-db (Malware/Social Engineering)
2. Wazuh Agent di setiap node mengumpulkan log dan mengirim alert ke Wazuh Manager
3. AI Model (Random Forest) mengklasifikasikan setiap alert sebagai TRUE_POSITIVE atau FALSE_POSITIVE
4. Jika TRUE_POSITIVE DDoS terdeteksi, SOAR layer (ddos-block.py) memblokir IP penyerang via iptables
5. Setiap keputusan SOAR dicatat ke soar_audit.jsonl sebagai audit trail terstruktur

---

## 3. Skenario Serangan

### 3.1 DDoS
Simulasi HTTP flood menggunakan ApacheBench dari agent-web ke target:

```bash
ab -n 1000 -c 50 http://20.244.51.91/wp-login.php
```

<img width="413" height="415" alt="Screenshot_4" src="https://github.com/user-attachments/assets/6c6e2f2d-040e-4bbc-8a28-8f25caf64195" />

SOAR otomatis mendeteksi dan memblokir IP penyerang. Audit trail tercatat di soar_audit.jsonl:

<img width="853" height="424" alt="Screenshot_5" src="https://github.com/user-attachments/assets/16dada41-8878-43d5-a7f3-f9f0d1036936" />

Konfirmasi iptables aktif memblokir IP:

<img width="369" height="50" alt="Screenshot_7" src="https://github.com/user-attachments/assets/52cfbf32-3dde-49c7-8c7d-7367b2a3d4b8" />

### 3.2 Malware
Simulasi dropper malware, C2 download, dan eksekusi payload di agent-db:

```bash
sudo /usr/local/bin/simulate-malware.sh
```

<img width="860" height="89" alt="image" src="https://github.com/user-attachments/assets/c3e4f9e8-ad99-4656-a565-b533a300159a" />

Alert malware terdeteksi di Wazuh Manager (rule 100601, level 14):

<img width="851" height="335" alt="Screenshot_8" src="https://github.com/user-attachments/assets/6fdb2a77-b62a-47c9-850c-6e59b1f59663" />

### 3.3 Social Engineering
Simulasi credential harvesting dan eksfiltrasi data di agent-db:

```bash
sudo /usr/local/bin/simulate-soceng.sh
```

<img width="849" height="83" alt="image" src="https://github.com/user-attachments/assets/53d7414c-f07c-429c-90fc-1ca548d588df" />

Alert social engineering terdeteksi di Wazuh Manager (rule 100702, level 14):

<img width="848" height="137" alt="Screenshot_9" src="https://github.com/user-attachments/assets/304d8007-7a02-4053-b014-b08a0bd038d2" />

---

## 4. Penjelasan AI yang Digunakan

### Algoritma
Sistem menggunakan dua model:
- **Random Forest Classifier** : model utama untuk klasifikasi supervised
- **Isolation Forest** : baseline unsupervised untuk deteksi anomali

### Proses Training
- Data : 11.390 alert dari log Wazuh nyata di Azure
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
Model disimpan sebagai file `.pkl` dan dipanggil oleh `ai_predict.py` setiap kali ada alert masuk. Output berupa label TRUE_POSITIVE atau FALSE_POSITIVE beserta confidence score.

Output training pipeline:

<img width="522" height="397" alt="Screenshot_1" src="https://github.com/user-attachments/assets/310aacfb-52a5-4aa0-90dc-a9e5ea92554c" />

Uji klasifikasi AI pada alert nyata:

<img width="841" height="254" alt="Screenshot_2" src="https://github.com/user-attachments/assets/41b17d4c-79a8-4d5e-9296-b30da7bc8265" />

Uji manual TRUE_POSITIVE dan FALSE_POSITIVE:

<img width="849" height="141" alt="Screenshot_3" src="https://github.com/user-attachments/assets/a3a88e9e-558b-4f72-abf8-b37797e31965" />

---

## 5. Benchmark Metrik

### Random Forest - Test Set (20%)
| Metrik | Nilai |
|--------|-------|
| Precision | 0.9984 |
| Recall | 0.9543 |
| F1-Score | 0.9759 |
| ROC-AUC | 0.9936 |
| CV F1 (5-fold) | 0.9831 +/- 0.0023 |

### Isolation Forest - Baseline Unsupervised
| Metrik | Nilai |
|--------|-------|
| Precision | 0.9708 |
| Recall | 0.7845 |
| F1-Score | 0.8678 |

Laporan evaluasi lengkap:

<img width="420" height="427" alt="Screenshot_6" src="https://github.com/user-attachments/assets/39322b22-6b37-4687-9cd3-227bf7272d83" />

---

## 6. Analisis Hasil

### Reduksi False Alarm
Dari 11.390 alert yang diproses, 9.955 (87.4%) diklasifikasikan sebagai False Positive. Tanpa AI, seluruh alert ini akan masuk ke antrean analis SOC. Dengan model Random Forest, sistem mampu memfilter FP dengan precision 0.9984, artinya hampir tidak ada True Positive yang salah dibuang.

### Deteksi Ancaman
Recall 0.9543 berarti sistem berhasil mendeteksi 95.43% ancaman nyata. Ini memenuhi tujuan proyek yaitu mengurangi false alarm tanpa mengorbankan akurasi deteksi.

### Keterbatasan
Label dihasilkan secara otomatis oleh heuristik, bukan oleh analis manusia. Metrik harus diinterpretasikan sebagai upper bound, bukan ground truth independen. Evaluasi lebih akurat membutuhkan dataset berlabel manual.

### SOAR Response
Sistem terbukti merespons serangan DDoS secara otomatis dalam hitungan detik. IP penyerang diblokir via iptables dan setiap keputusan dicatat dalam audit trail JSON terstruktur (soar_audit.jsonl).

---

## Struktur File
| File | Lokasi | Deskripsi |
|------|--------|-----------|
| `ai_false_alarm.py` | Wazuh Manager | Pipeline training model AI |
| `ai_predict.py` | Wazuh Manager | Inferensi AI per alert |
| `ai_model_report.txt` | Wazuh Manager | Laporan evaluasi dengan metrik |
| `ddos-block.py` | agent-web | SOAR active response + audit logging |
| `ddos-detect.sh` | agent-web | Skrip deteksi DDoS |
| `local_rules.xml` | Wazuh Manager | Custom detection rules |
| `local_decoder.xml` | Wazuh Manager | Custom log decoder |
| `simulate-malware.sh` | agent-db | Simulasi skenario Malware |
| `simulate-soceng.sh` | agent-db | Simulasi skenario Social Engineering |

## Cara Menjalankan

### Training Model AI (di Wazuh Manager)
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

### Monitor SOAR (di agent-web)
```bash
sudo tail -f /var/ossec/logs/soar_audit.jsonl
```
