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

## Arsitektur
- **Wazuh Manager** (Azure, 10.0.0.4) : SIEM, rule engine, integrasi AI
- **agent-web** (Azure, 10.0.0.6) : Web server agent, target DDoS, eksekusi SOAR
- **agent-db** (Azure, 10.0.0.7) : Database agent, skenario Malware dan Social Engineering
- **SOAR** : Layer orkestrasi kustom (ddos-block.py) dengan audit trail JSON terstruktur

## Skenario Serangan
| Skenario | Agent | Rule ID | Level |
|----------|-------|---------|-------|
| DDoS | agent-web | 100501 | 15 |
| Malware | agent-db | 100601 | 14 |
| Social Engineering | agent-db | 100702 | 14 |

## Model AI
- **Algoritma** : Random Forest Classifier + Isolation Forest (baseline unsupervised)
- **Data training** : 11.326 alert dari log Wazuh
- **Label** : Dihasilkan secara otomatis menggunakan heuristik (rule_id, firedtimes, decoder, groups)
- **Fitur** : 14 sinyal behavioral (rule_id dikecualikan untuk mencegah label leakage)
- **Label noise** : 10% diinjeksikan saat training untuk mensimulasikan ketidakpastian anotasi dunia nyata

### Metrik Evaluasi (test set 20%)
| Metrik | Random Forest | Isolation Forest |
|--------|--------------|-----------------|
| Precision | 0.9984 | 0.9708 |
| Recall | 0.9543 | 0.7845 |
| F1-Score | 0.9759 | 0.8678 |
| ROC-AUC | 0.9943 | - |
| CV F1 (5-fold) | 0.9831 ± 0.0023 | - |

## Kriteria False Alarm
- FP Rule ID : 510, 503, 502, 5402, 5501, 5502, 31108
- Level < 5 dari source IP internal = FP
- firedtimes > 50 = FP (recurring benign noise)
- Decoder rootcheck dan ossec = FP secara default

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

---

## Cara Menjalankan

### 1. Training Model AI (di Wazuh Manager)
```bash
sudo python3 /var/ossec/etc/ai_false_alarm.py
```

### 2. Uji Prediksi AI
```bash
sudo tail -n 1 /var/ossec/logs/alerts/alerts.json | sudo python3 /var/ossec/etc/ai_predict.py
```

### 3. Simulasi Skenario DDoS (dari WSL/laptop)
Jalankan HTTP flood menggunakan ApacheBench ke agent-web:
```bash
ab -n 1000 -c 50 http://20.244.51.91/wp-login.php
```
SOAR akan otomatis mendeteksi dan memblokir IP penyerang via iptables.
Monitor respons SOAR secara real-time di agent-web:
```bash
sudo tail -f /var/ossec/logs/soar_audit.jsonl
```

### 4. Simulasi Skenario Malware (di agent-db)
```bash
sudo /usr/local/bin/simulate-malware.sh
```

### 5. Simulasi Skenario Social Engineering (di agent-db)
```bash
sudo /usr/local/bin/simulate-soceng.sh
```

### 6. Monitor Alert di Wazuh Manager
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "100[67]0[0-9]|malware|phishing"
```
