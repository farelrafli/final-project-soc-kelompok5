# SOC False Alarm Reduction - Kelompok 5 MIKS ITS
Final Project SOC Genap 25/26

## Anggota Kelompok

| NRP | Nama |
|-----|------|
| 5027241075 | Muhammad Farrel Rafli Al Fasya |
| 5027241106 | Mohammad Abyan Ranuaji |
| 5027241025 | Christiano Ronaldo Silalahi |
| 5027221043 | GEORGE DAVID NEBORE |
| 5027231055 | DANAR BAGUS RASENDRIYA |

---

## Arsitektur
- Wazuh Manager + Wazuh Agent di Azure Free-Tier Student
- SOAR: auto-block IP via iptables (ddos-block.py)

## File Structure
- `ai_false_alarm.py` - Training pipeline AI model
- `ddos-block.py` - SOAR active response script (di agent-web)
- `ddos-detect.sh` - DDoS detection script (di agent-web)
- `local_rules.xml` - Custom Wazuh rules
- `local_decoder.xml` - Custom Wazuh decoder

## False Alarm Criteria
- Rule IDs: 510, 503, 502, 5402, 5501, 5502, 31108
- Level < 5 dari source internal = FP
- firedtimes > 50 = FP (recurring benign noise)
