# SOC False Alarm Reduction - Kelompok 6 MIKS ITS
Final Project SOC Genap 24/25

## Arsitektur
- Wazuh Manager + Wazuh Agent di Azure Free-Tier Student
- SOAR: auto-block IP via iptables (ddos-block.py)
- AI Model: Random Forest + Isolation Forest untuk reduce false alarm

## File Structure
- `ai_false_alarm.py` - Training pipeline AI model
- `ai_predict.py` - Deployment script (real-time prediction)
- `ddos-block.py` - SOAR active response script (di agent-web)
- `ddos-detect.sh` - DDoS detection script (di agent-web)
- `local_rules.xml` - Custom Wazuh rules
- `local_decoder.xml` - Custom Wazuh decoder
- `ai_model_report.txt` - Evaluation report

## AI Model Results
- Random Forest: Precision=1.0, Recall=1.0, F1=1.0, AUC=1.0
- Isolation Forest: Precision=1.0, Recall=0.72, F1=0.84
- Dataset: 7169 alerts (364 TP, 6805 FP)

## False Alarm Criteria
- Rule IDs: 510, 503, 502, 5402, 5501, 5502, 31108
- Level < 5 dari source internal = FP
- firedtimes > 50 = FP (recurring benign noise)
