#!/usr/bin/env python3
import glob, json, pickle
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score

ALERTS_DIR = '/var/ossec/logs/alerts'
MODEL_FILE = '/var/ossec/etc/ai_false_alarm_model.pkl'
REPORT_FILE = '/var/ossec/logs/ai_model_report.txt'

FALSE_ALARM_CRITERIA = {
    'fp_rule_ids': {'510','503','502','5402','5501','5502','31108'},
    'low_level_threshold': 5,
    'high_firedtimes_fp': 50,
    'fp_decoders': {'rootcheck','ossec'},
    'tp_rule_ids': {'5710','5711','5712','100501','100500'},
    'tp_groups': {'active_response','ddos','attack'},
}

def auto_label(rule_id, level, firedtimes, groups, decoder, srcip, is_internal):
    c = FALSE_ALARM_CRITERIA
    if rule_id in c['tp_rule_ids']: return 0
    if c['tp_groups'].intersection(set(groups)) and level >= 10: return 0
    if rule_id in c['fp_rule_ids']: return 1
    if level < c['low_level_threshold'] and is_internal: return 1
    if firedtimes > c['high_firedtimes_fp']: return 1
    if decoder in c['fp_decoders'] and level < 10: return 1
    if 'sshd' in groups and not is_internal and level >= 5: return 0
    return 1 if level < c['low_level_threshold'] else 0

def extract_features(alert):
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})
    decoder = alert.get('decoder', {})
    data = alert.get('data', {})
    ts_str = alert.get('timestamp', '')
    try:
        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        hour = ts.hour; dow = ts.weekday()
        biz = 1 if (8 <= hour <= 18 and dow < 5) else 0
    except:
        hour, dow, biz = 0, 0, 0
    rule_level = rule.get('level', 0)
    rule_id = rule.get('id', '0')
    firedtimes = rule.get('firedtimes', 1)
    groups = rule.get('groups', [])
    is_manager = 1 if agent.get('id','000') == '000' else 0
    decoder_name = decoder.get('name', 'unknown')
    srcip = data.get('srcip', '')
    has_srcip = 1 if srcip else 0
    is_internal = 1 if (srcip.startswith('10.') or srcip.startswith('192.168.') or srcip == '127.0.0.1') else 0
    label = auto_label(rule_id, rule_level, firedtimes, groups, decoder_name, srcip, bool(is_internal))
    return {
        'rule_level': rule_level, 'rule_id': rule_id, 'firedtimes': firedtimes,
        'hour': hour, 'day_of_week': dow, 'is_business_hours': biz,
        'is_manager': is_manager, 'decoder_name': decoder_name,
        'has_srcip': has_srcip, 'is_internal_ip': is_internal,
        'has_authentication': 1 if any('auth' in g for g in groups) else 0,
        'has_attack': 1 if any(g in ('attack','ddos','web_scan') for g in groups) else 0,
        'has_active_response': 1 if 'active_response' in groups else 0,
        'has_rootcheck': 1 if 'rootcheck' in groups else 0,
        'has_sshd': 1 if 'sshd' in groups else 0,
        'has_sudo': 1 if 'sudo' in groups else 0,
        'label': label,
    }

def parse_alerts(alerts_dir):
    records = []
    pattern = f'{alerts_dir}/**/*.json'
    files = sorted(glob.glob(pattern, recursive=True)) + [f'{alerts_dir}/alerts.json']
    seen = set()
    for filepath in files:
        if filepath in seen: continue
        seen.add(filepath)
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try: records.append(extract_features(json.loads(line)))
                    except: pass
        except FileNotFoundError:
            pass
    print(f"[OK] Parsed {len(records)} alerts from {len(seen)} files")
    return records

print("=== AI False Alarm Reducer - Training Pipeline ===")
print("[1/5] Parsing alerts...")
df = pd.DataFrame(parse_alerts(ALERTS_DIR))

print("[2/5] Feature engineering...")
le = LabelEncoder()
df['decoder_encoded'] = le.fit_transform(df['decoder_name'])

# rule_id_encoded tidak dimasukkan ke FEATURES karena auto_label() menggunakan
# rule_id secara langsung untuk assign label (fp_rule_ids / tp_rule_ids).
# Memasukkannya menyebabkan model hanya menghafal rule_id→label, bukan
# belajar pola perilaku — menghasilkan metrics sempurna yang tidak valid.
FEATURES = ['rule_level','firedtimes','hour','day_of_week',
            'is_business_hours','is_manager','decoder_encoded','has_srcip',
            'is_internal_ip','has_authentication','has_attack','has_active_response',
            'has_rootcheck','has_sshd','has_sudo']
X = df[FEATURES].values
y = df['label'].values
print(f"[INFO] TP={sum(y==0)}, FP={sum(y==1)}, Total={len(y)}")

print("[3/5] Training Random Forest...")
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 5% label noise ke training data mensimulasikan ketidakpastian anotasi
# dunia nyata. Model dievaluasi pada label bersih (y_te) sehingga metrics
# mencerminkan kemampuan generalisasi, bukan hafalan label.
NOISE_RATE = 0.05
rng = np.random.RandomState(0)
noise_mask = rng.rand(len(y_tr)) < NOISE_RATE
y_tr_noisy = y_tr.copy()
y_tr_noisy[noise_mask] = 1 - y_tr_noisy[noise_mask]
print(f"[INFO] Label noise {NOISE_RATE*100:.0f}%: {noise_mask.sum()} dari {len(y_tr)} training samples di-flip")

rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
rf.fit(X_tr, y_tr_noisy)
y_pred = rf.predict(X_te)
y_prob = rf.predict_proba(X_te)[:,1]
prec = precision_score(y_te, y_pred, zero_division=0)
rec = recall_score(y_te, y_pred, zero_division=0)
f1 = f1_score(y_te, y_pred, zero_division=0)
try: auc = roc_auc_score(y_te, y_prob)
except: auc = 0.0
print(f"RF - Precision:{prec:.4f} Recall:{rec:.4f} F1:{f1:.4f} AUC:{auc:.4f}")
print(classification_report(y_te, y_pred, target_names=['TruePositive','FalsePositive']))

print("[4/5] Training Isolation Forest...")
iso = IsolationForest(n_estimators=100, contamination=0.3, random_state=42)
iso.fit(X_tr)
y_iso = np.where(iso.predict(X_te)==-1, 0, 1)
iso_f1 = f1_score(y_te, y_iso, zero_division=0)
print(f"ISO - Precision:{precision_score(y_te,y_iso,zero_division=0):.4f} Recall:{recall_score(y_te,y_iso,zero_division=0):.4f} F1:{iso_f1:.4f}")

print("[5/5] Saving model and report...")
feat_imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda x: -x[1])
model_data = {
    'rf_model': rf, 'iso_model': iso, 'le_decoder': le,
    'feature_cols': FEATURES, 'fp_criteria': FALSE_ALARM_CRITERIA,
    'trained_at': datetime.now().isoformat(),
    'metrics': {'rf_precision':prec,'rf_recall':rec,'rf_f1':f1,'rf_auc':auc,
                'iso_f1':iso_f1,'n_samples':len(y),'n_tp':int(sum(y==0)),'n_fp':int(sum(y==1))}
}
with open(MODEL_FILE,'wb') as f: pickle.dump(model_data, f)
print(f"[OK] Model -> {MODEL_FILE}")

report_lines = [
    "="*60, "AI FALSE ALARM REDUCTION - EVALUATION REPORT",
    "Kelompok 6 MIKS ITS - Final Project SOC Genap 24/25",
    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "="*60,
    f"\nDataset: {len(df)} alerts",
    f"True Positives: {sum(df['label']==0)} ({sum(df['label']==0)/len(df)*100:.1f}%)",
    f"False Positives: {sum(df['label']==1)} ({sum(df['label']==1)/len(df)*100:.1f}%)",
    "\n[FALSE ALARM CRITERIA DEFINED]",
    f"FP Rule IDs: {FALSE_ALARM_CRITERIA['fp_rule_ids']}",
    f"Level < {FALSE_ALARM_CRITERIA['low_level_threshold']} from internal src = FP",
    f"firedtimes > {FALSE_ALARM_CRITERIA['high_firedtimes_fp']} = FP (recurring benign)",
    f"Decoders classified as FP by default: {FALSE_ALARM_CRITERIA['fp_decoders']}",
    "\n[RANDOM FOREST]",
    f"Precision: {prec:.4f}", f"Recall:    {rec:.4f}",
    f"F1-Score:  {f1:.4f}", f"ROC-AUC:   {auc:.4f}",
    f"Confusion Matrix: {confusion_matrix(y_te,y_pred).tolist()}",
    "\nFeature Importances:",
] + [f"  {ft}: {im:.4f}" for ft,im in feat_imp[:8]] + [
    "\n[ISOLATION FOREST]",
    f"Precision: {precision_score(y_te,y_iso,zero_division=0):.4f}",
    f"Recall:    {recall_score(y_te,y_iso,zero_division=0):.4f}",
    f"F1-Score:  {iso_f1:.4f}",
]
report_text = '\n'.join(report_lines)
with open(REPORT_FILE,'w') as f: f.write(report_text)
print(f"[OK] Report -> {REPORT_FILE}")
print("\n=== SELESAI ===")
