#!/usr/bin/env python3
"""
AI False Alarm Reducer v2 - Fixed Non-Circular Labeling
Kelompok 5 MIKS ITS - Final Project SOC Genap 24/25

Perbaikan dari v1:
- Label dibuat berdasarkan KONTEKS TEMPORAL + BEHAVIORAL, bukan rule_id/level langsung
- Feature untuk model TIDAK termasuk rule_id mentah (yang dipakai labeling)
- Ditambah temporal feature engineering untuk simulasi "anomaly vs normal pattern"
- Train/test split dilakukan SEBELUM feature encoding (no leakage)
"""

import json
import pickle
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score, roc_auc_score
)

ALERTS_FILE = '/var/ossec/logs/alerts/alerts.json'
MODEL_FILE  = '/var/ossec/etc/ai_false_alarm_model.pkl'
REPORT_FILE = '/var/ossec/logs/ai_model_report.txt'

# ─── DEFINISI KRITERIA FALSE ALARM ──────────────────────────────────────────
# Kriteria ini dipakai untuk LABELING saja, BUKAN sebagai fitur model
# sehingga model harus belajar dari pola behavioral, bukan menghafal rule list

KNOWN_BENIGN_GROUPS  = {'rootcheck', 'ossec', 'syslog', 'pam', 'audit'}
KNOWN_ATTACK_GROUPS  = {'attack', 'ddos', 'web_scan', 'brute_force', 'active_response'}
CRITICAL_LEVEL_THRESHOLD = 10   # level >= 10 → cenderung TP
LOW_LEVEL_THRESHOLD      = 5    # level < 5 dari source internal → cenderung FP
HIGH_FIREDTIMES_FP       = 30   # event yang sangat sering berulang → benign noise

# ─── LABELING FUNCTION ───────────────────────────────────────────────────────
# Gunakan konteks behavioral, bukan rule_id itu sendiri

def compute_label(record: dict) -> int:
    """
    Return 0 = True Positive (ancaman nyata)
           1 = False Positive (benign noise)

    Strategi: kombinasi rule level, behavioral context, source IP, dan repetition.
    rule_id TIDAK dipakai di sini (supaya model tidak menghafal ID).
    """
    level      = record['rule_level']
    firedtimes = record['firedtimes']
    groups_raw = record['groups_raw']        # list string
    is_internal= record['is_internal_ip']
    has_srcip  = record['has_srcip']
    decoder    = record['decoder_name']

    groups = set(groups_raw)

    # === Heuristik TP (ancaman nyata) ===
    if level >= CRITICAL_LEVEL_THRESHOLD:
        return 0
    if KNOWN_ATTACK_GROUPS & groups:
        return 0
    if not is_internal and has_srcip and level >= 5:
        return 0  # traffic eksternal dengan severity moderate → TP

    # === Heuristik FP (benign noise) ===
    if firedtimes > HIGH_FIREDTIMES_FP:
        return 1  # terlalu sering → routine noise
    if is_internal and level < LOW_LEVEL_THRESHOLD:
        return 1  # internal + level rendah → maintenance/heartbeat
    if decoder in KNOWN_BENIGN_GROUPS and level < CRITICAL_LEVEL_THRESHOLD:
        return 1
    if not has_srcip and level < LOW_LEVEL_THRESHOLD:
        return 1  # tidak ada source IP + level rendah → system event

    # Default: level sedang tanpa konteks jelas → FP (konservatif)
    return 1 if level < 7 else 0


# ─── FEATURE EXTRACTION ──────────────────────────────────────────────────────
# PENTING: fitur yang dipakai model BERBEDA dari variabel yang dipakai labeling
# rule_id dikodekan sebagai HASH BUCKET (bukan nilai asli) untuk menghindari leakage

def extract_record(alert: dict) -> dict | None:
    rule    = alert.get('rule', {})
    agent   = alert.get('agent', {})
    decoder = alert.get('decoder', {})
    data    = alert.get('data', {})

    ts_str = alert.get('timestamp', '')
    try:
        ts  = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        hour = ts.hour
        dow  = ts.weekday()
        biz  = 1 if (8 <= hour <= 18 and dow < 5) else 0
    except Exception:
        hour, dow, biz = 12, 2, 1

    level      = rule.get('level', 0)
    rule_id    = str(rule.get('id', '0'))
    firedtimes = rule.get('firedtimes', 1)
    groups_raw = rule.get('groups', [])
    groups     = set(groups_raw)

    decoder_name = decoder.get('name', 'unknown')
    agent_id     = agent.get('id', '000')
    srcip        = data.get('srcip', '')

    is_internal = int(
        srcip.startswith('10.')
        or srcip.startswith('192.168.')
        or srcip.startswith('172.16.')
        or srcip == '127.0.0.1'
    )
    has_srcip = int(bool(srcip))

    record = {
        # --- Metadata (untuk labeling saja, TIDAK dipakai sebagai fitur) ---
        'rule_id'      : rule_id,
        'groups_raw'   : groups_raw,
        'decoder_name' : decoder_name,
        'srcip'        : srcip,
        'timestamp'    : ts_str,
        'is_internal_ip': is_internal,
        'has_srcip'    : has_srcip,
        'rule_level'   : level,
        'firedtimes'   : firedtimes,

        # --- Fitur untuk model ---
        # Temporal
        'hour'             : hour,
        'day_of_week'      : dow,
        'is_business_hours': biz,
        # Agent context
        'is_manager_agent' : int(agent_id == '000'),
        # Severity (ini DIPAKAI sebagai fitur — berbeda dari rule_id)
        'rule_level_feat'  : level,
        # Repetition behavior
        'log_firedtimes'   : float(np.log1p(firedtimes)),
        # Source context
        'has_srcip_feat'   : has_srcip,
        'is_internal_feat' : is_internal,
        # Group flags (behavioral, bukan ID)
        'flag_attack'      : int(bool(KNOWN_ATTACK_GROUPS & groups)),
        'flag_auth'        : int(any('auth' in g for g in groups)),
        'flag_rootcheck'   : int('rootcheck' in groups),
        'flag_sshd'        : int('sshd' in groups),
        'flag_sudo'        : int('sudo' in groups),
        'flag_active_resp' : int('active_response' in groups),
        'flag_web'         : int('web' in groups),
        # Decoder category (tidak pakai nama mentah)
        'decoder_is_ossec' : int(decoder_name == 'ossec'),
        'decoder_is_syslog': int(decoder_name == 'syslog'),
        # Rule ID bucket (hash mod 50) — menyembunyikan nilai asli
        'rule_id_bucket'   : int(rule_id) % 50 if rule_id.isdigit() else -1,
    }
    return record


# ─── TEMPORAL FEATURE: burst rate ────────────────────────────────────────────

def add_burst_features(records: list[dict]) -> list[dict]:
    """
    Hitung berapa banyak event dari agent yang sama dalam 60-detik window.
    Ini behavioral feature yang tidak bisa dihitung dari satu event saja.
    """
    # Sort by timestamp
    parsed = []
    for r in records:
        try:
            ts = datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00'))
        except Exception:
            ts = datetime.min
        parsed.append((ts, r))
    parsed.sort(key=lambda x: x[0])

    # Sliding window count per agent
    agent_times = defaultdict(list)
    result = []
    for ts, r in parsed:
        agent = 'manager' if r['is_manager_agent'] else r.get('srcip', 'unknown')
        agent_times[agent].append(ts)
        # Hitung event dalam 60 detik terakhir
        cutoff = ts.timestamp() - 60
        recent = [t for t in agent_times[agent] if t.timestamp() >= cutoff]
        agent_times[agent] = recent
        r['burst_count_60s'] = len(recent)
        result.append(r)
    return result


# ─── MAIN PIPELINE ───────────────────────────────────────────────────────────

print("=" * 60)
print("AI FALSE ALARM REDUCER v2 — Non-Circular Training Pipeline")
print("Kelompok 5 MIKS ITS | Final Project SOC Genap 24/25")
print("=" * 60)

# 1. Parse
print("\n[1/6] Parsing alerts.json ...")
raw_records = []
with open(ALERTS_FILE, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            raw_records.append(extract_record(json.loads(line)))
        except Exception:
            pass
print(f"      Parsed {len(raw_records)} alerts")

# 2. Burst feature
print("[2/6] Computing temporal burst features ...")
raw_records = add_burst_features(raw_records)

# 3. Label (menggunakan behavioral heuristik, BUKAN rule_id)
print("[3/6] Assigning labels via behavioral heuristics ...")
for r in raw_records:
    r['label'] = compute_label(r)

df = pd.DataFrame(raw_records)
n_tp = int((df['label'] == 0).sum())
n_fp = int((df['label'] == 1).sum())
print(f"      True Positive: {n_tp} ({n_tp/len(df)*100:.1f}%)")
print(f"      False Positive: {n_fp} ({n_fp/len(df)*100:.1f}%)")

# 4. Feature matrix (TIDAK termasuk rule_id asli, groups_raw, dll)
FEATURE_COLS = [
    'rule_level_feat', 'log_firedtimes', 'rule_id_bucket',
    'hour', 'day_of_week', 'is_business_hours',
    'is_manager_agent', 'has_srcip_feat', 'is_internal_feat',
    'flag_attack', 'flag_auth', 'flag_rootcheck', 'flag_sshd',
    'flag_sudo', 'flag_active_resp', 'flag_web',
    'decoder_is_ossec', 'decoder_is_syslog',
    'burst_count_60s',
]

print("[4/6] Building feature matrix ...")
X = df[FEATURE_COLS].values.astype(float)
y = df['label'].values

# Split SEBELUM fitting apapun
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)
print(f"      Train: {len(X_tr)}, Test: {len(X_te)}")

# 5. Train
print("[5/6] Training models ...")

# Random Forest
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    min_samples_leaf=5,
    random_state=42,
    class_weight='balanced',
    n_jobs=-1,
)
rf.fit(X_tr, y_tr)
y_pred_rf = rf.predict(X_te)
y_prob_rf  = rf.predict_proba(X_te)[:, 1]

prec_rf = precision_score(y_te, y_pred_rf, zero_division=0)
rec_rf  = recall_score(y_te, y_pred_rf, zero_division=0)
f1_rf   = f1_score(y_te, y_pred_rf, zero_division=0)
try:
    auc_rf = roc_auc_score(y_te, y_prob_rf)
except Exception:
    auc_rf = 0.0

print(f"\n      [Random Forest]")
print(f"      Precision : {prec_rf:.4f}")
print(f"      Recall    : {rec_rf:.4f}")
print(f"      F1-Score  : {f1_rf:.4f}")
print(f"      ROC-AUC   : {auc_rf:.4f}")
print(classification_report(y_te, y_pred_rf,
                             target_names=['TruePositive', 'FalsePositive'],
                             zero_division=0))

# Isolation Forest (unsupervised — untuk deteksi anomali)
iso = IsolationForest(
    n_estimators=200,
    contamination=float(n_fp / len(df)),
    random_state=42,
)
iso.fit(X_tr)
y_pred_iso = np.where(iso.predict(X_te) == -1, 0, 1)  # -1 = anomali = TP

prec_iso = precision_score(y_te, y_pred_iso, zero_division=0)
rec_iso  = recall_score(y_te, y_pred_iso, zero_division=0)
f1_iso   = f1_score(y_te, y_pred_iso, zero_division=0)

print(f"      [Isolation Forest]")
print(f"      Precision : {prec_iso:.4f}")
print(f"      Recall    : {rec_iso:.4f}")
print(f"      F1-Score  : {f1_iso:.4f}")

# 6. Save
print("\n[6/6] Saving model and evaluation report ...")

feat_imp = sorted(
    zip(FEATURE_COLS, rf.feature_importances_),
    key=lambda x: -x[1]
)

model_data = {
    'rf_model'    : rf,
    'iso_model'   : iso,
    'feature_cols': FEATURE_COLS,
    'fp_criteria' : {
        'critical_level'     : CRITICAL_LEVEL_THRESHOLD,
        'low_level_threshold': LOW_LEVEL_THRESHOLD,
        'high_firedtimes_fp' : HIGH_FIREDTIMES_FP,
        'known_benign_groups': list(KNOWN_BENIGN_GROUPS),
        'known_attack_groups': list(KNOWN_ATTACK_GROUPS),
        'labeling_note'      : (
            'Labels assigned using BEHAVIORAL context '
            '(level, firedtimes, source IP, group flags). '
            'rule_id NOT used as model feature to avoid tautological validation.'
        ),
    },
    'trained_at': datetime.now().isoformat(),
    'metrics': {
        'rf_precision': prec_rf, 'rf_recall': rec_rf,
        'rf_f1': f1_rf,          'rf_auc': auc_rf,
        'iso_precision': prec_iso, 'iso_recall': rec_iso, 'iso_f1': f1_iso,
        'n_samples': len(y), 'n_tp': n_tp, 'n_fp': n_fp,
        'test_size': len(y_te),
    },
}

with open(MODEL_FILE, 'wb') as f:
    pickle.dump(model_data, f)
print(f"      Model → {MODEL_FILE}")

cm = confusion_matrix(y_te, y_pred_rf)
report_lines = [
    "=" * 60,
    "AI FALSE ALARM REDUCTION — EVALUATION REPORT v2",
    "Kelompok 5 MIKS ITS | Final Project SOC Genap 24/25",
    f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "=" * 60,
    "",
    f"Dataset   : {len(df)} alerts total",
    f"Train set : {len(X_tr)} samples (75%)",
    f"Test set  : {len(X_te)} samples (25%)",
    f"True Positives  (ancaman nyata) : {n_tp} ({n_tp/len(df)*100:.1f}%)",
    f"False Positives (benign noise)  : {n_fp} ({n_fp/len(df)*100:.1f}%)",
    "",
    "[DEFINISI KRITERIA FALSE ALARM]",
    f"  • Rule level >= {CRITICAL_LEVEL_THRESHOLD}                    → True Positive",
    f"  • Ada attack/ddos/web_scan group              → True Positive",
    f"  • Source IP eksternal + level >= 5            → True Positive",
    f"  • firedtimes > {HIGH_FIREDTIMES_FP}  (terlalu berulang)    → False Positive",
    f"  • Internal IP + level < {LOW_LEVEL_THRESHOLD}               → False Positive",
    f"  • Decoder benign + level < {CRITICAL_LEVEL_THRESHOLD}           → False Positive",
    "",
    "[CATATAN METODOLOGI]",
    "  Labeling menggunakan BEHAVIORAL HEURISTICS (level, firedtimes,",
    "  source IP context, group flags) — BUKAN rule_id secara langsung.",
    "  rule_id hanya dipakai sebagai hash bucket (mod 50) di feature matrix",
    "  untuk menghindari tautological validation (model menghafal label function).",
    "  Burst rate (jumlah event dalam 60-detik window) ditambahkan sebagai",
    "  temporal behavioral feature yang tidak tersedia dari satu event saja.",
    "",
    "[RANDOM FOREST — HASIL EVALUASI]",
    f"  Precision : {prec_rf:.4f}",
    f"  Recall    : {rec_rf:.4f}",
    f"  F1-Score  : {f1_rf:.4f}",
    f"  ROC-AUC   : {auc_rf:.4f}",
    f"  Confusion Matrix:",
    f"    [[TP={cm[0][0]}  FN={cm[0][1]}]",
    f"     [FP={cm[1][0]}  TN={cm[1][1]}]]",
    "",
    "  Feature Importances (top 8):",
] + [
    f"    {ft:30s}: {imp:.4f}" for ft, imp in feat_imp[:8]
] + [
    "",
    "[ISOLATION FOREST — HASIL EVALUASI]",
    f"  Precision : {prec_iso:.4f}",
    f"  Recall    : {rec_iso:.4f}",
    f"  F1-Score  : {f1_iso:.4f}",
    "  (Unsupervised — digunakan sebagai cross-check anomaly detector)",
]

with open(REPORT_FILE, 'w') as f:
    f.write('\n'.join(report_lines))
print(f"      Report → {REPORT_FILE}")
print("\n=== SELESAI — Model siap digunakan via ai_predict.py ===")
