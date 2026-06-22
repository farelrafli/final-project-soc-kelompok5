#!/usr/bin/env python3
"""
AI False Alarm Reducer - Training Pipeline
Kelompok 5 MIKS ITS - Final Project SOC Genap 25/26

Design note on labeling & metrics
----------------------------------
Labels are assigned by auto_label() using rule_level, firedtimes, decoder,
and group membership — the same signals used as model features. This means
the model partially learns the labeling function rather than an independent
ground truth. To mitigate over-optimism:
  1. rule_id is excluded from features (direct label leakage).
  2. 10% label noise is injected at training time.
  3. Precision@threshold and cross-val std are reported alongside point metrics
     so the reader can judge robustness without being misled by a single number.
"""

import glob, json, pickle, warnings
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve
)

warnings.filterwarnings('ignore')

ALERTS_DIR  = '/var/ossec/logs/alerts'
MODEL_FILE  = '/var/ossec/etc/ai_false_alarm_model.pkl'
REPORT_FILE = '/var/ossec/logs/ai_model_report.txt'

FALSE_ALARM_CRITERIA = {
    'fp_rule_ids'       : {'510','503','502','5402','5501','5502','31108'},
    'low_level_threshold': 5,
    'high_firedtimes_fp': 50,
    'fp_decoders'       : {'rootcheck','ossec'},
    'tp_rule_ids'       : {'5710','5711','5712','100501','100500'},
    'tp_groups'         : {'active_response','ddos','attack'},
}

# ── labeling ────────────────────────────────────────────────────────────────

def auto_label(rule_id, level, firedtimes, groups, decoder, srcip, is_internal):
    """
    Heuristic labeler.  Priority order:
      1. Hard-coded TP rule IDs  → True Positive (0)
      2. Attack group + high level → True Positive (0)
      3. Hard-coded FP rule IDs  → False Positive (1)
      4. Low level + internal src → False Positive (1)
      5. Very high firedtimes    → False Positive (1)
      6. Benign decoders         → False Positive (1)
      7. SSH from external + medium level → True Positive (0)
      8. Fallback: low level     → False Positive (1)
    """
    c = FALSE_ALARM_CRITERIA
    if rule_id in c['tp_rule_ids']:                             return 0
    if c['tp_groups'].intersection(set(groups)) and level >= 10: return 0
    if rule_id in c['fp_rule_ids']:                             return 1
    if level < c['low_level_threshold'] and is_internal:        return 1
    if firedtimes > c['high_firedtimes_fp']:                    return 1
    if decoder in c['fp_decoders'] and level < 10:              return 1
    if 'sshd' in groups and not is_internal and level >= 5:     return 0
    return 1 if level < c['low_level_threshold'] else 0

# ── feature extraction ───────────────────────────────────────────────────────

def extract_features(alert):
    rule        = alert.get('rule', {})
    agent       = alert.get('agent', {})
    decoder     = alert.get('decoder', {})
    data        = alert.get('data', {})
    ts_str      = alert.get('timestamp', '')

    try:
        ts  = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        hour, dow = ts.hour, ts.weekday()
        biz = 1 if (8 <= hour <= 18 and dow < 5) else 0
    except Exception:
        hour = dow = biz = 0

    rule_level   = rule.get('level', 0)
    rule_id      = str(rule.get('id', '0'))
    firedtimes   = rule.get('firedtimes', 1)
    groups       = rule.get('groups', [])
    is_manager   = 1 if agent.get('id', '000') == '000' else 0
    decoder_name = decoder.get('name', 'unknown')
    srcip        = data.get('srcip', '')
    has_srcip    = 1 if srcip else 0
    is_internal  = 1 if (
        srcip.startswith('10.') or
        srcip.startswith('192.168.') or
        srcip == '127.0.0.1'
    ) else 0

    label = auto_label(
        rule_id, rule_level, firedtimes, groups,
        decoder_name, srcip, bool(is_internal)
    )

    return {
        # behavioural signals (no rule_id — direct label leakage excluded)
        'rule_level'         : rule_level,
        'firedtimes'         : firedtimes,
        'hour'               : hour,
        'day_of_week'        : dow,
        'is_business_hours'  : biz,
        'is_manager'         : is_manager,
        'decoder_name'       : decoder_name,
        'has_srcip'          : has_srcip,
        'is_internal_ip'     : is_internal,
        'has_authentication' : 1 if any('auth' in g for g in groups) else 0,
        'has_attack'         : 1 if any(g in ('attack','ddos','web_scan') for g in groups) else 0,
        'has_active_response': 1 if 'active_response' in groups else 0,
        'has_rootcheck'      : 1 if 'rootcheck' in groups else 0,
        'has_sshd'           : 1 if 'sshd' in groups else 0,
        'has_sudo'           : 1 if 'sudo' in groups else 0,
        'label'              : label,
    }

# ── data loading ─────────────────────────────────────────────────────────────

def parse_alerts(alerts_dir):
    records = []
    files   = sorted(glob.glob(f'{alerts_dir}/**/*.json', recursive=True))
    files  += [f'{alerts_dir}/alerts.json']
    seen    = set()
    for fp in files:
        if fp in seen:
            continue
        seen.add(fp)
        try:
            with open(fp) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(extract_features(json.loads(line)))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
    print(f"[OK] Parsed {len(records)} alerts from {len(seen)} file(s)")
    return records

# ── main ─────────────────────────────────────────────────────────────────────

print("=== AI False Alarm Reducer - Training Pipeline ===")

print("[1/6] Parsing alerts...")
df = pd.DataFrame(parse_alerts(ALERTS_DIR))
if df.empty:
    print("[ERROR] No alerts found. Exiting.")
    raise SystemExit(1)

print("[2/6] Feature engineering...")
le = LabelEncoder()
df['decoder_encoded'] = le.fit_transform(df['decoder_name'])

FEATURES = [
    'firedtimes', 'hour', 'day_of_week',
    'is_business_hours', 'is_manager', 'decoder_encoded', 'has_srcip',
    'is_internal_ip', 'has_authentication', 'has_attack',
    'has_active_response', 'has_rootcheck', 'has_sshd', 'has_sudo',
]
X = df[FEATURES].values
y = df['label'].values
print(f"[INFO] TP={int(sum(y==0))}, FP={int(sum(y==1))}, Total={len(y)}")

print("[3/6] Train/test split + label noise...")
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 10% noise simulates real-world annotation uncertainty.
# Model is evaluated on clean y_te so metrics reflect generalisation,
# not memorisation. Higher noise → lower ceiling on train accuracy,
# which prevents artificially perfect test scores.
NOISE_RATE = 0.10
rng        = np.random.RandomState(0)
noise_mask = rng.rand(len(y_tr)) < NOISE_RATE
y_tr_noisy = y_tr.copy()
y_tr_noisy[noise_mask] ^= 1
print(f"[INFO] {noise_mask.sum()} / {len(y_tr)} training labels flipped ({NOISE_RATE*100:.0f}% noise)")

print("[4/6] Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=8,
    min_samples_leaf=10,   # prevents overfitting to rare TP patterns
    random_state=42,
    class_weight='balanced' # sklearn handles imbalance automatically
)
rf.fit(X_tr, y_tr_noisy)

# Default threshold 0.5 — no manual override
y_pred = rf.predict(X_te)
y_prob = rf.predict_proba(X_te)[:, 1]

prec = precision_score(y_te, y_pred, zero_division=0)
rec  = recall_score(y_te, y_pred, zero_division=0)
f1   = f1_score(y_te, y_pred, zero_division=0)
try:
    auc = roc_auc_score(y_te, y_prob)
except ValueError:
    auc = 0.0

print(f"RF - Precision:{prec:.4f}  Recall:{rec:.4f}  F1:{f1:.4f}  AUC:{auc:.4f}")
print(classification_report(y_te, y_pred, target_names=['TruePositive','FalsePositive']))

# Cross-validation for honest variance estimate
cv    = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_f1 = cross_val_score(rf, X, y, cv=cv, scoring='f1', n_jobs=-1)
print(f"[CV]  5-fold F1 = {cv_f1.mean():.4f} ± {cv_f1.std():.4f}")

# Precision@threshold analysis
precisions, recalls, thresholds = precision_recall_curve(y_te, y_prob)
pr_table = [(t, p, r) for t, p, r in zip(thresholds, precisions, recalls)]

print("[5/6] Training Isolation Forest (unsupervised baseline)...")
iso   = IsolationForest(n_estimators=100, contamination=0.3, random_state=42)
iso.fit(X_tr)
y_iso = np.where(iso.predict(X_te) == -1, 0, 1)
iso_p = precision_score(y_te, y_iso, zero_division=0)
iso_r = recall_score(y_te, y_iso, zero_division=0)
iso_f = f1_score(y_te, y_iso, zero_division=0)
print(f"ISO - Precision:{iso_p:.4f}  Recall:{iso_r:.4f}  F1:{iso_f:.4f}")

print("[6/6] Saving model + report...")
feat_imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda x: -x[1])

model_data = {
    'rf_model'    : rf,
    'iso_model'   : iso,
    'le_decoder'  : le,
    'feature_cols': FEATURES,
    'fp_criteria' : FALSE_ALARM_CRITERIA,
    'trained_at'  : datetime.now().isoformat(),
    'metrics'     : {
        'rf_precision': prec, 'rf_recall': rec,
        'rf_f1': f1, 'rf_auc': auc,
        'rf_cv_f1_mean': float(cv_f1.mean()),
        'rf_cv_f1_std' : float(cv_f1.std()),
        'iso_f1': iso_f,
        'n_samples': len(y),
        'n_tp': int(sum(y==0)),
        'n_fp': int(sum(y==1)),
        'noise_rate': NOISE_RATE,
    },
}
with open(MODEL_FILE, 'wb') as f:
    pickle.dump(model_data, f)
print(f"[OK] Model → {MODEL_FILE}")

# ── report ───────────────────────────────────────────────────────────────────

cm = confusion_matrix(y_te, y_pred).tolist()

# Sample P/R curve at 5 thresholds
pr_samples = []
for target_t in [0.3, 0.4, 0.5, 0.6, 0.7]:
    closest = min(pr_table, key=lambda x: abs(x[0] - target_t))
    pr_samples.append(f"  thresh={closest[0]:.2f}  P={closest[1]:.4f}  R={closest[2]:.4f}")

report_lines = [
    "=" * 60,
    "AI FALSE ALARM REDUCTION - EVALUATION REPORT",
    "Kelompok 5 MIKS ITS - Final Project SOC Genap 24/25",
    f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "=" * 60,

    f"\nDataset  : {len(df)} alerts",
    f"  True Positives  : {int(sum(df['label']==0))} ({sum(df['label']==0)/len(df)*100:.1f}%)",
    f"  False Positives : {int(sum(df['label']==1))} ({sum(df['label']==1)/len(df)*100:.1f}%)",

    "\n[LABELING METHOD & KNOWN LIMITATIONS]",
    "Labels are generated automatically by rule-based heuristics",
    "(auto_label) using: rule_level, firedtimes, decoder, groups,",
    "and source IP class. Because these same signals appear as model",
    "features, there is inherent overlap between the labeling function",
    "and the feature space. Mitigation steps taken:",
    "  - rule_id excluded from features (strongest direct leakage)",
    "  - 10% label noise injected at training time",
    "  - max_depth reduced to 8 to limit memorisation",
    "  - 5-fold CV reported to surface variance",
    "Metrics should be interpreted as upper bounds under this labeling",
    "regime, not as ground-truth generalisation performance.",

    "\n[FALSE ALARM CRITERIA]",
    f"  FP rule IDs   : {FALSE_ALARM_CRITERIA['fp_rule_ids']}",
    f"  Level < {FALSE_ALARM_CRITERIA['low_level_threshold']} from internal src = FP",
    f"  firedtimes > {FALSE_ALARM_CRITERIA['high_firedtimes_fp']} = FP (recurring benign noise)",
    f"  FP decoders   : {FALSE_ALARM_CRITERIA['fp_decoders']}",

    "\n[RANDOM FOREST — HELD-OUT TEST SET (20%)]",
    f"  Precision : {prec:.4f}",
    f"  Recall    : {rec:.4f}",
    f"  F1-Score  : {f1:.4f}",
    f"  ROC-AUC   : {auc:.4f}",
    f"  Confusion Matrix (TP/FP rows, predicted cols): {cm}",
    f"  Label noise applied to training set: {NOISE_RATE*100:.0f}%",

    "\n[RANDOM FOREST — 5-FOLD CROSS VALIDATION]",
    f"  F1 mean : {cv_f1.mean():.4f}",
    f"  F1 std  : {cv_f1.std():.4f}  (lower std = more stable)",
    "  Note: CV is run on auto-labeled data; see limitation note above.",

    "\n[PRECISION-RECALL CURVE — SELECTED THRESHOLDS]",
] + pr_samples + [

    "\n[FEATURE IMPORTANCES — TOP 8]",
] + [f"  {ft}: {im:.4f}" for ft, im in feat_imp[:8]] + [

    "\n[ISOLATION FOREST — UNSUPERVISED BASELINE]",
    f"  Precision : {iso_p:.4f}",
    f"  Recall    : {iso_r:.4f}",
    f"  F1-Score  : {iso_f:.4f}",
    "  (contamination=0.3; no labels used in training)",
    "=" * 60,
]

report_text = '\n'.join(report_lines)
with open(REPORT_FILE, 'w') as f:
    f.write(report_text)
print(f"[OK] Report → {REPORT_FILE}")
print("\n=== SELESAI ===")
