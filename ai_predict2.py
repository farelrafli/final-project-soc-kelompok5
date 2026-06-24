#!/usr/bin/env python3
"""
AI False Alarm Predictor v2 — deployment/inference script
Kelompok 5 MIKS ITS | Final Project SOC Genap 24/25

Usage:
    echo '<alert_json_line>' | sudo python3 /var/ossec/etc/ai_predict.py
    sudo tail -f /var/ossec/logs/alerts/alerts.json | sudo python3 /var/ossec/etc/ai_predict.py
"""

import json
import pickle
import sys
from datetime import datetime
from collections import defaultdict

import numpy as np

MODEL_FILE = '/var/ossec/etc/ai_false_alarm_model.pkl'

# Burst state (in-memory, resets jika script dijalankan ulang)
_agent_times: dict = defaultdict(list)

KNOWN_ATTACK_GROUPS = {'attack', 'ddos', 'web_scan', 'brute_force', 'active_response'}


def compute_burst(srcip: str, is_manager: int, ts: datetime) -> int:
    agent = 'manager' if is_manager else (srcip or 'unknown')
    _agent_times[agent].append(ts)
    cutoff = ts.timestamp() - 60
    recent = [t for t in _agent_times[agent] if t.timestamp() >= cutoff]
    _agent_times[agent] = recent
    return len(recent)


def build_feature_vector(alert: dict) -> list[float]:
    rule    = alert.get('rule', {})
    agent   = alert.get('agent', {})
    decoder = alert.get('decoder', {})
    data    = alert.get('data', {})

    ts_str = alert.get('timestamp', '')
    try:
        ts   = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        hour = ts.hour
        dow  = ts.weekday()
        biz  = 1 if (8 <= hour <= 18 and dow < 5) else 0
    except Exception:
        ts, hour, dow, biz = datetime.utcnow(), 12, 2, 1

    level      = rule.get('level', 0)
    rule_id    = str(rule.get('id', '0'))
    firedtimes = rule.get('firedtimes', 1)
    groups     = set(rule.get('groups', []))

    decoder_name = decoder.get('name', 'unknown')
    agent_id     = agent.get('id', '000')
    srcip        = data.get('srcip', '')

    is_internal = int(
        srcip.startswith('10.')
        or srcip.startswith('192.168.')
        or srcip.startswith('172.16.')
        or srcip == '127.0.0.1'
    )
    has_srcip    = int(bool(srcip))
    is_manager_a = int(agent_id == '000')

    burst = compute_burst(srcip, is_manager_a, ts)

    return [
        float(level),
        float(np.log1p(firedtimes)),
        float(int(rule_id) % 50 if rule_id.isdigit() else -1),
        float(hour),
        float(dow),
        float(biz),
        float(is_manager_a),
        float(has_srcip),
        float(is_internal),
        float(int(bool(KNOWN_ATTACK_GROUPS & groups))),
        float(int(any('auth' in g for g in groups))),
        float(int('rootcheck' in groups)),
        float(int('sshd' in groups)),
        float(int('sudo' in groups)),
        float(int('active_response' in groups)),
        float(int('web' in groups)),
        float(int(decoder_name == 'ossec')),
        float(int(decoder_name == 'syslog')),
        float(burst),
    ]


def main():
    print(f"[ai_predict] Loading model from {MODEL_FILE} ...", file=sys.stderr)
    with open(MODEL_FILE, 'rb') as f:
        model_data = pickle.load(f)

    rf = model_data['rf_model']
    print("[ai_predict] Model loaded. Reading alerts from stdin ...", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            X = [build_feature_vector(alert)]
            pred    = rf.predict(X)[0]
            prob    = rf.predict_proba(X)[0]
            label   = 'FALSE_POSITIVE' if pred == 1 else 'TRUE_POSITIVE'
            conf    = prob[pred]
            rule_id = alert.get('rule', {}).get('id', '?')
            level   = alert.get('rule', {}).get('level', '?')
            desc    = alert.get('rule', {}).get('description', '')[:60]
            ts      = alert.get('timestamp', '')[:19]
            print(
                f"[AI] {ts} | Rule {rule_id:>6} (lvl {level:>2}) | "
                f"{label:<15} | conf={conf:.2f} | {desc}"
            )
        except Exception as e:
            print(f"[AI] ERROR: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
