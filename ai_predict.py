#!/usr/bin/env python3
"""
AI False Alarm Predictor - deployment script
Usage: echo '<alert_json>' | python3 /var/ossec/etc/ai_predict.py
"""
import json, pickle, sys
import numpy as np

MODEL_FILE = '/var/ossec/etc/ai_false_alarm_model.pkl'

def extract_features_single(alert, model_data):
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})
    decoder = alert.get('decoder', {})
    data = alert.get('data', {})
    from datetime import datetime
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
    le = model_data['le_decoder']
    try:
        dec_enc = le.transform([decoder_name])[0]
    except:
        dec_enc = -1
    return [[
        rule_level, firedtimes, hour, dow, biz,
        is_manager, dec_enc, has_srcip, is_internal,
        1 if any('auth' in g for g in groups) else 0,
        1 if any(g in ('attack','ddos','web_scan') for g in groups) else 0,
        1 if 'active_response' in groups else 0,
        1 if 'rootcheck' in groups else 0,
        1 if 'sshd' in groups else 0,
        1 if 'sudo' in groups else 0,
    ]]

if __name__ == '__main__':
    with open(MODEL_FILE, 'rb') as f:
        model_data = pickle.load(f)
    rf = model_data['rf_model']
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            alert = json.loads(line)
            X = extract_features_single(alert, model_data)
            pred = rf.predict(X)[0]
            prob = rf.predict_proba(X)[0]
            label = 'FALSE_POSITIVE' if pred == 1 else 'TRUE_POSITIVE'
            confidence = prob[pred]
            rule_id = alert.get('rule', {}).get('id', '?')
            level = alert.get('rule', {}).get('level', '?')
            desc = alert.get('rule', {}).get('description', '')[:50]
            print(f"[AI] Rule {rule_id} (lvl {level}) | {label} | conf={confidence:.2f} | {desc}")
        except Exception as e:
            print(f"[AI] ERROR: {e}")
