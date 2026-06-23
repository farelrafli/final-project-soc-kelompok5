#!/usr/bin/env python3
import datetime, fcntl, json, re, subprocess, sys

ACTIVE_RESPONSE_LOG = '/var/ossec/logs/active-responses.log'
SOAR_AUDIT_LOG      = '/var/ossec/logs/soar_audit.jsonl'
LOCK_FILE           = '/var/ossec/active-response/bin/.ddos-block.lock'
INTERNAL_IPS = {'127.0.0.1','10.0.0.4','10.0.0.5','10.0.0.6','10.0.0.7'}

def ts():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def log_human(msg):
    with open(ACTIVE_RESPONSE_LOG, 'a') as f:
        f.write(f'[{ts()}] ddos-block: {msg}\n')

def log_soar(event):
    event['timestamp'] = ts()
    with open(SOAR_AUDIT_LOG, 'a') as f:
        f.write(json.dumps(event) + '\n')

def is_blocked(ip):
    input_hit = subprocess.run(
        ['iptables','-C','INPUT','-s',ip,'-j','DROP'], capture_output=True
    ).returncode == 0
    forward_hit = subprocess.run(
        ['iptables','-C','FORWARD','-s',ip,'-j','DROP'], capture_output=True
    ).returncode == 0
    return input_hit and forward_hit

def block(ip):
    r1 = subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP'], capture_output=True)
    r2 = subprocess.run(['iptables','-I','FORWARD','-s',ip,'-j','DROP'], capture_output=True)
    if r1.returncode != 0:
        log_human(f'IPTABLES ERROR (INPUT add {ip}): {r1.stderr.decode().strip()}')
    if r2.returncode != 0:
        log_human(f'IPTABLES ERROR (FORWARD add {ip}): {r2.stderr.decode().strip()}')
    return r1.returncode == 0 and r2.returncode == 0

def unblock(ip):
    r1 = subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'], capture_output=True)
    r2 = subprocess.run(['iptables','-D','FORWARD','-s',ip,'-j','DROP'], capture_output=True)
    if r1.returncode != 0:
        log_human(f'IPTABLES ERROR (INPUT del {ip}): {r1.stderr.decode().strip()}')
    if r2.returncode != 0:
        log_human(f'IPTABLES ERROR (FORWARD del {ip}): {r2.stderr.decode().strip()}')
    return r1.returncode == 0 and r2.returncode == 0

def run(raw):
    try:
        data   = json.loads(raw)
        action = data.get('command','add')
        alert  = data.get('parameters',{}).get('alert',{})
    except Exception as e:
        log_human(f'SOAR RECEIVE ERROR: {e}')
        return

    rule_id    = alert.get('rule',{}).get('id','unknown')
    rule_level = alert.get('rule',{}).get('level',0)
    src_ip     = alert.get('data',{}).get('srcip','')
    if not src_ip:
        m = re.search(r'DDOS_DETECTED SRC_IP=([\d.]+)', alert.get('full_log',''))
        src_ip = m.group(1) if m else ''

    is_internal = src_ip in INTERNAL_IPS or src_ip.startswith(('10.','192.168.'))
    base = {'src_ip':src_ip,'rule_id':rule_id,'rule_level':rule_level,
            'ip_class':'internal' if is_internal else 'external',
            'soar_workflow':'ddos_response_v1'}

    if not src_ip:
        log_human('SOAR SKIP — no_src_ip_found')
        log_soar({**base,'action':'skip','decision_reason':'no_src_ip_found','enforcement':'none'})
        return
    if is_internal:
        log_human(f'SOAR SKIP — internal_ip_protected: {src_ip}')
        log_soar({**base,'action':'skip','decision_reason':'internal_ip_protected','enforcement':'none'})
        return

    if action == 'add':
        if is_blocked(src_ip):
            log_human(f'SOAR ALREADY_BLOCKED — {src_ip}')
            log_soar({**base,'action':'add','decision_reason':'already_blocked','enforcement':'none_duplicate'})
        else:
            success = block(src_ip)
            if success:
                log_human(f'SOAR BLOCK — {src_ip} (rule {rule_id} lvl {rule_level})')
                log_soar({**base,'action':'add','decision_reason':'ddos_detected','enforcement':'iptables_INPUT+FORWARD_DROP'})
            else:
                log_human(f'SOAR BLOCK_FAILED — {src_ip}')
                log_soar({**base,'action':'add','decision_reason':'ddos_detected','enforcement':'failed'})
    elif action == 'delete':
        if not is_blocked(src_ip):
            log_human(f'SOAR UNBLOCK_SKIPPED — {src_ip} not currently blocked')
            log_soar({**base,'action':'delete','decision_reason':'active_response_timeout','enforcement':'none_not_blocked'})
        else:
            success = unblock(src_ip)
            if success:
                log_human(f'SOAR UNBLOCK — {src_ip}')
                log_soar({**base,'action':'delete','decision_reason':'active_response_timeout','enforcement':'iptables_INPUT+FORWARD_DROP_removed'})
            else:
                log_human(f'SOAR UNBLOCK_FAILED — {src_ip}')
                log_soar({**base,'action':'delete','decision_reason':'active_response_timeout','enforcement':'failed'})

if __name__ == '__main__':
    try:
        with open(LOCK_FILE, 'w') as lockf:
            fcntl.flock(lockf, fcntl.LOCK_EX)
            run(sys.stdin.readline())
    except Exception as e:
        log_human(f'SOAR FATAL ERROR: {e}')
