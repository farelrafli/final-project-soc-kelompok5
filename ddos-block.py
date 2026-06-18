#!/usr/bin/env python3
import sys
import json
import subprocess
import datetime
import re

LOG_FILE = '/var/ossec/logs/active-responses.log'
INTERNAL_IPS = {'127.0.0.1', '10.0.0.4', '10.0.0.5', '10.0.0.6', '10.0.0.7'}

def log(msg):
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{ts}] ddos-block: {msg}\n')

def is_blocked(ip):
    result = subprocess.run(
        ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
        capture_output=True
    )
    return result.returncode == 0

def block(ip):
    if is_blocked(ip):
        log(f'ALREADY BLOCKED {ip}')
        return
    subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
    subprocess.run(['iptables', '-I', 'FORWARD', '-s', ip, '-j', 'DROP'])
    log(f'BLOCKED {ip}')

def unblock(ip):
    subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'])
    log(f'UNBLOCKED {ip}')

def extract_ip_from_full_log(full_log):
    match = re.search(r'DDOS_DETECTED SRC_IP=([\d.]+)', full_log)
    if match:
        return match.group(1)
    return ''

if __name__ == '__main__':
    try:
        data = json.loads(sys.stdin.readline())
        action = data.get('command', 'add')
        alert = data.get('parameters', {}).get('alert', {})

        # Coba ambil srcip dari data field dulu
        src_ip = alert.get('data', {}).get('srcip', '')

        # Fallback: ekstrak dari full_log pakai regex
        if not src_ip:
            full_log = alert.get('full_log', '')
            src_ip = extract_ip_from_full_log(full_log)

        # Validasi IP
        if src_ip and src_ip not in INTERNAL_IPS:
            if action == 'add':
                block(src_ip)
            elif action == 'delete':
                unblock(src_ip)
        else:
            log(f'SKIP: IP tidak valid atau IP internal: {src_ip}')
    except Exception as e:
        log(f'ERROR: {str(e)}')
