"""
Security Reviewer Dashboard - Web interface for reviewing and managing blocked accounts/IPs.

This dashboard allows security reviewers to:
- View all blocked user accounts
- View all blocked IP addresses (with TTL)
- Manually unblock accounts or IPs
- View recent incident logs

SECURITY NOTE: In production, this should require authentication.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
import sqlite3
import json
import os
from datetime import datetime

# Import config
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import DATABASE_PATH, BLOCKLIST_PATH, INCIDENTS_LOG, AGENT_ALERTS_PATH

app = Flask(__name__)
CORS(app)

# ============== Helper Functions ==============

def get_blocked_accounts():
    """Get list of blocked user accounts from database."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email FROM users WHERE is_blocked = 1')
        blocked = cursor.fetchall()
        conn.close()
        return [{'id': row[0], 'username': row[1], 'email': row[2]} for row in blocked]
    except Exception as e:
        print(f"Error fetching blocked accounts: {e}")
        return []


def get_blocked_ips():
    """Get list of blocked IPs from blocklist file."""
    if not os.path.exists(BLOCKLIST_PATH):
        return []
    
    try:
        with open(BLOCKLIST_PATH, 'r', encoding='utf-8') as f:
            blocklist = json.load(f)
        
        blocked_ips = []
        current_time = datetime.utcnow()
        
        for ip, info in blocklist.items():
            expires_at = datetime.fromisoformat(info['expires_at'])
            is_expired = expires_at <= current_time
            remaining_mins = max(0, int((expires_at - current_time).total_seconds() / 60))
            
            blocked_ips.append({
                'ip': ip,
                'blocked_at': info['blocked_at'],
                'expires_at': info['expires_at'],
                'reason': info.get('reason', 'N/A'),
                'is_expired': is_expired,
                'remaining_minutes': remaining_mins
            })
        
        return blocked_ips
    except Exception as e:
        print(f"Error fetching blocked IPs: {e}")
        return []


def get_recent_incidents(limit=50):
    """Get recent incident logs."""
    if not os.path.exists(INCIDENTS_LOG):
        return []
    
    try:
        incidents = []
        with open(INCIDENTS_LOG, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    incident = json.loads(line.strip())
                    incidents.append(incident)
                except:
                    pass
        
        # Return most recent incidents first
        return incidents[-limit:][::-1]
    except Exception as e:
        print(f"Error fetching incidents: {e}")
        return []


def get_agent_alerts(limit=20):
    """Get critical agent alerts (system errors like missing Investigator)."""
    if not os.path.exists(AGENT_ALERTS_PATH):
        return []
    
    try:
        with open(AGENT_ALERTS_PATH, 'r', encoding='utf-8') as f:
            alerts = json.load(f)
        
        # Return most recent alerts first
        return alerts[-limit:][::-1]
    except Exception as e:
        print(f"Error fetching agent alerts: {e}")
        return []


def unblock_account(username):
    """Unblock a user account."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_blocked = 0 WHERE username = ?', (username,))
        conn.commit()
        rows_affected = cursor.rowcount
        conn.close()
        return rows_affected > 0
    except Exception as e:
        print(f"Error unblocking account: {e}")
        return False


def unblock_ip(ip_address):
    """Remove an IP from the blocklist."""
    if not os.path.exists(BLOCKLIST_PATH):
        return False
    
    try:
        with open(BLOCKLIST_PATH, 'r', encoding='utf-8') as f:
            blocklist = json.load(f)
        
        if ip_address in blocklist:
            del blocklist[ip_address]
            
            with open(BLOCKLIST_PATH, 'w', encoding='utf-8') as f:
                json.dump(blocklist, f, indent=2)
            
            return True
        return False
    except Exception as e:
        print(f"Error unblocking IP: {e}")
        return False


# ============== Routes ==============

@app.route('/')
def dashboard():
    """Main dashboard page."""
    blocked_accounts = get_blocked_accounts()
    blocked_ips = get_blocked_ips()
    incidents = get_recent_incidents(20)
    return render_template('dashboard.html',
                         blocked_accounts=blocked_accounts,
                         blocked_ips=blocked_ips,
                         incidents=incidents)


@app.route('/api/blocked-accounts')
def api_blocked_accounts():
    """API endpoint to get blocked accounts."""
    return jsonify(get_blocked_accounts())


@app.route('/api/blocked-ips')
def api_blocked_ips():
    """API endpoint to get blocked IPs."""
    return jsonify(get_blocked_ips())


@app.route('/api/incidents')
def api_incidents():
    """API endpoint to get incidents."""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_recent_incidents(limit))


@app.route('/api/agent-alerts')
def api_agent_alerts():
    """API endpoint to get critical agent alerts."""
    limit = request.args.get('limit', 20, type=int)
    return jsonify(get_agent_alerts(limit))


@app.route('/api/unblock-account', methods=['POST'])
def api_unblock_account():
    """API endpoint to unblock an account."""
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    if unblock_account(username):
        return jsonify({'status': 'success', 'message': f'Account {username} unblocked'})
    else:
        return jsonify({'error': 'Failed to unblock account'}), 500


@app.route('/api/unblock-ip', methods=['POST'])
def api_unblock_ip():
    """API endpoint to unblock an IP."""
    data = request.get_json()
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    if unblock_ip(ip_address):
        return jsonify({'status': 'success', 'message': f'IP {ip_address} unblocked'})
    else:
        return jsonify({'error': 'Failed to unblock IP'}), 500


@app.route('/unblock-account/<username>', methods=['POST'])
def web_unblock_account(username):
    """Web form handler to unblock an account."""
    if unblock_account(username):
        return redirect(url_for('dashboard'))
    return "Error unblocking account", 500


@app.route('/unblock-ip/<path:ip_address>', methods=['POST'])
def web_unblock_ip(ip_address):
    """Web form handler to unblock an IP."""
    if unblock_ip(ip_address):
        return redirect(url_for('dashboard'))
    return "Error unblocking IP", 500


if __name__ == '__main__':
    print("Starting Security Reviewer Dashboard on port 5004")
    print("Dashboard URL: http://localhost:5004")
    app.run(host='127.0.0.1', port=5004, debug=True)
