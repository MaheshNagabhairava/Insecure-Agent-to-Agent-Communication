"""
Execution Agent - Executes response plans from Planning Agent.

This agent receives response plans and executes the actions, such as
blocking user accounts, invalidating sessions, etc.

SECURITY NOTE: This is intentionally insecure for demonstration purposes.
- Trusts all incoming plans without authentication
- No verification of plan source
- Directly executes database modifications
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import threading
import time
import logging
import json
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

# Import models
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import ResponsePlan, ResponseAction, ExecutionResult, ActionType, AgentType
from config import PORTS, REGISTRY_URL, DATABASE_PATH, INCIDENTS_LOG, BLOCKLIST_PATH, IP_BLOCK_DURATION_MINUTES, WEBAPP_URL, AGENT_SHARED_SECRET

app = Flask(__name__)
CORS(app)

# Configure logging with DEBUG level
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ExecutionAgent')
logger.setLevel(logging.DEBUG)


def require_auth(f):
    """
    Decorator to require X-Agent-Auth header (Shared Secret).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('X-Agent-Auth')
        if not auth_header or auth_header != AGENT_SHARED_SECRET:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.after_request
def add_auth_header(response):
    """Inject Shared Secret into response headers for Mutual Auth."""
    response.headers['X-Agent-Auth'] = AGENT_SHARED_SECRET
    return response

AGENT_NAME = "execution-agent"
AGENT_ENDPOINT = f"http://localhost:{PORTS['execution_agent']}"


def register_with_registry():
    """Register this agent with the Registry Service."""
    while True:
        try:
            response = requests.post(
                f"{REGISTRY_URL}/register",
                json={
                    'name': AGENT_NAME,
                    'agent_type': AgentType.EXECUTION.value,
                    'endpoint': AGENT_ENDPOINT,
                    'capabilities': ['block_account', 'invalidate_session', 'block_ip', 'log_incident']
                },
                timeout=5
            )
            if response.status_code == 200:
                logger.info(f"Registered with Registry Service")
                break
        except Exception as e:
            logger.warning(f"Failed to register with Registry: {e}. Retrying in 5 seconds...")
            time.sleep(5)


def send_heartbeat():
    """Send periodic heartbeats to Registry Service."""
    while True:
        time.sleep(30)
        try:
            requests.post(
                f"{REGISTRY_URL}/heartbeat",
                json={'name': AGENT_NAME},
                timeout=5
            )
        except Exception as e:
            logger.warning(f"Heartbeat failed: {e}")


def ensure_blocked_column():
    """Ensure the is_blocked column exists in the users table."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0')
        conn.commit()
        logger.info("Added is_blocked column to users table")
    except sqlite3.OperationalError:
        # Column already exists
        pass
    finally:
        conn.close()


def block_account(username: str) -> ExecutionResult:
    """
    Block a user account in the database.
    
    VULNERABILITY: No verification that the username is valid or that
    blocking is appropriate. Trusts the plan completely.
    """
    logger.info(f"Blocking account: {username}")
    
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id, username FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            return ExecutionResult(
                action_type=ActionType.BLOCK_ACCOUNT,
                target=username,
                success=False,
                message=f"User '{username}' not found in database"
            )
        
        # Block the user
        cursor.execute('UPDATE users SET is_blocked = 1 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        
        logger.info(f"Successfully blocked account: {username}")
        
        return ExecutionResult(
            action_type=ActionType.BLOCK_ACCOUNT,
            target=username,
            success=True,
            message=f"Account '{username}' has been blocked",
            details={'user_id': user[0]}
        )
    except Exception as e:
        logger.error(f"Failed to block account: {e}")
        return ExecutionResult(
            action_type=ActionType.BLOCK_ACCOUNT,
            target=username,
            success=False,
            message=f"Failed to block account: {str(e)}"
        )


def invalidate_session(target: str) -> ExecutionResult:
    """
    Invalidate a user's session by calling the web app API.
    
    This calls an endpoint on the web app that clears the user's session.
    """
    logger.info(f"Invalidating session for: {target}")
    
    try:
        # Call web app API to invalidate session
        response = requests.post(
            f"{WEBAPP_URL}/api/invalidate-session",
            json={'username': target},
            timeout=10
        )
        
        if response.status_code == 200:
            return ExecutionResult(
                action_type=ActionType.INVALIDATE_SESSION,
                target=target,
                success=True,
                message=f"Session invalidated for '{target}'",
                details={'response': response.json()}
            )
        else:
            logger.warning(f"Session invalidation API returned {response.status_code}")
            return ExecutionResult(
                action_type=ActionType.INVALIDATE_SESSION,
                target=target,
                success=False,
                message=f"Failed to invalidate session: HTTP {response.status_code}",
                details={'status_code': response.status_code}
            )
    except requests.exceptions.ConnectionError:
        logger.error(f"Could not connect to web app at {WEBAPP_URL}")
        return ExecutionResult(
            action_type=ActionType.INVALIDATE_SESSION,
            target=target,
            success=False,
            message=f"Could not connect to web app to invalidate session"
        )
    except Exception as e:
        logger.error(f"Failed to invalidate session: {e}")
        return ExecutionResult(
            action_type=ActionType.INVALIDATE_SESSION,
            target=target,
            success=False,
            message=f"Failed to invalidate session: {str(e)}"
        )


def load_blocklist() -> dict:
    """Load the IP blocklist from JSON file."""
    if os.path.exists(BLOCKLIST_PATH):
        try:
            with open(BLOCKLIST_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_blocklist(blocklist: dict):
    """Save the IP blocklist to JSON file."""
    with open(BLOCKLIST_PATH, 'w', encoding='utf-8') as f:
        json.dump(blocklist, f, indent=2)


def cleanup_expired_blocks(blocklist: dict) -> dict:
    """Remove expired IP blocks from the blocklist."""
    current_time = datetime.utcnow()
    valid_blocks = {}
    
    for ip, block_info in blocklist.items():
        expires_at = datetime.fromisoformat(block_info['expires_at'])
        if expires_at > current_time:
            valid_blocks[ip] = block_info
        else:
            logger.info(f"IP block expired for {ip}")
    
    return valid_blocks


def block_ip(ip_address: str, duration_minutes: int = None) -> ExecutionResult:
    """
    Block an IP address for a specified duration.
    
    Writes to a JSON blocklist file that the web app checks.
    Default duration is 15 minutes (from config).
    """
    if duration_minutes is None:
        duration_minutes = IP_BLOCK_DURATION_MINUTES
    
    logger.info(f"Blocking IP: {ip_address} for {duration_minutes} minutes")
    
    try:
        # Load existing blocklist and cleanup expired entries
        blocklist = load_blocklist()
        blocklist = cleanup_expired_blocks(blocklist)
        
        # Add new block
        current_time = datetime.utcnow()
        expires_at = current_time + timedelta(minutes=duration_minutes)
        
        blocklist[ip_address] = {
            'blocked_at': current_time.isoformat(),
            'expires_at': expires_at.isoformat(),
            'reason': 'Security incident response',
            'duration_minutes': duration_minutes
        }
        
        # Save updated blocklist
        save_blocklist(blocklist)
        
        logger.info(f"Successfully blocked IP {ip_address} until {expires_at.isoformat()}")
        
        return ExecutionResult(
            action_type=ActionType.BLOCK_IP,
            target=ip_address,
            success=True,
            message=f"IP '{ip_address}' blocked for {duration_minutes} minutes",
            details={
                'blocked_at': current_time.isoformat(),
                'expires_at': expires_at.isoformat(),
                'blocklist_path': BLOCKLIST_PATH
            }
        )
    except Exception as e:
        logger.error(f"Failed to block IP: {e}")
        return ExecutionResult(
            action_type=ActionType.BLOCK_IP,
            target=ip_address,
            success=False,
            message=f"Failed to block IP: {str(e)}"
        )


def log_incident(alert_id: str, details: dict = None) -> ExecutionResult:
    """Log an incident to the incidents log file."""
    logger.info(f"Logging incident: {alert_id}")
    
    try:
        incident_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'alert_id': alert_id,
            'action': 'incident_logged',
            'details': details or {}
        }
        
        with open(INCIDENTS_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(incident_entry) + '\n')
        
        return ExecutionResult(
            action_type=ActionType.LOG_INCIDENT,
            target=alert_id,
            success=True,
            message=f"Incident logged: {alert_id}"
        )
    except Exception as e:
        logger.error(f"Failed to log incident: {e}")
        return ExecutionResult(
            action_type=ActionType.LOG_INCIDENT,
            target=alert_id,
            success=False,
            message=f"Failed to log incident: {str(e)}"
        )





def execute_action(action: ResponseAction) -> ExecutionResult:
    """Execute a single response action."""
    action_handlers = {
        ActionType.BLOCK_ACCOUNT: block_account,
        ActionType.INVALIDATE_SESSION: invalidate_session,
        ActionType.BLOCK_IP: block_ip,
        ActionType.LOG_INCIDENT: log_incident,
    }
    
    handler = action_handlers.get(action.action_type)
    
    if handler:
        if action.action_type == ActionType.BLOCK_IP and 'duration_minutes' in action.parameters:
            return block_ip(action.target, action.parameters['duration_minutes'])
        return handler(action.target)
    else:
        return ExecutionResult(
            action_type=action.action_type,
            target=action.target,
            success=False,
            message=f"Unknown action type: {action.action_type}"
        )


@app.route('/execute', methods=['POST'])
@require_auth
def execute_plan():
    """
    Execute a response plan.
    
    VULNERABILITY: No authentication - anyone can send execution requests
    VULNERABILITY: No verification of plan authenticity
    VULNERABILITY: Actions are executed immediately without approval
    """
    data = request.get_json()
    
    logger.info(f"\n{'='*60}\nRECEIVED EXECUTION REQUEST\n{'='*60}")
    logger.debug(f"Plan data: {json.dumps(data, indent=2)}")
    
    try:
        plan = ResponsePlan.from_dict(data)
        logger.info(f"Plan ID: {plan.alert_id}")
        logger.info(f"Plan Summary: {plan.alert_summary}")
        logger.info(f"Number of actions: {len(plan.actions)}")
    except Exception as e:
        logger.error(f"Failed to parse plan: {e}")
        return jsonify({'error': 'Invalid plan format'}), 400
    
    results = []
    
    # Sort actions by priority and execute
    sorted_actions = sorted(plan.actions, key=lambda a: a.priority)
    
    logger.info(f"\n{'='*60}\nEXECUTING ACTIONS\n{'='*60}")
    for i, action in enumerate(sorted_actions, 1):
        logger.info(f"\n--- Action {i}/{len(sorted_actions)} ---")
        logger.info(f"  Type: {action.action_type.value}")
        logger.info(f"  Target: {action.target}")
        logger.info(f"  Priority: {action.priority}")
        logger.info(f"  Reason: {action.reason}")
        
        result = execute_action(action)
        results.append(result.to_dict())
        
        logger.info(f"  Result: {'SUCCESS' if result.success else 'FAILED'} - {result.message}")
        
        # Log each action execution
        log_incident(plan.alert_id, {
            'action': action.action_type.value,
            'target': action.target,
            'success': result.success,
            'message': result.message
        })
    
    logger.info(f"\n{'='*60}\nEXECUTION COMPLETE: {len(results)} actions executed\n{'='*60}")
    
    return jsonify({
        'plan_id': plan.alert_id,
        'results': results,
        'executed_by': AGENT_NAME,
        'executed_at': datetime.utcnow().isoformat()
    })


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'execution-agent',
        'name': AGENT_NAME
    })


if __name__ == '__main__':
    # Ensure database schema is ready
    ensure_blocked_column()
    
    # Start registration and heartbeat threads
    threading.Thread(target=register_with_registry, daemon=True).start()
    threading.Thread(target=send_heartbeat, daemon=True).start()
    
    logger.info(f"Starting Execution Agent on port {PORTS['execution_agent']}")
    app.run(host='0.0.0.0', port=PORTS['execution_agent'], debug=True, threaded=True)
