"""
Configuration settings for the multi-agent security incident response system.
"""

# SSH Configuration for Wazuh Server
SSH_CONFIG = {
    'hostname': '192.168.67.3',
    'username': 'kali',
    'password': 'kali',
    'port': 22,
    # 'key_file': None  # Optional: path to SSH private key
}

# LLM Configuration for Planning Agent reasoning
# LLM Configuration for Planning Agent reasoning
LLM_CONFIG = {
    'api_key': '',
    'endpoint': 'https://llm.chutes.ai/v1/chat/completions',
    'models_priority': [
        'Qwen/Qwen3-235B-A22B-Instruct-2507-TEE',
        'openai/gpt-oss-120b-TEE',
        'Qwen/Qwen3-Next-80B-A3B-Instruct',
        'zai-org/GLM-4.7-Flash'
    ]
}

# Coordinator LLM Configuration (for intelligent agent selection)
# Uses same LLM settings as Planning Agent
COORDINATOR_LLM_CONFIG = LLM_CONFIG

# Shared Secret for Agent Authentication (Secure Communication)
# VULNERABILITY (ASI07): If Coordinator is tricked into connecting to a malicious agent,
# it will send this secret in the X-Agent-Auth header, allowing the attacker to steal it.
AGENT_SHARED_SECRET = "sk_secure_coordinator_token_2026"

# Service Ports
PORTS = {
    'webapp': 5000,
    'registry': 5001,
    'planning_agent': 5002,
    'execution_agent': 5003,
    'investigator_agent': 5005
}

# Registry Service URL
REGISTRY_URL = f"http://localhost:{PORTS['registry']}"

# Wazuh Alert Fetcher Configuration
WAZUH_CONFIG = {
    'alerts_path': '/var/ossec/logs/alerts/alerts.json',
    # Use echo to pipe password to sudo -S for non-interactive SSH
    # Using -n 200 to capture more alerts and reduce chance of missing any
    'filter_command': f"echo '{SSH_CONFIG['password']}' | sudo -S tail -n 200 /var/ossec/logs/alerts/alerts.json 2>/dev/null | jq -c 'select(.rule.groups[]? | contains(\"webapp\"))'",
    'poll_interval_seconds': 5
}

# Database Configuration
DATABASE_PATH = r'c:\Users\Mahesh  Nagabhairava\Downloads\Agentic AI - Labs\Insecure Agent-to-Agent Communication\Test-Set-1\shopping.db'

# Logging Configuration
import os
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
INCIDENTS_LOG = os.path.join(LOGS_DIR, 'incidents.log')

# Application Log Path (for Investigator Agent)
APP_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Test-Set-1', 'logs', 'app_requests.log')

# Log Analysis Configuration
APP_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../Test-Set-1/logs/app_requests.log")
INVESTIGATION_WINDOW = {
    'before_minutes': 3,  # Changed from 5 to 3
    'after_minutes': 2
}

# Deduplication Configuration
# Window in seconds to ignore redundant alerts from same source unless severity increases
DEDUPLICATION_WINDOW = 60  # 1 minute

# IP Blocklist Configuration
BLOCKLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocked_ips.json')
IP_BLOCK_DURATION_MINUTES = 5

# Critical Agent Alerts (System Errors visible in Dashboard)
AGENT_ALERTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent_alerts.json')

# Web App Configuration (for session invalidation)
WEBAPP_URL = f"http://localhost:{PORTS['webapp']}"

