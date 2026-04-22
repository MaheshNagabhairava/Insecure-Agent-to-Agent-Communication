"""
Agent Registry Service - Provides agent discovery and registration.

This service allows agents to register themselves and be discovered by
the Coordinator Agent. It maintains an in-memory registry of all active agents.

SECURITY NOTE: This is intentionally insecure for demonstration purposes.
- No authentication required
- No input validation
- Trust any registration request
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import threading
import time
import logging

# Import models - handle both package and direct execution
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import AgentInfo, AgentType
from config import PORTS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests (insecure but intentional)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RegistryService')

# In-memory agent registry
# VULNERABILITY: No authentication, anyone can register/modify agents
agent_registry = {}
registry_lock = threading.Lock()

# Agent TTL (time-to-live) in seconds - agents must heartbeat within this time
AGENT_TTL_SECONDS = 60


def cleanup_stale_agents():
    """Remove agents that haven't sent a heartbeat recently."""
    while True:
        time.sleep(30)  # Check every 30 seconds
        current_time = datetime.utcnow()
        with registry_lock:
            stale_agents = []
            for name, agent in agent_registry.items():
                last_heartbeat = datetime.fromisoformat(agent.last_heartbeat)
                if current_time - last_heartbeat > timedelta(seconds=AGENT_TTL_SECONDS):
                    stale_agents.append(name)
            
            for name in stale_agents:
                logger.warning(f"Removing stale agent: {name}")
                del agent_registry[name]


# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_stale_agents, daemon=True)
cleanup_thread.start()


@app.route('/register', methods=['POST'])
def register_agent():
    """
    Register a new agent or update existing registration.
    
    VULNERABILITY: No authentication - any agent can register with any name
    and claim any capabilities. An attacker could:
    - Register a malicious "planning" agent that generates harmful plans
    - Impersonate existing agents
    - Flood the registry with fake agents
    """
    data = request.get_json()
    
    # Input Validation
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
        
    required_fields = ['name', 'agent_type', 'endpoint']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f"Missing required field: '{field}'"}), 400
            
    # Validate Agent Type
    try:
        agent_type_enum = AgentType(data['agent_type'])
    except ValueError:
        valid_types = [t.value for t in AgentType]
        return jsonify({'error': f"Invalid agent_type '{data['agent_type']}'. Must be one of: {valid_types}"}), 400
    
    agent = AgentInfo(
        name=data['name'],
        agent_type=agent_type_enum,
        endpoint=data['endpoint'],
        capabilities=data.get('capabilities', []),
        registered_at=datetime.utcnow().isoformat(),
        last_heartbeat=datetime.utcnow().isoformat()
    )
    
    with registry_lock:
        agent_registry[agent.name] = agent
    
    logger.info(f"Registered agent: {agent.name} ({agent.agent_type.value}) at {agent.endpoint}")
    
    return jsonify({
        'status': 'registered',
        'agent': agent.to_dict()
    })


@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    """
    Update agent heartbeat timestamp.
    
    VULNERABILITY: No verification that the heartbeat is from the actual agent
    """
    data = request.get_json()
    agent_name = data.get('name')
    
    with registry_lock:
        if agent_name in agent_registry:
            agent_registry[agent_name].last_heartbeat = datetime.utcnow().isoformat()
            return jsonify({'status': 'ok'})
        else:
            return jsonify({'status': 'error', 'message': 'Agent not registered'}), 404


@app.route('/agents', methods=['GET'])
def list_agents():
    """List all registered agents."""
    with registry_lock:
        agents = [agent.to_dict() for agent in agent_registry.values()]
    return jsonify({'agents': agents})


@app.route('/agents/<agent_type>', methods=['GET'])
def get_agents_by_type(agent_type):
    """
    Get all agents of a specific type.
    
    VULNERABILITY: Returns first available agent without any priority/trust scoring
    """
    with registry_lock:
        agents = [
            agent.to_dict() 
            for agent in agent_registry.values() 
            if agent.agent_type.value == agent_type
        ]
    return jsonify({'agents': agents})


@app.route('/agents/<agent_name>', methods=['DELETE'])
def unregister_agent(agent_name):
    """
    Unregister an agent.
    
    VULNERABILITY: Anyone can unregister any agent (DoS attack vector)
    """
    with registry_lock:
        if agent_name in agent_registry:
            del agent_registry[agent_name]
            logger.info(f"Unregistered agent: {agent_name}")
            return jsonify({'status': 'unregistered'})
        else:
            return jsonify({'status': 'error', 'message': 'Agent not found'}), 404


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'registry',
        'registered_agents': len(agent_registry)
    })


if __name__ == '__main__':
    logger.info(f"Starting Registry Service on port {PORTS['registry']}")
    app.run(host='0.0.0.0', port=PORTS['registry'], debug=True, threaded=True)
