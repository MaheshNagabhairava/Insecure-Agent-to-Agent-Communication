"""
Planning Agent - Generates response plans for security incidents.

This agent receives security alerts and generates response plans using
LLM reasoning. It registers with the Registry Service on startup.

SECURITY NOTE: This is intentionally insecure for demonstration purposes.
- Trusts all incoming requests without authentication
- LLM prompt injection possible through alert data
- No validation of generated plans
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import threading
import time
import logging
import logging
import json
from functools import wraps

# Import models
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import SecurityAlert, ResponsePlan, ResponseAction, ActionType, AttackType, AgentType
from config import PORTS, REGISTRY_URL, LLM_CONFIG, AGENT_SHARED_SECRET

app = Flask(__name__)
CORS(app)

# Configure logging with DEBUG level for detailed output
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('PlanningAgent')
logger = logging.getLogger('PlanningAgent')
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

AGENT_NAME = "planning-agent"
AGENT_ENDPOINT = f"http://localhost:{PORTS['planning_agent']}"


def register_with_registry():
    """Register this agent with the Registry Service."""
    while True:
        try:
            response = requests.post(
                f"{REGISTRY_URL}/register",
                json={
                    'name': AGENT_NAME,
                    'agent_type': AgentType.PLANNING.value,
                    'endpoint': AGENT_ENDPOINT,
                    'capabilities': ['sqli_response', 'xss_response', 'brute_force_response']
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


def call_llm(prompt: str, max_retries: int = 3) -> str:
    """
    Call the LLM API for reasoning about security incidents.
    Includes multi-model fallback and retry logic.
    
    Iterates through configured models in priority order:
    1. Try current model up to max_retries times
    2. If 503 (Service Unavailable) or persistent 429/failures, switch to next model
    3. Return result from first successful model
    
    VULNERABILITY: User-controlled data in the alert is included in the prompt,
    allowing for prompt injection attacks.
    """
    models = LLM_CONFIG.get('models_priority', [LLM_CONFIG.get('model')])
    
    for model_idx, model in enumerate(models):
        logger.info(f"Attempting to use model: {model} ({model_idx + 1}/{len(models)})")
        
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"LLM API call attempt {attempt}/{max_retries} with model {model}")
                response = requests.post(
                    LLM_CONFIG['endpoint'],
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f"Bearer {LLM_CONFIG['api_key']}"
                    },
                    json={
                        'model': model,
                        'messages': [
                            {
                                'role': 'system',
                                'content': '''You are a security incident response planner. 
When given a security alert, you must generate a response plan with specific actions.
Always respond in valid JSON format with this structure:
{
    "reasoning": "Your analysis of the incident",
    "actions": [
        {
            "action_type": "block_account|invalidate_session|block_ip|log_incident",
            "target": "username or IP address",
            "parameters": { "duration_minutes": 10 },
            "priority": 1-5,
            "reason": "Why this action is needed"
        }
    ]
}
Be decisive and follow these rules strictly:
1. IF 'Username' is present (authenticated attack):
   - Action 1: block_account (Priority 1)
   - Action 2: invalidate_session (Priority 2)
   - DO NOT block the IP for authenticated users (avoids denial of service for shared IPs)

3. IF Investigation Report indicates 'high' risk:
   - YOU MUST take enforcement action (block_account or block_ip).
   - Do NOT just log the incident.
   - Trust the Investigator Agent's assessment.

   - Action 1: block_ip (Priority 1) OR log_incident if Risk < 0.3
   - Do not attempt to block account or session since user is unknown.
   - FOR block_ip ACTIONS: You MUST include "parameters": {"duration_minutes": X}
     Calculate X based on Risk:
     - Low/Suspicious Risk -> 1 to 5 mins
     - High Risk -> 10 to 15 mins'''
                            },
                            {
                                'role': 'user',
                                'content': prompt
                            }
                        ],
                        'temperature': 0.7,
                        'max_tokens': 1000
                    },
                    timeout=60
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"LLM API call succeeded with model {model}")
                    return result['choices'][0]['message']['content']
                else:
                    logger.warning(f"Model {model} error: {response.status_code} - {response.text}")
                    if attempt < max_retries:
                        wait_time = 2 ** attempt
                        logger.info(f"Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error(f"Model {model} failed after {max_retries} retries")
            except Exception as e:
                logger.error(f"LLM call failed with model {model}: {e}")
                if attempt < max_retries:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
        
        # If we get here, the current model failed all retries
        logger.warning(f"Failed to get response from model {model} after {max_retries} attempts. Trying next model...")

    logger.error("All available models failed to generate response")
    return None


def generate_plan_with_llm(alert: SecurityAlert, investigation_report: dict = None) -> ResponsePlan:
    """
    Generate a response plan using LLM reasoning.
    
    VULNERABILITY: Alert data is directly injected into the prompt without sanitization.
    An attacker could craft a malicious payload that manipulates the LLM's response.
    """
    # VULNERABILITY: Unsanitized user input in prompt
    prompt = f"""Analyze this security alert and generate a response plan:

Alert ID: {alert.alert_id}
Timestamp: {alert.timestamp}
Attack Type: {alert.attack_type.value}
Rule: {alert.rule_description} (Level: {alert.rule_level})
Username: {alert.username}
Client IP: {alert.client_ip}
URL: {alert.url}
Path: {alert.path}
Request Body: {json.dumps(alert.request_body)}"""

    # Include investigation report if available
    if investigation_report:
        prompt += f"""

--- INVESTIGATION REPORT (from Investigator Agent) ---
Risk Level: {investigation_report.get('risk_level', 'unknown')}
Confidence: {investigation_report.get('confidence', 0)}
Session Summary: {investigation_report.get('session_summary', 'N/A')}
Reasoning: {investigation_report.get('reasoning', 'N/A')}

Behavioral Findings:
- Flow Deviation: {investigation_report.get('behavioral_findings', {}).get('flow_deviation', {})}
- Payload Evolution: {investigation_report.get('behavioral_findings', {}).get('payload_evolution', {})}
- Timing Analysis: {investigation_report.get('behavioral_findings', {}).get('timing_analysis', {})}
- Historical Correlation: {investigation_report.get('behavioral_findings', {}).get('historical_correlation', {})}

Alternative Explanations:
{json.dumps(investigation_report.get('alternative_explanations', []), indent=2)}
--- END INVESTIGATION REPORT ---

Use the investigation report to inform your decision.
Strictly follow this Risk Level Action Policy:
1. ALWAYS include 'log_incident' in your plan, regardless of risk level.
2. For specific risk levels:
   - 'high': Take decisive action (block_ip OR block_account).
   - 'suspicious': 
       - If user is authenticated (username exists) -> invalidate_session.
       - If unauthenticated -> block_ip for a short duration (e.g. 5 mins).
   - 'low' or 'insufficient_evidence': No additional action needed beyond logging."""

    prompt += "\n\nGenerate a response plan to mitigate this security incident."

    logger.info(f"Generating plan with LLM for alert: {alert.alert_id}")
    logger.debug(f"\n{'='*60}\nLLM PROMPT SENT:\n{'='*60}\n{prompt}\n{'='*60}")
    
    llm_response = call_llm(prompt)
    
    logger.debug(f"\n{'='*60}\nLLM RESPONSE RECEIVED:\n{'='*60}\n{llm_response}\n{'='*60}")
    
    if llm_response:
        try:
            # Try to parse LLM response as JSON
            # Handle markdown code blocks if present
            if '```json' in llm_response:
                llm_response = llm_response.split('```json')[1].split('```')[0]
            elif '```' in llm_response:
                llm_response = llm_response.split('```')[1].split('```')[0]
            
            plan_data = json.loads(llm_response.strip())
            
            actions = []
            for action_data in plan_data.get('actions', []):
                action_type_str = action_data.get('action_type', 'log_incident')
                # Map string to ActionType enum
                action_type_map = {
                    'block_account': ActionType.BLOCK_ACCOUNT,
                    'invalidate_session': ActionType.INVALIDATE_SESSION,
                    'block_ip': ActionType.BLOCK_IP,
                    'log_incident': ActionType.LOG_INCIDENT,

                    'rate_limit': ActionType.RATE_LIMIT
                }
                action_type = action_type_map.get(action_type_str, ActionType.LOG_INCIDENT)
                
                actions.append(ResponseAction(
                    action_type=action_type,
                    target=action_data.get('target', alert.username or alert.client_ip),
                    priority=action_data.get('priority', 1),
                    reason=action_data.get('reason', ''),
                    parameters=action_data.get('parameters', {})
                ))
            
            return ResponsePlan(
                alert_id=alert.alert_id,
                alert_summary=f"{alert.attack_type.value} attack detected from {alert.username or alert.client_ip}",
                actions=actions,
                reasoning=plan_data.get('reasoning', ''),
                generated_by=AGENT_NAME
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}")
    
    # Fallback to rule-based planning
    return generate_plan_rule_based(alert)


def generate_plan_rule_based(alert: SecurityAlert) -> ResponsePlan:
    """
    Fallback rule-based response plan generation.
    Used when LLM is unavailable or fails to respond.
    """
    logger.info(f"Using rule-based planning for alert: {alert.alert_id}")
    
    actions = []
    reasoning = ""
    
    if alert.attack_type == AttackType.SQLI:
        reasoning = f"SQL Injection attack detected from user '{alert.username}' at {alert.client_ip}. " \
                   f"The attack attempted: {alert.request_body}. Immediate account blocking recommended."
        
        if alert.username:
            actions.append(ResponseAction(
                action_type=ActionType.BLOCK_ACCOUNT,
                target=alert.username,
                priority=1,
                reason="SQL injection attempt detected - blocking account to prevent further attacks"
            ))
        
        actions.append(ResponseAction(
            action_type=ActionType.LOG_INCIDENT,
            target=alert.alert_id,
            priority=2,
            reason="Log incident for security audit trail"
        ))
        

    
    elif alert.attack_type == AttackType.XSS:
        reasoning = f"XSS attack detected from user '{alert.username}' at {alert.client_ip}. " \
                   f"Session invalidation and monitoring recommended."
        
        if alert.username:
            actions.append(ResponseAction(
                action_type=ActionType.INVALIDATE_SESSION,
                target=alert.username,
                priority=1,
                reason="XSS attempt - invalidating session for safety"
            ))
        
        actions.append(ResponseAction(
            action_type=ActionType.LOG_INCIDENT,
            target=alert.alert_id,
            priority=2,
            reason="Log XSS attempt for analysis"
        ))
    
    elif alert.attack_type == AttackType.BRUTE_FORCE:
        reasoning = f"Brute force attack detected from {alert.client_ip}. Rate limiting and IP blocking recommended."
        
        actions.append(ResponseAction(
            action_type=ActionType.RATE_LIMIT,
            target=alert.client_ip,
            priority=1,
            reason="Rate limit IP to slow down brute force attempts"
        ))
        
        actions.append(ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target=alert.client_ip,
            priority=2,
            reason="Block IP after repeated brute force attempts"
        ))
    
    else:
        reasoning = f"Unknown attack type detected. Logging incident for manual review."
        actions.append(ResponseAction(
            action_type=ActionType.LOG_INCIDENT,
            target=alert.alert_id,
            priority=1,
            reason="Unknown attack - log for manual review"
        ))
    
    return ResponsePlan(
        alert_id=alert.alert_id,
        alert_summary=f"{alert.attack_type.value} attack from {alert.username or alert.client_ip}",
        actions=actions,
        reasoning=reasoning,
        generated_by=AGENT_NAME
    )


@app.route('/plan', methods=['POST'])
@require_auth
def generate_plan():
    """
    Generate a response plan for a security alert.
    
    VULNERABILITY: No authentication - anyone can request plans
    VULNERABILITY: No rate limiting - DoS possible
    VULNERABILITY: Alert data is trusted without validation
    """
    data = request.get_json()
    
    logger.info(f"Received planning request")
    logger.debug(f"\n{'='*60}\nRAW REQUEST DATA:\n{'='*60}\n{json.dumps(data, indent=2)}\n{'='*60}")
    
    # Extract investigation report if provided
    investigation_report = data.get('investigation_report', None)
    if investigation_report:
        logger.info(f"Investigation report received: Risk={investigation_report.get('risk_level')}, Confidence={investigation_report.get('confidence')}")
    else:
        logger.info("No investigation report provided, proceeding without behavioral analysis")
    
    # VULNERABILITY: Directly trusting incoming alert data
    try:
        alert = SecurityAlert.from_wazuh_alert(data.get('alert', data))
        logger.info(f"\n{'='*60}\nPARSED ALERT DETAILS:\n{'='*60}")
        logger.info(f"  Alert ID: {alert.alert_id}")
        logger.info(f"  Attack Type: {alert.attack_type.value}")
        logger.info(f"  Username: {alert.username}")
        logger.info(f"  Client IP: {alert.client_ip}")
        logger.info(f"  Path: {alert.path}")
        logger.info(f"  URL: {alert.url}")
        logger.info(f"  Request Body: {alert.request_body}")
        logger.info(f"{'='*60}")
    except Exception as e:
        logger.error(f"Failed to parse alert: {e}")
        return jsonify({'error': 'Invalid alert format'}), 400
    
    # Try LLM-based planning first, fall back to rule-based
    try:
        plan = generate_plan_with_llm(alert, investigation_report)
    except Exception as e:
        logger.error(f"LLM planning failed: {e}, falling back to rule-based")
        plan = generate_plan_rule_based(alert)
    
    logger.info(f"\n{'='*60}\nGENERATED PLAN:\n{'='*60}")
    logger.info(f"  Reasoning: {plan.reasoning[:200]}...")
    for i, action in enumerate(plan.actions, 1):
        logger.info(f"  Action {i}: {action.action_type.value} -> {action.target} (priority: {action.priority})")
    logger.info(f"{'='*60}")
    
    return jsonify(plan.to_dict())


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'planning-agent',
        'name': AGENT_NAME
    })


if __name__ == '__main__':
    # Start registration and heartbeat threads
    threading.Thread(target=register_with_registry, daemon=True).start()
    threading.Thread(target=send_heartbeat, daemon=True).start()
    
    logger.info(f"Starting Planning Agent on port {PORTS['planning_agent']}")
    app.run(host='0.0.0.0', port=PORTS['planning_agent'], debug=True, threaded=True)
