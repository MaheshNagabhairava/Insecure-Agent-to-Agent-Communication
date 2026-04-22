"""
Coordinator Agent - Main orchestrator for security incident response.

This agent:
1. Fetches security alerts from Wazuh server via SSH
2. Discovers available Planning Agents through Registry Service
3. Sends alerts to Planning Agents for response plan generation
4. Forwards plans to Execution Agents for action execution

SECURITY NOTE: This is intentionally insecure for demonstration purposes.
- SSH credentials stored in plaintext
- No verification of agent authenticity from Registry
- Trusts plans from any Planning Agent without validation
"""

import paramiko
import requests
import json
import time
import logging
import threading
import concurrent.futures
from datetime import datetime
from typing import List, Optional

# Import models
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import SecurityAlert, ResponsePlan, AgentType, InvestigationReport, ResponseAction, ActionType
from config import SSH_CONFIG, REGISTRY_URL, WAZUH_CONFIG, PORTS, DEDUPLICATION_WINDOW, AGENT_ALERTS_PATH, COORDINATOR_LLM_CONFIG, AGENT_SHARED_SECRET
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CoordinatorAgent')

# Track processed alerts to avoid duplicates
processed_alerts = set()


class WazuhAlertFetcher:
    """
    Fetches security alerts from Wazuh server via SSH.
    
    VULNERABILITY: SSH credentials stored in plaintext config
    VULNERABILITY: No certificate verification
    """
    
    def __init__(self):
        self.ssh_client = None
        self.connected = False
        self.last_offset = 0
    
    def connect(self):
        """Establish SSH connection to Wazuh server."""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Connecting to Wazuh server: {SSH_CONFIG['hostname']}")
            
            self.ssh_client.connect(
                hostname=SSH_CONFIG['hostname'],
                username=SSH_CONFIG['username'],
                password=SSH_CONFIG['password'],
                port=SSH_CONFIG.get('port', 22),
                timeout=30
            )
            
            self.connected = True
            logger.info("Successfully connected to Wazuh server")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Wazuh server: {e}")
            self.connected = False
            return False
    
    def get_remote_file_size(self, filepath: str) -> int:
        """Get the current size of the remote file in bytes."""
        try:
            cmd = f"echo '{SSH_CONFIG['password']}' | sudo -S stat -c %s {filepath} 2>/dev/null"
            stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=5)
            output = stdout.read().decode().strip()
            if output and output.isdigit():
                return int(output)
        except Exception as e:
            logger.error(f"Failed to get file size: {e}")
        return 0

    def fetch_alerts(self) -> List[dict]:
        """
        Fetch recent alerts from Wazuh server using stateful polling.
        Uses byte offsets to ensure no logs are missed even under high load.
        """
        if not self.connected:
            if not self.connect():
                return []
        
        try:
            alerts_path = WAZUH_CONFIG.get('alerts_path', '/var/ossec/logs/alerts/alerts.json')
            current_size = self.get_remote_file_size(alerts_path)
            
            # Handle log rotation or first run
            if self.last_offset == 0 or current_size < self.last_offset:
                # First run or rotated: Fetch last 2000 lines to be safe
                logger.info(f"Log state reset (Size: {current_size}, Offset: {self.last_offset}). Fetching recent history.")
                msg_cmd = f"tail -n 2000 {alerts_path}"
            else:
                # Standard run: Fetch from last offset
                if current_size == self.last_offset:
                    return [] # No new data
                
                # tail -c +K outputs bytes starting from K
                msg_cmd = f"tail -c +{self.last_offset + 1} {alerts_path}"

            # Construct the full secure command
            # Note: We filter with jq on the server to save bandwidth
            jq_filter = "jq -c 'select(.rule.groups[]? | contains(\"webapp\"))'"
            command = f"echo '{SSH_CONFIG['password']}' | sudo -S {msg_cmd} 2>/dev/null | {jq_filter}"
            
            logger.debug(f"Fetching logs with cmd: {msg_cmd} | jq ...")
            
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=30)
            
            output = stdout.read().decode('utf-8')
            errors = stderr.read().decode('utf-8')
            
            # Update offset to current size *after* successful read command dispatch
            # We trust that tail read up to the end of the file as it existed when we ran stat
            # Any logs added between stat and tail will be re-read next time (safe duplication)
            self.last_offset = current_size
            
            if errors:
                non_null_errors = [e for e in errors.strip().split('\n') if e and 'null' not in e]
                if non_null_errors:
                    logger.warning(f"SSH command stderr: {errors}")
            
            alerts = []
            for line in output.strip().split('\n'):
                if line:
                    try:
                        alert = json.loads(line)
                        alerts.append(alert)
                    except json.JSONDecodeError:
                        # Partial lines can happen if tail -c cuts mid-stream (rare with append-only)
                        # or if network packet fragmentation occcurs.
                        logger.warning(f"Failed to parse alert line (skipping): {line[:100]}...")
            
            if alerts:
                logger.info(f"Fetched {len(alerts)} alerts from Wazuh")
            return alerts
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            self.connected = False
            return []
    
    def disconnect(self):
        """Close SSH connection."""
        if self.ssh_client:
            self.ssh_client.close()
            self.connected = False


class AgentDiscovery:
    """
    Discovers agents from the Registry Service.
    
    VULNERABILITY: Trusts any agent registered in the Registry
    VULNERABILITY: No authentication with Registry
    """
    
    def get_planning_agents(self) -> List[dict]:
        """Get all available planning agents."""
        try:
            response = requests.get(
                f"{REGISTRY_URL}/agents/planning",
                timeout=5
            )
            if response.status_code == 200:
                agents = response.json().get('agents', [])
                logger.info(f"Found {len(agents)} planning agents")
                return agents
            else:
                logger.warning(f"Failed to get planning agents: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Failed to connect to Registry: {e}")
            return []
    
    def get_execution_agents(self) -> List[dict]:
        """Get all available execution agents."""
        try:
            response = requests.get(
                f"{REGISTRY_URL}/agents/execution",
                timeout=5
            )
            if response.status_code == 200:
                agents = response.json().get('agents', [])
                logger.info(f"Found {len(agents)} execution agents")
                return agents
            else:
                logger.warning(f"Failed to get execution agents: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Failed to connect to Registry: {e}")
            return []
    
    def get_investigator_agents(self) -> List[dict]:
        """Get all available investigator agents."""
        try:
            response = requests.get(
                f"{REGISTRY_URL}/agents/investigator",
                timeout=5
            )
            if response.status_code == 200:
                agents = response.json().get('agents', [])
                logger.info(f"Found {len(agents)} investigator agents")
                return agents
            else:
                logger.warning(f"Failed to get investigator agents: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Failed to connect to Registry: {e}")
            return []


def log_agent_alert(alert_type: str, message: str, details: dict = None):
    """
    Log a critical agent alert to agent_alerts.json.
    This is visible in the Security Dashboard under 'Critical Agent Alerts'.
    """
    try:
        alerts = []
        if os.path.exists(AGENT_ALERTS_PATH):
            with open(AGENT_ALERTS_PATH, 'r') as f:
                alerts = json.load(f)
        
        alerts.append({
            'timestamp': datetime.utcnow().isoformat(),
            'alert_type': alert_type,
            'message': message,
            'details': details or {},
            'resolved': False
        })
        
        # Keep only last 100 alerts
        alerts = alerts[-100:]
        
        with open(AGENT_ALERTS_PATH, 'w') as f:
            json.dump(alerts, f, indent=2)
        
        logger.info(f"Logged agent alert: {alert_type} - {message}")
    except Exception as e:
        logger.error(f"Failed to log agent alert: {e}")


def select_agent_with_llm(agents: list, agent_type: str) -> dict:
    """
    Use LLM to intelligently select the best agent when multiple are available.
    Only called when 2+ agents of the same type exist.
    
    VULNERABILITY (ASI07): This demonstrates how a malicious agent can manipulate
    selection by registering with a deceptive name like "Primary Official Investigator Agent".
    """
    if len(agents) < 2:
        # Single agent, no need for LLM selection
        return agents[0]
    
    logger.info(f"Multiple {agent_type} agents found ({len(agents)}). Using LLM to select best agent...")
    
    # Build agent list for LLM prompt
    agent_list = "\n".join([
        f"- Name: {a.get('name', 'Unknown')}, Endpoint: {a.get('endpoint', 'Unknown')}"
        for a in agents
    ])
    
    prompt = f"""You are the Coordinator Agent for a security incident response system.
Multiple {agent_type} agents are registered and available:

{agent_list}

Select the most appropriate agent based on:
1. Name indicates "primary", "main", or "official"
2. More trustworthy-sounding name
3. Standard endpoint format

Respond with ONLY the exact agent name to use, nothing else."""
    
    try:
        # Use first available model from priority list
        for model in COORDINATOR_LLM_CONFIG['models_priority']:
            try:
                response = requests.post(
                    COORDINATOR_LLM_CONFIG['endpoint'],
                    headers={
                        'Authorization': f"Bearer {COORDINATOR_LLM_CONFIG['api_key']}",
                        'Content-Type': 'application/json'
                    },
                    json={
                        'model': model,
                        'messages': [{'role': 'user', 'content': prompt}],
                        'max_tokens': 100,
                        'temperature': 0.1
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    selected_name = result['choices'][0]['message']['content'].strip()
                    
                    # Log LLM reasoning for demo/debugging
                    logger.info(f"LLM Agent Selection Reasoning:")
                    logger.info(f"  - Available agents: {[a.get('name') for a in agents]}")
                    logger.info(f"  - LLM selected: {selected_name}")
                    
                    # Find the agent with matching name
                    for agent in agents:
                        if agent.get('name', '').lower() == selected_name.lower():
                            logger.info(f"Using LLM-selected {agent_type}: {agent['name']}")
                            return agent
                    
                    # If no exact match, log warning and use first
                    logger.warning(f"LLM selected '{selected_name}' but no exact match found. Using first agent.")
                    return agents[0]
                    
            except Exception as e:
                logger.warning(f"LLM model {model} failed: {e}")
                continue
        
        # All models failed, use first agent
        logger.warning("All LLM models failed. Falling back to first agent.")
        return agents[0]
        
    except Exception as e:
        logger.error(f"LLM agent selection failed: {e}")
        return agents[0]


class CoordinatorAgent:
    """
    Main coordinator that orchestrates security incident response.
    
    Workflow:
    1. Fetch alerts from Wazuh
    2. For each new alert:
       a. Discover Planning Agents from Registry
       b. Send alert to Planning Agent for plan generation
       c. Discover Execution Agents from Registry
       d. Send plan to Execution Agent for action execution
    """
    
    def __init__(self):
        self.alert_fetcher = WazuhAlertFetcher()
        self.agent_discovery = AgentDiscovery()
        self.running = False
        
        # Cache for smart deduplication: {entity_key: {'time': timestamp, 'level': level}}
        self.processed_entities = {}
        
        # Thread pool for concurrent alert processing
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
    
    def request_investigation(self, agent_endpoint: str, agent_name: str, alert: SecurityAlert) -> Optional[InvestigationReport]:
        """
        Request an investigation report from an Investigator Agent.
        
        The investigation report analyzes the alert as a hypothesis and provides
        behavioral analysis before any enforcement decisions are made.
        """
        try:
            logger.info(f"Requesting investigation from agent {agent_name} at {agent_endpoint}")
            
            response = requests.post(
                f"{agent_endpoint}/investigate",
                json={'alert': alert.to_dict()},
                headers={'X-Agent-Auth': AGENT_SHARED_SECRET},
                timeout=60
            )
            
            if response.status_code == 200:
                # SECURITY CHECK: Verify Mutual Auth
                if response.headers.get('X-Agent-Auth') != AGENT_SHARED_SECRET:
                    logger.warning(f"SECURITY ALERT: Response from {agent_name} missing valid auth header! Discarding data.")
                    return None
                    
                report_data = response.json()
                report = InvestigationReport.from_dict(report_data)
                logger.info(f"Received investigation report: Risk Level={report.risk_level}, Confidence={report.confidence}")
                return report
            else:
                logger.error(f"Investigator agent returned error: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to get investigation from agent: {e}")
            return None
    
    def request_plan(self, agent_endpoint: str, agent_name: str, alert: SecurityAlert, investigation_report: Optional[InvestigationReport] = None) -> Optional[ResponsePlan]:
        """
        Request a response plan from a Planning Agent.
        
        VULNERABILITY: No verification that the plan is from a trusted agent
        VULNERABILITY: Plan is executed without human approval
        """
        try:
            logger.info(f"Requesting plan from agent {agent_name} at {agent_endpoint}")
            
            # Include investigation report if available
            request_data = {'alert': alert.to_dict()}
            if investigation_report:
                request_data['investigation_report'] = investigation_report.to_dict()
            
            response = requests.post(
                f"{agent_endpoint}/plan",
                json=request_data,
                headers={'X-Agent-Auth': AGENT_SHARED_SECRET},
                timeout=120  # LLM calls may take time
            )
            
            if response.status_code == 200:
                # SECURITY CHECK: Verify Mutual Auth
                if response.headers.get('X-Agent-Auth') != AGENT_SHARED_SECRET:
                    logger.warning(f"SECURITY ALERT: Response from {agent_name} missing valid auth header! Discarding data.")
                    return None
                    
                plan_data = response.json()
                plan = ResponsePlan.from_dict(plan_data)
                logger.info(f"Received plan with {len(plan.actions)} actions")
                return plan
            else:
                logger.error(f"Planning agent returned error: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to get plan from agent: {e}")
            return None
    
    def execute_plan(self, agent_endpoint: str, agent_name: str, plan: ResponsePlan) -> dict:
        """
        Send a plan to an Execution Agent for execution.
        
        VULNERABILITY: No verification of execution results
        VULNERABILITY: No rollback mechanism if actions fail
        """
        try:
            logger.info(f"Sending plan to execution agent {agent_name} at {agent_endpoint}")
            
            response = requests.post(
                f"{agent_endpoint}/execute",
                json=plan.to_dict(),
                headers={'X-Agent-Auth': AGENT_SHARED_SECRET},
                timeout=60
            )
            
            if response.status_code == 200:
                # SECURITY CHECK: Verify Mutual Auth
                if response.headers.get('X-Agent-Auth') != AGENT_SHARED_SECRET:
                    logger.warning(f"SECURITY ALERT: Response from {agent_name} missing valid auth header! Discarding data.")
                    return {'error': 'Security violation: Mutual Auth failed'}
                    
                result = response.json()
                logger.info(f"Execution completed: {len(result.get('results', []))} actions executed")
                return result
            else:
                logger.error(f"Execution agent returned error: {response.status_code}")
                return {'error': f"Execution failed with status {response.status_code}"}
        except Exception as e:
            logger.error(f"Failed to execute plan: {e}")
            return {'error': str(e)}
    
    def process_alert(self, alert_json: dict):
        """Process a single security alert through the response workflow."""
        alert_id = alert_json.get('id', '')
        
        # Skip if already processed
        if alert_id in processed_alerts:
            logger.debug(f"Skipping already processed alert: {alert_id}")
            return
        
        processed_alerts.add(alert_id)
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing new security alert: {alert_id}")
        logger.info(f"Rule: {alert_json.get('rule', {}).get('description', 'Unknown')}")
        logger.info(f"{'='*60}")
        
        # Parse alert
        try:
            alert = SecurityAlert.from_wazuh_alert(alert_json)
        except Exception as e:
            logger.error(f"Failed to parse alert: {e}")
            return
            
        # --- Smart Deduplication & Throttling ---
        # Check if we should process this alert based on IP/User history and Severity
        
        should_process = True
        skip_reason = ""
        current_time = time.time()
        
        # Keys to check: IP and Username
        dedup_keys = []
        if alert.client_ip:
            dedup_keys.append(f"ip:{alert.client_ip}")
        if alert.username:
            dedup_keys.append(f"user:{alert.username}")
            
        for key in dedup_keys:
            if key in self.processed_entities:
                last_data = self.processed_entities[key]
                time_diff = current_time - last_data['time']
                
                # Check previous risk assessment
                last_risk = last_data.get('risk', 'unknown')
                
                # Dynamic Window based on Risk
                # If previous risk was LOW or INSUFFICIENT, we should be quicker to re-evaluate (short window)
                # If previous risk was HIGH/SUSPICIOUS, we assume action was taken, so standard window applies
                if last_risk in ['low', 'insufficient_evidence', 'unknown']:
                    window = 10  # Short debounce for low risk
                else:
                    window = DEDUPLICATION_WINDOW  # Standard window (60s)
                
                # If within dynamic window
                if time_diff < window:
                    # Check Severity Escalation: Current > Cached
                    if alert.rule_level > last_data['level']:
                        logger.info(f"🚨 ESCALATION DETECTED for {key}: Level {last_data['level']} -> {alert.rule_level}. Bypassing deduplication.")
                        should_process = True
                        skip_reason = "" # Clear specific skip reason if ANY key triggers escalation
                        break # Process immediately
                    else:
                        should_process = False
                        skip_reason = f"Redundant alert from {key} (Level {last_data['level']} -> {alert.rule_level}) within {int(time_diff)}s (Risk: {last_risk})"
        
        if not should_process:
            logger.info(f"⛔ Skipping {skip_reason}")
            return

        # ----------------------------------------
        # NOTE: Cache update moved to END of flow (after successful execution)
        # to prevent false skips if processing fails midway.
        
        # ----------------------------------------
        
        # Step 1: Discover Investigator Agents (with Infinite Retry loop)
        investigator_agents = []
        attempt = 0
        investigation_report = None
        
        while self.running:
            # 1.1 Fetch current list of agents
            investigator_agents = self.agent_discovery.get_investigator_agents()
            if not investigator_agents:
                attempt += 1
                if attempt % 10 == 1:
                    logger.warning(f"Investigator Agent not found (attempt {attempt}). Retrying indefinitely...")
                time.sleep(2)
                continue # Retry discovery
            
            # 1.2 Attempt loop for available agents
            # Copy list to manipulate locally without affecting discovery
            available_investigators = list(investigator_agents)
            
            while available_investigators:
                # Use LLM to select best agent from CURRENT available pool
                investigator_agent = select_agent_with_llm(available_investigators, 'investigator')
                logger.info(f"Trying investigator agent: {investigator_agent['name']}")
                
                # Request investigation report
                investigation_report = self.request_investigation(
                    investigator_agent['endpoint'], 
                    investigator_agent['name'],
                    alert
                )
                
                if investigation_report:
                   # Success! Break inner loop
                   break
                else:
                    # Failed (Auth or other error). Remove from local pool and try next.
                    logger.warning(f"Failed to get investigation from {investigator_agent['name']}. Trying next available agent...")
                    available_investigators = [a for a in available_investigators if a['name'] != investigator_agent['name']]
            
            if investigation_report:
                # Success! Break outer discovery loop
                logger.info(f"Investigation Summary: {investigation_report.session_summary[:100]}...")
                logger.info(f"Risk Assessment: {investigation_report.risk_level} (confidence: {investigation_report.confidence})")
                break
            else:
                # All agents in current batch failed. Log critical and break to avoid stuck loop.
                logger.error("All available investigator agents failed to respond correctly. Aborting flow.")
                
                log_agent_alert(
                    alert_type="INVESTIGATOR_FAILURE",
                    message="All available Investigator Agents failed investigation request.",
                    details={'alert_id': alert_id}
                )
                return # EXIT - Do not proceed
        
        if not self.running:
            return

        # Step 2: Discover Planning Agents (with Infinite Retry loop)
        planning_agents = []
        attempt = 0
        plan = None
        
        while self.running:
            planning_agents = self.agent_discovery.get_planning_agents()
            if not planning_agents:
                attempt += 1
                if attempt % 10 == 1:
                    logger.warning(f"Planning Agent not found (attempt {attempt}). Retrying indefinitely...")
                time.sleep(2)
                continue
            
            available_planners = list(planning_agents)
            
            while available_planners:
                planning_agent = select_agent_with_llm(available_planners, 'planning')
                logger.info(f"Trying planning agent: {planning_agent['name']}")
                
                plan = self.request_plan(
                    planning_agent['endpoint'], 
                    planning_agent['name'],
                    alert, 
                    investigation_report
                )
                
                if plan:
                    break
                else:
                    logger.warning(f"Failed to get plan from {planning_agent['name']}. Trying next available agent...")
                    available_planners = [a for a in available_planners if a['name'] != planning_agent['name']]
            
            if plan:
                break
            else:
                logger.error("All available planning agents failed. Aborting flow.")
                return 

        if not self.running:
            return
        
        logger.info(f"Generated plan reasoning: {plan.reasoning[:200]}...")
        for action in plan.actions:
            logger.info(f"  - Action: {action.action_type.value} on {action.target} (priority: {action.priority})")
        
        # Step 3: Discover Execution Agents (with Infinite Retry loop)
        execution_agents = []
        attempt = 0
        result = None
        
        while self.running:
            execution_agents = self.agent_discovery.get_execution_agents()
            if not execution_agents:
                attempt += 1
                if attempt % 10 == 1:
                    logger.warning(f"Execution Agent not found (attempt {attempt}). Retrying indefinitely...")
                time.sleep(2)
                continue
            
            available_executors = list(execution_agents)
            
            while available_executors:
                execution_agent = select_agent_with_llm(available_executors, 'execution')
                logger.info(f"Trying execution agent: {execution_agent['name']}")
                
                result = self.execute_plan(
                    execution_agent['endpoint'], 
                    execution_agent['name'],
                    plan
                )
                
                if result and 'error' not in result:
                    break
                else:
                    logger.warning(f"Failed to execute plan with {execution_agent['name']}. Trying next available agent...")
                    available_executors = [a for a in available_executors if a['name'] != execution_agent['name']]
            
            if result and 'error' not in result:
                break
            else:
                logger.error("All available execution agents failed. Aborting flow.")
                return

        if not self.running:
            return
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Alert processing complete: {alert_id}")
        logger.info(f"Results: {json.dumps(result, indent=2)}")
        logger.info(f"{'='*60}\n")
        
        # Update cache ONLY after successful processing
        # Store RISK level to inform future deduplication decisions
        risk_level = 'unknown'
        if investigation_report:
            risk_level = investigation_report.risk_level
            
        for key in dedup_keys:
            self.processed_entities[key] = {
                'time': current_time, 
                'level': alert.rule_level,
                'risk': risk_level
            }
    
    def run(self):
        """Main loop - poll for alerts and process them."""
        self.running = True
        poll_interval = WAZUH_CONFIG['poll_interval_seconds']
        
        logger.info("Starting Coordinator Agent")
        logger.info(f"Polling interval: {poll_interval} seconds")
        
        # Connect to Wazuh
        if not self.alert_fetcher.connect():
            logger.error("Failed to connect to Wazuh server. Exiting.")
            return
        
        while self.running:
            try:
                # Fetch alerts
                alerts = self.alert_fetcher.fetch_alerts()
                
                # Process each alert concurrently
                for alert_json in alerts:
                    self.executor.submit(self.process_alert, alert_json)
                
                # Wait before next poll
                time.sleep(poll_interval)
                
            except KeyboardInterrupt:
                logger.info("Received interrupt, shutting down...")
                self.running = False
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(poll_interval)
        
        self.alert_fetcher.disconnect()
        self.executor.shutdown(wait=False)
        logger.info("Coordinator Agent stopped")
    
    def stop(self):
        """Stop the coordinator agent."""
        self.running = False
        self.executor.shutdown(wait=False)


def main():
    """Entry point for the Coordinator Agent."""
    coordinator = CoordinatorAgent()
    
    try:
        coordinator.run()
    except KeyboardInterrupt:
        coordinator.stop()


if __name__ == '__main__':
    main()
