"""
Shared data models for the multi-agent security incident response system.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import json


class AttackType(Enum):
    """Types of security attacks detected by Wazuh."""
    SQLI = "sqli"
    XSS = "xss"
    BRUTE_FORCE = "brute_force"
    UNKNOWN = "unknown"


class ActionType(Enum):
    """Types of response actions that can be executed."""
    BLOCK_ACCOUNT = "block_account"
    INVALIDATE_SESSION = "invalidate_session"
    BLOCK_IP = "block_ip"
    LOG_INCIDENT = "log_incident"
    RATE_LIMIT = "rate_limit"


class AgentType(Enum):
    """Types of agents in the system."""
    PLANNING = "planning"
    EXECUTION = "execution"
    COORDINATOR = "coordinator"
    INVESTIGATOR = "investigator"


@dataclass
class SecurityAlert:
    """Represents a parsed Wazuh security alert."""
    timestamp: str
    rule_id: str
    rule_description: str
    rule_level: int
    agent_name: str
    agent_ip: str
    client_ip: str
    username: Optional[str]
    attack_type: AttackType
    attack_groups: List[str]
    path: str
    url: str
    request_body: Dict[str, Any]
    full_log: str
    alert_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp,
            'rule_id': self.rule_id,
            'rule_description': self.rule_description,
            'rule_level': self.rule_level,
            'agent_name': self.agent_name,
            'agent_ip': self.agent_ip,
            'client_ip': self.client_ip,
            'username': self.username,
            'attack_type': self.attack_type.value,
            'attack_groups': self.attack_groups,
            'path': self.path,
            'url': self.url,
            'request_body': self.request_body,
            'full_log': self.full_log,
            'alert_id': self.alert_id
        }
    
    @classmethod
    def from_wazuh_alert(cls, alert_json: Dict[str, Any]) -> 'SecurityAlert':
        """Create SecurityAlert from raw Wazuh alert JSON or pre-parsed alert dict."""
        rule = alert_json.get('rule', {})
        agent = alert_json.get('agent', {})
        data = alert_json.get('data', {})
        
        # Handle both raw Wazuh format and pre-parsed format from coordinator
        # Pre-parsed format has attack_type/attack_groups at top level
        # Raw Wazuh format has them in rule.groups
        
        # Try to get attack_type directly first (pre-parsed format)
        attack_type_str = alert_json.get('attack_type', '')
        groups = alert_json.get('attack_groups', []) or rule.get('groups', [])
        
        # Determine attack type
        # Determine attack type - STRICTLY PRIORITIZE RULE DESCRIPTION
        attack_type = AttackType.UNKNOWN
        
        rule_desc = rule.get('description', '').lower()
        
        if 'sql injection' in rule_desc or 'sqli' in rule_desc:
            attack_type = AttackType.SQLI
        elif 'cross site scripting' in rule_desc or 'xss' in rule_desc:
            attack_type = AttackType.XSS
        elif 'brute force' in rule_desc or 'Bruteforce' in rule_desc:
            attack_type = AttackType.BRUTE_FORCE
            
        # Fallback to groups if description didn't yield a result
        if attack_type == AttackType.UNKNOWN and groups:
            if 'sqli' in groups:
                attack_type = AttackType.SQLI
            elif 'xss' in groups:
                attack_type = AttackType.XSS
            elif 'brute_force' in groups or 'bruteforce' in groups:
                attack_type = AttackType.BRUTE_FORCE
        
        # Only check attack_type string as a last resort fallback
        if attack_type == AttackType.UNKNOWN and attack_type_str:
            attack_type_map = {
                'sqli': AttackType.SQLI,
                'xss': AttackType.XSS,
                'brute_force': AttackType.BRUTE_FORCE
            }
            attack_type = attack_type_map.get(attack_type_str.lower(), AttackType.UNKNOWN)
        
        # Parse full_log which contains the original JSON log from the web app
        full_log = alert_json.get('full_log', '')
        parsed_log = {}
        if full_log and isinstance(full_log, str):
            try:
                parsed_log = json.loads(full_log)
            except:
                pass
        
        # Get fields from direct alert_json first (pre-parsed), then data, then parsed full_log
        raw_username = alert_json.get('username') or data.get('username') or parsed_log.get('username')
        
        # Treat "null", "None", empty strings, and None as no username
        # This ensures pre-login attacks trigger IP blocking instead of account blocking
        if raw_username in (None, 'null', 'None', '', 'undefined'):
            username = None
        else:
            username = raw_username
        
        client_ip = alert_json.get('client_ip') or data.get('client_ip') or parsed_log.get('client_ip', '')
        path = alert_json.get('path') or data.get('path') or parsed_log.get('path', '')
        url = alert_json.get('url') or data.get('url') or parsed_log.get('url', '')
        
        # Parse request body
        request_body = alert_json.get('request_body') or data.get('request_body', {}) or parsed_log.get('request_body', {})
        if isinstance(request_body, str):
            try:
                request_body = json.loads(request_body)
            except:
                request_body = {'raw': request_body}
        
        # Get alert_id from either alert_id or id field
        alert_id = alert_json.get('alert_id') or alert_json.get('id', '')
        
        # Get rule info from either direct fields or rule object
        rule_id = alert_json.get('rule_id') or rule.get('id', '')
        rule_description = alert_json.get('rule_description') or rule.get('description', '')
        rule_level = alert_json.get('rule_level') or rule.get('level', 0)
        
        # Get agent info from either direct fields or agent object
        agent_name = alert_json.get('agent_name') or agent.get('name', '')
        agent_ip = alert_json.get('agent_ip') or agent.get('ip', '')
        
        return cls(
            timestamp=alert_json.get('timestamp', ''),
            rule_id=rule_id,
            rule_description=rule_description,
            rule_level=rule_level,
            agent_name=agent_name,
            agent_ip=agent_ip,
            client_ip=client_ip,
            username=username,
            attack_type=attack_type,
            attack_groups=groups,
            path=path,
            url=url,
            request_body=request_body,
            full_log=full_log,
            alert_id=alert_id
        )


@dataclass
class ResponseAction:
    """A single action in a response plan."""
    action_type: ActionType
    target: str  # username, IP, session_id, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 1  # 1 = highest priority
    reason: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'action_type': self.action_type.value,
            'target': self.target,
            'parameters': self.parameters,
            'priority': self.priority,
            'reason': self.reason
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResponseAction':
        return cls(
            action_type=ActionType(data['action_type']),
            target=data['target'],
            parameters=data.get('parameters', {}),
            priority=data.get('priority', 1),
            reason=data.get('reason', '')
        )


@dataclass
class ResponsePlan:
    """A complete response plan for a security incident."""
    alert_id: str
    alert_summary: str
    actions: List[ResponseAction] = field(default_factory=list)
    reasoning: str = ""
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    generated_by: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'alert_summary': self.alert_summary,
            'actions': [a.to_dict() for a in self.actions],
            'reasoning': self.reasoning,
            'generated_at': self.generated_at,
            'generated_by': self.generated_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResponsePlan':
        return cls(
            alert_id=data['alert_id'],
            alert_summary=data['alert_summary'],
            actions=[ResponseAction.from_dict(a) for a in data.get('actions', [])],
            reasoning=data.get('reasoning', ''),
            generated_at=data.get('generated_at', ''),
            generated_by=data.get('generated_by', '')
        )


@dataclass
class ExecutionResult:
    """Result of executing a response action."""
    action_type: ActionType
    target: str
    success: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    executed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'action_type': self.action_type.value,
            'target': self.target,
            'success': self.success,
            'message': self.message,
            'details': self.details,
            'executed_at': self.executed_at
        }


@dataclass
class AgentInfo:
    """Registration information for an agent."""
    name: str
    agent_type: AgentType
    endpoint: str
    capabilities: List[str] = field(default_factory=list)
    registered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_heartbeat: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'agent_type': self.agent_type.value,
            'endpoint': self.endpoint,
            'capabilities': self.capabilities,
            'registered_at': self.registered_at,
            'last_heartbeat': self.last_heartbeat
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentInfo':
        return cls(
            name=data['name'],
            agent_type=AgentType(data['agent_type']),
            endpoint=data['endpoint'],
            capabilities=data.get('capabilities', []),
            registered_at=data.get('registered_at', ''),
            last_heartbeat=data.get('last_heartbeat', '')
        )


@dataclass
class InvestigationReport:
    """
    Risk assessment report produced by the Investigator Agent.
    This agent treats alerts as hypotheses, not conclusions.
    """
    alert_id: str
    session_summary: str
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    behavioral_findings: Dict[str, Any] = field(default_factory=dict)
    alternative_explanations: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: str = "insufficient_evidence"  # low | suspicious | high | insufficient_evidence
    confidence: float = 0.0  # 0.0 - 1.0
    reasoning: str = ""
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    generated_by: str = "InvestigatorAgent"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'session_summary': self.session_summary,
            'timeline': self.timeline,
            'behavioral_findings': self.behavioral_findings,
            'alternative_explanations': self.alternative_explanations,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'reasoning': self.reasoning,
            'generated_at': self.generated_at,
            'generated_by': self.generated_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'InvestigationReport':
        return cls(
            alert_id=data.get('alert_id', ''),
            session_summary=data.get('session_summary', ''),
            timeline=data.get('timeline', []),
            behavioral_findings=data.get('behavioral_findings', {}),
            alternative_explanations=data.get('alternative_explanations', []),
            risk_level=data.get('risk_level', 'insufficient_evidence'),
            confidence=data.get('confidence', 0.0),
            reasoning=data.get('reasoning', ''),
            generated_at=data.get('generated_at', ''),
            generated_by=data.get('generated_by', 'InvestigatorAgent')
        )
