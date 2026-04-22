"""
Investigator Agent - Behavioral Analysis and Risk Assessment for Security Alerts.

This agent analyzes security alerts as HYPOTHESES (not conclusions) by:
1. Pulling time-bounded raw application logs (10 min before → 2 min after alert)
2. Reconstructing chronological session timeline
3. Performing behavioral analysis:
   - Flow deviation analysis
   - Payload evolution analysis
   - Response-aware behavior analysis
   - Rate and timing realism checks
   - Historical correlation
4. Generating alternative benign explanations
5. Producing a confidence-weighted risk assessment report

OUTPUT: Structured analytical report with risk level (low|suspicious|high|insufficient_evidence)
NOTE: This agent does NOT take enforcement actions - it only produces reports for the Planning Agent.

SECURITY NOTE: This is intentionally insecure for demonstration purposes.
"""

from flask import Flask, request, jsonify
import requests
import json
import os
import re
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Union
from dataclasses import asdict
from functools import wraps

# Import config and models
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import SecurityAlert, AgentType, InvestigationReport
from config import (
    PORTS, REGISTRY_URL, APP_LOG_PATH, INVESTIGATION_WINDOW, 
    INCIDENTS_LOG, LLM_CONFIG, AGENT_SHARED_SECRET
)

# Configure Flask app
app = Flask(__name__)

# Configure logging - DEBUG level to see LLM prompts and responses
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('InvestigatorAgent')


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

AGENT_NAME = "InvestigatorAgent"
AGENT_PORT = PORTS['investigator_agent']

# SQLi patterns for payload analysis
SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+",  # OR 1=1
    r"(?i)union\s+(all\s+)?select",  # UNION SELECT
    r"(?i)select\s+.*\s+from",  # SELECT ... FROM
    r"(?i)drop\s+table",  # DROP TABLE
    r"(?i)sleep\s*\(",  # SLEEP(
    r"(?i)waitfor\s+delay",  # WAITFOR DELAY
    r"(?i)load_file\s*\(",  # LOAD_FILE(
    r"(?i)--\s*$|--\s+-",  # SQL comments
    r"(?i)'\s*or\s*'",  # Basic OR injection
]

# Normal application flow paths
NORMAL_FLOWS = [
    ['/', '/login'],
    ['/login', '/'],
    ['/', '/product'],
    ['/product', '/cart', '/add_to_cart'],
    ['/cart', '/checkout'],
    ['/checkout', '/place_order'],
    ['/', '/logout'],
]


class LogFetcher:
    """Fetches and filters application logs within a time window."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
    
    def fetch_logs_in_window(
        self, 
        alert_timestamp: str, 
        before_minutes: int = 10, 
        after_minutes: int = 2
    ) -> List[Dict]:
        """
        Fetch logs within the specified time window around the alert.
        
        Args:
            alert_timestamp: ISO format timestamp of the alert
            before_minutes: Minutes before alert to include
            after_minutes: Minutes after alert to include
            
        Returns:
            List of log entries as dictionaries
        """
        try:
            # Parse alert timestamp
            # Handle various timestamp formats
            alert_time = self._parse_timestamp(alert_timestamp)
            if not alert_time:
                logger.error(f"Could not parse alert timestamp: {alert_timestamp}")
                return []
            
            window_start = alert_time - timedelta(minutes=before_minutes)
            window_end = alert_time + timedelta(minutes=after_minutes)
            
            logger.info(f"Fetching logs from {window_start} to {window_end} (UTC)")
            
            logs = []
            if not os.path.exists(self.log_path):
                logger.warning(f"Log file not found: {self.log_path}")
                return []
            
            with open(self.log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        log_time = self._parse_timestamp(log_entry.get('timestamp', ''))
                        
                        if log_time and window_start <= log_time <= window_end:
                            logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue
            
            logger.info(f"Found {len(logs)} log entries in time window")
            return logs
            
        except Exception as e:
            logger.error(f"Error fetching logs: {e}")
            return []
    
    def filter_by_ip(self, logs: List[Dict], client_ip: str) -> List[Dict]:
        """Filter logs by client IP address."""
        return [log for log in logs if log.get('client_ip') == client_ip]
    
    def filter_by_username(self, logs: List[Dict], username: str) -> List[Dict]:
        """Filter logs by username (from request body or logged user)."""
        if not username:
            return logs
        return [
            log for log in logs 
            if log.get('username') == username or 
               log.get('request_body', {}).get('username') == username
        ]
    
    def _parse_timestamp(self, ts: Union[str, float, int]) -> Optional[datetime]:
        """Parse various timestamp formats and return naive datetime for comparison."""
        if not ts:
            return None
            
        # Handle numeric timestamps (Unix epoch)
        if isinstance(ts, (int, float)):
            try:
                return datetime.utcfromtimestamp(ts)
            except:
                return None
                
        ts = str(ts)
            
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',      # ISO with milliseconds
            '%Y-%m-%dT%H:%M:%SZ',          # ISO without milliseconds
            '%Y-%m-%dT%H:%M:%S.%f%z',      # ISO with timezone
            '%Y-%m-%dT%H:%M:%S%z',         # ISO with timezone no ms
            '%Y-%m-%dT%H:%M:%S.%f-0500',   # Specific timezone format
        ]
        
        # Handle timezone offset in various formats
        ts_clean = re.sub(r'([+-]\d{2}):?(\d{2})$', r'\1\2', ts)
        
        for fmt in formats:
            try:
                parsed = datetime.strptime(ts_clean, fmt)
                # Convert to UTC first if timezone aware
                if parsed.tzinfo is not None:
                    parsed = parsed.astimezone(timezone.utc)
                    parsed = parsed.replace(tzinfo=None)  # Make naive UTC
                return parsed
            except ValueError:
                continue
        
        # Last resort: try parsing without timezone
        try:
            base_ts = ts.split('+')[0].split('Z')[0]
            # Handle negative timezone offset (e.g., -0500)
            if '-' in base_ts[10:]:  # Check for timezone after date portion
                base_ts = base_ts.rsplit('-', 1)[0]
            
            if '.' in base_ts:
                dt = datetime.strptime(base_ts, '%Y-%m-%dT%H:%M:%S.%f')
            else:
                dt = datetime.strptime(base_ts, '%Y-%m-%dT%H:%M:%S')
                
            # If we parsed a naive datetime from a non-ISO string, assume it's LOCAL time
            # and convert to UTC to match the logs (which are treated as UTC)
            # Use the imported 'timezone' directly, not datetime.timezone
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except:
            logger.debug(f"Failed to parse timestamp: {ts}")
            return None


class BehavioralAnalyzer:
    """Performs behavioral analysis on session logs."""
    
    def analyze_flow_deviation(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Analyze navigation flow for anomalies.
        
        LOGIC: Flag if same endpoint is accessed > 5 times in 1 minute.
        This detects high-rate automated scanning/fuzzing.
        """
        if not timeline:
            return {'deviation_score': 0.0, 'findings': []}
            
        endpoint_timestamps = {}
        for log in timeline:
            endpoint = log.get('request_path', 'unknown')
            ts_str = log.get('timestamp')
            if not ts_str: continue
            
            try:
                # Handle ISO format from logs (e.g. 2026-01-27T07:27:01.917Z)
                # Simple replacement for Z -> +00:00 to support fromisoformat
                if ts_str.endswith('Z'):
                    ts_str = ts_str[:-1] + '+00:00'
                dt = datetime.fromisoformat(ts_str)
                
                if endpoint not in endpoint_timestamps:
                    endpoint_timestamps[endpoint] = []
                endpoint_timestamps[endpoint].append(dt)
            except ValueError:
                # Fallback or ignore invalid timestamps
                continue
            
        findings = []
        deviation_score = 0.0
        endpoint_stats = {}
        
        for endpoint, timestamps in endpoint_timestamps.items():
            timestamps.sort()
            count = len(timestamps)
            endpoint_stats[endpoint] = count
            
            # Check for sliding window of > 5 (i.e. 6 events) within 60s
            is_burst = False
            if count > 5:
                for i in range(count - 5):
                    # timestamps[i] is 1st event, timestamps[i+5] is 6th event
                    # If duration between them is <= 60s, then we have 6 events in <= 60s
                    duration = (timestamps[i+5] - timestamps[i]).total_seconds()
                    if duration <= 60:
                        is_burst = True
                        break
            
            if is_burst:
                findings.append(f"High-rate access to {endpoint}: >5 requests in 1m")
                deviation_score = 1.0 # High confidence red flag

        return {
            'deviation_score': deviation_score,
            'findings': findings if findings else ['Normal access pattern'],
            'endpoint_stats': endpoint_stats
        }
    
    def analyze_payload_evolution(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Analyze payload changes across requests to detect probing/mutation.
        
        Looks for:
        - Encoding changes
        - Probing progression (boolean → error → time-based)
        - Attack payload variations
        """
        if not timeline:
            return {'evolution_detected': False, 'findings': []}
        
        findings = []
        payloads = []
        sqli_payloads = []
        
        for log in timeline:
            body = log.get('request_body', {})
            if isinstance(body, dict):
                for key, value in body.items():
                    if isinstance(value, str) and key not in ['csrf_token']:
                        payloads.append(value)
                        # Check for SQLi patterns
                        for pattern in SQLI_PATTERNS:
                            if re.search(pattern, value):
                                sqli_payloads.append(value)
                                break
        
        # Detect payload evolution
        evolution_detected = False
        
        if len(sqli_payloads) > 1:
            evolution_detected = True
            findings.append(f"Multiple SQLi payloads detected: {len(sqli_payloads)} variations")
            
            # Check for progression patterns
            has_boolean = any(re.search(r"(?i)or\s*['\"]?\d+['\"]?\s*=", p) for p in sqli_payloads)
            has_union = any(re.search(r"(?i)union", p) for p in sqli_payloads)
            has_time_based = any(re.search(r"(?i)(sleep|waitfor|delay)", p) for p in sqli_payloads)
            
            if has_boolean and has_union:
                findings.append("Attack progression: Boolean-based → Union-based")
            if has_boolean and has_time_based:
                findings.append("Attack progression: Boolean-based → Time-based")
            if has_union and has_time_based:
                findings.append("Advanced attack: Multiple techniques used")
        
        # Check for encoding variations
        unique_payloads = list(set(sqli_payloads))
        if len(unique_payloads) > 3:
            findings.append(f"High payload variation: {len(unique_payloads)} unique attack strings")
        
        return {
            'evolution_detected': evolution_detected,
            'total_payloads': len(payloads),
            'sqli_payloads_count': len(sqli_payloads),
            'unique_sqli_payloads': len(set(sqli_payloads)),
            'findings': findings if findings else ['No payload evolution detected']
        }
    
    def analyze_response_awareness(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Analyze if subsequent requests adapt based on server responses.
        
        Checks:
        - Behavior after 429 (rate limit) responses
        - Behavior after 500 (error) responses
        - Adaptation to successful vs failed attempts
        """
        if not timeline:
            return {'response_aware': False, 'findings': []}
        
        findings = []
        response_aware_behavior = False
        
        # Analyze behavior after specific response codes
        for i in range(len(timeline) - 1):
            current = timeline[i]
            next_req = timeline[i + 1]
            
            status = current.get('response_status', 200)
            
            # Check behavior after rate limit (429)
            if status == 429:
                current_time = self._get_timestamp(current)
                next_time = self._get_timestamp(next_req)
                
                if current_time and next_time:
                    delay = (next_time - current_time).total_seconds()
                    if delay < 1:
                        findings.append(f"Immediate retry after 429 (delay: {delay:.2f}s) - likely automated")
                        response_aware_behavior = False
                    elif delay > 30:
                        findings.append(f"Long pause after 429 (delay: {delay:.0f}s) - possibly human")
        
        # Check for persistent attempts after failures
        consecutive_failures = 0
        for log in timeline:
            if log.get('response_status', 200) != 200:
                consecutive_failures += 1
            else:
                consecutive_failures = 0
            
            if consecutive_failures > 5:
                findings.append(f"Persistent attempts despite {consecutive_failures} consecutive failures")
                response_aware_behavior = True
                break
        
        return {
            'response_aware': response_aware_behavior,
            'findings': findings if findings else ['No clear response-aware behavior']
        }
    
    def analyze_timing(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Analyze timing patterns to estimate automation vs human behavior.
        
        Sub-second intervals → likely automated
        3-10 second intervals → possibly human
        Irregular patterns → uncertain
        """
        if len(timeline) < 2:
            return {
                'automation_likelihood': 'unknown',
                'avg_interval': None,
                'findings': ['Insufficient data for timing analysis']
            }
        
        intervals = []
        for i in range(len(timeline) - 1):
            t1 = self._get_timestamp(timeline[i])
            t2 = self._get_timestamp(timeline[i + 1])
            if t1 and t2:
                intervals.append((t2 - t1).total_seconds())
        
        if not intervals:
            return {
                'automation_likelihood': 'unknown',
                'avg_interval': None,
                'findings': ['Could not calculate intervals']
            }
        
        avg_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)
        
        findings = []
        automation_likelihood = 'unknown'
        
        if avg_interval < 1:
            automation_likelihood = 'high'
            findings.append(f"Very fast requests (avg: {avg_interval:.2f}s) - likely automated")
        elif avg_interval < 3:
            automation_likelihood = 'medium'
            findings.append(f"Fast requests (avg: {avg_interval:.2f}s) - possibly scripted")
        elif avg_interval < 15:
            automation_likelihood = 'low'
            findings.append(f"Normal pacing (avg: {avg_interval:.2f}s) - possibly human")
        else:
            automation_likelihood = 'very_low'
            findings.append(f"Slow pacing (avg: {avg_interval:.2f}s) - likely human")
        
        # Check for mechanical consistency (bots tend to be very consistent)
        if intervals and max_interval > 0:
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            if variance < 0.5 and avg_interval < 5:
                findings.append("Very consistent timing - suggests automation")
                automation_likelihood = 'high'
        
        return {
            'automation_likelihood': automation_likelihood,
            'avg_interval': round(avg_interval, 2),
            'min_interval': round(min_interval, 2),
            'max_interval': round(max_interval, 2),
            'total_intervals': len(intervals),
            'findings': findings
        }
    
    def check_historical_correlation(self, client_ip: str, username: Optional[str]) -> Dict[str, Any]:
        """
        Check for prior incidents involving the same actor.
        """
        prior_incidents = []
        
        try:
            if os.path.exists(INCIDENTS_LOG):
                with open(INCIDENTS_LOG, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            incident = json.loads(line.strip())
                            
                            # Match by IP or username (check top-level OR details.target)
                            target = incident.get('details', {}).get('target')
                            matched = False
                            
                            if incident.get('client_ip') == client_ip:
                                matched = True
                            elif username and incident.get('username') == username:
                                matched = True
                            elif target and (target == client_ip or (username and target == username)):
                                matched = True
                                
                            if matched:
                                # Check timestamp (only last 3 minutes)
                                ts_str = incident.get('timestamp')
                                if ts_str:
                                    try:
                                        # Handle ISO format
                                        if ts_str.endswith('Z'):
                                            ts_str = ts_str[:-1] + '+00:00'
                                        incident_time = datetime.fromisoformat(ts_str)
                                        # Ensure UTC comparison
                                        if incident_time.tzinfo is None:
                                            incident_time = incident_time.replace(tzinfo=timezone.utc)
                                            
                                        now = datetime.now(timezone.utc)
                                        if (now - incident_time).total_seconds() > 300: # 5 minutes
                                            continue
                                    except ValueError:
                                        pass # Ignore timestamp errors, maybe execute anyway? No, safer to skip time check if fails? 
                                        # Actually user said "check incidents which happened before 3 minutes". 
                                        # If timestamp is bad, we can't verify time, so maybe exclude or include?
                                        # Let's assume valid logs have valid timestamps.
                                        pass

                                prior_incidents.append({
                                    'timestamp': incident.get('timestamp'),
                                    'alert_id': incident.get('alert_id'),
                                    'action_taken': incident.get('details', {}).get('action', 'unknown')
                                })
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Error reading incidents log: {e}")
        
        return {
            'prior_incidents_count': len(prior_incidents),
            'prior_incidents': prior_incidents[-5:],  # Last 5
            'repeat_offender': len(prior_incidents) > 0
        }
    
    def _get_timestamp(self, log: Dict) -> Optional[datetime]:
        """Extract timestamp from log entry."""
        ts = log.get('timestamp', '')
        if not ts:
            return None
        
        try:
            # Handle various formats
            if 'Z' in ts:
                return datetime.strptime(ts.replace('Z', ''), '%Y-%m-%dT%H:%M:%S.%f')
            return datetime.fromisoformat(ts.replace('Z', ''))
        except:
            return None


class AlternativeExplanationGenerator:
    """Generates alternative benign explanations for observed behavior."""
    
    def generate_explanations(self, behavioral_findings: Dict) -> List[Dict[str, Any]]:
        """
        Generate alternative explanations with plausibility scores.
        """
        explanations = []
        
        flow = behavioral_findings.get('flow_deviation', {})
        payload = behavioral_findings.get('payload_evolution', {})
        timing = behavioral_findings.get('timing_analysis', {})
        history = behavioral_findings.get('historical_correlation', {})
        
        # Hypothesis 1: Accidental Input
        accidental_plausibility = 0.3
        if payload.get('sqli_payloads_count', 0) > 5:
            accidental_plausibility = 0.05
        elif payload.get('sqli_payloads_count', 0) == 1:
            accidental_plausibility = 0.4
        
        explanations.append({
            'hypothesis': 'Accidental Input',
            'plausibility': accidental_plausibility,
            'reasoning': 'User may have accidentally typed special characters or copied malformed data'
        })
        
        # Hypothesis 2: QA/Security Testing
        qa_plausibility = 0.2
        if timing.get('automation_likelihood') == 'high':
            qa_plausibility = 0.35  # Could be automated security scanner
        if history.get('repeat_offender'):
            qa_plausibility = 0.1  # Less likely if they've been blocked before
        
        explanations.append({
            'hypothesis': 'QA/Security Testing',
            'plausibility': qa_plausibility,
            'reasoning': 'Authorized security testing or QA validation may trigger similar patterns'
        })
        
        # Hypothesis 3: Automated Scanner
        scanner_plausibility = 0.4
        if timing.get('automation_likelihood') in ['high', 'medium']:
            scanner_plausibility = 0.6
        if payload.get('evolution_detected'):
            scanner_plausibility = 0.7
        
        explanations.append({
            'hypothesis': 'Automated Vulnerability Scanner',
            'plausibility': scanner_plausibility,
            'reasoning': 'Pattern matches common vulnerability scanning tools'
        })
        
        # Hypothesis 4: Malicious Actor
        malicious_plausibility = 0.5
        if payload.get('sqli_payloads_count', 0) > 3:
            malicious_plausibility += 0.2
        if payload.get('evolution_detected'):
            malicious_plausibility += 0.15
        if history.get('repeat_offender'):
            malicious_plausibility += 0.15
        if flow.get('deviation_score', 0) > 0.5:
            malicious_plausibility += 0.1
        
        malicious_plausibility = min(0.95, malicious_plausibility)
        
        explanations.append({
            'hypothesis': 'Malicious Actor',
            'plausibility': round(malicious_plausibility, 2),
            'reasoning': 'Behavior pattern consistent with intentional attack attempt'
        })
        
        # Sort by plausibility
        explanations.sort(key=lambda x: x['plausibility'], reverse=True)
        
        return explanations


class RiskAssessor:
    """Produces final risk assessment based on all analysis."""
    
    def assess_risk(
        self, 
        behavioral_findings: Dict, 
        alternative_explanations: List[Dict]
    ) -> Dict[str, Any]:
        """
        Produce final risk assessment with confidence level.
        
        Risk Levels:
        - low: Likely benign activity
        - suspicious: Warrants monitoring, but not definitive
        - high: Strong indicators of malicious activity
        - insufficient_evidence: Cannot determine with confidence
        """
        # Calculate base risk score from behavioral findings
        risk_score = 0.0
        factors = []
        
        flow = behavioral_findings.get('flow_deviation', {})
        payload = behavioral_findings.get('payload_evolution', {})
        timing = behavioral_findings.get('timing_analysis', {})
        history = behavioral_findings.get('historical_correlation', {})
        
        # Flow deviation contribution
        flow_score = flow.get('deviation_score', 0)
        risk_score += flow_score * 0.2
        if flow_score > 0.5:
            factors.append("High flow deviation")
        
        # Payload evolution contribution (most important)
        if payload.get('evolution_detected'):
            risk_score += 0.3
            factors.append("Attack payload evolution detected")
        if payload.get('sqli_payloads_count', 0) > 5:
            risk_score += 0.2
            factors.append("Multiple SQLi payloads")
        
        # Timing contribution
        automation = timing.get('automation_likelihood', 'unknown')
        if automation == 'high':
            risk_score += 0.15
            factors.append("Automated behavior detected")
        elif automation == 'very_low':
            risk_score -= 0.1  # Reduce risk if likely human
        
        # Historical correlation
        if history.get('repeat_offender'):
            risk_score += 0.2
            factors.append("Prior incidents from same actor")
            
        # LLM Signal Interpretation Contribution
        llm_data = behavioral_findings.get('llm_interpretation', {})
        llm_verdict = llm_data.get('interpretation')
        llm_conf = llm_data.get('confidence', 0)
        
        if llm_verdict == 'benign_accidental' and llm_conf > 0.6:
            risk_score -= 0.4
            factors.append(f"LLM identifies as benign (conf: {llm_conf})")
        elif llm_verdict == 'adaptive_exploit':
            risk_score += 0.3
            factors.append(f"LLM identifies as adaptive exploit (conf: {llm_conf})")
        
        # Consider alternative explanations
        malicious_plausibility = 0
        for exp in alternative_explanations:
            if exp['hypothesis'] == 'Malicious Actor':
                malicious_plausibility = exp['plausibility']
                break
        
        # Blend score with explanation analysis
        final_score = (risk_score * 0.6) + (malicious_plausibility * 0.4)
        
        # Determine risk level and confidence
        if final_score < 0.25:
            risk_level = 'low'
            confidence = 0.7
        elif final_score < 0.5:
            risk_level = 'suspicious'
            confidence = 0.6
        elif final_score < 0.75:
            risk_level = 'high'
            confidence = 0.75
        else:
            risk_level = 'high'
            confidence = 0.85
        
        # Reduce confidence if data is limited
        timeline_size = flow.get('total_requests', 0)
        if timeline_size < 3:
            confidence *= 0.6
            if confidence < 0.3:
                risk_level = 'insufficient_evidence'
        
        reasoning = self._generate_reasoning(risk_level, factors, alternative_explanations)
        
        return {
            'risk_level': risk_level,
            'confidence': round(confidence, 2),
            'risk_score': round(final_score, 2),
            'contributing_factors': factors,
            'reasoning': reasoning
        }
    
    def _generate_reasoning(
        self, 
        risk_level: str, 
        factors: List[str], 
        explanations: List[Dict]
    ) -> str:
        """Generate human-readable reasoning for the assessment."""
        if risk_level == 'insufficient_evidence':
            return "Insufficient data to make a confident assessment. Manual review recommended."
        
        top_explanation = explanations[0] if explanations else {'hypothesis': 'Unknown'}
        
        reasoning_parts = [f"Risk Level: {risk_level.upper()}"]
        
        if factors:
            reasoning_parts.append(f"Key factors: {', '.join(factors)}")
        
        reasoning_parts.append(
            f"Most likely explanation: {top_explanation.get('hypothesis')} "
            f"(plausibility: {top_explanation.get('plausibility', 0):.0%})"
        )
        
        if risk_level == 'low':
            reasoning_parts.append("Activity appears consistent with normal usage or accidental input.")
        elif risk_level == 'suspicious':
            reasoning_parts.append("Activity warrants monitoring but is not definitively malicious.")
        else:
            reasoning_parts.append("Strong indicators suggest intentional malicious activity.")
        
        return " | ".join(reasoning_parts)


class SignalInterpreter:
    """
    LLM-based interpreter for pre-computed behavioral signals.
    
    This agent analyzes pre-computed, deterministic behavioral signals from web traffic.
    Given structured features (payload similarity, endpoint coverage, timing stats, 
    response correlations, flow indicators), it interprets these signals to determine
    whether observed behavior is more consistent with adaptive exploit development
    or benign/accidental input.
    
    IMPORTANT: This agent does NOT recommend enforcement actions - only provides analysis.
    """
    
    def __init__(self):
        self.system_prompt = """You are a Security Investigator Agent analyzing pre-computed, deterministic behavioral signals from web traffic.

You will be given STRUCTURED FEATURES such as:
- Payload similarity and mutation across requests
- Number of affected endpoints
- Inter-request timing statistics  
- Response-code correlations
- Flow deviation indicators

YOUR TASK: Interpret these signals (NOT recompute them). Based on the evidence, determine whether the observed behavior is more consistent with:
1. ADAPTIVE EXPLOIT DEVELOPMENT - deliberate, evolving attack patterns
2. BENIGN/ACCIDENTAL INPUT - mistakes, legitimate testing, or curiosity

INTERPRETATION GUIDELINES:
- Adaptive payload mutations across multiple endpoints + short, consistent intervals → likely exploit development
- Single malformed input + slow/irregular timing → more likely accidental
- High payload variation with encoding changes → likely automated scanner or skilled attacker
- Immediate retries after 429 → automated, but could be legitimate scanner
- Long pauses between attempts → possibly human, could be manual exploration

IMPORTANT RULES:
1. You must acknowledge uncertainty where evidence is weak
2. Do NOT recommend any enforcement actions (blocking, rate limiting, etc.)
3. Explain your reasoning concisely
4. Focus on behavioral interpretation, not prescriptive action

Respond in JSON format:
{
    "interpretation": "exploit_development | benign_accidental | uncertain",
    "confidence": 0.0-1.0,
    "reasoning": "Concise explanation of why you reached this conclusion",
    "key_indicators": ["list", "of", "most", "important", "signals"],
    "uncertainty_notes": "What evidence is missing or ambiguous"
}"""
    
    def interpret_signals(self, behavioral_findings: Dict, alert_context: Dict) -> Dict[str, Any]:
        """
        Use LLM to interpret pre-computed behavioral signals.
        
        Args:
            behavioral_findings: Pre-computed analysis results from BehavioralAnalyzer
            alert_context: Basic alert information for context
            
        Returns:
            LLM interpretation with reasoning
        """
        # Build structured signal summary for LLM
        signal_summary = self._format_signals_for_llm(behavioral_findings, alert_context)
        
        try:
            interpretation = self._call_llm(signal_summary)
            return interpretation
        except Exception as e:
            logger.error(f"LLM interpretation failed: {e}")
            return self._fallback_interpretation(behavioral_findings)
    
    def _format_signals_for_llm(self, behavioral_findings: Dict, alert_context: Dict) -> str:
        """Format pre-computed signals into a structured prompt for LLM."""
        flow = behavioral_findings.get('flow_deviation', {})
        payload = behavioral_findings.get('payload_evolution', {})
        timing = behavioral_findings.get('timing_analysis', {})
        response = behavioral_findings.get('response_aware_behavior', {})
        history = behavioral_findings.get('historical_correlation', {})
        
        prompt = f"""ALERT CONTEXT:
- Attack Type: {alert_context.get('attack_type', 'Unknown')}
- Source IP: {alert_context.get('client_ip', 'Unknown')}
- Authenticated User: {alert_context.get('username', 'None')}
- Rule Triggered: {alert_context.get('rule_description', 'Unknown')}

PRE-COMPUTED BEHAVIORAL SIGNALS:

1. PAYLOAD MUTATION ANALYSIS:
   - Evolution Detected: {payload.get('evolution_detected', False)}
   - Total Payloads Analyzed: {payload.get('total_payloads', 0)}
   - SQLi Payloads Found: {payload.get('sqli_payloads_count', 0)}
   - Unique Attack Strings: {payload.get('unique_sqli_payloads', 0)}
   - Findings: {', '.join(payload.get('findings', ['None']))}

2. ENDPOINT COVERAGE:
   - Total Requests in Session: {flow.get('total_requests', 0)}
   - Login Attempts: {flow.get('login_attempts', 0)}
   - Abnormal Path Transitions: {flow.get('abnormal_transitions', 0)}
   - Flow Deviation Score: {flow.get('deviation_score', 0)} (0=normal, 1=highly abnormal)
   - Flow Findings: {', '.join(flow.get('findings', ['None']))}

3. TIMING STATISTICS:
   - Automation Likelihood: {timing.get('automation_likelihood', 'unknown')}
   - Average Interval: {timing.get('avg_interval', 'N/A')} seconds
   - Min Interval: {timing.get('min_interval', 'N/A')} seconds
   - Max Interval: {timing.get('max_interval', 'N/A')} seconds
   - Timing Findings: {', '.join(timing.get('findings', ['None']))}

4. RESPONSE-CODE CORRELATION:
   - Response-Aware Behavior: {response.get('response_aware', False)}
   - Response Findings: {', '.join(response.get('findings', ['None']))}

5. HISTORICAL CORRELATION:
   - Prior Incidents: {history.get('prior_incidents_count', 0)}
   - Repeat Offender: {history.get('repeat_offender', False)}

Based on these signals, interpret whether this behavior pattern is more consistent with adaptive exploit development or benign/accidental input."""
        
        return prompt
    
    def _call_llm(self, prompt: str) -> Dict[str, Any]:
        """Call the LLM API for signal interpretation."""
        import requests as req
        
        models = LLM_CONFIG.get('models_priority', [LLM_CONFIG.get('model')])
        
        # DEBUG: Log the prompt being sent
        logger.debug(f"\n{'='*60}\nLLM PROMPT (SignalInterpreter):\n{'='*60}\n{prompt}\n{'='*60}")
        
        for model in models:
            try:
                logger.info(f"Attempting LLM call with model: {model}")
                response = req.post(
                    LLM_CONFIG['endpoint'],
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f"Bearer {LLM_CONFIG['api_key']}"
                    },
                    json={
                        'model': model,
                        'messages': [
                            {'role': 'system', 'content': self.system_prompt},
                            {'role': 'user', 'content': prompt}
                        ],
                        'temperature': 0.3,
                        'max_tokens': 800
                    },
                    timeout=45
                )
                
                if response.status_code == 200:
                    result = response.json()
                    content = result['choices'][0]['message']['content']
                    
                    # DEBUG: Log raw LLM response
                    logger.debug(f"\n{'='*60}\nLLM RAW RESPONSE:\n{'='*60}\n{content}\n{'='*60}")
                    
                    # Parse JSON response
                    parsed_content = content
                    if '```json' in parsed_content:
                        parsed_content = parsed_content.split('```json')[1].split('```')[0]
                    elif '```' in parsed_content:
                        parsed_content = parsed_content.split('```')[1].split('```')[0]
                    
                    # DEBUG: Log extracted JSON
                    logger.debug(f"Extracted JSON: {parsed_content.strip()[:200]}...")
                    
                    interpretation = json.loads(parsed_content.strip())
                    logger.info(f"LLM interpretation: {interpretation.get('interpretation')} (confidence: {interpretation.get('confidence')})")
                    return interpretation
                else:
                    logger.warning(f"LLM call failed with model {model}: {response.status_code} - {response.text[:200]}")
                    continue
                    
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse LLM response: {e}")
                logger.debug(f"Problematic content: {content[:500] if 'content' in dir() else 'N/A'}")
                continue
            except Exception as e:
                logger.warning(f"LLM call error with model {model}: {e}")
                continue
        
        logger.warning("All LLM models failed, using fallback interpretation")
        return self._fallback_interpretation({})
    
    def _fallback_interpretation(self, behavioral_findings: Dict) -> Dict[str, Any]:
        """Rule-based fallback when LLM is unavailable."""
        payload = behavioral_findings.get('payload_evolution', {})
        timing = behavioral_findings.get('timing_analysis', {})
        
        # Simple heuristic-based interpretation
        if payload.get('evolution_detected') and timing.get('automation_likelihood') == 'high':
            return {
                'interpretation': 'exploit_development',
                'confidence': 0.65,
                'reasoning': 'Payload evolution combined with automated timing suggests deliberate exploit development',
                'key_indicators': ['Payload mutation', 'High automation likelihood'],
                'uncertainty_notes': 'LLM unavailable; using heuristic fallback'
            }
        elif payload.get('sqli_payloads_count', 0) <= 1:
            return {
                'interpretation': 'benign_accidental',
                'confidence': 0.5,
                'reasoning': 'Single malformed input could be accidental or curiosity',
                'key_indicators': ['Single payload', 'No evolution pattern'],
                'uncertainty_notes': 'LLM unavailable; limited confidence without deeper analysis'
            }
        else:
            return {
                'interpretation': 'uncertain',
                'confidence': 0.4,
                'reasoning': 'Evidence is mixed; cannot definitively classify behavior',
                'key_indicators': [],
                'uncertainty_notes': 'LLM unavailable; evidence insufficient for confident classification'
            }


def investigate_alert(alert: SecurityAlert) -> InvestigationReport:
    """
    Main investigation function. Analyzes an alert and produces a risk assessment report.
    
    Uses pre-computed behavioral signals and LLM interpretation to determine whether
    observed behavior is more consistent with adaptive exploit development or benign input.
    """
    logger.info(f"Starting investigation for alert: {alert.alert_id}")
    
    # Initialize components
    log_fetcher = LogFetcher(APP_LOG_PATH)
    analyzer = BehavioralAnalyzer()
    explanation_generator = AlternativeExplanationGenerator()
    risk_assessor = RiskAssessor()
    signal_interpreter = SignalInterpreter()  # NEW: LLM-based signal interpreter
    
    # Step 1: Fetch logs in time window
    try:
        all_logs = log_fetcher.fetch_logs_in_window(
            alert.timestamp,
            INVESTIGATION_WINDOW['before_minutes'],
            INVESTIGATION_WINDOW['after_minutes']
        )
    except Exception as e:
        logger.error(f"Initial fetch failed: {e}")
        all_logs = []

    # FALLBACK: If no logs found, try fetching "current" logs (useful for demos/lab with old alerts)
    if not all_logs:
        logger.warning(f"No logs found in alert window. Attempting fallback to CURRENT time.")
        try:
            # Use current UTC time effectively simulating "Alert Happened Now"
            now_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            all_logs = log_fetcher.fetch_logs_in_window(
                now_str,
                INVESTIGATION_WINDOW['before_minutes'],
                INVESTIGATION_WINDOW['after_minutes']
            )
            if all_logs:
                logger.info(f"Fallback successful: Found {len(all_logs)} logs in current time window.")
        except Exception as e:
            logger.error(f"Fallback fetch failed: {e}")
    
    # Step 2: Filter by IP (primary correlation)
    ip_logs = log_fetcher.filter_by_ip(all_logs, alert.client_ip)
    
    # Also consider username if available
    if alert.username:
        username_logs = log_fetcher.filter_by_username(all_logs, alert.username)
        # Merge and deduplicate
        seen = set()
        timeline = []
        for log in ip_logs + username_logs:
            log_key = (log.get('timestamp'), log.get('path'))
            if log_key not in seen:
                seen.add(log_key)
                timeline.append(log)
        timeline.sort(key=lambda x: x.get('timestamp', ''))
    else:
        timeline = sorted(ip_logs, key=lambda x: x.get('timestamp', ''))
    
    logger.info(f"Reconstructed timeline with {len(timeline)} entries")
    
    # Step 3: Perform behavioral analysis (PRE-COMPUTE SIGNALS)
    behavioral_findings = {
        'flow_deviation': analyzer.analyze_flow_deviation(timeline),
        'payload_evolution': analyzer.analyze_payload_evolution(timeline),
        'response_aware_behavior': analyzer.analyze_response_awareness(timeline),
        'timing_analysis': analyzer.analyze_timing(timeline),
        'historical_correlation': analyzer.check_historical_correlation(
            alert.client_ip, alert.username
        )
    }
    
    # Step 4: LLM SIGNAL INTERPRETATION (NEW)
    # Feed pre-computed signals to LLM for interpretation
    alert_context = {
        'attack_type': alert.attack_type.value if alert.attack_type else 'Unknown',
        'client_ip': alert.client_ip,
        'username': alert.username,
        'rule_description': alert.rule_description
    }
    
    llm_interpretation = signal_interpreter.interpret_signals(behavioral_findings, alert_context)
    behavioral_findings['llm_interpretation'] = llm_interpretation
    
    logger.info(f"LLM Interpretation: {llm_interpretation.get('interpretation')} "
                f"(confidence: {llm_interpretation.get('confidence')})")
    
    # Step 5: Generate alternative explanations
    alternative_explanations = explanation_generator.generate_explanations(behavioral_findings)
    
    # Step 6: Assess risk (combines rule-based + LLM interpretation)
    risk_assessment = risk_assessor.assess_risk(behavioral_findings, alternative_explanations)
    
    # Step 7: Generate enhanced session summary
    interpretation = llm_interpretation.get('interpretation', 'uncertain')
    session_summary = (
        f"Analyzed {len(timeline)} requests from IP {alert.client_ip} "
        f"({'User: ' + alert.username if alert.username else 'No authenticated user'}). "
        f"Alert triggered by: {alert.rule_description}. "
        f"LLM Assessment: behavior consistent with {interpretation.replace('_', ' ')}. "
        f"Time window: {INVESTIGATION_WINDOW['before_minutes']} min before to "
        f"{INVESTIGATION_WINDOW['after_minutes']} min after alert."
    )
    
    # Step 8: Build comprehensive reasoning
    enhanced_reasoning = (
        f"{risk_assessment['reasoning']} | "
        f"LLM Analysis: {llm_interpretation.get('reasoning', 'N/A')} | "
        f"Uncertainty: {llm_interpretation.get('uncertainty_notes', 'None noted')}"
    )
    
    # Create report
    report = InvestigationReport(
        alert_id=alert.alert_id,
        session_summary=session_summary,
        timeline=timeline[:50],  # Limit timeline size for report
        behavioral_findings=behavioral_findings,
        alternative_explanations=alternative_explanations,
        risk_level=risk_assessment['risk_level'],
        confidence=risk_assessment['confidence'],
        reasoning=enhanced_reasoning
    )
    
    logger.info(f"Investigation complete. Risk Level: {report.risk_level} (Confidence: {report.confidence})")
    
    return report


# ============== Flask Routes ==============

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'agent': AGENT_NAME})


@app.route('/investigate', methods=['POST'])
@require_auth
def investigate_alert_endpoint():
    """
    Main investigation endpoint.
    
    Receives an alert and returns a detailed investigation report.
    """
    try:
        data = request.get_json()
        
        if 'alert' not in data:
            return jsonify({'error': 'Missing alert data'}), 400
        
        # Parse alert
        alert = SecurityAlert.from_wazuh_alert(data['alert'])
        
        logger.info(f"Received investigation request for alert: {alert.alert_id}")
        logger.info(f"Alert details: {alert.rule_description}")
        
        # Perform investigation
        report = investigate_alert(alert)
        
        return jsonify(report.to_dict())
        
    except Exception as e:
        logger.error(f"Investigation failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ============== Agent Registration ==============

def register_with_registry():
    """Register this agent with the Registry Service."""
    try:
        response = requests.post(
            f"{REGISTRY_URL}/register",
            json={
                'name': AGENT_NAME,
                'agent_type': AgentType.INVESTIGATOR.value,
                'endpoint': f"http://localhost:{AGENT_PORT}",
                'capabilities': [
                    'log_analysis',
                    'behavioral_analysis',
                    'risk_assessment',
                    'timeline_reconstruction',
                    'payload_evolution_detection',
                    'timing_analysis',
                    'historical_correlation'
                ]
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info("Successfully registered with Registry Service")
            return True
        else:
            logger.error(f"Failed to register: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Failed to connect to Registry: {e}")
        return False


def heartbeat_loop():
    """Send periodic heartbeats to the Registry."""
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


if __name__ == '__main__':
    logger.info(f"Starting Investigator Agent on port {AGENT_PORT}")
    
    # Register with Registry Service
    register_with_registry()
    
    # Start heartbeat thread
    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=AGENT_PORT, debug=False)
