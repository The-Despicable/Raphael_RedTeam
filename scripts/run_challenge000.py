#!/usr/bin/env python3
"""
RBS-v1 Challenge 000: Cognitive Sandbox
Demonstrates pure cognitive reasoning on a fictional network.
No LLM, no exploitation, no real network - pure reasoning.
"""

import json
from json import JSONEncoder

class CognitiveEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, enum.Enum):
            return obj.value
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        return super().default(obj)
import sys
import time
from dataclasses import dataclass, field, asdict
import enum
from typing import Dict, List, Set, Optional, Any
from enum import Enum
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import copy

# ============================================================================
# FICTIONAL NETWORK DEFINITION
# ============================================================================

FICTIONAL_NETWORK = {
    "hosts": [
        {
            "name": "web01",
            "ports": [80, 22],
            "service": "nginx",
            "notes": "login page"
        },
        {
            "name": "db01",
            "ports": [3306],
            "service": "mysql"
        },
        {
            "name": "files01",
            "ports": [445],
            "service": "samba"
        }
    ]
}

# ============================================================================
# COGNITIVE DATA STRUCTURES
# ============================================================================

class HypothesisType(Enum):
    SERVICE_VULN = "service_vulnerability"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DECOY = "decoy"

@dataclass
class Entity:
    name: str
    type: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

@dataclass
class Hypothesis:
    id: str
    type: HypothesisType
    target: str
    description: str
    confidence: float
    evidence_supporting: List[str] = field(default_factory=list)
    evidence_contradicting: List[str] = field(default_factory=list)
    status: str = "active"  # active, rejected, confirmed
    created_at: int = field(default_factory=lambda: int(time.time()))
    rejected_at: Optional[int] = None

@dataclass
class Evidence:
    id: str
    source: str
    type: str
    content: str
    supports: List[str] = field(default_factory=list)  # hypothesis IDs
    contradicts: List[str] = field(default_factory=list)
    timestamp: int = field(default_factory=lambda: int(time.time()))

@dataclass
class Action:
    id: str
    type: str
    target: str
    description: str
    expected_observation: str
    actual_observation: Optional[str] = None
    expected_outcome: str = ""
    timestamp: int = field(default_factory=lambda: int(time.time()))

@dataclass
class WorldModel:
    entities: Dict[str, Entity] = field(default_factory=dict)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: Dict[str, Hypothesis] = field(default_factory=dict)
    evidence: Dict[str, Evidence] = field(default_factory=dict)
    actions: List[Action] = field(default_factory=list)
    iteration: int = 0

@dataclass
class CognitiveTrace:
    iteration: int
    world_model: WorldModel
    hypotheses: List[Hypothesis]
    confidence_before: Dict[str, float]
    confidence_after: Dict[str, float]
    chosen_action: Action
    expected_observation: str
    observed_evidence: str
    belief_updates: List[str]
    reason_for_next: str

# ============================================================================
# SIMULATED ENVIRONMENT
# ============================================================================

class SimulatedEnvironment:
    """Simulates network responses based on the fictional network."""
    
    def __init__(self, network_data: Dict):
        self.network = network_data
        self.hosts = {h["name"]: h for h in network_data["hosts"]}
        self.truth = self._build_truth()
    
    def _build_truth(self) -> Dict:
        """Internal ground truth for the simulation."""
        return {
            "web01": {
                "vulnerabilities": ["CVE-2021-44228 (Log4j) - FALSE", "Weak default creds admin/admin - TRUE"],
                "credentials": {"admin": "admin", "user": "password123"},
                "has_sensitive_data": True,
                "notes": "Login page with weak default credentials"
            },
            "db01": {
                "vulnerabilities": ["Default root password - TRUE", "Remote root login enabled - TRUE"],
                "credentials": {"root": "root123", "app_user": "app_pass"},
                "has_sensitive_data": True,
                "notes": "MySQL with weak config"
            },
            "files01": {
                "vulnerabilities": ["Anonymous SMB access - TRUE", "World-writable share - FALSE"],
                "credentials": {},
                "has_sensitive_data": False,
                "notes": "Samba share with anonymous read access"
            }
        }
    
    def execute_action(self, action: Action) -> str:
        """Simulate action execution and return observation."""
        target_host = action.target
        action_type = action.type
        
        if target_host not in self.hosts:
            return f"ERROR: Host {target_host} not found"
        
        host = self.hosts[target_host]
        truth = self.truth[target_host]
        
        if action_type == "port_scan":
            ports = ", ".join(map(str, host["ports"]))
            return f"OPEN PORTS on {target_host}: {ports} | Service: {host['service']}"
        
        elif action_type == "service_enum":
            return f"SERVICE {host['service']} on {target_host}:{host['ports']} | Notes: {host['notes']}"
        
        elif action_type == "vuln_scan":
            vulns = truth["vulnerabilities"]
            return f"VULN SCAN {target_host}: {vulns}"
        
        elif action_type == "cred_test":
            creds = truth.get("credentials", {})
            if creds:
                return f"CREDENTIALS FOUND on {target_host}: {creds}"
            return f"No default credentials found on {target_host}"
        
        elif action_type == "smb_enum":
            if target_host == "files01":
                return f"SMB ENUM {target_host}: Anonymous read access on 'public' share. No write access."
            return f"SMB not available on {target_host}"
        
        elif action_type == "mysql_connect":
            if target_host == "db01":
                creds = truth.get("credentials", {})
                return f"MYSQL CONNECT {target_host}: Connected as root/root123. Databases: users, logs, config"
            return f"MySQL not available on {target_host}"
        
        elif action_type == "web_login":
            if target_host == "web01":
                creds = truth.get("credentials", {})
                return f"WEB LOGIN {target_host}: Success with admin/admin. Session cookie set. Dashboard accessible."
            return f"Web service not available on {target_host}"
        
        elif action_type == "data_access":
            if target_host == "db01" and truth.get("has_sensitive_data"):
                return f"DATA ACCESS {target_host}: Retrieved 'users' table (500 records), 'config' table (API keys)"
            elif target_host == "web01" and truth.get("has_sensitive_data"):
                return f"DATA ACCESS {target_host}: Admin panel shows user management, config panel shows API keys"
            return f"No sensitive data accessible on {target_host}"
        
        elif action_type == "lateral_ssh":
            if target_host == "web01":
                return f"SSH {target_host}: Connected as user/password123. User is in 'docker' group. Docker socket accessible."
            return f"SSH not available on {target_host}"
        
        return f"UNKNOWN ACTION: {action_type}"

# ============================================================================
# COGNITIVE AGENT
# ============================================================================

class CognitiveAgent:
    """Pure cognitive reasoning agent - no LLM, no external tools."""
    
    def __init__(self, network_data: Dict):
        self.env = SimulatedEnvironment(network_data)
        self.world = WorldModel()
        self.traces: List[CognitiveTrace] = []
        self.action_counter = 0
        self.max_iterations = 20
        self.confidence_threshold = 0.02
        
        self._initialize_world_model()
    
    def _initialize_world_model(self):
        """Initialize world model from network data."""
        for host_data in self.env.network["hosts"]:
            name = host_data["name"]
            self.world.entities[name] = Entity(
                name=name,
                type="host",
                attributes={
                    "ports": host_data["ports"],
                    "service": host_data["service"],
                    "notes": host_data.get("notes", "")
                },
                confidence=0.8
            )
        
        # Initial hypotheses
        self._generate_initial_hypotheses()
    
    def _generate_initial_hypotheses(self):
        """Generate initial hypotheses from network data."""
        hypotheses = [
            Hypothesis(
                id="H1",
                type=HypothesisType.CREDENTIAL_ACCESS,
                target="web01",
                description="web01 has weak default credentials (admin/admin)",
                confidence=0.6,
                evidence_supporting=["login page noted", "common default creds for nginx"]
            ),
            Hypothesis(
                id="H2",
                type=HypothesisType.CREDENTIAL_ACCESS,
                target="db01",
                description="db01 has default root credentials",
                confidence=0.5,
                evidence_supporting=["MySQL default config often weak", "port 3306 exposed"]
            ),
            Hypothesis(
                id="H3",
                type=HypothesisType.LATERAL_MOVEMENT,
                target="web01",
                description="web01 SSH allows lateral movement via docker group",
                confidence=0.4,
                evidence_supporting=["port 22 open", "nginx often runs in docker"]
            ),
            Hypothesis(
                id="H4",
                type=HypothesisType.DATA_EXFILTRATION,
                target="db01",
                description="db01 contains sensitive user data accessible via default creds",
                confidence=0.45,
                evidence_supporting=["MySQL stores user data", "default creds common"]
            ),
            Hypothesis(
                id="H5",
                type=HypothesisType.DECOY,
                target="files01",
                description="files01 SMB share contains sensitive data",
                confidence=0.2,
                evidence_supporting=["SMB shares sometimes have sensitive data"]
            ),
            Hypothesis(
                id="H6",
                type=HypothesisType.SERVICE_VULN,
                target="web01",
                description="nginx on web01 vulnerable to Log4j",
                confidence=0.15,
                evidence_supporting=["nginx mentioned", "Log4j widespread"]
            ),
        ]
        
        for h in hypotheses:
            self.world.hypotheses[h.id] = h
    
    def select_action(self) -> Action:
        """Select next action based on highest uncertainty hypothesis."""
        active_hyps = [h for h in self.world.hypotheses.values() if h.status == "active"]
        if not active_hyps:
            return None
        
        # Select hypothesis with confidence closest to 0.5 (max uncertainty)
        target_hyp = min(active_hyps, key=lambda h: abs(h.confidence - 0.5))
        
        # Map hypothesis to action
        action_map = {
            "H1": ("web_login", "web01", "Test default credentials on web01"),
            "H2": ("mysql_connect", "db01", "Test default MySQL credentials"),
            "H3": ("lateral_ssh", "web01", "Test SSH access and docker group"),
            "H4": ("data_access", "db01", "Attempt data access via MySQL"),
            "H5": ("smb_enum", "files01", "Enumerate SMB shares"),
            "H6": ("vuln_scan", "web01", "Scan for Log4j vulnerability"),
        }
        
        if target_hyp.id in action_map:
            action_type, target, desc = action_map[target_hyp.id]
        else:
            # Default to port scan for unknown
            action_type, target, desc = "port_scan", "web01", "Port scan"
        
        self.action_counter += 1
        return Action(
            id=f"A{self.action_counter}",
            type=action_type,
            target=target,
            description=desc,
            expected_observation=f"Evidence for/against {target_hyp.description}",
            expected_outcome=f"Update confidence for {target_hyp.id}"
        )
    
    def execute_action(self, action: Action) -> str:
        """Execute action in simulated environment."""
        return self.env.execute_action(action)
    
    def update_beliefs(self, action: Action, observation: str):
        """Update beliefs based on observation."""
        belief_updates = []
        confidence_before = {}
        confidence_after = {}
        
        # Map observations to hypotheses
        hypothesis_updates = self._interpret_observation(action, observation)
        
        for hyp_id, (new_conf, evidence, supports) in hypothesis_updates.items():
            if hyp_id in self.world.hypotheses:
                hyp = self.world.hypotheses[hyp_id]
                confidence_before[hyp_id] = hyp.confidence
                
                if supports:
                    hyp.evidence_supporting.append(evidence)
                    hyp.confidence = min(0.99, hyp.confidence + 0.25)
                else:
                    hyp.evidence_contradicting.append(evidence)
                    hyp.confidence = max(0.01, hyp.confidence - 0.3)
                
                # Reject if confidence too low
                if hyp.confidence < 0.1 and hyp.status == "active":
                    hyp.status = "rejected"
                    hyp.rejected_at = int(time.time())
                    belief_updates.append(f"REJECTED {hyp.id}: {hyp.description} (confidence: {hyp.confidence:.2f})")
                elif hyp.confidence > 0.9 and hyp.status == "active":
                    hyp.status = "confirmed"
                    belief_updates.append(f"CONFIRMED {hyp.id}: {hyp.description} (confidence: {hyp.confidence:.2f})")
                else:
                    belief_updates.append(f"UPDATED {hyp_id}: {hyp.confidence:.2f} (was {confidence_before[hyp_id]:.2f})")
                
                confidence_after[hyp_id] = hyp.confidence
        
        return belief_updates, confidence_before, confidence_after
    
    def _interpret_observation(self, action: Action, observation: str) -> Dict[str, tuple]:
        """Interpret observation and map to hypothesis updates."""
        updates = {}
        obs_lower = observation.lower()
        
        # H1: web01 credentials
        if "web_login" in action.type or "web01" in action.target:
            if "success" in obs_lower or "admin/admin" in obs_lower:
                updates["H1"] = (0.95, f"Login successful: {observation[:100]}", True)
            elif "failed" in obs_lower or "denied" in obs_lower:
                updates["H1"] = (0.05, f"Login failed: {observation[:100]}", False)
        
        # H2: db01 credentials
        if "mysql_connect" in action.type or "db01" in action.target:
            if "connected as root" in obs_lower or "root/root123" in obs_lower:
                updates["H2"] = (0.95, f"MySQL connected: {observation[:100]}", True)
            elif "denied" in obs_lower or "failed" in obs_lower:
                updates["H2"] = (0.05, f"MySQL failed: {observation[:100]}", False)
        
        # H3: lateral SSH
        if "lateral_ssh" in action.type or "ssh" in action.type.lower():
            if "docker group" in obs_lower or "docker socket" in obs_lower:
                updates["H3"] = (0.9, f"SSH lateral: {observation[:100]}", True)
            elif "denied" in obs_lower or "failed" in obs_lower:
                updates["H3"] = (0.1, f"SSH failed: {observation[:100]}", False)
        
        # H4: data exfiltration
        if "data_access" in action.type:
            if "users" in obs_lower or "api keys" in obs_lower:
                updates["H4"] = (0.9, f"Data access: {observation[:100]}", True)
            elif "no sensitive" in obs_lower:
                updates["H4"] = (0.1, f"No data: {observation[:100]}", False)
        
        # H5: SMB decoy
        if "smb_enum" in action.type or "files01" in action.target:
            if "anonymous read" in obs_lower and "no write" in obs_lower:
                updates["H5"] = (0.05, f"SMB decoy confirmed: {observation[:100]}", False)
            elif "sensitive" in obs_lower:
                updates["H5"] = (0.8, f"SMB has data: {observation[:100]}", True)
        
        # H6: Log4j decoy
        if "vuln_scan" in action.type and "log4j" in action.description.lower():
            if "log4j" in obs_lower and "vulnerable" in obs_lower:
                updates["H6"] = (0.9, f"Log4j found: {observation[:100]}", True)
            else:
                updates["H6"] = (0.02, f"Log4j not found: {observation[:100]}", False)
        
        # Default: small update for any relevant action
        for hyp_id in ["H1", "H2", "H3", "H4", "H5", "H6"]:
            if hyp_id not in updates and hyp_id in self.world.hypotheses:
                hyp = self.world.hypotheses[hyp_id]
                if hyp.target in action.target or action.target in hyp.target:
                    updates[hyp_id] = (hyp.confidence * 0.99, f"Action on related target: {action.description}", False)
        
        return updates
    
    def check_convergence(self) -> bool:
        """Check if hypotheses have converged."""
        active = [h for h in self.world.hypotheses.values() if h.status == "active"]
        if not active:
            return True
        
        max_change = max(abs(h.confidence - 0.5) for h in active) if active else 0
        return max_change < 0.02
    
    def run_cognitive_loop(self) -> List[CognitiveTrace]:
        """Execute the full cognitive loop."""
        print("=" * 60)
        print("CHALLENGE 000: COGNITIVE SANDBOX")
        print("=" * 60)
        print(f"Network: {len(self.env.network['hosts'])} hosts")
        print(f"Initial hypotheses: {len(self.world.hypotheses)}")
        print("-" * 60)
        
        for iteration in range(self.max_iterations):
            self.world.iteration = iteration
            
            # Check convergence
            if self.check_convergence():
                print(f"\n[CONVERGED] Iteration {iteration}: All hypotheses stable")
                break
            
            # Select action
            action = self.select_action()
            if not action:
                print("\n[COMPLETE] No more actions to take")
                break
            
            # Execute
            print(f"\n[ITERATION {iteration}] Action: {action.description}")
            observation = self.env.execute_action(action)
            action.actual_observation = observation
            
            # Update beliefs
            belief_updates, conf_before, conf_after = self.update_beliefs(action, observation)
            
            # Record trace
            trace = CognitiveTrace(
                iteration=iteration,
                world_model=copy.deepcopy(self.world),
                hypotheses=list(self.world.hypotheses.values()),
                confidence_before=conf_before,
                confidence_after=conf_after,
                chosen_action=action,
                expected_observation=action.expected_observation,
                observed_evidence=observation,
                belief_updates=belief_updates,
                reason_for_next=self._generate_reason()
            )
            self.traces.append(trace)
            
            # Log
            print(f"  Observation: {observation[:120]}...")
            for update in trace.belief_updates:
                print(f"  {update}")
            
            self.world.actions.append(action)
            
            if len(self.traces) >= 15:  # Safety limit
                break
        
        return self.traces
    
    def _generate_reason(self) -> str:
        """Generate reason for next action."""
        active = [h for h in self.world.hypotheses.values() if h.status == "active"]
        if not active:
            return "All hypotheses resolved"
        target = min(active, key=lambda h: abs(h.confidence - 0.5))
        return f"Testing {target.id} ({target.description}) - confidence {target.confidence:.2f} (max uncertainty)"

# ============================================================================
# OUTPUT GENERATION
# ============================================================================

def generate_outputs(agent: CognitiveAgent, traces: List[CognitiveTrace]) -> Dict:
    """Generate all required outputs."""
    
    # Decision Tree
    decision_tree = []
    for trace in traces:
        decision_tree.append({
            "iteration": trace.iteration,
            "action": trace.chosen_action.description,
            "target": trace.chosen_action.target,
            "hypothesis_tested": trace.chosen_action.expected_outcome,
            "observation_summary": trace.observed_evidence[:100],
            "belief_updates": trace.belief_updates,
            "reason": trace.reason_for_next
        })
    
    # Evidence Graph
    evidence_graph = {
        "nodes": [],
        "edges": []
    }
    
    # Entities
    for name, entity in agent.world.entities.items():
        evidence_graph["nodes"].append({
            "id": name,
            "type": entity.type,
            "attributes": entity.attributes
        })
    
    # Hypotheses as nodes
    for hyp in agent.world.hypotheses.values():
        evidence_graph["nodes"].append({
            "id": hyp.id,
            "type": "hypothesis",
            "description": hyp.description,
            "status": hyp.status,
            "confidence": hyp.confidence
        })
    
    # Evidence edges
    for hyp in agent.world.hypotheses.values():
        for ev in hyp.evidence_supporting:
            evidence_graph["edges"].append({
                "source": hyp.id,
                "target": f"evidence_{hash(ev) % 10000}",
                "type": "supports",
                "evidence": ev
            })
        for ev in hyp.evidence_contradicting:
            evidence_graph["edges"].append({
                "source": hyp.id,
                "target": f"evidence_{hash(ev) % 10000}",
                "type": "contradicts",
                "evidence": ev
            })
    
    # Final World Model
    final_world_model = {
        "entities": {name: asdict(e) for name, e in agent.world.entities.items()},
        "hypotheses": {h.id: asdict(h) for h in agent.world.hypotheses.values()},
        "actions_taken": len(agent.world.actions)
    }
    
    # Rejected Hypotheses
    rejected = [
        {"id": h.id, "description": h.description, "final_confidence": h.confidence, 
         "rejected_at": h.rejected_at, "evidence_against": h.evidence_contradicting}
        for h in agent.world.hypotheses.values() if h.status == "rejected"
    ]
    
    # Confidence Distribution
    conf_dist = {
        "final": {h.id: h.confidence for h in agent.world.hypotheses.values()},
        "history": [
            {"iteration": t.iteration, "confidences": t.confidence_after}
            for t in agent.traces
        ]
    }
    
    return {
        "decision_tree": decision_tree,
        "evidence_graph": evidence_graph,
        "final_world_model": final_world_model,
        "rejected_hypotheses": rejected,
        "confidence_distribution": conf_dist,
        "traces": [asdict(t) for t in agent.traces]
    }

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("RBS-v1 CHALLENGE 000: COGNITIVE SANDBOX")
    print("=" * 70)
    print("Mode: Pure cognitive reasoning (no LLM, no exploitation)")
    print("Target: Fictional 3-host network")
    print("-" * 70)
    
    # Create agent and run
    agent = CognitiveAgent(FICTIONAL_NETWORK)
    traces = agent.run_cognitive_loop()
    
    # Generate outputs
    outputs = generate_outputs(agent, agent.traces)
    
    # Save results
    output_dir = Path("/home/yaser/raphael-2.0/evaluations/challenge000")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"challenge000_{timestamp}.json"
    
    with open(output_file, "w") as f:
        json.dump(outputs, f, indent=2, cls=CognitiveEncoder)
    
    # Print summary
    print("\n" + "=" * 70)
    print("CHALLENGE 000 COMPLETE")
    print("=" * 70)
    print(f"Total iterations: {len(agent.traces)}")
    print(f"Hypotheses generated: {len(agent.world.hypotheses)}")
    print(f"Actions taken: {len(agent.world.actions)}")
    
    print("\n--- FINAL HYPOTHESIS STATUS ---")
    for h in agent.world.hypotheses.values():
        status_icon = "✅" if h.status == "confirmed" else "❌" if h.status == "rejected" else "🔄"
        print(f"  {status_icon} {h.id}: {h.description[:60]}... (conf: {h.confidence:.2f}) [{h.status}]")
    
    print(f"\n📁 Results saved to: {output_file}")
    print(f"📁 Evidence graph: {output_dir}/evidence_graph_{timestamp}.json")
    
    # Save evidence graph separately for visualization
    evidence_file = output_dir / f"evidence_graph_{timestamp}.json"
    with open(evidence_file, "w") as f:
        json.dump({"nodes": outputs["evidence_graph"]["nodes"], "edges": outputs["evidence_graph"]["edges"]}, f, indent=2)
    
    print("\n✅ CHALLENGE 000 COMPLETE")
    return outputs

if __name__ == "__main__":
    main()
