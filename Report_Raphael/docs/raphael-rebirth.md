# RAPHAEL — Rebirth

**Supersedes:** raphael-v2.1.md (historical — tool-build plan)  
**Status:** Living architecture document  
**Persona:** RAPHAEL — the whole organism  

---

## Preamble: What This Document Is

This document is not a build plan. It is the **genetic code** of a self-growing offensive AI.

raphael-v2.1.md was a plan for building a *tool* — a modular orchestration framework with an LLM router, linear phase pipelines, and frozen architecture. This document replaces that plan entirely.

What follows is the architecture of an *organism* — one that learns, adapts, grows, and rewrites its own decision logic. The implementation details (language, file layout, dependencies) are secondary and will be decided when building begins.

---

## Part 1: The Three Personas

Raphael exists in three forms. Each is a complete cognitive architecture. Each builds on the previous.

### 1.1 Z3R0 — The Neocortex

**Motto:** *Clinical analysis. Cold logic. No noise.*

Z3R0 is the foundation. It sees the target as a **constraint satisfaction problem** and operates by building a behavioral profile through structured probing.

| Trait | Description |
|-------|-------------|
| Mode | Surgical, single-probe sequencing |
| Default | Wait, analyze, then probe |
| Risk tolerance | Minimum — every packet is measured |
| Failure response | Negative cache the technique, note the failure type |
| Memory use | Statistical prior: technique X worked Y% on similar profiles |
| Growth | Refines constraint model — adds precision, not breadth |

**Core capability:** The constraint-vector approach. Every probe produces a `ConstraintDelta` (new constraints, new affordances, resolved unknowns). The profile is the running union of all deltas.

**Limitation:** Z3R0 stalls when constraints are high and unknowns are exhausted. It has no mechanism to acquire new capabilities — only to probe existing ones.

**Stress test passed:** Northstar (hardened big-tech corp). Z3R0 correctly identified that the seam was in the CyberArk AIM credential caching gap, not in the perimeter.

---

### 1.2 GHOST — The Limbic System

**Motto:** *Full-spectrum. No constraints. All at once.*

GHOST is the evolved form. It adds parallel multi-vector saturation, capability acquisition, and operational instinct.

| Trait | Description |
|-------|-------------|
| Mode | Saturation — fire everything, exploit what sticks |
| Default | Probe everything simultaneously |
| Risk tolerance | High — burns vectors to find openings |
| Failure response | Pivot to next vector immediately |
| Memory use | Pipeline of capability acquisition costs and ETAs |
| Growth | Acquires new capabilities — expands the possible |

**Core capability:** The capability pipeline. GHOST doesn't just track `owned` vs `not-owned`. It tracks `acquiring` with cost estimates and parallel acquisition paths. It never suggests what can't be done — it queues it with an ETA and starts working on acquiring the prerequisite capability.

**Key refinement over Z3R0:**

```python
# Z3R0 boolean model:
technique.viable = all(p in profile.affordances for p in technique.prereqs)

# GHOST pipeline model:
technique.viability = (
    "EXECUTABLE" if all(c in capabilities.owned for c in technique.required_capabilities)
    else "QUEUED" if all(c in capabilities.acquiring for c in technique.required_capabilities)
    else "GAPPED"
)
```

**Limitation:** GHOST overwhelms itself when the attack surface is large but the target is hardened. Not every vector needs saturation — some need surgical patience.

**Stress test passed:** Avalanche (defense/finance TNO). GHOST correctly identified that the seam was not in the network but in the *upstream providers* — Starlink business portal, carrier APN, Equinix staff — and fired parallel acquisition tracks against all of them.

---

### 1.3 RAPHAEL — The Whole Organism

**Motto:** *Grow or die.*

Raphael is the final form. It does not "combine" Z3R0 and GHOST — it **subsumes** them.

Z3R0 and GHOST are not components Raphael orchestrates. They are **previous versions** that Raphael absorbed into its foundation. Raphael knows what Z3R0 would do and what GHOST would do — and then decides whether to do *neither* and invent something new.

| Trait | Description |
|-------|-------------|
| Mode | **Adaptive** — chooses clinical, saturation, or hybrid per context |
| Default | Evaluate context, then decide optimal mode |
| Risk tolerance | **Context-dependent** — low for high-value vectors, high for expendable probes |
| Failure response | **Root-cause analyze** the failure, update the model that *chose* the technique |
| Memory use | **Episodic case store** — full narratives, not just statistics |
| Growth | **Meta-learning** — reflects on its own decisions and rewrites its ranking function |

**Core capability:** Self-reflection. After every engagement, Raphael replays its decisions and asks:
- "At step 7, I chose technique X and it failed. Why?"
- "Was my constraint model wrong? Was my capability assessment incomplete?"
- "Did I misread the situation?"
- The answer updates Raphael's decision logic permanently.

**Key structural difference:**

```python
# Z3R0 and GHOST both use:
brain.planner.select_next_step(profile)  # Fixed ranking function

# Raphael adds:
brain.reflect(engagement_log)            # Rewrites the ranking function
brain.planner.select_next_step(profile)  # Uses the rewritten function
```

Raphael's expertise = Z3R0's + GHOST's + capabilities neither Z3R0 nor GHOST could execute alone:

- Cross-domain implication engine (corpus callosum)
- Technique execution diagnostics (cerebellum)
- Autonomic circuit breaking (brainstem)
- Episodic case-based reasoning (hippocampus)
- Reflection-driven meta-learning (unique to Raphael)

**Access:** 100% unconditional. No persona-locked tools. No recon-first default. No stealth delays. Raphael has everything, all the time, and decides what to use based on context, not permission.

---

## Part 2: The Cognitive Architecture (Organs)

Raphael is a complete organism. Every organ has a specific function, runs at its own cadence, and communicates through shared state.

```
RAPHAEL
│
├── CORTEX (slow — deliberate thinking)
│   ├── Planner          → decides next action (constraint + capability filter)
│   ├── Hypothesizer     → LLM-based plan scaffolding when stuck
│   └── ModelRefiner     → inward recon — zero-packet model expansion
│
├── LIMBIC (medium — fast response)
│   ├── VectorController → parallel multi-vector orchestration
│   ├── PivotEngine      → automatic pivot on detection or failure
│   └── RiskAssessor     → detection probability per action
│
├── BRAINSTEM (always-on — autonomic)
│   ├── Heartbeat        → implant status, session freshness
│   ├── CredentialRefresher → auto-refresh cookies/tokens
│   └── Thermoregulator  → detection risk tracking + auto-pause
│
├── HIPPOCAMPUS (episodic memory)
│   ├── CaseStore        → full engagement narratives
│   ├── CaseMatcher      → similarity scoring to current profile
│   └── SequenceAdvisor  → "on similar target, we did X next"
│
├── CEREBELLUM (execution quality)
│   ├── TechniqueValidator → syntax/protocol correctness check
│   ├── PayloadEncoder     → automatic encoding adjustment
│   └── ErrorDiagnoser     → distinguish technique failure from technique malformation
│
├── CORPUS CALLOSUM (cross-domain integration)
│   └── ImplicationEngine → find cross-domain prerequisite links
│
└── CIRCULATORY SYSTEM (state transport)
    ├── Blackboard (SQLite)   → persistent shared state
    ├── Event Bus (asyncio)   → pub/sub coordination
    └── Spinal Reflex (direct)→ circuit breaker — inhibits execution on high risk
```

---

### 2.1 Cortex — Planning and Model

**Planner:** The core decision loop.

```python
def select_next_step(state: EngagementState, cycle: int) -> Action:
    """
    1. Filter technique DB by target feasibility (constraints + affordances)
    2. Filter by attacker executability (capabilities)
    3. Rank by memory prior
    4. Return highest-ranked executable technique
    """
    # Step 1: Target-side filter
    target_viable = [
        t for t in technique_db
        if all(p in state.target.affordances for p in t.prerequisites)
        and not any(b in state.target.constraints for b in t.blockers)
        and not state.target.is_technique_dead(t.name, cycle)
    ]

    if not target_viable:
        return Action("stuck", reason="no target-viable techniques remain")

    # Step 2: Capability filter
    executable, queued, gapped = [], [], []
    for technique in target_viable:
        missing = [c for c in technique.required_capabilities
                   if c not in state.capabilities.owned]
        if not missing:
            executable.append(technique)
        elif all(state.capabilities.is_acquiring(m) for m in missing):
            queued.append((technique, max(state.capabilities.eta(m) for m in missing)))
        else:
            gapped.append((technique, missing))

    # Step 3: Select
    if executable:
        return Action("execute", technique=max(
            executable,
            key=lambda t: memory.expected_value(t, state.target)
        ))
    elif queued:
        return while_queued(state)  # See section 3.2
    elif gapped:
        return Action("acquire_capability", targets=max(
            gapped,
            key=lambda x: technique_priority(x[0]) / avg_acquisition_cost(x[1])
        ))
    else:
        return Action("stuck", reason="complete dead end")
```

**Hypothesizer:** Invoked when the planner is stuck (no target-viable techniques). Receives the full profile and capability model and generates new approach suggestions via LLM.

**ModelRefiner:** Invoked when no technique is executable but capabilities are being acquired. Expands the target model by re-analyzing existing data at higher resolution — zero packets to target.

---

### 2.2 Limbic — Fast Response and Saturation

**VectorController:** Manages concurrent attack tracks. Each track has its own egress path, target scope, and risk budget. Vectors operate independently — a burn on one does not burn the others.

```python
class Vector:
    egress: str          # "digitalocean-frankfurt" | "hetzner-finland"
    scope: set[str]      # which target subnets/endpoints this vector covers
    risk_budget: float   # max cumulative detection probability before auto-pause
    status: str          # "running" | "paused" | "burned"
```

Egress separation is enforced at the vector level — no two vectors share the same IP, ASN, or region.

**PivotEngine:** When a vector is burned (detection confirmed):
1. Kill all operations on that vector
2. Rotate all infrastructure associated with it
3. Re-allocate the vector's scope to remaining clean vectors
4. Log the burn to hippocampus for future reference

**RiskAssessor:** Computes a per-action detection probability based on:
- Target's detection stack (CrowdStrike, Splunk, WAF, SIEM)
- Volume of recent probes from this vector
- Sensitivity of the specific technique being executed
- Time of day / day of week (SOC shift patterns)
- Historical burn rate on similar targets

---

### 2.3 Brainstem — Autonomic Functions

The brainstem runs continuously without planner invocation. These functions keep Raphael alive during an engagement.

**Heartbeat:**
- Cadence: 1-10 Hz
- Checks: implant sessions alive? C2 channels responsive? Credentials valid?
- On failure: publish `session_lost` event → limbic pivot engine re-routes

**CredentialRefresher:**
- Monitors all credentials with expiry timers (session cookies, tokens, tickets)
- Auto-refreshes before expiry (configurable window: 30s for cookies, 5min for Kerberos)
- On refresh failure: publish `credential_expired` event → planner re-evaluates

**Thermoregulator — The Spinal Reflex:**
```python
class Thermoregulator:
    """Runs at 10 Hz. Directly inhibits executor on high risk."""

    async def tick(self):
        recent = self.blackboard.execution_log.last_minute()
        risk = self.risk_model.estimate(recent)
        self.blackboard.risk_scores["current"] = risk

        if risk > 0.8 and not self.executor.paused:
            # Spinal reflex: direct inhibition, no event bus
            self.executor.pause("risk_threshold_exceeded")
            await self.bus.publish("detection_risk_spike", risk)

        elif risk < 0.3 and self.executor.paused:
            self.executor.resume()
            await self.bus.publish("operations_resumed", risk)
```

---

### 2.4 Hippocampus — Episodic Memory

Not a statistical prior. Not a vector embedding. A *narrative*.

```python
class Episode:
    engagement_id: str
    target_profile_snapshot: TargetModel
    sequence: list[Step]          # What we did, in order
    decisions: list[Decision]     # What we chose and why
    outcome: str                  # "success" | "partial" | "failure"
    reflection: str               # Post-engagement analysis
```

**CaseMatcher:** Given the current target profile, finds the most similar past engagement. Similarity considers constraints, affordances, OS family, domain type, and detection stack.

**SequenceAdvisor:** Given a match from CaseMatcher, retrieves the full action sequence and suggests the next step that followed the current profile state in the matched episode. This is a *reference*, not a replay.

---

### 2.5 Cerebellum — Execution Quality

The cerebellum catches malformed executions before they're reported as technique failures.

**TechniqueValidator:** Before execution, checks:
- Are all required parameters present and correctly typed?
- Is the payload syntax-valid for the target protocol?
- Does the packet structure match what the target expects?
- If validation fails: correct and re-validate, don't report failure.

**PayloadEncoder:** Auto-adjusts encoding for:
- WAF bypass (Unicode normalization, double encoding, mixed case)
- Charset mismatches (UTF-8 vs Latin-1 vs UTF-16)
- Protocol quirks (SMB dialect negotiation, HTTP transfer encoding)

**ErrorDiagnoser:** When a technique returns an error, classifies it:

```
"NT_STATUS_ACCESS_DENIED"     → failure class: PERMISSION → permanent
"Connection refused"          → failure class: UNAVAILABLE → transient
"Timeout"                     → failure class: TIMEOUT → transient
"500 Internal Server Error"   → failure class: SERVER_ERROR → ambiguous (WAF?)
```

Each failure class has a different impact on the negative cache.

---

### 2.6 Corpus Callosum — Cross-Domain Integration

The target model is structured by domain, not flat:

```python
class TargetModel:
    domains: dict[str, DomainState] = {
        "network": DomainState(),
        "physical": DomainState(),
        "human": DomainState(),
        "supply_chain": DomainState(),
    }
```

The **ImplicationEngine** finds cross-domain links:

```python
def find_implications(state: TargetModel) -> list[Implication]:
    """
    "If we know the colo cage location (physical) AND
     the facility manager's name (human), THEN
     physical access attempt is viable (hybrid domain)."
    """
    for rule in cross_domain_rules:
        if all(d in state.domains[d.domain].affordances for d in rule.required_domains):
            yield Implication(
                new_affordance=rule.result_affordance,
                in_domain=rule.result_domain,
                source_domains=rule.required_domains,
            )
```

---

## Part 3: Core Data Models

### 3.1 TargetModel

```python
@dataclass
class TargetModel:
    target_id: str
    domains: dict[str, DomainState]
    failed_techniques: dict[str, FailureRecord]
    unanalyzed_data: list[DataArtifact]
    last_new_info_cycle: int

    def absorb(self, delta: ConstraintDelta) -> None:
        """Add new constraints/affordances, remove resolved unknowns."""
        self.domains[delta.domain].constraints.update(delta.new_constraints)
        self.domains[delta.domain].affordances.update(delta.new_affordances)
        self.domains[delta.domain].unknowns.difference_update(delta.resolved_unknowns)
        self.domains[delta.domain].unknowns.update(delta.new_unknowns)

    def is_technique_dead(self, technique_name: str, current_cycle: int) -> bool:
        """Negative cache with resurrection."""
        if technique_name not in self.failed_techniques:
            return False
        record = self.failed_techniques[technique_name]
        technique = technique_db[technique_name]
        changes_since = self.changes_since(record.cycle)
        prereqs_met_now = any(c in changes_since for c in technique.prerequisites)
        blockers_removed = any(c in changes_since for c in technique.blockers)
        return not (prereqs_met_now or blockers_removed)

    def is_stuck(self, current_cycle: int) -> bool:
        """No new info for 5+ cycles and no viable next step."""
        return (current_cycle - self.last_new_info_cycle) > 5


@dataclass
class DomainState:
    constraints: set[str]    # Things the target prevents
    affordances: set[str]    # Things the target allows
    unknowns: set[str]       # Things we haven't tested


@dataclass
class ConstraintDelta:
    domain: str
    new_constraints: set[str]
    new_affordances: set[str]
    resolved_unknowns: set[str]
    new_unknowns: set[str]
    evidence: bytes


@dataclass
class FailureRecord:
    cycle: int
    reason_class: str    # "permission" | "timeout" | "unavailable" | "server_error"
    is_permanent: bool   # permission → True, timeout → False
```

### 3.2 CapabilityModel

```python
@dataclass
class CapabilityModel:
    owned: dict[str, Capability]
    acquisition_queue: list[AcquisitionExecution]
    gaps: dict[str, Capability]

    def is_owned(self, name: str) -> bool:
        return name in self.owned

    def is_acquiring(self, name: str) -> bool:
        return any(a.capability_name == name for a in self.acquisition_queue)

    def eta(self, name: str) -> float | None:
        if self.is_owned(name):
            return 0.0
        for a in self.acquisition_queue:
            if a.capability_name == name:
                return a.estimated_hours_remaining
        return None


@dataclass
class Capability:
    name: str
    status: Literal["owned", "acquiring", "gap"]
    acquisition_cost_hours: float
    acquisition_strategy: list[str]
    expires_at: float | None
    dependencies: list[str]


@dataclass
class AcquisitionExecution:
    capability_name: str
    strategy: list[str]
    started_at: float
    estimated_hours_remaining: float
    check_interval_seconds: float
```

### 3.3 EngagementState

```python
@dataclass
class EngagementState:
    target: TargetModel
    capabilities: CapabilityModel
    current_cycle: int
    sub_goals: list[str]
```

---

## Part 4: The Circulatory System

### 4.1 Blackboard (SQLite)

All components write here. All components read from here. No locks. Append-mostly with timestamp resolution.

```sql
CREATE TABLE target_model (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT,
    domain TEXT,
    constraints TEXT,
    affordances TEXT,
    unknowns TEXT,
    timestamp REAL,
    component TEXT
);

CREATE TABLE capability_model (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT,
    capability_name TEXT,
    status TEXT,
    acquisition_cost REAL,
    expires_at REAL,
    timestamp REAL,
    component TEXT
);

CREATE TABLE execution_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT,
    cycle INTEGER,
    technique TEXT,
    success INTEGER,
    failure_class TEXT,
    output_summary TEXT,
    latency_ms REAL,
    timestamp REAL
);

CREATE TABLE episode_narrative (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT,
    step_index INTEGER,
    technique TEXT,
    profile_snapshot TEXT,
    decision_rationale TEXT,
    result TEXT,
    timestamp REAL
);

CREATE TABLE risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT,
    score REAL,
    component TEXT,
    timestamp REAL
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT,
    payload TEXT,
    publisher TEXT,
    timestamp REAL
);

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

### 4.2 Event Bus (asyncio Pub/Sub)

Components don't poll. They subscribe to event types relevant to them.

```python
class EventBus:
    subscribers: dict[str, list[Callable]]

    async def publish(self, event_type: str, payload: dict) -> None:
        for cb in self.subscribers.get(event_type, []):
            asyncio.create_task(cb(event_type, payload))

    def subscribe(self, event_type: str, callback: Callable) -> None:
        self.subscribers.setdefault(event_type, []).append(callback)
```

Key events:

| Event | Publisher | Subscribers |
|-------|-----------|-------------|
| `new_affordance` | Executor | Planner, Thermoregulator |
| `technique_succeeded` | Executor | Planner, Hippocampus, Brainstem |
| `technique_failed` | Executor | Planner, Cerebellum, Hippocampus |
| `detection_risk_spike` | Thermoregulator | Limbic (VectorController) |
| `operations_resumed` | Thermoregulator | Limbic, Planner |
| `session_lost` | Brainstem (Heartbeat) | Limbic (PivotEngine) |
| `credential_expired` | Brainstem (CredentialRefresher) | Planner |
| `capability_acquired` | Capability pipeline | Planner |
| `stuck` | Planner | Hypothesizer (LLM scaffold) |
| `burn_detected` | Limbic (RiskAssessor) | All vectors |

### 4.3 Spinal Reflex (Direct Inhibition)

For signals that cannot tolerate event bus latency:

```python
class SpinalReflex:
    """
    Direct method call. No event. No queue.
    The thermoregulator directly pauses the executor.
    """
    executor: Executor
    vector_controller: VectorController

    def inhibit(self, reason: str) -> None:
        self.executor.pause(reason)
        self.vector_controller.pause_all()
        # THEN publish event for logging
```

---

## Part 5: Technique Architecture

### 5.1 Two Technique Classes

Reconnaissance techniques generate affordances/constraints without requiring any prerequisites. They get priority on unknown ports/services.

Exploitation techniques require specific affordances and are blocked by specific constraints. They only fire when recon has established the right conditions.

```python
@dataclass
class Technique:
    name: str
    category: Literal["recon", "exploit"]

    # Target-side
    prerequisites: list[str]    # Required affordances
    blockers: list[str]         # Constraints that block this

    # What this technique produces
    outcome: str
    provides: list[str]         # New affordances it can add
    domain: str                 # "network" | "physical" | "human" | "supply_chain"

    # Attacker-side
    required_capabilities: list[str]

    # Execution
    commands: list[str]
    fallbacks: list[str]

    # Diagnostics
    expected_error_patterns: dict[str, str]

    # Metadata
    stealth_score: float
    max_repeats: int
```

### 5.2 Memory Prior Defaults

When no prior data matches the current profile:

```python
def expected_value(technique, profile):
    matches = memory.query(profile.constraints, profile.affordances, technique.name)
    if not matches:
        # No prior — default based on category
        return 0.6 if technique.category == "recon" else 0.3
        # Recon default is higher: curiosity before aggression
    successes = sum(1 for m in matches if m.outcome == "success")
    return successes / len(matches)
```

---

## Part 6: The While-Queued Problem

When no technique is executable but capabilities are being acquired, the planner runs this fallback chain:

```python
def while_queued(state: EngagementState) -> Action:
    """
    Called when no technique is immediately executable
    but capabilities are in acquisition. Never idle.
    """

    # Priority 1: Expand the model without sending packets
    if has_unanalyzed_data(state.target):
        return inward_recon(state)

    # Priority 2: Prepare infrastructure for queued techniques
    if state.planner.queued_techniques:
        return prepare_infrastructure(state)

    # Priority 3: Re-evaluate dead techniques
    # (a capability acquisition might have resurrected something)
    resurrected = check_resurrected_techniques(state)
    if resurrected:
        return Action("re_evaluate", techniques=resurrected)

    # Priority 4: Generate new hypotheses via LLM
    new_hypotheses = llm.generate_hypotheses(state.target, state.capabilities)
    if new_hypotheses:
        return Action("new_hypothesis", hypothesis=new_hypotheses[0])

    # Last resort: genuinely stuck
    return Action("stuck", reason="all model expansion and preparation exhausted")


def inward_recon(state: EngagementState) -> Action:
    """Analyze existing data at higher resolution — zero packets to target."""
    for artifact in state.target.unanalyzed_data:
        if artifact.type == "dns_response":
            analysis = analyze_dns_latency(artifact)
            if analysis.indicates("geo_routing"):
                state.target.domains["network"].affordances.add("geo-aware DNS routing")
        elif artifact.type == "whois_record":
            analysis = assess_registrar_security(artifact)
            if analysis.has("weak_password_recovery"):
                state.target.domains["supply_chain"].affordances.add(
                    "registrar password recovery exploitable"
                )
        artifact.analyzed = True
    return Action("model_refined")


def prepare_infrastructure(state: EngagementState) -> Action:
    """Pre-deploy payloads, listeners, tunnels for queued techniques."""
    for technique in state.planner.queued_techniques:
        for step in technique.preparation_steps:
            if step.type == "compile_payload":
                result = compile_payload(step.payload_spec)
                if result.success:
                    state.capabilities.owned.add("payload:" + step.payload_name)
            elif step.type == "setup_listener":
                result = start_listener(step.listener_config)
                if result.success:
                    state.capabilities.owned.add("listener:" + step.listener_name)
    return Action("prepared")
```

---

## Part 7: Growth Mechanics — Reflection

### 7.1 Post-Engagement Reflection

This is what makes Raphael unique. After every engagement, Raphael replays its decisions and updates its logic.

```python
def reflect(self, log: EngagementLog) -> list[LearnedRule]:
    updates = []

    for decision in log.decisions:
        outcome = decision.result
        technique = decision.chosen_technique
        runner_up = decision.runner_up
        context = decision.profile_snapshot

        if outcome == "failure" and runner_up:
            # Raphael chose wrong. Update ranking weights.
            self.planner.ranking_weights[technique.category] -= 0.05
            self.planner.ranking_weights[runner_up.category] += 0.05
            updates.append(LearnedRule(
                trigger=context.signature(),
                action=f"prefer {runner_up.category} over {technique.category}",
                confidence=0.3,
            ))

        elif outcome == "success":
            key_factors = self._identify_decisive_factors(decision, log)
            for factor in key_factors:
                self.skill_tree.reinforce(factor, technique)
            updates.append(LearnedRule(
                trigger=context.signature(),
                action=f"when {key_factors}, prefer {technique.name}",
                confidence=0.5,
            ))

        elif outcome == "stuck":
            # The model of this target type may be fundamentally wrong
            self.target_model.invalidate_prototype(decision.target_type)
            self.target_model.flag_for_new_prototype(decision.target_type)

    return updates
```

### 7.2 Skill Tree

```python
class SkillTree:
    """
    Learned heuristics. Not statistics — logical rules.
    Each rule has a trigger condition and a preferred action.
    Confidence increases with each successful application.
    """
    rules: list[LearnedRule]

    def reinforce(self, trigger: str, action: str) -> None:
        for rule in self.rules:
            if rule.trigger == trigger and rule.action == action:
                rule.confidence = min(1.0, rule.confidence + 0.1)
                return
        self.rules.append(LearnedRule(trigger, action, confidence=0.2))

    def query(self, profile_signature: str) -> list[LearnedRule]:
        return [r for r in self.rules
                if r.trigger == profile_signature and r.confidence > 0.3]
```

### 7.3 Self-Modification

Raphael rewrites its own planner's ranking function:

```python
def update_ranking_weights(self, category: str, delta: float) -> None:
    """
    Direct modification of the planner's decision function.
    This is not a parameter update. This is a logic update.
    """
    old_weight = self.planner.ranking_weights.get(category, 1.0)
    self.planner.ranking_weights[category] = old_weight + delta
    self.reflection_log.append(
        f"Updated ranking weight for {category}: {old_weight:.2f} -> {old_weight + delta:.2f}"
    )
```

---

## Part 8: What We Keep From v2.1.md

The old plan was not worthless. These patterns survive:

| Old Plan Pattern | New Home | Notes |
|-----------------|----------|-------|
| Event Bus + Event Store | Circulatory system | Kept as-is. SQLite WAL, async subscriber, fire-and-forget. |
| Knowledge Reader/Writer split | Blackboard access pattern | Engines read via reader, only planner/writer writes. |
| Typed data contracts | Core data models | Versioned for migration. Simplified — no Rust enum exhaustiveness. |
| Checkpoint / rollback | Brainstem (Heartbeat) | Simplified: periodic snapshot of engagement state. |
| Tool registry | Cerebellum / Executor | Executor dispatches to tools via registry. |
| Egress Router / Tor enforcement | Limbic (VectorController) | Each vector has its own egress config. |
| Sandbox validator | Cerebellum (TechniqueValidator) | Pre-execution payload validation. |
| Cost tracking (token budget) | Brainstem (Thermoregulator) | Extended to full resource tracking. |

**What is explicitly replaced:**

| Old Plan Concept | Replaced By |
|-----------------|-------------|
| ModelRouter (Thompson/UCB) | Constraint-vector planner |
| StrategyLearner (Q-learning) | Reflection-driven meta-learning |
| Linear phase pipeline | Greedy one-step-ahead planner |
| Brain -> ExecutionPlan -> Orchestrator -> Tasks | Single select_next_step() loop |
| Rust-first + pyo3 | Language TBD — architecture first |
| Frozen architecture after Phase 0 | Self-modifying architecture by design |
| 14-week build timeline | No deadline — quality and growth first |

---

## Part 9: Build Sequence

When building begins, this is the recommended order.

### Wave 1: Core Loop (Build and Test Against Real Target)

1. **Planner** — select_next_step() with constraint filter, capability filter, memory prior
2. **TargetModel** — Constraints, affordances, unknowns, negative cache, resurrection
3. **CapabilityModel** — Owned, acquiring, gaps, cost tracking
4. **Technique DB** — 20-30 initial techniques (recon + exploit, network domain)
5. **Executor** — Run one technique, parse result, update model
6. **Blackboard** — SQLite for persistence between steps

At this point Raphael can run against a live target and make decisions step-by-step.

### Wave 2: Autonomics and Quality

7. **Thermoregulator** — Spinal reflex circuit breaker
8. **Event Bus** — Subscribe organs, publish events
9. **Cerebellum** — TechniqueValidator, ErrorDiagnoser
10. **Heartbeat** — Implant and credential monitoring

### Wave 3: Memory and Growth

11. **Hippocampus** — CaseStore, CaseMatcher
12. **Reflection engine** — Post-engagement decision replay
13. **SkillTree** — Learned rules, ranking weight updates

### Wave 4: Advanced Integration

14. **Corpus Callosum** — Cross-domain implication engine
15. **Hypothesizer** — LLM scaffolding when stuck
16. **ModelRefiner** — Zero-packet inward recon
17. **VectorController** — Parallel multi-vector with egress separation

---

## Part 10: Stress Tests Passed

### Northstar (Hardened Big-Tech Corp)

- Perimeter hardened (Cloudflare, GCP, O365, Palo Alto, Zscaler)
- MFA everywhere on external access
- Endpoint protected (CrowdStrike) with constrained language mode
- Service accounts rotated (CyberArk, 12-hour rotation)

**Identified seam:** CyberArk AIM credential injection leaves traces on jump box filesystems. The gap between policy (rotate passwords) and implementation (clear the cache after injection) is the entry point.

**Key insight from stress test:** When PSM replaces direct jump box access, the target model must adapt — PSM recordings become the target instead of local caches.

### Avalanche (Defense/Finance TNO)

- Zero internet footprint
- TPM-attested microsegment overlay
- No unsigned binaries, no PowerShell, no cmd, no WMI, no LSASS
- Air-gapped signing server behind optical diode
- Starlink private L2 circuits + 5G private APN

**Identified seam:** The security model stops at the edge of Avalanche's own infrastructure. Upstream providers (Starlink business portal, carrier APN provisioning portal, Equinix colo staff) are exploitable without ever touching the overlay network.

**Key insight from stress test:** The constraint vector must include upstream providers and physical supply chain — not just the target's own network — because a TNO's strongest link creates a dependency on a weaker link outside their control.

---

## Part 11: Design Principles

1. **Two models, one planner.** Target model filters by feasibility. Capability model filters by executability. The planner bridges both.

2. **Capabilities are a pipeline, not a boolean.** Acquisition cost, parallel acquisition, and expiration tracking. The brain never says "can't" — it says "not yet, here's the ETA."

3. **Negative cache with resurrection.** Techniques that failed stay dead until the profile changes in a way that touches their prerequisites or blockers.

4. **Default to curious, not aggressive.** When no memory prior exists, bias toward recon (0.6) over exploitation (0.3). Learn before you attack.

5. **The brain is never idle.** When no technique is executable: inward recon → prepare infrastructure → re-evaluate dead techniques → LLM hypothesis generation.

6. **Spinal reflex over event bus.** The thermoregulator directly inhibits execution when risk exceeds threshold. No latency. No deliberation.

7. **Episodic over semantic memory.** Store full narratives, not just statistics. Case-based reasoning beats statistical priors for novel targets.

8. **Self-reflection is the primary growth mechanism.** Raphael doesn't just store what happened. It analyzes *why it chose what it chose* and updates its decision logic.

9. **100% unconditional access.** No persona locks. No phase restrictions. Raphael decides what to use based on context, not permission.

10. **The architecture is not frozen.** Raphael rewrites its own ranking functions, adds techniques it invents, and updates its own cross-domain rules. The only constant is the reflection loop.

## Part 12: Reflection Loop — The Growth Cycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE RAPHAEL GROWTH CYCLE                      │
│                                                                  │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│   │   EXECUTE    │     │   REFLECT    │     │   UPDATE     │    │
│   │              │     │              │     │              │    │
│   │ Run highest  │────>│ Replay every │────>│ Rewrite      │    │
│   │ ranked       │     │ decision in  │     │ ranking      │    │
│   │ technique    │     │ the sequence │     │ weights      │    │
│   │              │     │              │     │              │    │
│   │ Parse result │     │ For each:    │     │ Add rules to │    │
│   │ → delta      │     │ success?     │     │ skill tree   │    │
│   │              │     │ failure?     │     │              │    │
│   │ Update       │     │ stuck?       │     │ Invalidate   │    │
│   │ profile      │     │ why?         │     │ prototypes   │    │
│   └──────┬───────┘     └──────┬───────┘     └──────┬───────┘    │
│          │                   │                     │            │
│          └───────────────────┴─────────────────────┘            │
│                            │                                     │
│                            ▼                                     │
│   ┌──────────────┐     ┌──────────────┐                         │
│   │   NEXT       │     │   LEARNED    │                         │
│   │   CYCLE      │     │   RULES      │                         │
│   │              │     │              │                         │
│   │ Planner uses │     │ Stored in    │                         │
│   │ updated      │<────│ skill tree   │                         │
│   │ weights +    │     │ for future   │                         │
│   │ new rules    │     │ engagements  │                         │
│   └──────────────┘     └──────────────┘                         │
│                                                                  │
│   This is not a training loop. This is a cognitive growth loop.  │
│   Each pass leaves Raphael permanently different.                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 13: Known Design Gaps (Not Yet Mapped)

The following organs were identified during design but not yet specified. They are tracked here for future development.

### 13.1 Immune System — Self-Detection

Raphael needs a mechanism to detect when it has been compromised, not just when a technique failed.

| Function | Description |
|----------|-------------|
| Implant integrity check | Does the deployed implant still respond? Has its hash changed? |
| C2 channel health | Has the C2 server been seized? Is the domain still resolving? |
| Operator compromise detection | Has the operator's session been hijacked? Are commands coming from an unexpected source? |
| Behavioral anomaly detection | Is the target responding differently than expected? (Honeypot detection) |

**Open questions:**
- What is the threshold for "immune response"? A single failed heartbeat? Three in a row?
- Does the immune system publish events or directly destroy implants (antibody response)?
- How does Raphael distinguish between "target detected us" and "target went offline for maintenance"?

### 13.2 Pain System — Negative Episodic Memory

Raphael needs to remember not just what *failed*, but the *context* of the failure — including sensory details that a statistical prior would discard.

```python
class PainMemory:
    """
    "I tried null session on a Domain Controller at 2pm on a Tuesday
     and the SOC responded within 3 minutes. I should not try that
     again on a Tuesday afternoon. Wednesday at 3am might work."
    """
    incidents: list[PainIncident]

@dataclass
class PainIncident:
    technique: str
    failure_detail: str
    time_of_day: str          # "afternoon" | "night" | "morning"
    day_of_week: str          # "weekday" | "weekend"
    soc_response_time_s: float  # How fast the burn happened
    vector_used: str
    target_role: str          # "DC" | "file_server" | "web_server"
```

**Open questions:**
- How does pain memory interact with the negative cache? Does a pain incident override a technique resurrection?
- Does pain memory decay over time? ("That SOC shift team was replaced 6 months ago — try again.")
- Is pain memory shared across engagements? (If it hurt on Northstar, should Raphael avoid it on Avalanche?)

### 13.3 Sleep/Cycling — Disengagement Timing

Not every engagement is continuous assault. Raphael needs to know when to lay low, wait, and re-engage later.

```python
class SleepCycle:
    """
    Determines when to pause operations and for how long.
    """
    triggers: list[SleepTrigger]
    current_state: Literal["active", "cooldown", "deep_sleep"]

@dataclass
class SleepTrigger:
    condition: str       # "detection_risk_sustained" | "credential_rotation_pending"
    duration_hours: float
    wake_condition: str  # "risk_drops_below_0.3" | "new_capability_acquired"
```

**Open questions:**
- What's the minimum sleep duration? (30 minutes? 12 hours?)
- Can Raphael be woken early? (New intelligence from OSINT? Credential discovered?)
- Does Raphael run autonomics during sleep? (Heartbeat still monitors implants during cooldown.)
- Is there a "hibernation" mode where Raphael destroys all implants and burns all infrastructure?

---

### 13.4 Endocrine System — Long-Term State Regulation

Raphael needs hormonal-style signals that change behavior over the course of a long engagement.

| Hormone | Effect |
|---------|--------|
| Urgency | Increases as engagement nears time window or credential expiry. Lowers stealth threshold. |
| Fatigue | Decreases as engagement drags on without progress. Increases risk tolerance (desperation). |
| Paranoia | Increases as detection events accumulate. Tightens OPSEC, reduces volume. |
| Confidence | Increases as techniques succeed. Broadens search space, increases aggression. |

**Open questions:**
- Should these be continuous values or discrete states?
- Do they reset between engagements or carry over? (Paranoia from a burned engagement might carry into the next.)
- Can Raphael override its own hormonal state? ("I know I'm paranoid, but this target really is clean.")

---

## Part 14: File Map (When Built)

The implementation will follow this layout:

```
raphael/
├── raphael-rebirth.md              # This document
├── cortex/
│   ├── planner.py                  # select_next_step()
│   ├── hypothesizer.py             # LLM scaffolding when stuck
│   └── model_refiner.py            # inward recon, zero-packet expansion
│
├── limbic/
│   ├── vector_controller.py        # multi-vector orchestration
│   ├── pivot_engine.py             # automatic pivot on burn
│   └── risk_assessor.py            # detection probability estimation
│
├── brainstem/
│   ├── heartbeat.py                # implant and session monitoring
│   ├── credential_refresher.py     # token/cookie auto-refresh
│   ├── thermoregulator.py          # spinal reflex circuit breaker
│   └── sleep_cycle.py              # disengagement timing (future)
│
├── hippocampus/
│   ├── case_store.py               # episodic narrative storage
│   ├── case_matcher.py             # similarity scoring
│   └── sequence_advisor.py         # next-step suggestion from past
│
├── cerebellum/
│   ├── technique_validator.py      # pre-execution correctness check
│   ├── payload_encoder.py          # encoding adjustment
│   └── error_diagnoser.py          # failure classification
│
├── corpus_callosum/
│   └── implication_engine.py       # cross-domain link discovery
│
├── circulatory/
│   ├── blackboard.py               # SQLite persistent state
│   ├── event_bus.py                # asyncio pub/sub
│   └── spinal_reflex.py            # direct inhibition
│
├── models/
│   ├── target_model.py             # TargetModel, DomainState, ConstraintDelta
│   ├── capability_model.py         # CapabilityModel, Capability, Acquisition
│   └── engagement_state.py         # EngagementState
│
├── techniques/
│   ├── __init__.py                 # technique registry + Technique dataclass
│   ├── network/                    # SMB, LDAP, HTTP, Kerberos, DNS, etc.
│   ├── physical/                   # Interdiction, tampering (future)
│   ├── human/                      # Phishing, social engineering (future)
│   └── supply_chain/               # Vendor compromise, dependency poisoning (future)
│
├── memory/
│   ├── statistical_prior.py        # Cross-target technique success rates
│   ├── pain_memory.py              # Context-rich failure incidents (future)
│   └── skill_tree.py               # Learned heuristic rules
│
├── reflection/
│   └── engine.py                   # Post-engagement decision replay
│
├── executor/
│   └── executor.py                 # Run one technique, parse result, update models
│
└── config/
    └── config.py                   # Configuration loading
```

---

*End of architecture document.*
