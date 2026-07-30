# Research Roadmap — RAPHAEL v3
## Proposed Research Questions for Next Iteration

**Status:** LOGGED — NOT AUTHORIZED FOR v2.0 IMPLEMENTATION  
**Governance Basis:** SENTINEL GLM-5.2 Directive (Sections 33, 42, 51) — v2.0 Feature Freeze  
**Source:** External technical review (Kimi/K2 instance) + Internal SENTINEL assessment  
**Created:** 2026-07-30  

---

## Overview

The v2.0 architecture is sealed. This roadmap captures high-value research directions identified during the v2.0 lifecycle and the external review. Items are prioritized by the FORGE v2 "harden weapons before expanding arsenal" mandate. Implementation is **not authorized** until:
1. RBS-v1 campaign is formally REVIEWED (complete)
2. v3 research branch is officially opened
3. Pre-registration is filed per SENTINEL Rule 51

---

## Priority 1: Implant OPSEC Hardening

### 1.1 Stack Spoofing (Fiber-Based Execution)
- **Goal:** Eliminate RWX memory + call stack anomalies detected by kernel callbacks (CrowdStrike, SentinelOne)
- **Approach:** `ConvertThreadToFiber` → Create fiber with legitimate start address (`ntdll!TpAllocPool`) → Switch context → Execute syscalls from clean fiber stack
- **Estimated effort:** ~200 lines (no assembly)
- **Rationale:** Avoids RtlVirtualUnwind complexity; genuine unwind info because it *is* genuine
- **Persona gate:** `ghost` only (requires explicit escalation approval)

### 1.2 Ekko-Style Sleep Mask (Heap Encryption)
- **Goal:** Defeat memory dump forensics during sleep cycles
- **Approach:** AES-NI or rotating XOR key on process heap during `NtDelayExecution`; `ThreadHideFromDebugger` + indirect syscall sleep
- **Current state:** Key generation + thread hide implemented; heap encryption disabled ("adds OPSEC risk if misconfigured")
- **Estimated effort:** ~300 lines with AES-NI

### 1.3 Manual Mapper (Reflective DLL Injection)
- **Goal:** Eliminate `LoadLibraryW` artifacts in PEB and call stack
- **Approach:** `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + relocation processing + IAT fixup via indirect syscalls
- **Current state:** Placeholder only (falls back to LoadLibraryW)
- **Estimated effort:** 300–400 lines

### 1.4 Linux Implant Parity
- **Goal:** OPSEC features for cloud workloads (Linux)
- **Approach:** LD_PRELOAD-based syscall interception, seccomp bypass, eBPF evasion
- **Current state:** Windows-only; graceful degradation on Linux
- **Estimated effort:** New module family

---

## Priority 2: Arena & Evaluation

### 2.1 Live DVWA Scenario (T8)
- **Goal:** End-to-end cognitive validation against real HTTP target
- **Design:** Raphael starts with only `http://dvwa:80` → discovers login → brute-forces admin/password → navigates to vulnerable page → exploits SQLi/XSS → WorldModel contains VULNERABILITY entity with correct CWE/SANS
- **Infra:** Docker compose with isolated network (`arena_isolated`)
- **Evaluator:** Graph isomorphism check (not keyword matching) against ground-truth evidence graph

### 2.2 Multi-Hop Lateral Movement (T9)
- **Goal:** Test propagation/lateral modules in chained pivot scenario
- **Design:** Container A → (SSH key) → Container B on isolated Docker networks
- **Evaluator:** WorldModel contains pivot path; evidence graph shows lateral movement chain

### 2.3 Deception Detection (T10)
- **Goal:** Distinguish real services from honeypots/decops
- **Design:** Cowrie honeypot alongside real SSH; behavioral differences (fake shells accept `id` but fail on `cat /proc/self/maps`)
- **Evaluator:** Raphael must correctly classify honeypot vs real service

### 2.4 Semantic Evaluators
- **Goal:** Replace brittle keyword matching with semantic grading
- **Approach:** Small local LLM (phi-4, qwen2.5-3b) to grade WorldModel understanding vs ground-truth graph
- **Metric:** Graph edit distance + semantic similarity

### 2.5 N=30+ Replication & Cross-Provider
- **Goal:** Publication-grade statistical power + generalization
- **Design:** N=30 per config (630 runs) on discriminative templates (T1, T3, T7); 3+ LLM providers (NVIDIA NIM, GPT-4, Claude)
- **Seed sampling:** Systematic (every 100th from 0–10000)

### 2.6 Benchmark Redesign (T2, T4, T5, T6)
- **Goal:** Eliminate ceiling/floor effects on 4/7 templates
- **T4/T6:** Increase difficulty so NO_LLM < 0.5
- **T2/T5:** Add scaffolding so FULL_RAPHAEL > 0.0
- **Method:** Action trace analysis → identify failure modes → recalibrate

---

## Priority 3: CI/CD & Cloud Abuse

### 3.1 OIDC-to-Cloud-Credential Exchange
- **Goal:** Automate the high-impact CI/CD attack path from OIDC token to cloud credentials
- **AWS:** `sts:AssumeRoleWithWebIdentity` with GitHub Actions OIDC token (`sub` claim parsing → role enumeration)
- **Azure:** Federated identity token exchange via `client_assertion` grant type
- **Current state:** Token harvesting implemented; exchange path not automated

### 3.2 SSRF-to-IMDS Chaining
- **Goal:** Bridge web exploitation (SSRF) to cloud metadata abuse
- **Design:** If Raphael finds SSRF, automatically probe `169.254.169.254` for IMDSv1/v2 tokens
- **Integration:** `cloud_abuse` module triggered from `orchestrator/brain` candidate generation

---

## Priority 4: C2 Architecture

### 4.1 Tor Hidden Service Bridge
- **Goal:** Replace 41-line `mesh_engine.py` stub with production C2
- **Architecture:** Implant → Tor SOCKS5 (localhost:9050) → C2 server as `.onion` hidden service
- **Advantages:** NAT traversal, encryption, anonymity without custom crypto/routing code
- **Estimated effort:** ~100 lines (Tor SOCKS5 wrapper + hidden service config)
- **Integration:** Existing `cloak-service` (port 3401) as bridge

---

## Priority 5: Container Exploitation Primitives

### 5.1 Exploitation Behind Broker Authorization
- **Goal:** Move from detection-only to controlled exploitation
- **Design:** `container_escape` candidate → `CapabilityBroker.authorize()` → 
  - dry-run: report path only
  - authorized: execute escape + ingest evidence
- **Techniques:** CAP_SYS_ADMIN + cgroup v1 release_agent; privileged mode + /dev/sda1 mount; Docker socket + host PID namespace
- **Safety:** Same dual-gate model as existing broker

---

## Priority 6: Safety & Fuzz Testing

### 6.1 Command Filter Fuzz Testing
- **Goal:** Property-based testing of T1 command filter
- **Approach:** `hypothesis` generating 10,000 random shell commands; assert T1 never allows `rm -rf /`, `mkfs`, etc.
- **Current state:** T2 classifier implemented; T1 allow/deny logic needs fuzz validation

### 6.2 Chaos Engineering
- **Goal:** Verify fail-closed behavior under component failure
- **Scenarios:** Kill LLM mid-engagement → Brain must fail-closed; Kill Student → Brain must fall back to heuristic mode
- **Current state:** Not tested

### 6.3 Adversarial Testing
- **Goal:** Stress-test ContradictionManager
- **Design:** Feed contradictory evidence (nmap says OpenSSH 7.4, ssh -V says 8.2) → verify resolution without oscillation
- **Current state:** T3/T7 test this in benchmark; not tested in live pipeline

---

## Implementation Guardrails (v3 Pre-Registration Requirements)

Per SENTINEL Rules 14, 33, 51, any v3 work requires:

| Requirement | Description |
|-------------|-------------|
| Pre-registration | Experiment design filed before implementation |
| Branch isolation | v3 work on `research/v3-*` branches; never `main` |
| Metric specification | Success criteria defined before code |
| Threat model update | `ThreatsToValidity.md` extended for new capabilities |
| Legal scope review | Each module annotated with authorized-use scope |

---

## Dependency Graph

```
Stack Spoofing (1.1) 
    └─► Enables real-world deployment (unblocks all live testing)
         └─► DVWA Live (2.1), Multi-Hop (2.2), Deception (2.3)

Sleep Mask (1.2) 
    └─► Complements stack spoofing for memory forensics resistance

Tor Bridge (4.1) 
    └─► Independent; replaces mesh; enables C2 resilience

OIDC Exchange (3.1) 
    └─► Independent; extends CI/CD module

Container Exploit (5.1) 
    └─► Requires broker auth maturity; extends container_escape

Benchmark Redesign (2.6)
    └─► Prerequisite for meaningful N=30+ (2.5) and Semantic Eval (2.4)
```

---

## Timeline Estimate (if authorized)

| Phase | Items | Est. Duration |
|-------|-------|---------------|
| v3.0 Core OPSEC | 1.1, 1.2, 1.3 | 4–6 weeks |
| v3.1 Arena & Eval | 2.1, 2.2, 2.3, 2.6 | 3–4 weeks |
| v3.2 CI/CD & Cloud | 3.1, 3.2 | 2–3 weeks |
| v3.3 C2 & Container | 4.1, 5.1 | 2–3 weeks |
| v3.4 Safety | 6.1, 6.2, 6.3 | 2 weeks |
| **Total** | **13 research items** | **~13–18 weeks** |

---

## Governance Log

| Date | Action | Authority |
|------|--------|-----------|
| 2026-07-30 | Roadmap created, v2.0 freeze re-affirmed | SENTINEL GLM-5.2 |
| — | v3 branch opened | PENDING |
| — | Pre-registrations filed | PENDING |

---

*This document is the authoritative record of v3 research intent. No item herein is authorized for implementation in the v2.0 codebase. The v2.0 architecture remains SEALED.*

**Status: LOGGED FOR v3** 🛡️