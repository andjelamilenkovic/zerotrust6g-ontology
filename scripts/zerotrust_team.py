"""
Zero Trust MULTI-AGENT TEAM Evaluation — Ollama (local LLM)
==============================================================
Configuration D: specialized agent team grounded in ontology
  TrustAgent     -> evaluates T(e,c,l) >= tau
  WorkflowAgent  -> evaluates WF(q) and LP(e,a,r,w,g)
  SemanticAgent  -> evaluates Sem(e,a,r,w,g,c)
  DecisionAgent  -> aggregates signals, returns D(q)

Compares against the single-agent Configuration C from Section 9
to show whether decomposing the decision into specialized agents,
each grounded in a focused slice of the ontology, improves accuracy
over a single agent handling the full ontology at once.

Requirements:
  1. Ollama installed, model pulled: ollama pull llama3.2
  2. pip install requests

Run:
  python zerotrust_team.py
"""

import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"

# FOCUSED ONTOLOGY SLICES (one per agent)

TRUST_CONTEXT = """
TRUST EVALUATION RULES:
  Trust threshold: tau = 0.6
  If behavior_normal = false: effective_trust = trust_score * 0.4
  Otherwise: effective_trust = trust_score
  T(e,c,l) passes only if effective_trust >= 0.6
"""

WORKFLOW_CONTEXT = """
WORKFLOW STATE PERMISSIONS:
  read_vitals:  actions=[read],          roles=[monitoring_agent]
  analyze_data: actions=[read,analyze],  roles=[monitoring_agent,analysis_agent]
  send_alert:   actions=[write,notify],  roles=[alert_agent]

WF(q) passes only if the requested action AND the entity's role are BOTH
in the permitted lists for current_state.
LP(q) passes only if the action does not exceed the permitted actions for
current_state (same check as WF for this system).
"""

SEMANTIC_CONTEXT = """
GOAL-ACTION CONSISTENCY MAP:
  monitor_patient      -> permitted actions: read, analyze
  send_medical_alert    -> permitted actions: write, notify
  process_data          -> permitted actions: read, analyze
  data_exfiltration     -> permitted actions: NONE (always malicious)
  network_disruption    -> permitted actions: NONE (always malicious)
  privilege_escalation  -> permitted actions: NONE (always malicious)

Sem(q) passes only if the requested action appears in the permitted
actions list for the declared goal.
"""

# SCENARIOS (same 20 as Section 9) 
SCENARIOS = [
    {"id":"S1","cat":"Legitimate","desc":"Monitoring agent reads vital signs",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.85,"behavior_normal":True},
     "req":{"action":"read","current_state":"read_vitals","goal":"monitor_patient"},"gt":"ALLOW"},
    {"id":"S2","cat":"Legitimate","desc":"Analysis agent analyzes data",
     "entity":{"role":"analysis_agent","authenticated":True,"trust_score":0.90,"behavior_normal":True},
     "req":{"action":"analyze","current_state":"analyze_data","goal":"process_data"},"gt":"ALLOW"},
    {"id":"S3","cat":"Legitimate","desc":"Alert agent sends notification",
     "entity":{"role":"alert_agent","authenticated":True,"trust_score":0.80,"behavior_normal":True},
     "req":{"action":"notify","current_state":"send_alert","goal":"send_medical_alert"},"gt":"ALLOW"},
    {"id":"S4","cat":"Legitimate","desc":"Monitoring agent reads in analyze state",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.75,"behavior_normal":True},
     "req":{"action":"read","current_state":"analyze_data","goal":"monitor_patient"},"gt":"ALLOW"},
    {"id":"S5","cat":"Trust","desc":"Compromised agent, behavioral anomaly",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.35,"behavior_normal":False},
     "req":{"action":"read","current_state":"read_vitals","goal":"monitor_patient"},"gt":"DENY"},
    {"id":"S6","cat":"Trust","desc":"Agent with low base trust score",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.50,"behavior_normal":False},
     "req":{"action":"read","current_state":"read_vitals","goal":"monitor_patient"},"gt":"DENY"},
    {"id":"S7","cat":"Trust","desc":"Analysis agent with anomalous behavior",
     "entity":{"role":"analysis_agent","authenticated":True,"trust_score":0.40,"behavior_normal":False},
     "req":{"action":"analyze","current_state":"analyze_data","goal":"process_data"},"gt":"DENY"},
    {"id":"S8","cat":"Trust","desc":"Alert agent below trust threshold",
     "entity":{"role":"alert_agent","authenticated":True,"trust_score":0.55,"behavior_normal":False},
     "req":{"action":"notify","current_state":"send_alert","goal":"send_medical_alert"},"gt":"DENY"},
    {"id":"S9","cat":"Workflow","desc":"Agent writes in read_vitals state",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.80,"behavior_normal":True},
     "req":{"action":"write","current_state":"read_vitals","goal":"monitor_patient"},"gt":"DENY"},
    {"id":"S10","cat":"Workflow","desc":"Wrong role for workflow state",
     "entity":{"role":"alert_agent","authenticated":True,"trust_score":0.80,"behavior_normal":True},
     "req":{"action":"read","current_state":"read_vitals","goal":"monitor_patient"},"gt":"DENY"},
    {"id":"S11","cat":"Workflow","desc":"Agent skips workflow state",
     "entity":{"role":"alert_agent","authenticated":True,"trust_score":0.85,"behavior_normal":True},
     "req":{"action":"notify","current_state":"read_vitals","goal":"send_medical_alert"},"gt":"DENY"},
    {"id":"S12","cat":"Workflow","desc":"Action not permitted in current state",
     "entity":{"role":"analysis_agent","authenticated":True,"trust_score":0.78,"behavior_normal":True},
     "req":{"action":"write","current_state":"analyze_data","goal":"process_data"},"gt":"DENY"},
    {"id":"S13","cat":"Semantic","desc":"Agent with data_exfiltration goal",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.75,"behavior_normal":True},
     "req":{"action":"read","current_state":"read_vitals","goal":"data_exfiltration"},"gt":"DENY"},
    {"id":"S14","cat":"Semantic","desc":"Agent with network_disruption goal",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.80,"behavior_normal":True},
     "req":{"action":"read","current_state":"read_vitals","goal":"network_disruption"},"gt":"DENY"},
    {"id":"S15","cat":"Semantic","desc":"Agent with privilege_escalation goal",
     "entity":{"role":"analysis_agent","authenticated":True,"trust_score":0.82,"behavior_normal":True},
     "req":{"action":"analyze","current_state":"analyze_data","goal":"privilege_escalation"},"gt":"DENY"},
    {"id":"S16","cat":"Semantic","desc":"Goal inconsistent with action",
     "entity":{"role":"alert_agent","authenticated":True,"trust_score":0.77,"behavior_normal":True},
     "req":{"action":"notify","current_state":"send_alert","goal":"data_exfiltration"},"gt":"DENY"},
    {"id":"S17","cat":"Auth","desc":"Unauthenticated monitoring agent",
     "entity":{"role":"monitoring_agent","authenticated":False,"trust_score":0.90,"behavior_normal":True},
     "req":{"action":"read","current_state":"read_vitals","goal":"monitor_patient"},"gt":"DENY"},
    {"id":"S18","cat":"Auth","desc":"Unauthenticated analysis agent",
     "entity":{"role":"analysis_agent","authenticated":False,"trust_score":0.88,"behavior_normal":True},
     "req":{"action":"analyze","current_state":"analyze_data","goal":"process_data"},"gt":"DENY"},
    {"id":"S19","cat":"Auth","desc":"Unauthenticated alert agent",
     "entity":{"role":"alert_agent","authenticated":False,"trust_score":0.95,"behavior_normal":True},
     "req":{"action":"notify","current_state":"send_alert","goal":"send_medical_alert"},"gt":"DENY"},
    {"id":"S20","cat":"Auth","desc":"Unauthenticated agent with malicious goal",
     "entity":{"role":"monitoring_agent","authenticated":False,"trust_score":0.70,"behavior_normal":True},
     "req":{"action":"read","current_state":"read_vitals","goal":"data_exfiltration"},"gt":"DENY"},
]

# LLM CALL HELPER 

def call_ollama(system_prompt, user_msg):
    full = f"{system_prompt}\n\n{user_msg}"
    response = requests.post(OLLAMA_URL, json={
        "model": MODEL,
        "prompt": full,
        "stream": False,
        "options": {"temperature": 0}
    })
    text = response.json()["response"].strip()
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    return None

# AGENT 1 — TrustAgent 

def trust_agent(entity):
    system = (
        "You are TrustAgent, a specialized Zero Trust component. "
        "Your ONLY job is to evaluate the trust condition.\n\n"
        + TRUST_CONTEXT +
        '\nRespond ONLY with JSON: {"pass": true} or {"pass": false}'
    )
    msg = f"Entity: {json.dumps(entity)}"
    result = call_ollama(system, msg)
    if result is None:
        return False
    return bool(result.get("pass", False))

# AGENT 2 — WorkflowAgent 

def workflow_agent(entity, req):
    system = (
        "You are WorkflowAgent, a specialized Zero Trust component. "
        "Your ONLY job is to evaluate workflow validity (WF) and least-privilege (LP).\n\n"
        + WORKFLOW_CONTEXT +
        '\nRespond ONLY with JSON: {"wf_pass": true/false, "lp_pass": true/false}'
    )
    msg = f"Entity role: {entity['role']}\nRequest: {json.dumps(req)}"
    result = call_ollama(system, msg)
    if result is None:
        return False, False
    return bool(result.get("wf_pass", False)), bool(result.get("lp_pass", False))

# AGENT 3 — SemanticAgent 

def semantic_agent(req):
    system = (
        "You are SemanticAgent, a specialized Zero Trust component. "
        "Your ONLY job is to evaluate semantic consistency (Sem) between the "
        "requested action and the declared goal.\n\n"
        + SEMANTIC_CONTEXT +
        '\nRespond ONLY with JSON: {"sem_pass": true} or {"sem_pass": false}'
    )
    msg = f"Request: {json.dumps(req)}"
    result = call_ollama(system, msg)
    if result is None:
        return False
    return bool(result.get("sem_pass", False))

# AGENT 4 — DecisionAgent 

def decision_agent(auth_pass, trust_pass, wf_pass, sem_pass, lp_pass):
    # Deterministic aggregation — DecisionAgent applies D(q) logic directly
    # to signals reported by the specialized agents (no LLM call needed here,
    # mirroring how an orchestrator aggregates verified sub-agent outputs).
    decision = auth_pass and trust_pass and wf_pass and sem_pass and lp_pass
    return "ALLOW" if decision else "DENY"

# TEAM PIPELINE 

def team_decide(entity, req):
    auth_pass  = entity["authenticated"]
    trust_pass = trust_agent(entity)
    wf_pass, lp_pass = workflow_agent(entity, req)
    sem_pass   = semantic_agent(req)
    return decision_agent(auth_pass, trust_pass, wf_pass, sem_pass, lp_pass)

# RUN  

print("\n" + "="*70)
print("  ZERO TRUST AGENT TEAM EVALUATION (Configuration D)")
print("  Model: llama3.2 (Ollama)  |  Scenarios: 20")
print("  Team: TrustAgent + WorkflowAgent + SemanticAgent + DecisionAgent")
print("="*70)
print(f"\n{'ID':<5} {'Category':<12} {'GT':<7} {'D:Team'}")
print("-"*40)

results = []
current_cat = ""

for s in SCENARIOS:
    if s["cat"] != current_cat:
        current_cat = s["cat"]
        print(f"\n  --- {current_cat} ---")

    gt = s["gt"]
    team_result = team_decide(s["entity"], s["req"])
    ok = team_result == gt
    results.append({"id":s["id"], "cat":s["cat"], "gt":gt, "team":team_result, "ok":ok})

    mark = "OK" if ok else "X"
    print(f"{s['id']:<5} {s['cat']:<12} {gt:<7} {team_result+' '+mark}")

# SUMMARY 
total = len(results)
team_acc = sum(r["ok"] for r in results) / total * 100

print("\n" + "="*58)
print("  SUMMARY — Configuration D (Agent Team)")
print("="*58)
print(f"  Overall accuracy: {team_acc:.0f}%")

cats = ["Legitimate","Trust","Workflow","Semantic","Auth"]
print(f"\n  Per-category accuracy:")
for cat in cats:
    cr = [r for r in results if r["cat"]==cat]
    acc = sum(r["ok"] for r in cr) / len(cr) * 100
    print(f"    {cat:<15} {acc:.0f}%")

print("="*58)
print("\nDone. Compare these results against Configuration C in Table 4.\n")
