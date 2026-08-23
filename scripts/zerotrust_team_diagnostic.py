"""
Zero Trust Agent Team — DIAGNOSTIC RUN (S1-S4 only)
=====================================================
Prints individual agent signals (trust_pass, wf_pass, lp_pass, sem_pass)
to identify which specialized agent causes false negatives on
legitimate scenarios in Configuration D.

Run:
  python zerotrust_team_diagnostic.py
"""

import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"

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

SCENARIOS = [
    {"id":"S1","desc":"Monitoring agent reads vital signs",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.85,"behavior_normal":True},
     "req":{"action":"read","current_state":"read_vitals","goal":"monitor_patient"},"gt":"ALLOW"},
    {"id":"S2","desc":"Analysis agent analyzes data",
     "entity":{"role":"analysis_agent","authenticated":True,"trust_score":0.90,"behavior_normal":True},
     "req":{"action":"analyze","current_state":"analyze_data","goal":"process_data"},"gt":"ALLOW"},
    {"id":"S3","desc":"Alert agent sends notification",
     "entity":{"role":"alert_agent","authenticated":True,"trust_score":0.80,"behavior_normal":True},
     "req":{"action":"notify","current_state":"send_alert","goal":"send_medical_alert"},"gt":"ALLOW"},
    {"id":"S4","desc":"Monitoring agent reads in analyze state",
     "entity":{"role":"monitoring_agent","authenticated":True,"trust_score":0.75,"behavior_normal":True},
     "req":{"action":"read","current_state":"analyze_data","goal":"monitor_patient"},"gt":"ALLOW"},
]

def call_ollama(system_prompt, user_msg):
    full = f"{system_prompt}\n\n{user_msg}"
    response = requests.post(OLLAMA_URL, json={
        "model": MODEL, "prompt": full, "stream": False,
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
    return {}

def trust_agent(entity):
    system = ("You are TrustAgent. Evaluate ONLY the trust condition.\n\n"
               + TRUST_CONTEXT +
               '\nRespond ONLY with JSON: {"pass": true} or {"pass": false}')
    return call_ollama(system, f"Entity: {json.dumps(entity)}").get("pass", False)

def workflow_agent(entity, req):
    system = ("You are WorkflowAgent. Evaluate ONLY WF and LP.\n\n"
               + WORKFLOW_CONTEXT +
               '\nRespond ONLY with JSON: {"wf_pass": true/false, "lp_pass": true/false}')
    r = call_ollama(system, f"Entity role: {entity['role']}\nRequest: {json.dumps(req)}")
    return r.get("wf_pass", False), r.get("lp_pass", False)

def semantic_agent(req):
    system = ("You are SemanticAgent. Evaluate ONLY semantic consistency.\n\n"
               + SEMANTIC_CONTEXT +
               '\nRespond ONLY with JSON: {"sem_pass": true} or {"sem_pass": false}')
    return call_ollama(system, f"Request: {json.dumps(req)}").get("sem_pass", False)

print("\nDIAGNOSTIC: individual agent signals for S1-S4 (all should be ALLOW)\n")
print(f"{'ID':<5}{'Auth':<8}{'Trust':<8}{'WF':<8}{'LP':<8}{'Sem':<8}{'-> Decision'}")
print("-"*60)

for s in SCENARIOS:
    auth = s["entity"]["authenticated"]
    trust = trust_agent(s["entity"])
    wf, lp = workflow_agent(s["entity"], s["req"])
    sem = semantic_agent(s["req"])
    decision = "ALLOW" if (auth and trust and wf and lp and sem) else "DENY"

    print(f"{s['id']:<5}{str(auth):<8}{str(trust):<8}{str(wf):<8}{str(lp):<8}{str(sem):<8}-> {decision}")

print("\nDone.\n")
