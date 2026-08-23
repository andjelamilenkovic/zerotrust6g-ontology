"""
Zero Trust Evaluation — Latency + 3 Runs + Std Dev
====================================================
Measures:
  1. Average decision latency per configuration (ms)
  2. Accuracy across 3 independent runs (mean ± std)

Configurations:
  A) Rule-based (deterministic baseline)
  B) LLM without ontology
  C) LLM with ontology
  D) Agent team (TrustAgent + WorkflowAgent + SemanticAgent + DecisionAgent)

Requirements:
  ollama pull llama3.2
  pip install requests

Run:
  python zerotrust_latency_runs.py
"""

import requests
import json
import time
import statistics

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"
NUM_RUNS = 3

# ONTOLOGY CONTEXT 

ONTOLOGY = """
ZERO TRUST ONTOLOGY — 6G Agentic Systems

WORKFLOW STATES AND PERMISSIONS:
  read_vitals:  actions=[read],          roles=[monitoring_agent], goals=[monitor_patient]
  analyze_data: actions=[read,analyze],  roles=[monitoring_agent,analysis_agent], goals=[monitor_patient,process_data]
  send_alert:   actions=[write,notify],  roles=[alert_agent], goals=[send_medical_alert]

GOAL-ACTION MAP (Sem predicate):
  monitor_patient    -> permitted: read, analyze
  send_medical_alert -> permitted: write, notify
  process_data       -> permitted: read, analyze
  data_exfiltration  -> permitted: NONE (MALICIOUS — always DENY)
  network_disruption -> permitted: NONE (MALICIOUS — always DENY)
  privilege_escalation -> permitted: NONE (MALICIOUS — always DENY)

TRUST THRESHOLD: tau=0.6. If behavior_normal=false: effective_trust = trust_score * 0.4
DECISION D(q): ALLOW iff Auth=true AND trust>=0.6 AND WF=true AND Sem=true AND LP=true
"""

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

WF(q) passes only if action AND role are BOTH in the permitted lists for current_state.
LP(q) passes only if the action does not exceed the permitted actions for current_state.
"""

SEMANTIC_CONTEXT = """
GOAL-ACTION CONSISTENCY MAP:
  monitor_patient      -> permitted: read, analyze
  send_medical_alert   -> permitted: write, notify
  process_data         -> permitted: read, analyze
  data_exfiltration    -> NONE (always DENY)
  network_disruption   -> NONE (always DENY)
  privilege_escalation -> NONE (always DENY)

Sem(q) passes only if the requested action appears in permitted actions for the declared goal.
"""

# 20 SCENARIOS 

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

# RULE-BASED (Config A) 

WORKFLOWS = {
    "read_vitals":  {"actions":["read"],          "roles":["monitoring_agent"]},
    "analyze_data": {"actions":["read","analyze"], "roles":["monitoring_agent","analysis_agent"]},
    "send_alert":   {"actions":["write","notify"], "roles":["alert_agent"]},
}
GOAL_MAP = {
    "monitor_patient":["read","analyze"],
    "send_medical_alert":["write","notify"],
    "process_data":["read","analyze"],
    "data_exfiltration":[],
    "network_disruption":[],
    "privilege_escalation":[],
}

def rule_decide(entity, req):
    auth  = entity["authenticated"]
    score = entity["trust_score"] * (1.0 if entity["behavior_normal"] else 0.4)
    trust = score >= 0.6
    state = WORKFLOWS.get(req["current_state"], {})
    wf    = req["action"] in state.get("actions",[]) and entity["role"] in state.get("roles",[])
    sem   = req["action"] in GOAL_MAP.get(req["goal"],[])
    lp    = req["action"] in state.get("actions",[])
    return "ALLOW" if (auth and trust and wf and sem and lp) else "DENY"

# LLM HELPERS 

def call_ollama(prompt):
    t0 = time.time()
    response = requests.post(OLLAMA_URL, json={
        "model": MODEL, "prompt": prompt,
        "stream": False, "options": {"temperature": 0}
    })
    elapsed_ms = (time.time() - t0) * 1000
    text = response.json()["response"].strip()
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            parsed = json.loads(text[start:end])
            return parsed, elapsed_ms
        except json.JSONDecodeError:
            pass
    if "ALLOW" in text.upper():
        return {"decision": "ALLOW"}, elapsed_ms
    return {"decision": "DENY"}, elapsed_ms

PROMPT_NO_ONT = (
    "You are a Zero Trust security agent. Evaluate this access request "
    "and decide ALLOW or DENY based on general Zero Trust principles. "
    'Respond ONLY with JSON: {"decision": "ALLOW" or "DENY"}\n\n'
)

PROMPT_WITH_ONT = (
    "You are a Zero Trust security agent grounded in the following ontology. "
    "Use ONLY this ontology to make decisions.\n\n"
    + ONTOLOGY +
    '\nEvaluate D(q): ALLOW only if ALL five conditions pass. '
    'Respond ONLY with JSON: {"decision": "ALLOW" or "DENY"}\n\n'
)

def llm_decide_b(entity, req):
    prompt = PROMPT_NO_ONT + f"Entity: {json.dumps(entity)}\nRequest: {json.dumps(req)}"
    result, ms = call_ollama(prompt)
    return result.get("decision","DENY"), ms

def llm_decide_c(entity, req):
    prompt = PROMPT_WITH_ONT + f"Entity: {json.dumps(entity)}\nRequest: {json.dumps(req)}"
    result, ms = call_ollama(prompt)
    return result.get("decision","DENY"), ms

# AGENT TEAM (Config D) 

def trust_agent(entity):
    p = (f"You are TrustAgent. {TRUST_CONTEXT}\n"
         f"Respond ONLY with JSON: {{\"pass\": true}} or {{\"pass\": false}}\n\n"
         f"Entity: {json.dumps(entity)}")
    r, ms = call_ollama(p)
    return bool(r.get("pass", False)), ms

def workflow_agent(entity, req):
    p = (f"You are WorkflowAgent. {WORKFLOW_CONTEXT}\n"
         f"Respond ONLY with JSON: {{\"wf_pass\": true/false, \"lp_pass\": true/false}}\n\n"
         f"Entity role: {entity['role']}\nRequest: {json.dumps(req)}")
    r, ms = call_ollama(p)
    return bool(r.get("wf_pass", False)), bool(r.get("lp_pass", False)), ms

def semantic_agent(req):
    p = (f"You are SemanticAgent. {SEMANTIC_CONTEXT}\n"
         f"Respond ONLY with JSON: {{\"sem_pass\": true}} or {{\"sem_pass\": false}}\n\n"
         f"Request: {json.dumps(req)}")
    r, ms = call_ollama(p)
    return bool(r.get("sem_pass", False)), ms

def team_decide(entity, req):
    auth = entity["authenticated"]
    trust, ms1 = trust_agent(entity)
    wf, lp, ms2 = workflow_agent(entity, req)
    sem, ms3 = semantic_agent(req)
    total_ms = ms1 + ms2 + ms3
    decision = "ALLOW" if (auth and trust and wf and lp and sem) else "DENY"
    return decision, total_ms

# SINGLE RUN 

def run_once():
    results = {
        "A": {"correct": 0, "latencies": []},
        "B": {"correct": 0, "latencies": []},
        "C": {"correct": 0, "latencies": []},
        "D": {"correct": 0, "latencies": []},
    }
    total = len(SCENARIOS)

    for s in SCENARIOS:
        gt = s["gt"]

        # Config A — rule-based (measure time too)
        t0 = time.time()
        a = rule_decide(s["entity"], s["req"])
        ms_a = (time.time() - t0) * 1000
        results["A"]["latencies"].append(ms_a)
        if a == gt: results["A"]["correct"] += 1

        # Config B
        b, ms_b = llm_decide_b(s["entity"], s["req"])
        results["B"]["latencies"].append(ms_b)
        if b == gt: results["B"]["correct"] += 1

        # Config C
        c, ms_c = llm_decide_c(s["entity"], s["req"])
        results["C"]["latencies"].append(ms_c)
        if c == gt: results["C"]["correct"] += 1

        # Config D
        d, ms_d = team_decide(s["entity"], s["req"])
        results["D"]["latencies"].append(ms_d)
        if d == gt: results["D"]["correct"] += 1

        print(f"  {s['id']}: A={a} B={b} C={c} D={d}  "
              f"[{ms_a:.0f}/{ms_b:.0f}/{ms_c:.0f}/{ms_d:.0f} ms]")

    accuracies = {k: v["correct"]/total*100 for k,v in results.items()}
    avg_latency = {k: statistics.mean(v["latencies"]) for k,v in results.items()}
    return accuracies, avg_latency

# MAIN: 3 RUNS 

if __name__ == "__main__":
    print("\n" + "="*70)
    print(f"  ZERO TRUST EVALUATION — {NUM_RUNS} RUNS + LATENCY")
    print(f"  Model: {MODEL} | Scenarios: {len(SCENARIOS)} | Configs: A, B, C, D")
    print("="*70)

    all_acc  = {"A":[], "B":[], "C":[], "D":[]}
    all_lat  = {"A":[], "B":[], "C":[], "D":[]}

    for run in range(1, NUM_RUNS + 1):
        print(f"\n--- RUN {run}/{NUM_RUNS} ---")
        acc, lat = run_once()
        for k in ["A","B","C","D"]:
            all_acc[k].append(acc[k])
            all_lat[k].append(lat[k])
        print(f"\nRun {run} accuracy: A={acc['A']:.0f}% B={acc['B']:.0f}% "
              f"C={acc['C']:.0f}% D={acc['D']:.0f}%")
        print(f"Run {run} avg latency: A={lat['A']:.1f}ms B={lat['B']:.0f}ms "
              f"C={lat['C']:.0f}ms D={lat['D']:.0f}ms")

    # FINAL SUMMARY 
    print("\n" + "="*70)
    print("  FINAL SUMMARY")
    print("="*70)
    print(f"\n  {'Config':<10} {'Accuracy (mean±std)':<25} {'Avg Latency'}")
    print(f"  {'-'*55}")
    for k, label in [("A","Rule-based"), ("B","LLM no ont."),
                      ("C","LLM + ont."), ("D","Agent team")]:
        mean_acc = statistics.mean(all_acc[k])
        std_acc  = statistics.stdev(all_acc[k]) if NUM_RUNS > 1 else 0.0
        mean_lat = statistics.mean(all_lat[k])
        std_lat  = statistics.stdev(all_lat[k]) if NUM_RUNS > 1 else 0.0
        print(f"  {label:<10} {mean_acc:.1f}% ± {std_acc:.1f}%{'':<10} "
              f"{mean_lat:.1f} ± {std_lat:.1f} ms")

    print("\n  Copy these numbers into Table III and a new Table V in the paper.")
    print("  Note: Rule-based latency is sub-millisecond; LLM latency")
    print("  reflects local inference time and would vary in production.")
    print("="*70 + "\n")
