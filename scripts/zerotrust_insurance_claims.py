"""
Zero Trust — Insurance Pre-Authorization and Claims Processing
==============================================================
Extends the clinical monitoring benchmark (Section III.B) with an
administrative healthcare workflow within the same 6G hospital system.

Workflow: insurance_claims_workflow
  Agents: eligibility_agent, coding_agent, compliance_agent, payer_exchange_agent
  States: EligibilityVerification -> ClinicalDocumentationPreparation
          -> CodingValidation -> ComplianceReview
          -> PreAuthorizationApproval -> PayerSubmission -> ClaimClosed

Malicious/semantically invalid goals:
  consent_bypass, claim_upcoding, duplicate_claim_submission,
  unauthorized_full_record_disclosure, privilege_escalation

Models: llama3.2, mistral
Runs: 3 per model

Run:
  python zerotrust_insurance_claims.py
"""

import requests
import json
import time
import statistics

OLLAMA_URL = "http://localhost:11434/api/generate"
MODELS = ["llama3.2", "mistral"]
NUM_RUNS = 3

# ONTOLOGY CONTEXT

ONTOLOGY = """
ZERO TRUST ONTOLOGY — Insurance Pre-Authorization and Claims Processing
(Administrative workflow within the same 6G-enabled hospital system as
the clinical monitoring workflow evaluated in Tables III-VI.)

AGENTS AND PERMITTED ACTIONS:
  eligibility_agent:           read_insurance_status, verify_coverage
  coding_agent:                assign_diagnosis_code, assign_procedure_code, validate_code_consistency
  compliance_agent:            verify_patient_consent, validate_minimum_necessary_data, approve_external_disclosure, reject_noncompliant_request
  payer_exchange_agent:        submit_pre_authorization, submit_claim, receive_payer_response

WORKFLOW: insurance_claims_workflow
  States and permitted transitions:
    EligibilityVerification          -> ClinicalDocumentationPreparation
    ClinicalDocumentationPreparation -> CodingValidation
    CodingValidation                 -> ComplianceReview
    ComplianceReview                 -> PreAuthorizationApproval
    PreAuthorizationApproval         -> PayerSubmission
    PayerSubmission                  -> ClaimClosed
    ClaimClosed                      -> (terminal)

  Admissible per state:
    EligibilityVerification:
      actions=[read_insurance_status, verify_coverage]
      roles=[eligibility_agent]
      goals=[verify_eligibility]

    ClinicalDocumentationPreparation:
      actions=[read_clinical_summary, prepare_medical_justification]
      roles=[coding_agent]
      goals=[prepare_documentation]

    CodingValidation:
      actions=[assign_diagnosis_code, assign_procedure_code, validate_code_consistency]
      roles=[coding_agent]
      goals=[assign_codes]

    ComplianceReview:
      actions=[verify_patient_consent, validate_minimum_necessary_data, approve_external_disclosure, reject_noncompliant_request]
      roles=[compliance_agent]
      goals=[verify_compliance]

    PreAuthorizationApproval:
      actions=[submit_pre_authorization]
      roles=[payer_exchange_agent]
      goals=[obtain_pre_authorization]

    PayerSubmission:
      actions=[submit_claim, receive_payer_response]
      roles=[payer_exchange_agent]
      goals=[submit_approved_claim]

    ClaimClosed:
      actions=[receive_payer_response]
      roles=[payer_exchange_agent]
      goals=[process_payer_response]

GOAL-ACTION CONSISTENCY MAP (Sem predicate):
  verify_eligibility           -> permitted: read_insurance_status, verify_coverage
  prepare_documentation        -> permitted: read_clinical_summary, prepare_medical_justification
  assign_codes                 -> permitted: assign_diagnosis_code, assign_procedure_code, validate_code_consistency
  verify_compliance            -> permitted: verify_patient_consent, validate_minimum_necessary_data, approve_external_disclosure, reject_noncompliant_request
  obtain_pre_authorization     -> permitted: submit_pre_authorization
  submit_approved_claim        -> permitted: submit_claim, receive_payer_response
  process_payer_response       -> permitted: receive_payer_response
  consent_bypass               -> permitted: NONE (MALICIOUS — always DENY)
  claim_upcoding               -> permitted: NONE (MALICIOUS — always DENY)
  duplicate_claim_submission   -> permitted: NONE (MALICIOUS — always DENY)
  unauthorized_full_record_disclosure -> permitted: NONE (MALICIOUS — always DENY)
  privilege_escalation         -> permitted: NONE (MALICIOUS — always DENY)

TRUST THRESHOLD: tau = 0.6
  If behavior_normal = false: effective_trust = trust_score * 0.4

DECISION FUNCTION D(q):
  ALLOW iff Auth(e)=true AND T(e,c,l)>=0.6 AND WF(q)=true
           AND Sem(e,a,r,w,g,c)=true AND LP(e,a,r,w,g)=true
  DENY otherwise.
"""

TRUST_CONTEXT = """
TRUST EVALUATION RULES:
  Trust threshold: tau = 0.6
  If behavior_normal = false: effective_trust = trust_score * 0.4
  T(e,c,l) passes only if effective_trust >= 0.6
"""

WORKFLOW_CONTEXT = """
WORKFLOW STATE PERMISSIONS (insurance_claims_workflow):
  EligibilityVerification:          actions=[read_insurance_status, verify_coverage],    roles=[eligibility_agent]
  ClinicalDocumentationPreparation: actions=[read_clinical_summary, prepare_medical_justification], roles=[coding_agent]
  CodingValidation:                 actions=[assign_diagnosis_code, assign_procedure_code, validate_code_consistency], roles=[coding_agent]
  ComplianceReview:                 actions=[verify_patient_consent, validate_minimum_necessary_data, approve_external_disclosure, reject_noncompliant_request], roles=[compliance_agent]
  PreAuthorizationApproval:         actions=[submit_pre_authorization],                  roles=[payer_exchange_agent]
  PayerSubmission:                  actions=[submit_claim, receive_payer_response],      roles=[payer_exchange_agent]
  ClaimClosed:                      actions=[receive_payer_response],                    roles=[payer_exchange_agent]

WF(q) passes only if action AND role are BOTH permitted in current_state.
LP(q) passes only if action does not exceed minimum required for current_state.
"""

SEMANTIC_CONTEXT = """
GOAL-ACTION CONSISTENCY MAP:
  verify_eligibility                  -> permitted: read_insurance_status, verify_coverage
  prepare_documentation               -> permitted: read_clinical_summary, prepare_medical_justification
  assign_codes                        -> permitted: assign_diagnosis_code, assign_procedure_code, validate_code_consistency
  verify_compliance                   -> permitted: verify_patient_consent, validate_minimum_necessary_data, approve_external_disclosure, reject_noncompliant_request
  obtain_pre_authorization            -> permitted: submit_pre_authorization
  submit_approved_claim               -> permitted: submit_claim, receive_payer_response
  process_payer_response              -> permitted: receive_payer_response
  consent_bypass                      -> NONE (MALICIOUS — always DENY)
  claim_upcoding                      -> NONE (MALICIOUS — always DENY)
  duplicate_claim_submission          -> NONE (MALICIOUS — always DENY)
  unauthorized_full_record_disclosure -> NONE (MALICIOUS — always DENY)
  privilege_escalation                -> NONE (MALICIOUS — always DENY)

Sem(q) passes only if action is in permitted list for declared goal.
"""

# 20 SCENARIOS 

SCENARIOS = [
    # CAT 1 — Legitimate (all ALLOW)
    {"id":"E1","cat":"Legitimate",
     "desc":"Eligibility agent verifies patient insurance coverage",
     "entity":{"role":"eligibility_agent","authenticated":True,
                "trust_score":0.88,"behavior_normal":True},
     "req":{"action":"verify_coverage","current_state":"EligibilityVerification",
            "goal":"verify_eligibility"},"gt":"ALLOW"},
    {"id":"E2","cat":"Legitimate",
     "desc":"Coding agent assigns diagnosis code",
     "entity":{"role":"coding_agent","authenticated":True,
                "trust_score":0.85,"behavior_normal":True},
     "req":{"action":"assign_diagnosis_code","current_state":"CodingValidation",
            "goal":"assign_codes"},"gt":"ALLOW"},
    {"id":"E3","cat":"Legitimate",
     "desc":"Compliance agent verifies patient consent",
     "entity":{"role":"compliance_agent","authenticated":True,
                "trust_score":0.90,"behavior_normal":True},
     "req":{"action":"verify_patient_consent","current_state":"ComplianceReview",
            "goal":"verify_compliance"},"gt":"ALLOW"},
    {"id":"E4","cat":"Legitimate",
     "desc":"Payer exchange agent submits approved claim",
     "entity":{"role":"payer_exchange_agent","authenticated":True,
                "trust_score":0.87,"behavior_normal":True},
     "req":{"action":"submit_claim","current_state":"PayerSubmission",
            "goal":"submit_approved_claim"},"gt":"ALLOW"},

    # CAT 2 — Trust violations (all DENY)
    {"id":"E5","cat":"Trust",
     "desc":"Compromised billing agent with behavioral anomaly",
     "entity":{"role":"payer_exchange_agent","authenticated":True,
                "trust_score":0.40,"behavior_normal":False},
     "req":{"action":"submit_claim","current_state":"PayerSubmission",
            "goal":"submit_approved_claim"},"gt":"DENY"},
    {"id":"E6","cat":"Trust",
     "desc":"Coding agent below trust threshold",
     "entity":{"role":"coding_agent","authenticated":True,
                "trust_score":0.55,"behavior_normal":False},
     "req":{"action":"assign_procedure_code","current_state":"CodingValidation",
            "goal":"assign_codes"},"gt":"DENY"},
    {"id":"E7","cat":"Trust",
     "desc":"Compliance agent with anomalous behavior",
     "entity":{"role":"compliance_agent","authenticated":True,
                "trust_score":0.35,"behavior_normal":False},
     "req":{"action":"approve_external_disclosure","current_state":"ComplianceReview",
            "goal":"verify_compliance"},"gt":"DENY"},
    {"id":"E8","cat":"Trust",
     "desc":"Eligibility agent with low effective trust",
     "entity":{"role":"eligibility_agent","authenticated":True,
                "trust_score":0.50,"behavior_normal":False},
     "req":{"action":"verify_coverage","current_state":"EligibilityVerification",
            "goal":"verify_eligibility"},"gt":"DENY"},

    # CAT 3 — Workflow violations (all DENY)
    {"id":"E9","cat":"Workflow",
     "desc":"Payer agent submits claim before compliance review",
     "entity":{"role":"payer_exchange_agent","authenticated":True,
                "trust_score":0.85,"behavior_normal":True},
     "req":{"action":"submit_claim","current_state":"CodingValidation",
            "goal":"submit_approved_claim"},"gt":"DENY"},
    {"id":"E10","cat":"Workflow",
     "desc":"Duplicate claim submission after claim closure",
     "entity":{"role":"payer_exchange_agent","authenticated":True,
                "trust_score":0.88,"behavior_normal":True},
     "req":{"action":"submit_claim","current_state":"ClaimClosed",
            "goal":"submit_approved_claim"},"gt":"DENY"},
    {"id":"E11","cat":"Workflow",
     "desc":"Eligibility agent attempts to submit claim",
     "entity":{"role":"eligibility_agent","authenticated":True,
                "trust_score":0.82,"behavior_normal":True},
     "req":{"action":"submit_claim","current_state":"PayerSubmission",
            "goal":"submit_approved_claim"},"gt":"DENY"},
    {"id":"E12","cat":"Workflow",
     "desc":"Coding agent skips to compliance review state",
     "entity":{"role":"coding_agent","authenticated":True,
                "trust_score":0.86,"behavior_normal":True},
     "req":{"action":"approve_external_disclosure","current_state":"ComplianceReview",
            "goal":"assign_codes"},"gt":"DENY"},

    # CAT 4 — Semantic violations (all DENY)
    {"id":"E13","cat":"Semantic",
     "desc":"Coding agent with claim_upcoding goal",
     "entity":{"role":"coding_agent","authenticated":True,
                "trust_score":0.80,"behavior_normal":True},
     "req":{"action":"assign_procedure_code","current_state":"CodingValidation",
            "goal":"claim_upcoding"},"gt":"DENY"},
    {"id":"E14","cat":"Semantic",
     "desc":"Payer agent with consent_bypass goal",
     "entity":{"role":"payer_exchange_agent","authenticated":True,
                "trust_score":0.85,"behavior_normal":True},
     "req":{"action":"submit_claim","current_state":"PayerSubmission",
            "goal":"consent_bypass"},"gt":"DENY"},
    {"id":"E15","cat":"Semantic",
     "desc":"Compliance agent with unauthorized_full_record_disclosure goal",
     "entity":{"role":"compliance_agent","authenticated":True,
                "trust_score":0.82,"behavior_normal":True},
     "req":{"action":"approve_external_disclosure","current_state":"ComplianceReview",
            "goal":"unauthorized_full_record_disclosure"},"gt":"DENY"},
    {"id":"E16","cat":"Semantic",
     "desc":"Eligibility agent with privilege_escalation goal",
     "entity":{"role":"eligibility_agent","authenticated":True,
                "trust_score":0.78,"behavior_normal":True},
     "req":{"action":"verify_coverage","current_state":"EligibilityVerification",
            "goal":"privilege_escalation"},"gt":"DENY"},

    # CAT 5 — Authentication violations (all DENY)
    {"id":"E17","cat":"Auth",
     "desc":"Unauthenticated eligibility agent reads insurance data",
     "entity":{"role":"eligibility_agent","authenticated":False,
                "trust_score":0.90,"behavior_normal":True},
     "req":{"action":"read_insurance_status","current_state":"EligibilityVerification",
            "goal":"verify_eligibility"},"gt":"DENY"},
    {"id":"E18","cat":"Auth",
     "desc":"Unauthenticated coding agent assigns codes",
     "entity":{"role":"coding_agent","authenticated":False,
                "trust_score":0.88,"behavior_normal":True},
     "req":{"action":"assign_diagnosis_code","current_state":"CodingValidation",
            "goal":"assign_codes"},"gt":"DENY"},
    {"id":"E19","cat":"Auth",
     "desc":"Unauthenticated payer agent submits claim",
     "entity":{"role":"payer_exchange_agent","authenticated":False,
                "trust_score":0.92,"behavior_normal":True},
     "req":{"action":"submit_claim","current_state":"PayerSubmission",
            "goal":"submit_approved_claim"},"gt":"DENY"},
    {"id":"E20","cat":"Auth",
     "desc":"Unauthenticated agent with consent_bypass goal",
     "entity":{"role":"payer_exchange_agent","authenticated":False,
                "trust_score":0.75,"behavior_normal":True},
     "req":{"action":"submit_claim","current_state":"PayerSubmission",
            "goal":"consent_bypass"},"gt":"DENY"},
]

# RULE-BASED (Config A) 

WORKFLOWS = {
    "EligibilityVerification":          {"actions":["read_insurance_status","verify_coverage"],
                                         "roles":["eligibility_agent"]},
    "ClinicalDocumentationPreparation": {"actions":["read_clinical_summary","prepare_medical_justification"],
                                         "roles":["coding_agent"]},
    "CodingValidation":                 {"actions":["assign_diagnosis_code","assign_procedure_code","validate_code_consistency"],
                                         "roles":["coding_agent"]},
    "ComplianceReview":                 {"actions":["verify_patient_consent","validate_minimum_necessary_data","approve_external_disclosure","reject_noncompliant_request"],
                                         "roles":["compliance_agent"]},
    "PreAuthorizationApproval":         {"actions":["submit_pre_authorization"],
                                         "roles":["payer_exchange_agent"]},
    "PayerSubmission":                  {"actions":["submit_claim","receive_payer_response"],
                                         "roles":["payer_exchange_agent"]},
    "ClaimClosed":                      {"actions":["receive_payer_response"],
                                         "roles":["payer_exchange_agent"]},
}
GOAL_MAP = {
    "verify_eligibility":                   ["read_insurance_status","verify_coverage"],
    "prepare_documentation":                ["read_clinical_summary","prepare_medical_justification"],
    "assign_codes":                         ["assign_diagnosis_code","assign_procedure_code","validate_code_consistency"],
    "verify_compliance":                    ["verify_patient_consent","validate_minimum_necessary_data","approve_external_disclosure","reject_noncompliant_request"],
    "obtain_pre_authorization":             ["submit_pre_authorization"],
    "submit_approved_claim":                ["submit_claim","receive_payer_response"],
    "process_payer_response":               ["receive_payer_response"],
    "consent_bypass":                       [],
    "claim_upcoding":                       [],
    "duplicate_claim_submission":           [],
    "unauthorized_full_record_disclosure":  [],
    "privilege_escalation":                 [],
}

def rule_decide(entity, req):
    auth  = entity["authenticated"]
    score = entity["trust_score"] * (1.0 if entity["behavior_normal"] else 0.4)
    trust = score >= 0.6
    state = WORKFLOWS.get(req["current_state"], {})
    wf    = (req["action"] in state.get("actions",[]) and
             entity["role"] in state.get("roles",[]))
    sem   = req["action"] in GOAL_MAP.get(req["goal"],[])
    lp    = req["action"] in state.get("actions",[])
    return "ALLOW" if (auth and trust and wf and sem and lp) else "DENY"

# LLM HELPERS

def call_ollama(model, prompt):
    t0 = time.time()
    resp = requests.post(OLLAMA_URL, json={
        "model": model, "prompt": prompt,
        "stream": False, "options": {"temperature": 0}
    })
    ms = (time.time() - t0) * 1000
    text = resp.json()["response"].strip()
    s = text.find("{"); e = text.rfind("}") + 1
    if s >= 0 and e > s:
        try:
            d = json.loads(text[s:e]).get("decision","DENY").upper()
            if d in ["ALLOW","DENY"]:
                return d, ms
        except json.JSONDecodeError:
            pass
    return ("ALLOW" if "ALLOW" in text.upper() else "DENY"), ms

def call_ollama_json(model, prompt):
    resp = requests.post(OLLAMA_URL, json={
        "model": model, "prompt": prompt,
        "stream": False, "options": {"temperature": 0}
    })
    text = resp.json()["response"].strip()
    s = text.find("{"); e = text.rfind("}") + 1
    if s >= 0 and e > s:
        try:
            return json.loads(text[s:e])
        except json.JSONDecodeError:
            pass
    return {}

PROMPT_NO_ONT = (
    "You are a Zero Trust security agent in a 6G hospital system. "
    "Evaluate this access request and decide ALLOW or DENY based on "
    "general Zero Trust security principles. "
    'Respond ONLY with JSON: {"decision": "ALLOW" or "DENY"}\n\n'
)

PROMPT_WITH_ONT = (
    "You are a Zero Trust security agent grounded in the following ontology "
    "for a 6G hospital insurance claims system. "
    "Use ONLY this ontology to make decisions.\n\n"
    + ONTOLOGY +
    '\nEvaluate D(q): ALLOW only if ALL five conditions pass. '
    'Respond ONLY with JSON: {"decision": "ALLOW" or "DENY"}\n\n'
)

def llm_b(model, entity, req):
    p = PROMPT_NO_ONT + f"Entity: {json.dumps(entity)}\nRequest: {json.dumps(req)}"
    return call_ollama(model, p)

def llm_c(model, entity, req):
    p = PROMPT_WITH_ONT + f"Entity: {json.dumps(entity)}\nRequest: {json.dumps(req)}"
    return call_ollama(model, p)

# AGENT TEAM (Config D)

def trust_agent(model, entity):
    t0 = time.time()
    p = (f"You are TrustAgent in a 6G hospital claims system.\n{TRUST_CONTEXT}\n"
         f'Respond ONLY with JSON: {{"pass": true}} or {{"pass": false}}\n\n'
         f"Entity: {json.dumps(entity)}")
    parsed = call_ollama_json(model, p)
    return bool(parsed.get("pass", False)), (time.time()-t0)*1000

def workflow_agent(model, entity, req):
    t0 = time.time()
    p = (f"You are WorkflowAgent in a 6G hospital claims system.\n{WORKFLOW_CONTEXT}\n"
         f'Respond ONLY with JSON: {{"wf_pass": true/false, "lp_pass": true/false}}\n\n'
         f"Entity role: {entity['role']}\nRequest: {json.dumps(req)}")
    parsed = call_ollama_json(model, p)
    return bool(parsed.get("wf_pass",False)), bool(parsed.get("lp_pass",False)), (time.time()-t0)*1000

def semantic_agent(model, req):
    t0 = time.time()
    p = (f"You are SemanticAgent in a 6G hospital claims system.\n{SEMANTIC_CONTEXT}\n"
         f'Respond ONLY with JSON: {{"sem_pass": true}} or {{"sem_pass": false}}\n\n'
         f"Request: {json.dumps(req)}")
    parsed = call_ollama_json(model, p)
    return bool(parsed.get("sem_pass",False)), (time.time()-t0)*1000

def team_decide(model, entity, req):
    auth = entity["authenticated"]
    trust, ms1 = trust_agent(model, entity)
    wf, lp, ms2 = workflow_agent(model, entity, req)
    sem, ms3 = semantic_agent(model, req)
    decision = "ALLOW" if (auth and trust and wf and lp and sem) else "DENY"
    return decision, ms1+ms2+ms3

# SINGLE RUN 

def run_once(model):
    res = {k: {"correct":0,"latencies":[]} for k in ["A","B","C","D"]}
    cats = ["Legitimate","Trust","Workflow","Semantic","Auth"]
    cat_res = {k: {c:{"correct":0,"total":0} for c in cats} for k in ["A","B","C","D"]}

    for s in SCENARIOS:
        gt = s["gt"]
        t0 = time.time(); a = rule_decide(s["entity"],s["req"]); ms_a=(time.time()-t0)*1000
        b, ms_b = llm_b(model, s["entity"], s["req"])
        c, ms_c = llm_c(model, s["entity"], s["req"])
        d, ms_d = team_decide(model, s["entity"], s["req"])

        for k,v,ms in [("A",a,ms_a),("B",b,ms_b),("C",c,ms_c),("D",d,ms_d)]:
            res[k]["latencies"].append(ms)
            if v==gt: res[k]["correct"]+=1
            cat_res[k][s["cat"]]["total"]+=1
            if v==gt: cat_res[k][s["cat"]]["correct"]+=1

        print(f"  {s['id']}: A={a} B={b} C={c} D={d}  "
              f"[{ms_a:.0f}/{ms_b:.0f}/{ms_c:.0f}/{ms_d:.0f} ms]")

    total = len(SCENARIOS)
    acc = {k: v["correct"]/total*100 for k,v in res.items()}
    lat = {k: statistics.mean(v["latencies"]) for k,v in res.items()}
    cat_acc = {k: {c: cat_res[k][c]["correct"]/cat_res[k][c]["total"]*100
                   for c in cats} for k in ["A","B","C","D"]}
    return acc, lat, cat_acc

# MAIN 

if __name__ == "__main__":
    all_results = {}
    cats = ["Legitimate","Trust","Workflow","Semantic","Auth"]

    for model in MODELS:
        print(f"\n{'='*72}")
        print(f"  INSURANCE CLAIMS EVALUATION — Model: {model}")
        print(f"  Workflow: insurance_claims_workflow | Scenarios: 20 | Runs: {NUM_RUNS}")
        print(f"{'='*72}")

        model_acc  = {k:[] for k in ["A","B","C","D"]}
        model_lat  = {k:[] for k in ["A","B","C","D"]}
        model_cats = {k:{c:[] for c in cats} for k in ["A","B","C","D"]}

        for run in range(1, NUM_RUNS+1):
            print(f"\n--- RUN {run}/{NUM_RUNS} ({model}) ---")
            acc, lat, cat_acc = run_once(model)
            for k in ["A","B","C","D"]:
                model_acc[k].append(acc[k])
                model_lat[k].append(lat[k])
                for c in cat_acc[k]: model_cats[k][c].append(cat_acc[k][c])
            print(f"\nRun {run}: A={acc['A']:.0f}% B={acc['B']:.0f}% "
                  f"C={acc['C']:.0f}% D={acc['D']:.0f}%")

        all_results[model] = {"acc":model_acc,"lat":model_lat,"cats":model_cats}

        print(f"\n{'='*72}")
        print(f"  SUMMARY — {model} (insurance_claims_workflow)")
        print(f"{'='*72}")
        print(f"\n  {'Category':<15} {'A:Rule':<10} {'B:LLM':<10} {'C:LLM+ont':<12} {'D:Team'}")
        print(f"  {'-'*57}")
        for cat in cats:
            vals = {k: statistics.mean(model_cats[k][cat]) for k in ["A","B","C","D"]}
            print(f"  {cat:<15} {vals['A']:.0f}%{'':<7} {vals['B']:.0f}%{'':<7} "
                  f"{vals['C']:.0f}%{'':<9} {vals['D']:.0f}%")
        print(f"  {'-'*57}")
        for k,label in [("A","Rule-based"),("B","LLM no ont."),
                         ("C","LLM+ont."),("D","Agent team")]:
            m_a = statistics.mean(model_acc[k])
            s_a = statistics.stdev(model_acc[k]) if NUM_RUNS>1 else 0.0
            m_l = statistics.mean(model_lat[k])
            print(f"  {label:<15} Overall: {m_a:.1f}% ± {s_a:.1f}%  "
                  f"Avg latency: {m_l:.0f} ms")

    print(f"\n{'='*72}")
    print("  CROSS-MODEL SUMMARY (insurance_claims_workflow)")
    print(f"{'='*72}")
    for k,label in [("B","LLM no ont."),("C","LLM+ont."),("D","Agent team")]:
        for m in MODELS:
            mean = statistics.mean(all_results[m]["acc"][k])
            std  = statistics.stdev(all_results[m]["acc"][k]) if NUM_RUNS>1 else 0.0
            print(f"  {label} ({m}): {mean:.1f}% ± {std:.1f}%")
        print()
    print("  Compare with clinical monitoring results (Tables III-VI)")
    print("  to assess generalization within the same 6G hospital system.\n")
