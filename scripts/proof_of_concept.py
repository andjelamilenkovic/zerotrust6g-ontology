"""
Zero Trust Decision Function - Proof of Concept
================================================
Formal model: D(q) = Allow iff Auth(e)=1 ∧ T(e,c,l)≥τ ∧ WF(q)=1 ∧ Sem(e,a,r,w,g,c)=1 ∧ LP(e,a,r,w,g)=1

This script simulates 5 scenarios showing how the decision function evaluates
access requests from autonomous agents in 6G agentic systems.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# DATA STRUCTURES


class InfrastructureLayer(Enum):
    CLOUD = "cloud"
    EDGE = "edge"
    CONTROL = "control"

@dataclass
class WorkflowState:
    name: str
    permitted_actions: list[str]
    permitted_roles: list[str]
    permitted_resources: list[str]
    next_states: list[str]

@dataclass
class Entity:
    id: str
    role: str
    authenticated: bool
    trust_score: float          # 0.0 – 1.0
    layer: InfrastructureLayer
    current_workflow: str
    current_state: str
    current_goal: str
    behavior_normal: bool = True

@dataclass
class AccessRequest:
    entity: Entity
    action: str
    resource: str
    workflow: str
    goal: str


# WORKFLOW DEFINITIONS


WORKFLOWS = {
    "patient_data_workflow": {
        "read_vitals": WorkflowState(
            name="read_vitals",
            permitted_actions=["read"],
            permitted_roles=["monitoring_agent"],
            permitted_resources=["vital_signs_db"],
            next_states=["analyze_data"]
        ),
        "analyze_data": WorkflowState(
            name="analyze_data",
            permitted_actions=["read", "analyze"],
            permitted_roles=["monitoring_agent", "analysis_agent"],
            permitted_resources=["vital_signs_db", "analysis_engine"],
            next_states=["send_alert"]
        ),
        "send_alert": WorkflowState(
            name="send_alert",
            permitted_actions=["write", "notify"],
            permitted_roles=["alert_agent"],
            permitted_resources=["alert_system"],
            next_states=[]
        ),
    }
}

GOAL_ACTION_MAP = {
    "monitor_patient": ["read", "analyze"],
    "send_medical_alert": ["write", "notify"],
    "data_exfiltration": [],        # malicious goal — no permitted actions
    "network_disruption": [],
}

TRUST_THRESHOLD = 0.6


# DECISION FUNCTION COMPONENTS


def auth(entity: Entity) -> bool:
    return entity.authenticated

def trust(entity: Entity) -> float:
    score = entity.trust_score
    if not entity.behavior_normal:
        score *= 0.4    # behavioral anomaly penalty
    return round(score, 2)

def workflow_valid(req: AccessRequest) -> bool:
    wf = WORKFLOWS.get(req.workflow)
    if not wf:
        return False
    state = wf.get(req.entity.current_state)
    if not state:
        return False
    return (
        req.action in state.permitted_actions and
        req.entity.role in state.permitted_roles and
        req.resource in state.permitted_resources
    )

def semantic_consistent(req: AccessRequest) -> bool:
    permitted = GOAL_ACTION_MAP.get(req.goal, [])
    return req.action in permitted

def least_privilege(req: AccessRequest) -> bool:
    wf = WORKFLOWS.get(req.workflow)
    if not wf:
        return False
    state = wf.get(req.entity.current_state)
    if not state:
        return False
    # Action must be minimum necessary — not exceed what state allows
    return req.action in state.permitted_actions

def decide(req: AccessRequest) -> dict:
    a = auth(req.entity)
    t = trust(req.entity)
    t_pass = t >= TRUST_THRESHOLD
    wf = workflow_valid(req)
    sem = semantic_consistent(req)
    lp = least_privilege(req)
    decision = a and t_pass and wf and sem and lp
    return {
        "decision": "ALLOW" if decision else "DENY",
        "Auth(e)": a,
        "T(e,c,l)": t,
        "T≥τ": t_pass,
        "WF(q)": wf,
        "Sem(e,a,r,w,g,c)": sem,
        "LP(e,a,r,w,g)": lp,
    }


# SCENARIOS


scenarios = [
    {
        "name": "S1 – Legitimate monitoring agent reads vital signs",
        "request": AccessRequest(
            entity=Entity(
                id="agent_001", role="monitoring_agent", authenticated=True,
                trust_score=0.85, layer=InfrastructureLayer.EDGE,
                current_workflow="patient_data_workflow",
                current_state="read_vitals", current_goal="monitor_patient"
            ),
            action="read", resource="vital_signs_db",
            workflow="patient_data_workflow", goal="monitor_patient"
        )
    },
    {
        "name": "S2 – Compromised agent with low trust score",
        "request": AccessRequest(
            entity=Entity(
                id="agent_002", role="monitoring_agent", authenticated=True,
                trust_score=0.35, layer=InfrastructureLayer.EDGE,
                current_workflow="patient_data_workflow",
                current_state="read_vitals", current_goal="monitor_patient",
                behavior_normal=False
            ),
            action="read", resource="vital_signs_db",
            workflow="patient_data_workflow", goal="monitor_patient"
        )
    },
    {
        "name": "S3 – Agent requests action outside its workflow state",
        "request": AccessRequest(
            entity=Entity(
                id="agent_003", role="monitoring_agent", authenticated=True,
                trust_score=0.80, layer=InfrastructureLayer.EDGE,
                current_workflow="patient_data_workflow",
                current_state="read_vitals",  # state does NOT permit write
                current_goal="monitor_patient"
            ),
            action="write", resource="alert_system",
            workflow="patient_data_workflow", goal="monitor_patient"
        )
    },
    {
        "name": "S4 – Agent with malicious goal (semantic violation)",
        "request": AccessRequest(
            entity=Entity(
                id="agent_004", role="monitoring_agent", authenticated=True,
                trust_score=0.75, layer=InfrastructureLayer.EDGE,
                current_workflow="patient_data_workflow",
                current_state="read_vitals", current_goal="data_exfiltration"
            ),
            action="read", resource="vital_signs_db",
            workflow="patient_data_workflow", goal="data_exfiltration"
        )
    },
    {
        "name": "S5 – Unauthenticated agent",
        "request": AccessRequest(
            entity=Entity(
                id="agent_005", role="monitoring_agent", authenticated=False,
                trust_score=0.90, layer=InfrastructureLayer.EDGE,
                current_workflow="patient_data_workflow",
                current_state="read_vitals", current_goal="monitor_patient"
            ),
            action="read", resource="vital_signs_db",
            workflow="patient_data_workflow", goal="monitor_patient"
        )
    },
]


# RUN & PRINT RESULTS


print("=" * 72)
print("  ZERO TRUST DECISION FUNCTION — PROOF OF CONCEPT")
print(f"  Trust threshold τ = {TRUST_THRESHOLD}")
print("=" * 72)

for s in scenarios:
    result = decide(s["request"])
    print(f"\n{s['name']}")
    print(f"  Decision:           {result['decision']}")
    print(f"  Auth(e):            {result['Auth(e)']}")
    print(f"  T(e,c,l) = {result['T(e,c,l)']:.2f}    T≥τ: {result['T≥τ']}")
    print(f"  WF(q):              {result['WF(q)']}")
    print(f"  Sem(e,a,r,w,g,c):   {result['Sem(e,a,r,w,g,c)']}")
    print(f"  LP(e,a,r,w,g):      {result['LP(e,a,r,w,g)']}")
    print(f"  {'ALLOWED' if result['decision']=='ALLOW' else 'DENIED'}")

print("\n" + "=" * 72)
