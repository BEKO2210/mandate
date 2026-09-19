from __future__ import annotations

from datetime import timedelta

from .crypto import utcnow, verify_object
from .engine import Engine
from .models import Constraint
from .store import Store


def run_belkis_demo() -> None:
    engine = Engine(Store(".mandate-demo"))
    belkis, belkis_kp = engine.register_principal("Belkis Aslani", kind="person", jurisdiction="DE")
    aslani, _ = engine.register_principal("Aslani GmbH", kind="org", jurisdiction="DE")
    agent, agent_kp = engine.register_agent(
        name="ProcureBot", operator_did=aslani.did, developer="Mandate Labs",
        model="demo-agent-0.1", skills=["procurement", "negotiation", "vendor-research"],
    )
    grant = engine.issue_grant(
        principal=belkis, principal_kp=belkis_kp, agent=agent,
        organization="Aslani GmbH", purpose="Büro- und IT-Beschaffung Q3",
        scopes=["purchase.office", "purchase.it", "negotiate.vendor"],
        not_after=utcnow() + timedelta(days=5),
        constraints=Constraint(currency="EUR", max_amount=5000.0, max_daily_amount=6000.0,
                              require_human_above=2500.0, counterparties_deny=["shady-imports.example"]),
    )
    print("=" * 72)
    print("MANDATE — Delegation")
    print("=" * 72)
    print(f"Mandantin : {belkis.name}  {belkis.did}")
    print(f"Organisation: {aslani.name}  {aslani.did}")
    print(f"Agent     : {agent.name}  {agent.did}")
    print(f"Grant     : {grant['id']}")
    print(f"Limit     : {grant['constraints']['max_amount']} EUR until {grant['not_after']}")
    print(f"Signatur  : {'gültig' if verify_object(grant, belkis.did) else 'UNGÜLTIG'}")
    print()
    cases = [
        dict(action="purchase.office", amount=120.0, currency="EUR", counterparty="büro-bedarf.de", summary="Kopierpapier 10 Kartons"),
        dict(action="purchase.it", amount=3200.0, currency="EUR", counterparty="dell.com", summary="Workstation für Entwicklung"),
        dict(action="purchase.it", amount=8200.0, currency="EUR", counterparty="dell.com", summary="GPU-Server — über Limit"),
        dict(action="wire.payroll", amount=900.0, currency="EUR", counterparty="bank", summary="Gehalt überweisen — falscher Scope"),
        dict(action="purchase.office", amount=80.0, currency="EUR", counterparty="shady-imports.example", summary="Toner von gesperrtem Lieferanten"),
    ]
    print("MANDATE — Runtime decisions")
    for i, case in enumerate(cases, 1):
        receipt = engine.propose(agent_kp, grant["id"], **case)
        d = receipt["decision"]
        mark = "ALLOW" if d["allowed"] else ("HUMAN" if d.get("requires_human") else "DENY ")
        print(f"{i}. [{mark}] {case['summary']}  reasons={d['reasons']}")
    print("Fertig. Receipts in .mandate-demo/receipts/")
