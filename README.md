# Mandate

**Identity + Permission + Transaction OS for AI agents.**

Ein Agent darf nicht *so tun, als wäre er du*.
Ein Agent braucht eine eigene Identität, eine nachvollziehbare Delegation und eine Quittung für jede Handlung.

```
Belkis
  → autorisiert Agent ProcureBot
  → für Aslani GmbH
  → Aufgabe: Büro- und IT-Beschaffung
  → maximal 5.000 €
  → gültig bis Freitag
```

Genau das ist Version 1 von Mandate. Laufend. Signiert. Prüfbar.

## Warum das jetzt gebaut werden muss

Stand September 2026:

- MCP verbindet Agenten mit Tools. A2A verbindet Agenten mit Agenten.
- **Es gibt keinen ratifizierten Standard für Agenten-Identität.** IETF-Drafts sind Individual Submissions.
- Seit 2. August 2026 verlangt Art. 50 AI Act: ein Agent muss offenlegen, *dass* er KI ist — und *in wessen Auftrag* er handelt.
- EUDI-Wallets rollen 2026 aus.

Mandate setzt in diese Lücke: Rechte, Identität, Delegation, Audit.

## 30 Sekunden

```bash
python3 -m mandate demo
```

1. Kopierpapier 120 € → ALLOW
2. Workstation 3.200 € → HUMAN (Schwelle 2.500 €)
3. GPU-Server 8.200 € → DENY
4. Gehaltsüberweisung → DENY (falscher Scope)
5. Gesperrter Lieferant → DENY

## Bibliothek

```python
from datetime import timedelta
from mandate import Engine, Constraint
from mandate.crypto import utcnow

engine = Engine()
belkis, belkis_key = engine.register_principal("Belkis Aslani")
agent, agent_key = engine.register_agent(
    "ProcureBot", operator_did=belkis.did, developer="Mandate Labs", model="demo"
)
grant = engine.issue_grant(
    belkis, belkis_key, agent,
    organization="Aslani GmbH",
    purpose="Beschaffung Q3",
    scopes=["purchase.office", "purchase.it"],
    not_after=utcnow() + timedelta(days=5),
    constraints=Constraint(max_amount=5000, require_human_above=2500),
)
receipt = engine.propose(
    agent_key, grant["id"],
    action="purchase.office", amount=120, currency="EUR",
    summary="Kopierpapier",
)
print(receipt["decision"])
print(receipt["disclosure"]["human_readable"])
```

## Design

1. Delegation, nicht Impersonation.
2. Jeder Hop verengt Vollmacht.
3. did:key + Ed25519, keine Registry nötig.
4. Art. 50 / EUDI als Nachfrage, nicht nur Compliance.
5. Modellunabhängig.

## Roadmap

| Version | Schicht |
|---|---|
| 0.1 | Identitäten, Grants, Policy, Receipts, Art. 50 |
| 0.2 | HTTP-Gateway, MCP, A2A Agent Card |
| 0.3 | Agent Payments, Step-up-Freigabe |
| 0.4 | EUDI-Wallet-Bridge |
| 0.5 | Marketplace + Haftpflicht |
| 1.0 | Secure Element / lokaler Agent-Hub |

Apache-2.0
