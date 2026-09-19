# Mandate

**Identity + Permission + Transaction OS for AI agents.**

Art. 50 verlangt Transparenz darueber, dass eine Person mit KI interagiert.
Mandate erweitert das um kryptografisch pruefbare Auftraggeber-, Delegations-
und Handlungsvollmachten. Das verlangt Art. 50 nicht — das ist die Produktschicht.

EUDI-Wallets sind ein moeglicher Traeger, kein heutiger Art.-50-Zwang.

Der Pitch ist nicht „niemand hat Agent Identity gesehen“. Die Standardschlacht
(OAuth/WIMSE, AIP-Drafts, MCP, A2A) laeuft. Mandate zielt auf die Runtime
dazwischen: Enforcement, das Agenten ohne eigene Auth-Architektur nutzen.

## v0.1.1 Trust Core

- Receipts werden vom **Enforcer** signiert, nicht vom Agenten
- Private Keys verlassen den Prozess nicht (kein `private_hex` auf Disk)
- `max_daily_amount` ist wirklich taeglich
- Intent hat `audience` + `nonce` (Replay-Schutz)
- `engine.approve(receipt_id, principal_key)` hebt ein HUMAN-Hold auf
- `organization=` bleibt in 0.1.1 ein Label, kein Org-Nachweis
- Subdelegation ist geplant, nicht implementiert

Ohne Gateway vor dem Tool kann ein Agent die Bibliothek noch umgehen.
Als Naechstes: v0.2 Enforcement Gateway.

```bash
python3 -m mandate demo
```
