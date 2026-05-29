# Red-Team Demo (Verifier)

This demo proves Artifact Two is not only a happy-path checker.
It mutates a valid ATP bundle into known failure states and verifies deterministic reason codes.

## Run

```bash
python3 tools/redteam_demo.py --bundle examples/atp-photo-handoff/valid
```

## Output

The tool prints a compact table:

```text
case | expected | actual | pass
valid | OK | OK | PASS
tampered_receipt | TAMPER | TAMPER | PASS
...
```

## Notes

- Demo-only tool; no verifier logic changes.
- Uses temporary copied bundles per case.
- Intended for product demos, CI smoke checks, and trust explainability.
