# Receipt Bundle V0

## Bundle Shape

A receipt bundle is a directory containing the evidence needed to verify a
single ATP handoff without trusting the original runtime.

Required files:

```text
public-keys.json
envelopes.jsonl
transcript.jsonl
contract.json
leases.json
lease-access-log.jsonl
receipt.json
artifacts/
```

Recommended files:

```text
capability-card.json
verification.json
```

## Primary Commitments

The verifier treats these as the primary public commitments:

- `receipt.receiptHash`
- `receipt.eventRoot`
- canonical artifact hashes listed under `receipt.changed.artifacts`

## Canonical JSON

Artifact Two uses ATP v0.3 canonical JSON:

- UTF-8
- sorted object keys
- no insignificant whitespace
- `ensure_ascii = false`

The SHA-256 digest format is:

```text
sha256:<64 lowercase hex characters>
```

## Receipt Hash Rule

`receiptHash` is SHA-256 over the canonical receipt body with these fields
removed:

- `receiptHash`
- `signatures`

## Receipt Signature Rule

Receipt signatures are verified over the canonical receipt body with this field
removed:

- `signatures`

For v0, Artifact Two verifies Ed25519 signatures using `public-keys.json`.

## Transcript Rule

The transcript must match `envelopes.jsonl` one-to-one.

For each envelope, the verifier recomputes:

```text
bodyHash = sha256(canonical(envelope.body))
eventHash = sha256(envelope.prev + envelope.verb + envelope.issuer + bodyHash + envelope.createdAt + envelope.nonce)
```

Each transcript row must match the recomputed event row.

## Event Root Rule

For ATP v0.3-style bundles:

- the receipt `eventRoot` must equal the `SETTLE` event hash
- the final `ATTEST` envelope `prev` must equal `receipt.eventRoot`
- the final `ATTEST` envelope body must equal `receipt.json`

## Lease Evidence Rule

The verifier checks lease evidence from `lease-access-log.jsonl`.

V0 requires:

- at least one allowed read
- at least one allowed write when changed artifacts exist
- no denied access unless policy allows expected negative test evidence
- every allowed access must reference a lease listed in `leases.json`
- every accessed lease in `receipt.accessed.leases` must exist in `leases.json`

The default policy allows one expected denied write ending in
`illegal-worker-write.txt`, because the current ATP demo deliberately records a
negative lease-guard test.

## Trust Policy `L`

For v0, the trust set is `public-keys.json`.

Future versions may accept an explicit trust policy file:

```json
{
  "trustedKids": ["did:example:agent:worker-42#key-1"],
  "trustedIssuers": ["did:example:agent:worker-42"],
  "lanes": ["classic_ed25519_v1"]
}
```

## Verification Policy `tau`

The v0 verifier has conservative defaults:

- no wall-clock expiry enforcement for archived bundles
- optional clock-skew enforcement when explicitly requested
- expected ATP verb sequence enforcement
- deterministic first-failure reason code
