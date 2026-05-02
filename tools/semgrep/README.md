# fd0 semgrep rules

Each rule corresponds to a real bug class found during the
multi-module security review. The rules act as guardrails so
the same bug class can never re-emerge silently.

## Rules

| Rule | Caught bug |
|---|---|
| `cap-leak.yaml` | `EdPrivToX25519` returned `h[:32]` from a 64-byte SHA-512 buffer; callers re-sliced to read the Ed25519 prefix. |
| `wipe-keepalive.yaml` | Hand-rolled zeroing loops (without `runtime.KeepAlive`) get optimised away — passphrases / OEKs lingered in heap memory. |
| `path-traversal.yaml` | `fdhome.ScopeChain` joined raw `scopeID` with the chains directory; hostile peer could feed `../etc/passwd`. |
| `nil-vs-empty.yaml` | `len(prev_hash) != 0` accepted CBOR empty bytes when spec required CBOR nil. |
| `argon2-validation.yaml` | `argon2.IDKey` called directly bypassed param validation; T=0 panic, huge M = OOM. |
| `ed25519-length-check.yaml` | `ed25519.Sign / Verify` panic on wrong-size keys; needs explicit length gates when `priv` / `pub` are untrusted. |
| `dead-function-value.yaml` | `_ = pkg.Func` discards the function value — the function never runs. |
| `scope-binding.yaml` | Server push must bind outer-frame scope to inner signed_prefix.scope; otherwise cross-chain forge. |

## Running locally

```bash
# One-time install
pip install semgrep

# From repo root
make lint-semgrep
# or directly
semgrep --config tools/semgrep/rules/ --error
```

## CI integration

Add to your CI pipeline:

```yaml
- name: Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: tools/semgrep/rules/
```

## Adding a new rule

When a new bug is found:

1. Reproduce as a unit test FIRST.
2. Fix the bug.
3. Write a semgrep rule that would have caught the bug pattern.
4. Document it here with a link to the bug commit.
5. Add a `// fd0-semgrep:disable=<rule-id>` comment for any
   intentional exception (rare; the goal is no exceptions).

The rule should be precise enough that hand-written exceptions
are NEVER needed. A noisy rule is a broken rule.
