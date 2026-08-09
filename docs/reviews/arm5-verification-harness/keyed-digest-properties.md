# F2 keyed-digest properties to verify on the corrected head

At e48db09 the digest was unsalted SHA256 over `namespace + U+001F + name`.
I recovered `namespace="prod", name="OPENAI_API_KEY"` in 10 guesses from a
7 x 8 wordlist, after confirming a standalone Swift reproduction emitted the
identical hex string. These are the properties the replacement must hold.

## Must hold

1. **Not enumerable from public information.** An attacker who knows the
   algorithm, the separator, and a wordlist of plausible namespaces and names,
   but not the key, cannot recover a reference from a receipt. Re-run the
   dictionary attack against a digest produced by the new implementation and
   confirm it does not recover.

2. **Stable within a daemon instance.** The same reference digested twice by
   the same `DaemonBootstrap` yields the same string, otherwise receipts stop
   being correlatable and the audit story breaks.

3. **Unstable across instances or boots.** Two independently constructed
   daemons digesting the same reference yield different strings. This is the
   property that actually defeats the dictionary attack; without it a keyed
   hash with a hardcoded or derived-from-public-input key is no better than
   the unsalted version.

4. **Collision-distinct.** Two different references digested by the same
   instance yield different strings. `DaemonBootstrapTests` already asserts
   this for the unkeyed version; it must survive the change.

5. **Key is never in a receipt, a log, or an encoded payload.** Re-run the
   `BrokeredReceipt` shape assertion and confirm the encoded key set has not
   grown a key, salt, or nonce field.

## Watch for

- A "keyed" implementation whose key is derived from the reference itself, the
  process ID, the hostname, or any other value the attacker also knows. That
  reintroduces enumerability while looking fixed.
- A key held in a `static let`, which makes it constant across every daemon in
  the fleet and therefore precomputable once leaked.
- The existing assertion `!requestDigest.contains("FAKE_PRESENT")` being left
  as the only digest privacy test. It is trivially true of any hash function
  and gives false assurance; it should be replaced by a real recovery-resistance
  assertion, not merely supplemented.

## Reusable attack script

`digest_probe.py` in the parent scratchpad directory implements the dictionary
attack. It needs the new canonicalization and key handling wired in before it
can be pointed at the corrected implementation.
