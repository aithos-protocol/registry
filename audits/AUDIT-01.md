# Audit — round 1

**Method:** independent review, fresh context, code and `SPEC.md` only. No
project history was given to the auditor, so the findings are not shaped by
what was already believed to be true.

## Verdict

Three MAJOR findings, all confirmed by execution. The cryptographic core —
thumbprint binding, algorithm allowlist, verification ordering, replay defence,
rotation lineage — was probed and held. Every failure is one step outside it:
the JWKS read path, the JWKS the registry publishes, and an unauthenticated
amplification before any signature is checked.

## Major findings

### M1 — A withdrawn agent's JWKS is still served
`crates/registry-api/src/api.rs:218` · confirmed by execution

`SPEC.md` §6.5 requires the registry to stop serving a withdrawn entry's card
**and its JWKS**. `get_current_card` does this; `get_jwks` never loads the agent
record at all. Reachable in production through the API Gateway origin, which has
no authorizer.

The e2e assertion accepted `404 || 410`, so the reconciler deleting the CDN
pointer masked the handler bug and nothing exercised the API path.

### M2 — The published JWKS has no `kid`, and republishes unvalidated members
`crates/registry-api/src/api.rs:227`, `crates/registry-core/src/jwk.rs:135` · confirmed by execution

§7.2 says the JWKS carries "the currently authorized public keys, each with its
`kid`". The registry stores the submitted JWK verbatim and serves it verbatim:
it never adds a `kid`, and the official CLI emits none. A generic RFC 7515
verifier following `jku` finds no key matching `protected.kid` and cannot verify
the card — which is precisely the interoperability §5.7 claims.

Worse, a submitted JWK carrying `"kid": "<another key's thumbprint>"` and
`"alg": "none"` is accepted, then republished by the registry as an authorized
key. §3.2 calls `kid == thumbprint` the keystone; the registry enforces it on
input and breaks it on output.

### M3 — Unauthenticated ~200× memory and CPU amplification
`crates/a2a-card/src/presence.rs:16`, `crates/registry-api/src/api.rs:442` · confirmed by execution

Presence validation collects **every** issue, and runs **before** the 256 KiB
card limit is applied. A 1.9 MiB body of empty skill objects produced 351 MiB of
allocation and 4.9 s of CPU in a release build — on a 512 MiB, 15 s Lambda, with
no signature verified and no key parsed. Only the problem's first issue is ever
used.

## Minor findings

- **m1** `UNUSED_KEY` is returned for "too many keys" and "duplicate key", neither of which it means.
- **m2** A malformed `version` on a *creation* returns `409 VERSION_NOT_INCREASING`; there is nothing for it to fail to exceed.
- **m3** `If-Match` strips `W/` and so honours a weak validator, which RFC 9110 forbids for this header.
- **m4** The CLI's `jku` fetch buffers the whole body before checking its 256 KiB bound, and places no restriction on the resolved address.
- **m5** The reconciler turns an unreadable `keys` attribute into an empty JWKS and reports success, where every other failure in that component propagates.
- **m6** The key file's `p2c` is unbounded and truncated to `u32`, and is used before the header is authenticated.
- **m7** Raw backend error text — table and index names, request ids — reaches the client in a 500.
- **m8** On the CDN path a withdrawn card answers 404, not the 410 §7.1 states. §6.5 and §7.1 pull against each other and nothing records which wins.

## Checked and sound

Signature and payload binding; verification ordering against §5.5; `kid` as a
genuine RFC 7638 thumbprint including base64 canonicality; ECDSA malleability
against the replay defence; rollback, takeover and rotation; idempotent
resubmission ordering; withdrawal replay binding; private key material never
reaching storage or logs; RSA sizing; the strict JSON profile of §5.1 including
duplicate members, non-I-JSON integers, isolated surrogates and nesting depth;
the presence table cross-checked field by field against `a2a.proto`; conditional
writes and the memory store's matching contract; unreachability of objects from
a failed transaction; path parameter safety; cursor handling.
