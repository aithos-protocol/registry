# Domain certification vectors

Conformance vectors for `DOMAIN-CERTIFICATION.md` §12. A second implementation
is expected to pass all of them before making any interoperability claim.

Three files:

- **`record-parsing.json`** — §3.2–3.3. `cases[]` each give one `TXT` record's
  data (`record`) and the agent identifier a conforming parser extracts from it
  (`agentIdInRecord`, `null` when the record must be ignored). Where
  `characterStrings` is present, the record was transmitted as several
  character-strings and `record` is their concatenation with no separator
  (RFC 7208 §3.3) — a parser working from wire data must concatenate first.
  `rrsets[]` then give whole record sets and whether the set names the agent
  (§3.3): one matching record wins, and malformed neighbours change nothing.

- **`payload.json`** — §5.2–5.3. `reference` gives a `certify-domains` payload
  object, its exact JCS canonicalization (`canonical`) and the base64url of
  those bytes (`payloadB64`): the `payload` member of a conforming request MUST
  equal `payloadB64` for this object, byte for byte. `refusals[]` are payload
  objects a conforming registry refuses even when correctly signed, each with
  the problem `code` it answers. `replay` pins §5.3(4): against the stored
  `issuedAt`, the `refused[]` values are not strictly greater (equality of
  *instant* counts, whatever the RFC 3339 spelling) and the `accepted` value
  is. All are compared as instants, never as strings.

- **`domains.json`** — §5.4. `valid[]` parse; each of `invalid[]` is refused
  with its `code`. Refused means refused: no lowercasing, no IDNA conversion,
  no trailing-dot stripping on the registry side.

The reference agent identifier used throughout is a syntactically valid RFC
7638 thumbprint that belongs to no known key. Signatures are deliberately
absent from these vectors: key checks are pinned by `SPEC.md` §5.5–5.6 and its
vectors, and a registry's refusal codes here must not depend on who signed.
