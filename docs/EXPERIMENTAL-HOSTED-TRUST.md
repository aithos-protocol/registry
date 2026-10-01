# PR117 hosted-agent observations (experimental)

This implements the personal publisher / independent contributor experiment at
AI Catalog PR117 revision `51df07b58e831f71ab6047672d6482ef93f5015f`.
It uses the signing library pinned to `d11e5fd48a8645b7e2252cec5cd1160128e480e3`.
The registry signs its own contribution. It does not sign as the personal domain.

## Assurance and lifetime

Each issuance requires a current authorized registry key's fresh, JCS-signed
consent; a currently certified domain; a fresh `_a2a` TXT observation; a valid
hosting ES256 receipt and online hosting status; and an independently fetched
exact card-byte digest. Only `agents.aithos.app` is accepted as a host in v1.
The owner's hosting credential goes directly to that host and never to registry.

The registry stores the complete signed consent, hosting receipt and DNS answer
inside the signed contribution. A DynamoDB transaction checks active status,
sequence, card digest, authorized key set and the complete certification state,
then inserts the immutable issuance and latest pointer. A changed state aborts
publication. Signing alone never publishes. Identical retries return the original
stored signature; reuse of a nonce for different evidence is rejected.

This is a narrower first delivery than the full trust design: **there is no
independent transparency witness, Merkle log or offline certification claim**.
The signed evidence explicitly requires online revalidation. The API stores an
audit record, which must not be presented as a witnessed transparency log.
Issuances last at most ten minutes and never outlive either consent or hosting
receipt. An expired issuance remains retrievable as history. A production
profile with offline reliance must implement the full log/witness design first.
DNS and hosting observations occur at different times; there is no distributed
atomic snapshot across the services. The claim is demonstrated technical
control at the stated times, not legal ownership or an agent safety assessment.

## API

Enabled only with `REGISTRY_TRUST_KEY_ID`, a dedicated P-256 KMS signing key.
Terraform `experimental_trust_enabled=true` creates it with destruction protection
and grants GetPublicKey/Sign only to the API role. It is separate from agent
owner keys and hosting platform keys. The issuer DID follows the deployment's
origin. Retain a key until every unexpired issuance using it has expired; this
initial implementation advertises only the configured active assertion key.

- `GET /.well-known/did.json`: public assertion key.
- `POST /v1/experimental/trust/agents/{registryId}/issuances`: entry, receipt and
  signed consent; see the checked-in client for the exact payload.
- `GET /v1/experimental/trust/agents/{registryId}/issuances/{nonce}`: stored result.
- `GET /v1/experimental/trust/agents/{registryId}/issuances/{nonce}/status`:
  current DNS, registry state, exact source bytes and host proof status.
- `GET /trustmanifest/{registryId}`: latest stored issuance, only when still
  current; 410 when stale, 503 when evidence cannot be checked.
- `GET /schemas/host-domain-observation/v1`: experimental evidence descriptor.

All routes are no-store. Status/current lookups never sign. Host keys and card
bytes are fetched with the library's HTTPS allowlist, address pinning, no
redirects/proxies, response bound and timeout. Request handling has a 20-second
budget inside a 30-second Lambda timeout. External failures fail closed.

## Run the actual example

1. Create a dedicated owner registry key with the CLI, preserve its private file,
   and publish an owner-signed copy of the served Agent Card. A2A default-value
   normalization may change registry-copy bytes; the manifest targets the
   independently fetched hosting bytes, never the registry copy's digest.
2. Publish `_a2a.mathieucolla.com TXT "v=A2A1; k=<registryId>"` at IONOS.
3. Run `aithos certify <registryId> --key <registryId> --domains mathieucolla.com`
   with the isolated `AITHOS_HOME` for this identity. Certification replaces the
   complete domain set; preserve any previously requested domains when renewing.
4. Install `scripts/trust-requirements.txt` in a local virtual environment. Run:

```sh
python scripts/issue-hosted-trust.py \
  --owner-file /absolute/path/to/agent-private.json \
  --registry-key /absolute/path/to/registry-key.jwk \
  --out /absolute/path/to/new-issuance-directory
```

For development, pass `--registry https://registry-dev.aithos.world` after
publishing/certifying the identity there. The same domain record can name the
same genesis-key identity in both registries; signatures bind their origins.

The script independently verifies the hosting and PR117 signatures in Python,
checks issuer key authorization, exact card bytes, release and complete claim
coverage, expiry, and online registry status. Output contains public artifacts
only. A successful verification reports `publisherSignature: false`: Mathieu can
add a separate publisher signature later. Each run creates a fresh host receipt,
which conservatively invalidates earlier receipts. Keep output directories for
historical review. This does not modify the catalog or invoke the agent.
