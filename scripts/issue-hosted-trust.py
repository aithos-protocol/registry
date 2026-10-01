#!/usr/bin/env python3
"""Issue and independently verify the experimental PR117 hosted-agent contribution.
Only the hosting origin receives the owner credential. No agent is invoked.
Requires cryptography and rfc8785 (see scripts/trust-requirements.txt).
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
import rfc8785
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes

HOST = 'https://agents.aithos.app'
CATALOG = 'https://catalog.aithos.me/.well-known/ai-catalog.json'
IDENTIFIER = 'urn:air:mathieucolla.com:agent:meeting'
HOST_ID = 'f072a0c1-d945-4a9c-b4ce-d805a4a50eab'
SCHEMA = 'https://registry.aithos.world/schemas/host-domain-observation/v1'

def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def unb64(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
def digest(b): return 'sha256:' + hashlib.sha256(b).hexdigest()
def canonical(v): return rfc8785.dumps(v)
def require(ok, message):
    if not ok: raise ValueError(message)
def unique(pairs):
    d = {}
    for k, v in pairs:
        require(k not in d, 'duplicate JSON member')
        d[k] = v
    return d
def parse(b): return json.loads(b, object_pairs_hook=unique)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None

def request(url, origins, data=None, owner=None):
    u = urllib.parse.urlsplit(url)
    require(u.scheme == 'https' and not u.username and not u.password and not u.fragment
            and f'{u.scheme}://{u.netloc}' in origins, 'unexpected URL origin')
    headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
    if data is not None: headers['Content-Type'] = 'application/json'
    if owner:
        require(f'{u.scheme}://{u.netloc}' == HOST, 'owner credential destination refused')
        headers['Authorization'] = 'Bearer ' + owner
    req = urllib.request.Request(url, data=canonical(data) if data is not None else None, headers=headers)
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(req, timeout=30) as r:
        require(r.headers.get('Content-Encoding', 'identity') == 'identity', 'encoded response')
        body = r.read(1_048_577)
        require(len(body) <= 1_048_576, 'response too large')
        return body

def verify_raw(jwk, signature, data):
    require(jwk['kty'] == 'EC' and jwk['crv'] == 'P-256' and 'd' not in jwk, 'invalid public key')
    sig = unb64(signature)
    require(len(sig) == 64, 'invalid ES256 length')
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(jwk['x']), 'big'), int.from_bytes(unb64(jwk['y']), 'big'), ec.SECP256R1()).public_key()
    key.verify(encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), data, ec.ECDSA(hashes.SHA256()))

def verify(entry, artifact, document, issuer):
    require(document['id'] == issuer, 'DID mismatch')
    sig = next(s for s in entry['signatures'] if s['signer'] == issuer)
    require(sig['profile'] == 'did-web-v1', 'profile mismatch')
    header, empty, raw = sig['jws'].split('.')
    require(empty == '', 'expected detached JWS')
    h = parse(unb64(header))
    require(set(h) == {'alg', 'kid'} and h['alg'] == 'ES256', 'unexpected JWS header')
    require(h['kid'] in document['assertionMethod'], 'unauthorized assertion key')
    methods = [m for m in document['verificationMethod'] if m['id'] == h['kid'] and m['controller'] == issuer]
    require(len(methods) == 1, 'ambiguous key')
    required = [['identifier'], ['type'], ['url'], ['digest'], ['trustManifests', issuer]]
    if 'version' in entry: required.append(['version'])
    require(all(p in sig['paths'] for p in required), 'incomplete coverage')
    fields = []
    for path in sorted(sig['paths'], key=lambda p: [s.encode('utf-16be') for s in p]):
        require(path and path[0] != 'signatures', 'invalid signature path')
        value = entry
        for name in path:
            require(isinstance(value, dict), 'array traversal refused')
            value = value[name]
        fields.append([path, value])
    payload = {'context': 'ai-catalog-entry-signature', 'signer': issuer, 'profile': sig['profile'], 'fields': fields, 'issuedAt': sig['issuedAt'], 'expiresAt': sig['expiresAt']}
    verify_raw(methods[0]['publicKeyJwk'], raw, (header + '.' + b64(canonical(payload))).encode())
    now = datetime.now(timezone.utc)
    require(datetime.fromisoformat(sig['issuedAt'].replace('Z', '+00:00')) <= now < datetime.fromisoformat(sig['expiresAt'].replace('Z', '+00:00')), 'signature is not fresh')
    require(entry['identifier'] == IDENTIFIER and entry['url'] == f'{HOST}/agents/{HOST_ID}/agent-card.json' and entry['type'] == 'application/a2a-agent-card+json', 'release identity mismatch')
    require(entry['digest'] == digest(artifact), 'artifact digest mismatch')

def secret_file(path):
    require(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, 'private file permissions must be 0600')
    return parse(path.read_bytes())

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--owner-file', required=True, type=Path)
    ap.add_argument('--registry-key', required=True, type=Path)
    ap.add_argument('--registry', choices=['https://registry.aithos.world', 'https://registry-dev.aithos.world'], default='https://registry.aithos.world')
    ap.add_argument('--out', required=True, type=Path)
    a = ap.parse_args()
    require(not a.out.exists(), 'output directory already exists; choose a fresh one')
    origins = {HOST, 'https://catalog.aithos.me', a.registry}
    get = lambda url: parse(request(url, origins))
    private = secret_file(a.registry_key)
    public = {k: private[k] for k in ['crv', 'kty', 'x', 'y']}
    agent = b64(hashlib.sha256(canonical(public)).digest())
    owner = secret_file(a.owner_file)
    require(owner['id'] == HOST_ID, 'owner file identifies another agent')
    # Fail before creating a hosting receipt if domain certification is missing.
    record = get(f'{a.registry}/v1/agents/{agent}')
    require(record['status'] == 'ACTIVE', 'registry identity is not active')
    require(any(d['domain'] == 'mathieucolla.com' for d in record.get('domains', [])), 'certify mathieucolla.com in the registry first')
    catalog = get(CATALOG)
    entries = [e for e in catalog['entries'] if e.get('identifier') == IDENTIFIER]
    require(len(entries) == 1, 'catalog entry is missing or ambiguous')
    source = entries[0]
    entry = {k: source[k] for k in ['identifier', 'type', 'url', 'version'] if k in source}
    require(entry['url'] == f'{HOST}/agents/{HOST_ID}/agent-card.json', 'unexpected catalog card URL')
    nonce = b64(secrets.token_bytes(32))
    result = parse(request(f'{HOST}/v1/agents/{HOST_ID}/control-proofs', origins, {'registryAgentId': agent, 'domain': 'mathieucolla.com', 'nonce': nonce, 'audience': a.registry}, owner['owner_key']))
    receipt = result['receipt']
    header, encoded, signature = receipt.split('.')
    h, claims = parse(unb64(header)), parse(unb64(encoded))
    require(set(h) == {'alg', 'typ', 'kid'} and h['alg'] == 'ES256' and h['typ'] == 'aithos-host-control+jwt', 'unexpected hosting proof')
    keys = [k for k in get(HOST + '/.well-known/jwks.json')['keys'] if k['kid'] == h['kid']]
    require(len(keys) == 1, 'host key missing or ambiguous')
    verify_raw(keys[0], signature, (header + '.' + encoded).encode())
    require(claims['nonce'] == nonce and claims['aud'] == a.registry and claims['iss'] == HOST and claims['registryAgentId'] == agent and claims['domain'] == 'mathieucolla.com' and claims['hostedAgentId'] == HOST_ID and claims['cardUrl'] == entry['url'], 'host binding mismatch')
    now = datetime.now(timezone.utc).replace(microsecond=0)
    require(claims['iat'] <= now.timestamp() < claims['exp'] <= claims['iat'] + 600, 'host proof is not fresh')
    payload = {'action': 'issue-host-domain-trust-v1', 'agentId': agent, 'registryOrigin': a.registry, 'seq': record['seq'], 'domain': 'mathieucolla.com', 'nonce': nonce, 'entryDigest': digest(canonical(entry)), 'receiptDigest': digest(receipt.encode()), 'issuedAt': now.isoformat().replace('+00:00', 'Z'), 'expiresAt': (now + timedelta(seconds=600)).isoformat().replace('+00:00', 'Z')}
    key = ec.derive_private_key(int.from_bytes(unb64(private['d']), 'big'), ec.SECP256R1())
    protected = b64(canonical({'alg': 'ES256', 'typ': 'JOSE', 'kid': agent}))
    encoded = b64(canonical(payload))
    r, s = decode_dss_signature(key.sign((protected + '.' + encoded).encode(), ec.ECDSA(hashes.SHA256())))
    consent = {'protected': protected, 'payload': encoded, 'signature': b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big')), 'key': public}
    issuance = parse(request(f'{a.registry}/v1/experimental/trust/agents/{agent}/issuances', origins, {'entry': entry, 'receipt': receipt, 'consent': consent}))
    artifact = request(entry['url'], origins)
    issuer = 'did:web:' + urllib.parse.urlsplit(a.registry).hostname
    document = get(a.registry + '/.well-known/did.json')
    verify(issuance['entry'], artifact, document, issuer)
    evidence = issuance['entry']['trustManifests'][issuer]['extensions'][SCHEMA]
    require(evidence['registryAgentId'] == agent and evidence['domain'] == 'mathieucolla.com' and evidence['hostReceipt'] == receipt and evidence['consent'] == consent, 'issued evidence mismatch')
    require(evidence['experimental'] and evidence['transparency'] == {'independentWitness': False, 'requiresOnlineRevalidation': True}, 'unexpected assurance level')
    expected_status = f'{a.registry}/v1/experimental/trust/agents/{agent}/issuances/{nonce}/status'
    require(issuance['statusUrl'] == expected_status, 'unexpected status URL')
    require(get(expected_status)['current'] is True, 'issuance is already stale')
    a.out.mkdir(parents=True, mode=0o700)
    for name, value in [('issuance.json', issuance), ('entry.json', issuance['entry']), ('did.json', document)]:
        (a.out / name).write_bytes(canonical(value) + b'\n')
    (a.out / 'agent-card.json').write_bytes(artifact)
    print(json.dumps({'verified': True, 'registryAgentId': agent, 'issuer': issuer, 'publisherSignature': False, 'experimental': True, 'expiresAt': issuance['expiresAt'], 'manifestUrl': a.registry + '/trustmanifest/' + agent, 'output': str(a.out.resolve())}))

if __name__ == '__main__':
    try: main()
    except urllib.error.HTTPError as e: raise SystemExit(f'HTTP {e.code} from {urllib.parse.urlsplit(e.url).hostname}; no credentials printed') from None
    except Exception as e: raise SystemExit(f'{type(e).__name__}: {e}') from None
