# Handoff d'implémentation — certification de domaine

**Date :** 2026-09-01
**Pour :** une session sans contexte préalable, dans `agents-card-registery-2`
**Objet :** implémenter `DOMAIN-CERTIFICATION.md` 0.1.0 de bout en bout
**Branche de départ :** `domain-certification` (commit `bfa6e50`, non mergée dans `main`)

---

## 0. À lire avant d'écrire une ligne

1. **`DOMAIN-CERTIFICATION.md`** (racine) — la spec. C'est la référence normative ; en cas de doute, elle tranche, pas ce handoff.
2. **`SPEC.md`** §3.2 (kid = thumbprint), §5.5–5.6 (JWS, clés soumises), §6.5 (retrait — **le patron exact** à recopier), §6.6 (convergence), §9 (problèmes).
3. Mémoire projet : `domain_certification_2026-09.md` (les décisions et leurs raisons), `outillage_cowork_rust.md` (pièges de la VM : cargo, /tmp, locks git).

Chaque règle de la spec porte le paragraphe qui dit *quel défaut elle empêche*. Ne pas « simplifier » une règle sans avoir lu ce paragraphe.

---

## 1. Invariants à ne pas violer

- **`registry-core` reste pur** : aucune I/O, aucun réseau, aucune horloge. La résolution DNS n'y entre pas ; seuls le parsing et les règles y vont.
- **Aucun octet de carte n'est touché.** Rien de ce travail n'ajoute un champ à `AgentCard`, ne modifie `cardBytes`, ni ne change un digest. Si un test de canonicalisation bouge, c'est un bug.
- **Un seul endroit définit `_a2a` et `A2A1`** — des constantes dans `registry-core`, réexportées. Aucune de ces chaînes ne doit apparaître deux fois dans le code.
- **Le chemin de publication ne résout aucun DNS.** Seul `PUT /v1/agents/{id}/domains` résout, parce que c'est son métier.
- **La publication ne doit pas effacer les certifications** — voir le piège §11.1, c'est le bug le plus probable de tout ce chantier.

---

## 2. Décisions d'architecture prises ici

**Un nouveau crate `crates/registry-dns`.** Il porte le trait de résolution et son implémentation réelle. Raison : `registry-api` (serveur), `registry-lambda` et `aithos-cli` en ont tous besoin, et `aithos-cli` ne doit surtout pas dépendre de `registry-api` — le commentaire de son `Cargo.toml` est explicite, ça tirerait le SDK AWS dans chaque `cargo install`. Il sera publié sur crates.io comme les autres dépendances de chemin du CLI (`version = "0.1.0"`).

*Alternative si on refuse un quatrième crate publié :* mettre le trait dans `registry-api` et dupliquer une quarantaine de lignes de glu dans le CLI. Moins bien, mais acceptable.

**Répartition :**

| Où | Quoi |
| --- | --- |
| `registry-core` | parsing du TXT, validation de domaine, payload `certify-domains`, autorisation, constantes |
| `registry-dns` | `trait Resolver`, implémentation hickory, résolveur factice pour les tests |
| `registry-api` | route, handler, contrat `Store`, `MemoryStore`, codes de problème, projection |
| `registry-lambda` | item DynamoDB, câblage du résolveur réel, revalidation dans le *sweeper* |
| `aithos-cli` | `certify`, l'affichage dans `verify` |

---

## 3. Étape 1 — `registry-core` : parsing et règles (pur, sans réseau)

### 3.1 `crates/registry-core/src/domain.rs` (nouveau)

```rust
/// Le nom souligné sous lequel une zone déclare ses agents (§3.1).
pub const DNS_LABEL: &str = "_a2a";
/// La valeur exigée du premier tag (§3.2).
pub const TXT_VERSION: &str = "A2A1";
/// §8.
pub const MAX_DOMAINS: usize = 8;
pub const MAX_TXT_RECORDS: usize = 32;
pub const MAX_TXT_BYTES: usize = 4096;

/// Un domaine validé selon §5.4 : A-label, minuscule, sans point final.
pub struct Domain(String);
impl Domain { pub fn parse(raw: &str) -> Result<Self>; pub fn query_name(&self) -> String; }

/// §3.2–3.3 : le champ `k` d'un enregistrement bien formé, s'il y en a un.
/// `record` est déjà la concaténation des character-strings.
pub fn agent_id_in_record(record: &str) -> Option<&str>;

/// §3.3 : au moins un enregistrement du RRset nomme cet agent.
pub fn rrset_names_agent(records: &[String], agent_id: &str) -> bool;
```

Règles à implémenter littéralement :

- `Domain::parse` — A-label uniquement (rejeter tout octet non ASCII : c'est le refus des U-labels de §5.4, pas une conversion), minuscules, pas de point final, pas de schéma/port/chemin, labels de 1 à 63 octets, nom ≤ 253 octets, caractères LDH, pas de littéral IP, **pas un suffixe public**.
- Le suffixe public a besoin de la PSL. Crate `publicsuffix` ou `psl`, liste embarquée à la compilation. Choisir une liste embarquée et non téléchargée : le registre ne doit pas dépendre d'un fetch au démarrage.
- `agent_id_in_record` — découper sur `;`, retirer espaces et tabulations ASCII autour des tags et des `=`, exiger `v=A2A1` **en premier tag**, retourner la valeur de `k`. Tag inconnu → ignoré. Tag `v` absent ou différent → `None`. Rien ne renvoie d'erreur : §3.3 exige d'**ignorer**, pas de rejeter.
- `rrset_names_agent` — vrai dès qu'un enregistrement correspond. Un enregistrement malformé au milieu d'un RRset valide ne doit rien casser.

### 3.2 `crates/registry-core/src/certify.rs` (nouveau)

Recopier la structure de `evaluate_withdrawal` dans `write.rs` — mêmes helpers (`decode_bound_payload`, `expect_exactly`, `expect`, `expect_timestamp`, `index_keys`, `jws::parse_protected`, `jws::verify_detached`), même ordre de vérifications, même style d'erreurs. Rendre ces helpers `pub(crate)` si nécessaire.

```rust
pub const CERTIFY_ACTION: &str = "certify-domains";

pub struct Certification {
    pub kid: String,
    pub domains: Vec<Domain>,   // dans l'ordre signé, déjà validé
    pub issued_at: String,
}

pub fn evaluate_certification(
    state: &AgentState,
    registry_origin: &str,
    last_issued_at: Option<&str>,
    protected_b64: &str,
    payload_b64: &str,
    signature_b64: &str,
    submitted_keys: &[Value],
) -> Result<Certification>;
```

Ordre exact (§5.3) :

1. `state.status == Withdrawn` → `Code::Withdrawn`.
2. `decode_bound_payload` — le ré-encodage canonique est vérifié, comme pour le retrait.
3. `expect_exactly(&["action", "agentId", "domains", "issuedAt", "registryOrigin"])`, puis `action == CERTIFY_ACTION`, `agentId == state.agent_id`, `registryOrigin == registry_origin`, `issuedAt` horodatage RFC 3339 valide.
4. `domains` : tableau de chaînes, ≤ `MAX_DOMAINS`, **strictement croissant en ordre de points de code** (ce qui interdit aussi les doublons) → sinon `DomainsNotCanonical` ; chaque élément passe `Domain::parse`. Tableau vide accepté.
5. Clés soumises : aucune clé qui ne signe pas (`UnusedKey`, comme le retrait), `kid` dans `state.authorized_kids` sinon `NotAuthorizedKey`, `kid` résolu vers une clé soumise sinon `KidNotThumbprint`, puis `verify_detached`.
6. `issuedAt` **strictement supérieur** à `last_issued_at` s'il existe → sinon `CertificationNotIncreasing`. Comparaison sur l'instant, pas sur la chaîne : deux graphies RFC 3339 du même instant existent. Parser avec `time`.

### 3.3 `error.rs`

Ajouter à `Code` : `DomainSyntaxInvalid`, `DomainIsPublicSuffix`, `DomainsNotCanonical`, `TooManyDomains`, `CertificationNotIncreasing`. `as_str` → les chaînes de §11. `http_status` → 422 partout **sauf** `CertificationNotIncreasing` = 409 (le `_ => 422` existant s'en charge pour les autres ; ajouter le bras 409).

`DnsRecordAbsent` et `DnsUnresolved` **ne vont pas ici** : `registry-core` ne résout rien, ces deux-là naissent dans `registry-api`.

### 3.4 `lib.rs`

Ajouter `pub mod certify; pub mod domain;` et réexporter `Certification`, `Domain`, `evaluate_certification`, `CERTIFY_ACTION`, `DNS_LABEL`, `TXT_VERSION`, `MAX_DOMAINS`.

**Fin d'étape :** `cargo test -p aithos-registry-core` passe, `cargo clippy --all-targets -- -D warnings` propre, aucune dépendance réseau ajoutée au crate.

---

## 4. Étape 2 — vecteurs de conformité (§12)

Dans `crates/registry-core/tests/` (à côté de `write_rules.rs`) et dans `vectors/` pour ce qui est publié.

- Parsing TXT : enregistrement en plusieurs character-strings concaténés ; tag inconnu ignoré ; `v` absent ; `v` inconnu ; `k` qui ne correspond pas ; enregistrement malformé partageant le nom avec un valide (le valide gagne).
- Payload : bytes canoniques d'un `certify-domains` de référence ; membre en trop refusé ; `domains` non trié refusé ; doublon refusé ; `registryOrigin` étranger refusé.
- Rejeu : `issuedAt` égal refusé, antérieur refusé.
- Domaines : U-label refusé, suffixe public refusé, majuscule refusée, point final refusé, littéral IP refusé, 9 domaines refusés.

Écrire ces tests **avant** l'étape 3 : ils sont la définition de « ça marche » et ils ne demandent aucune infrastructure.

---

## 5. Étape 3 — `crates/registry-dns` (nouveau crate)

```rust
#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    /// Le RRset TXT à `name`, chaque enregistrement déjà concaténé.
    async fn txt(&self, name: &str) -> Result<Vec<String>, ResolveError>;
}

pub enum ResolveError { NoRecords, Failed(String) }   // absent vs. non résolu (§5.5)
```

- `NoRecords` couvre `NXDOMAIN` et `NODATA` — ce sont des **réponses**. `Failed` couvre `SERVFAIL`, timeout, troncature non réparée par TCP, limite de redirections. La spec §11 fait dépendre deux codes distincts de cette distinction ; ne pas la perdre.
- Implémentation réelle avec `hickory-resolver` : `QTYPE=TXT` uniquement, jamais `ANY` ; resolvers propres au service, **jamais** un resolver nommé dans la requête ; bascule TCP si tronqué ; 8 redirections CNAME/DNAME au plus ; 5 s au total par domaine.
- Fournir `StaticResolver` (une `HashMap<String, Result<Vec<String>, ResolveError>>`) pour les tests de `registry-api`. C'est ce qui permet de tester tout le handler sans réseau.

**Fin d'étape :** un test d'intégration `#[ignore]` qui résout un vrai nom public, et les tests unitaires sur le résolveur statique.

---

## 6. Étape 4 — `registry-api` : contrat, route, handler

### 6.1 `store.rs`

```rust
pub struct DomainRecord {
    pub domain: String,
    pub certified_at: String,
    pub last_checked_at: String,
    pub consecutive_failures: u8,
}

pub struct CertificationState {
    pub requested: BTreeSet<String>,
    pub observed: Vec<DomainRecord>,
    pub issued_at: Option<String>,
}
```

Trois méthodes sur `Store` :

```rust
async fn get_certification(&self, agent_id: &str) -> StoreResult<CertificationState>;
/// Conditionnel sur `expected_issued_at` (monotone), PAS sur `seq`.
async fn put_certification(&self, agent_id: &str, expected_issued_at: Option<&str>,
                           state: &CertificationState) -> StoreResult<()>;
/// Utilisé par la revalidation : met à jour `observed` seul, sans toucher à `requested`.
async fn put_observations(&self, agent_id: &str, observed: &[DomainRecord]) -> StoreResult<()>;
```

La condition porte sur `issued_at` et non sur `seq` : c'est ce qui fait que certifier et publier ne se disputent pas la même écriture conditionnelle (§4.3 de la spec, et piège §11.1 ici).

### 6.2 `memory.rs`

Implémenter les trois méthodes sur `MemoryStore`. C'est ce qui rend toute la suite HTTP testable sans AWS — comme le dit `lib.rs`, « exercised against `MemoryStore` with no AWS in sight ».

### 6.3 `api.rs`

- `AppState` gagne `resolver: Arc<dyn Resolver>`. `router()` prend le résolveur en paramètre (ou `RegistryConfig` le porte).
- Route : `.route("/v1/agents/{agent_id}/domains", put(put_domains))`.
- `parse_certify_body` — calqué sur `parse_withdraw_body` : `{ "certification": {protected,payload,signature}, "keys": [...] }`, `reject_unknown` pour tout le reste, même limite de corps.
- Handler `put_domains`, dans cet ordre :
  1. charger l'agent (`404` inconnu, `410` retiré),
  2. charger `get_certification` pour `issued_at`,
  3. `evaluate_certification` — toute erreur est un `Problem` par le mapping existant,
  4. **résoudre chaque domaine** via `Resolver` — de préférence en parallèle (`futures::join_all`), 8 × 5 s sinon,
  5. **atomique** : si un seul domaine n'est pas *observé*, ne rien écrire et refuser (§5.5),
  6. `put_certification` avec `expected_issued_at` = celui lu en (2) ; `StoreError::Conflict` → `409 CONFLICT`,
  7. `200 OK` avec la projection.
- `agent_json` : ajouter `domains[]` = **`observed` uniquement, jamais `requested`** (§6), trié par domaine.
- `get_agent` fait désormais un second appel au store. Ne pas fusionner les deux lectures en une transaction : rien n'en dépend.

### 6.4 `problem.rs`

Ajouter `DNS_RECORD_ABSENT` (422) et `DNS_UNRESOLVED` (422). Les deux **doivent** porter un membre `domains` donnant l'issue par domaine — sinon une requête à quatre domaines s'explore par bissection (§11).

### 6.5 Manifeste `/v1/registry`

Ajouter le nom souligné et la version du tag, la limite de domaines, et l'intervalle de revalidation. Un second implémenteur doit pouvoir vérifier qu'il interroge le même nom.

**Fin d'étape :** dans `tests/http.rs`, avec `StaticResolver` — certification acceptée ; enregistrement absent ; un domaine sur trois absent (rien n'est écrit) ; `SERVFAIL` → `DNS_UNRESOLVED` ; clé non autorisée ; rejeu ; ensemble vide qui vide la liste ; agent retiré → `410` ; la projection ne montre que `observed`.

---

## 7. Étape 5 — `registry-lambda` : stockage et revalidation

### 7.1 `item.rs` / `aws_store.rs`

**Item séparé, une par agent** : `PK = AGENT#<agentId>`, `SK = CERT`. Il porte `requestedDomains`, `observed` (≤ 8 entrées) et `certificationIssuedAt`.

**Ne pas mettre ces attributs sur l'item de l'agent.** `Commit` remplace l'item entier — le commentaire de `store.rs` le dit — donc la prochaine publication effacerait silencieusement toutes les certifications. C'est le piège §11.1.

`put_certification` → `UpdateItem` avec `ConditionExpression: attribute_not_exists(certificationIssuedAt) OR certificationIssuedAt < :t`.

### 7.2 Câblage

Dans `main.rs`, mode `"api"` : construire le résolveur hickory et le passer à `router()`. Les serveurs DNS viennent de l'environnement Lambda ; laisser une variable d'environnement pour les forcer en développement.

### 7.3 Revalidation (mode `"sweeper"`, horaire)

Pour chaque agent `ACTIVE` ayant un item `CERT` : résoudre chaque domaine de `requested`, puis (§7 de la spec)

- *observé* → `last_checked_at = now`, `consecutive_failures = 0` ; absent de `observed` → l'ajouter avec `certified_at = now` ;
- *absent* ou *non résolu* → `consecutive_failures += 1` ; **à 3, retirer de `observed`** ; en dessous, ne rien changer d'autre.

`requested` n'est jamais modifié par la revalidation. Émettre une métrique par retrait — un retrait est un événement, pas une routine.

**Ne pas** toucher au `reconciler` (mode `"reconciler"`, flux DynamoDB) : il converge les objets carte et JWKS vers S3, et la projection du record est servie par l'API depuis DynamoDB. Vérifier tout de même que le bord route bien `/v1/agents/{id}` vers l'API et non vers l'object store.

**Fin d'étape :** tests unitaires du compteur d'échecs (0→1→2→3, retour à *observé* au milieu qui remet à zéro), et un passage manuel du sweeper sur `registry-dev`.

---

## 8. Étape 6 — `aithos-cli`

Nouvelle sous-commande, à côté de `Withdraw` :

```rust
Certify {
    agent: String,
    #[arg(long = "key")] key: String,
    #[arg(long, value_delimiter = ',')] domains: Vec<String>,
}
```

Déroulé :

1. valider chaque domaine avec `Domain::parse` — refuser localement, avec un message qui dit quoi corriger ;
2. résoudre `_a2a.<D>` pour chacun via `registry-dns` ;
3. **s'il en manque** : imprimer les lignes de zone à coller et s'arrêter sans rien envoyer —
   ```text
   _a2a.acme.com.   IN   TXT   "v=A2A1; k=<agentId>"
   ```
   suivi de « laisse-les publiés : c'est la preuve, pas un défi à usage unique » ;
4. tous présents : construire le payload (domaines **triés**), signer avec la clé, `PUT`, afficher le résultat.

`--domains ""` envoie l'ensemble vide et retire tout ; le dire dans l'aide.

`verify` gagne une ligne par domaine, **résolue en direct par le client**, jamais lue depuis le registre — une certification que le lecteur ne peut pas reproduire est une certification qu'il doit croire. Afficher l'A-label brut, jamais d'U-label, jamais de coche (§9).

Ajouter `registry-dns` aux dépendances du CLI et vérifier que `cargo build -p aithos` ne tire pas le SDK AWS.

---

## 9. Étape 7 — `registry-e2e`

Un test `#[ignore]` de plus dans `tests/live.rs` : créer un agent, certifier un domaine de test dont on contrôle la zone, lire le record, retirer l'agent, vérifier que les domaines disparaissent. Il faut une zone réelle avec un TXT stable — la poser dans la zone de `registry-dev` et le noter dans `infra/RUNBOOK-PROD.md`.

---

## 10. Étape 8 — documentation

- `SPEC.md` : une phrase en §10 qui renvoie vers `DOMAIN-CERTIFICATION.md` comme réalisation du point réservé. **Ne rien changer d'autre dans `SPEC.md`.**
- `README.md` : la commande dans le Quickstart, et une phrase qui dit ce que la certification n'établit pas — le paragraphe existant sur ce que `verify` n'établit pas doit rester vrai.
- `crates/aithos-cli/README.md` : idem.
- `audits/LEDGER.md` : consigner la décision « item DynamoDB séparé » et son motif.

---

## 11. Pièges

**11.1 — L'écrasement à la publication.** `Commit` remplace l'item de l'agent. Toute certification stockée sur cet item disparaît à la prochaine publication, sans erreur, sans trace. D'où l'item `CERT` séparé. **Écrire le test qui publie après avoir certifié et vérifie que les domaines survivent** : c'est le seul test qui attrape ce bug.

**11.2 — Comparaison d'horodatages sur les chaînes.** `2026-09-01T09:00:00Z` et `2026-09-01T09:00:00.000Z` sont le même instant et deux chaînes différentes. Comparer des instants parsés.

**11.3 — Le tri de `domains`.** Ordre de **points de code**, pas l'ordre de la locale. Et JCS ne trie pas les tableaux : c'est bien nous qui l'exigeons, la vérification doit être explicite.

**11.4 — La casse.** Les noms DNS sont insensibles à la casse et un resolver peut en varier la casse (0x20) ; `k=` est du base64url, sensible à la casse. Normaliser le **nom**, jamais la **valeur**.

**11.5 — Le résolveur du client.** Ne jamais utiliser un serveur DNS nommé dans la requête. C'est une SSRF déguisée.

**11.6 — Atomicité.** Il est tentant d'enregistrer les domaines qui ont résolu et de signaler les autres. Non : `requested` doit toujours être exactement ce qu'une clé a signé.

**11.7 — Les locks git de la VM.** `git` ne peut pas supprimer ses verrous ici ; les déplacer vers `_to_delete/gitlocks/<date>/` après chaque commit, comme le note `outillage_cowork_rust.md`.

---

## 12. Terminé quand

```sh
cargo test                                      # suite offline, aucun réseau
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo build -p aithos-a2a-card --target wasm32-unknown-unknown
REGISTRY_E2E_ORIGIN=https://registry-dev.aithos.world \
  cargo test -p registry-e2e -- --ignored --test-threads=1
```

et :

- les vecteurs de §12 de la spec sont publiés dans `vectors/` ;
- `/v1/registry` annonce le nom souligné, la limite de domaines et l'intervalle de revalidation ;
- un `grep -rn '_a2a' crates/` ne montre la chaîne qu'à **un** endroit ;
- publier après avoir certifié conserve les domaines (11.1) ;
- `aithos verify` affiche les domaines résolus par le client, sans coche.

---

## 13. Ce qui n'est pas dans ce lot

DNSSEC, résolution multi-points-de-vue, le contrôle `.well-known`, la portée sous-arbre, toute attestation signée par le registre. §10 de la spec dit pourquoi chacun est dehors. En ajouter un change le modèle de confiance et se rediscute avant, pas pendant.

Le volet IANA et W3C est un chantier séparé : `docs/HANDOFF-IANA-CG.md`.
