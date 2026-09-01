# Handoff — réservation du nom `_a2a` à l'IANA et présence au CG W3C

**Date :** 2026-09-01
**Pour :** une session sans contexte préalable
**Projet :** Aithos Agent Card Registry (`agents-card-registery-2`)
**Document source :** `DOMAIN-CERTIFICATION.md` v0.1.0 — le profil de certification de domaine. Il est indispensable à ce travail. À la date de ce handoff il n'est **pas encore committé au dépôt** ; le récupérer avant de commencer.

---

## 1. Le contexte, en dix lignes

Aithos est un registre public de cartes d'agents A2A. Pas de comptes : l'identifiant d'une entrée (`agentId`) est l'empreinte RFC 7638 de la clé qui l'a créée, et toute écriture est autorisée par une signature JWS. Les règles normatives sont dans `SPEC.md` 0.1.0, qui exclut explicitement la vérification de domaine (§1, §10) et réserve son ajout comme un attribut du *record*, jamais comme un champ de la carte.

On vient d'écrire ce profil additif. Il repose sur un enregistrement DNS :

```text
_a2a.acme.com.   IN   TXT   "v=A2A1; k=<agentId>"
```

Deux chantiers en découlent, tous deux indépendants du code et menables en parallèle de l'implémentation :

1. **Réserver `_a2a`** dans le registre IANA des noms de nœuds DNS soulignés.
2. **Exister dans le Community Group W3C** dont le périmètre est exactement le nôtre, avant qu'il ne publie quoi que ce soit.

C'est l'objet de ce handoff. **Il ne s'agit pas d'écrire du code.**

---

## 2. Ce qui est déjà tranché — ne pas rouvrir

- Le porteur de preuve est un **TXT**, pas un CNAME. Le CNAME sert uniquement à la délégation (`_a2a.acme.com CNAME _a2a.acme.hebergeur.net`), gratuitement, puisque les resolvers le suivent.
- L'enregistrement est **permanent**, pas un défi éphémère à la ACME. C'est ce qui garde le registre hors du chemin de confiance : il publie une observation que n'importe qui peut refaire, pas une attestation qu'il faudrait croire. Corollaire : `SPEC.md` §10 n'exige pas de log de transparence.
- Le préfixe est posé **directement sous le nom certifié** (`_a2a.<D>`), jamais à un emplacement choisi par le publisher — sinon quiconque contrôle un sous-domaine quelconque peut faire certifier le parent.
- Premier tag obligatoire `v=A2A1`, **tout enregistrement qui ne commence pas par là doit être ignoré et non rejeté**. C'est la clause de coexistence : elle rend un usage futur non lié du même préfixe non destructeur.
- `k=` porte l'`agentId`, c'est-à-dire une empreinte de clé RFC 7638 — pas un identifiant propre à notre registre. C'est ce qui rend le mécanisme utilisable sans nous, et c'est l'argument de standardisation.
- Les domaines sont en A-labels (punycode), minuscules.

---

## 3. État vérifié le 2026-09-01

**Registre IANA.** Il s'appelle exactement **« Underscored and Globally Scoped DNS Node Names »**, créé par la RFC 8552, hébergé dans la page *DNS Parameters* de l'IANA.

- Politique d'enregistrement : **Expert Review** (RFC 8126).
- Experts désignés à ce jour : **Frederico A. C. Neves** et **Paul Wouters**.
- Trois champs par entrée : *RR Type*, *_NODE NAME*, *Reference*.
- L'expert vérifie deux choses : que « les détails sont suffisamment clairs, précis et complets », et que le couple (nom souligné, type d'enregistrement) est unique dans la table.
- Exemples d'entrées existantes : `TXT / _acme-challenge / RFC 8555`, `SRV / _tcp / RFC 2782`, `TLSA / _dane / RFC 7671`, `HTTPS / _https / RFC 9460`.
- **`_a2a` est libre.** Aucune entrée agentique dans le registre. *À revérifier avant de déposer.*

**Community Group W3C.** *Agent Identity Registry Protocol Community Group*, `https://www.w3.org/community/agent-identity/`.

- Proposé le 22/04/2026, lancé le 24/04/2026.
- 45 participants. Un président : Adolfo Grego Micha.
- **Aucun draft ni rapport publié.** Dernière activité documentée : l'appel à participation d'avril.
- Liste publique `public-agent-identity@w3.org` (archives ouvertes), dépôt `w3c-cg/agent-identity`, IRC `#agent-identity`.
- Adhésion : compte W3C gratuit, **pas** besoin d'être membre du W3C ; signature du *Community Contributor License Agreement*.
- Périmètre annoncé : méthodes DID, formats de credentials, protocoles de négociation de confiance, exigences post-quantiques.

Deux autres CG à surveiller sans s'y disperser : *AI Agent Protocol CG* (`agentprotocol`) et *Agent Trust Protocol CG* (did:atp, Ed25519 + ML-DSA-65).

---

## 4. Le livrable central : un Internet-Draft

Rien ne peut être demandé à l'IANA sans une référence publiable et stable. Le véhicule normal est un **Internet-Draft** déposé au datatracker de l'IETF : gratuit, ouvert à n'importe qui, sans adhésion, archivé à vie, citable. C'est aussi le document à présenter au CG. **Un seul effort pour les deux chantiers.**

### 4.1 Périmètre du draft — le point le plus important

Le draft spécifie **uniquement le mécanisme générique**, pas Aithos :

| Dans le draft | Hors du draft |
| --- | --- |
| Le nom `_a2a.<domaine>` et son placement | L'API du registre |
| La syntaxe `v=A2A1; k=…` et la règle d'ignorance | L'opération signée `certify-domains` |
| La règle de correspondance (§3.3 du profil) | Les ensembles `requestedDomains` / `certifiedDomains` |
| Ce que la liaison affirme et n'affirme pas | La revalidation, les codes d'erreur, la CLI |
| Considérations de sécurité | Tout ce qui est propre à `registry.aithos.world` |

Deux raisons. D'abord, un expert IANA accueille beaucoup mieux une référence qui décrit une liaison DNS générique qu'une qui décrit l'API d'une société. Ensuite, la partie générique est précisément celle que d'autres peuvent adopter — un enregistrement qui dit « ce domaine déclare que cette clé parle pour lui » est utilisable par n'importe quel vérificateur A2A, sur n'importe quelle carte signée, sans aucun registre. Tout le reste du profil Aithos reste dans le dépôt.

### 4.2 Nom du fichier

Convention : `draft-<nom de famille de l'auteur>-<mot-clé>-<numéro>`. Par exemple `draft-colla-a2a-domain-binding-00`. Le nom n'engage à rien et peut changer entre versions, mais garder le même racine facilite le suivi.

### 4.3 Ossature attendue

1. Introduction — le problème : une carte A2A signée ne dit rien du domaine.
2. Terminologie (RFC 2119/8174).
3. L'enregistrement : nom, syntaxe, correspondance, records multiples, délégation par CNAME, permanence.
4. Ce que la liaison affirme — et la liste explicite de ce qu'elle n'affirme pas.
5. Considérations de sécurité : bidirectionnalité (le DNS seul ne prouve qu'un sens), suffixes publics, IDN et homographes, fraîcheur et revalidation, DNSSEC non exigé, résolution multi-points-de-vue laissée hors périmètre.
6. **Considérations IANA** — c'est ici que la demande est formulée noir sur blanc (voir §5.2 et l'annexe A).
7. Références normatives : RFC 1035, 8552, 8553, 7515, 7638, 5890/5891, 7208 §3.3, 6376 §3.2 ; A2A v1.0.1.

Les §1, §3 et §9 du profil `DOMAIN-CERTIFICATION.md` se transposent presque tels quels — ils ont été écrits dans ce style pour cette raison.

### 4.4 Mécanique de dépôt

- Dépôt : `https://datatracker.ietf.org/submit/`. Gratuit, compte requis, aucune adhésion.
- Format attendu : **xml2rfc v3**. Le chemin le plus court depuis du Markdown est **kramdown-rfc** (ou mmark), qui produit le XML ; `xml2rfc` produit ensuite le texte et le HTML.
- Passer l'**id-nits** avant de soumettre (le datatracker le fait aussi, mais autant ne pas découvrir les erreurs à la soumission).
- **BCP 78 / BCP 79** : en soumettant, l'auteur accorde à l'IETF les droits de publication et déclare les brevets connus. À valider avec qui détient la PI d'Aithos **avant** le dépôt — c'est irréversible.
- Un draft **expire au bout de 6 mois**. Il faut redéposer un `-01` avant, sinon la référence citée dans la demande IANA devient un document expiré, ce que l'expert peut légitimement refuser.
- Il existe une **période de gel** avant chaque réunion IETF pendant laquelle les nouveaux drafts ne peuvent pas être soumis. Vérifier le calendrier du datatracker avant de viser une date.

### 4.5 Où le faire relire (facultatif, mais peu cher)

La liste `dnsop@ietf.org` est l'endroit naturel pour un mécanisme fondé sur un nom souligné. L'adoption par un groupe de travail **n'est pas requise** pour une politique Expert Review — mais une relecture publique désamorce à l'avance les objections que l'expert soulèverait, et la trace de la discussion est un argument de stabilité.

---

## 5. La demande à l'IANA

### 5.1 Deux chemins

**A — demande directe (recommandé).** Expert Review n'exige pas une RFC. On envoie la demande par courriel en référençant l'Internet-Draft publié. L'IANA la transmet aux experts désignés, qui approuvent, refusent ou posent des questions. Ordre de grandeur : quelques semaines.

**B — par publication d'une RFC.** Le draft est adopté (flux IETF via dnsop, ou flux Indépendant via l'ISE) et l'enregistrement est effectué à la publication ; quand la demande accompagne un document IETF, la revue de l'expert a lieu pendant l'*IETF Last Call*. Ordre de grandeur : des mois à des années. À garder comme aboutissement, pas comme préalable.

Faire A. Poursuivre B ensuite si le mécanisme prend.

### 5.2 Le courriel à envoyer

Destinataire : **`iana@iana.org`**. Objet et corps, à adapter :

```text
Objet : Registration request — Underscored and Globally Scoped DNS Node Names — _a2a

Bonjour,

Je demande l'enregistrement d'une entrée dans le registre
« Underscored and Globally Scoped DNS Node Names »
(DNS Parameters, créé par la RFC 8552).

  RR Type    : TXT
  _NODE NAME : _a2a
  Reference  : draft-<nom>-a2a-domain-binding-00
               https://datatracker.ietf.org/doc/draft-<nom>-a2a-domain-binding/

Le document spécifie un enregistrement TXT publié à _a2a.<domaine> par
lequel le titulaire d'une zone DNS déclare qu'une clé publique donnée,
identifiée par son empreinte JWK (RFC 7638), est associée à ce domaine
pour le protocole Agent2Agent (A2A). Le format impose un premier tag
« v=A2A1 » et exige que tout enregistrement ne commençant pas par ce tag
soit ignoré, ce qui permet la coexistence avec d'éventuels autres usages
du même nom.

Le couple (TXT, _a2a) ne figure pas actuellement dans la table.

Contact : <nom>, <adresse>

Cordialement,
```

### 5.3 Objections probables de l'expert, et les réponses

- **« La référence est-elle stable ? »** → l'I-D est archivé et versionné ; s'engager à maintenir le document à jour, et donner le chemin de publication visé.
- **« Le couple est-il unique ? »** → oui, vérifié ; joindre la date de vérification.
- **« Pourquoi un nom générique plutôt qu'un nom propre au fournisseur ? »** → parce que le contenu de l'enregistrement est une empreinte de clé standard (RFC 7638) et non un identifiant de registre : le mécanisme est utilisable par tout vérificateur A2A, sans aucun registre. C'est un point à défendre, il est solide.
- **« `_a2a` désigne le protocole A2A, qui n'est pas le vôtre. »** → voir juste en dessous. C'est l'objection sérieuse.

### 5.4 Le risque principal, à traiter en premier

`_a2a` nomme **A2A**, protocole porté par la Linux Foundation (dépôt `a2aproject/A2A`), pas par Aithos. Déposer une demande sur ce préfixe sans avoir parlé aux mainteneurs est à la fois discourtois et fragile : l'expert peut demander leur avis, et un désaccord public tue la demande.

**Action, avant toute soumission :** ouvrir une issue ou une discussion chez `a2aproject/A2A` présentant le mécanisme, et demander soit une reprise en amont (le meilleur résultat de très loin — le mécanisme entre dans A2A et Aithos n'est qu'un implémenteur), soit une non-objection à l'enregistrement du préfixe. Documenter la réponse et la joindre à la demande IANA.

**Plan B sur le nom**, si ça bloque : `_agent-card` (générique, libre, sans revendication sur A2A) ou `_aithos` (aucun risque, aucune ambition). Le coût d'un changement après déploiement se paie en zones DNS de clients à modifier — donc **trancher avant la mise en production**, pas après.

---

## 6. Le Community Group W3C

### 6.1 Pourquoi

Le CG *Agent Identity Registry Protocol* a exactement notre périmètre — registre d'identité d'agents — et **n'a rien publié depuis avril**. C'est la fenêtre : la première contribution de fond fixe le vocabulaire et les hypothèses de départ. Attendre un premier draft, c'est arriver pour commenter les choix des autres.

### 6.2 Comment entrer

Créer un compte W3C (gratuit), rejoindre le groupe depuis sa page, signer le *Community Contributor License Agreement*. S'abonner à `public-agent-identity@w3.org`, lire les archives depuis avril, regarder le dépôt `w3c-cg/agent-identity`. Se présenter brièvement sur la liste.

### 6.3 Quoi y apporter — et quoi ne pas y apporter

**Apporter :** la liaison DNS comme mécanisme générique ; l'argument de bidirectionnalité (une déclaration DNS seule ne prouve qu'un sens, il faut aussi une signature de la clé, sinon on reproduit le défaut que `SPEC.md` §6.1 refuse déjà sous `UNPROVEN_KEY`) ; et le cadrage « observation, pas attestation », qui est ce qui évite d'avoir à construire un log de transparence.

**Ne pas apporter :** l'API du registre, et surtout aucune revendication d'alignement W3C. Le point d'étape du 30/08/2026 était sans ambiguïté : *compatible par construction, conforme à rien* — aucun standard W3C finalisé ne norme les registres d'agents, le socle réel est IETF (JOSE, RFC 8785, RFC 7638) plus A2A v1.0.1 (Linux Foundation). Dire autre chose se verrait.

### 6.4 Articulation IETF / W3C

Elles ne se substituent pas. **Un nom DNS se réserve à l'IANA, jamais dans un CG W3C** — le CG n'a aucune autorité là-dessus et ne peut pas en obtenir. Inversement, l'IETF ne dira rien du cadrage « identité d'agent ». Donc : l'Internet-Draft est l'artefact normatif, le CG est où l'on cherche l'adoption, la relecture et l'alignement de vocabulaire. Le même document sert aux deux, présenté différemment.

---

## 7. Ordre d'exécution

1. **Récupérer `DOMAIN-CERTIFICATION.md`** et le committer au dépôt (il n'y est pas encore).
2. **Trancher la question `_a2a` avec le projet A2A** — bloquant pour tout le reste (§5.4).
3. **Valider la cession de droits BCP 78/79** avec qui détient la PI (§4.4).
4. **Rédiger l'I-D `-00`** au périmètre du §4.1, le passer à id-nits, le déposer.
5. **Rejoindre le CG**, se présenter, y poster le draft.
6. *(facultatif)* Le poster sur `dnsop@ietf.org` pour relecture.
7. **Envoyer la demande IANA** en référençant l'I-D publié (§5.2).
8. **Tenir le draft vivant** : redéposer un `-01` avant les 6 mois.

Les étapes 1 à 3 sont des décisions, pas de la rédaction. Elles se règlent en une journée et elles conditionnent tout.

---

## 8. Risques

| Risque | Effet | Parade |
| --- | --- | --- |
| Le projet A2A revendique `_a2a` ou définit autre chose dessous | La demande échoue, ou pire, elle passe et on entre en collision plus tard | Le contacter d'abord (§5.4) ; plan B `_agent-card` |
| Quelqu'un enregistre le nom entre-temps | Il faut renommer | Revérifier le registre juste avant de déposer |
| L'expert juge la référence trop instable | Blocage | Passer par le flux Indépendant (ISE) ou dnsop, chemin B |
| Le draft expire à 6 mois | La demande référence un document mort | Calendrier de redépôt |
| Le CG publie un mécanisme concurrent pendant qu'on attend | On devient l'implémentation divergente | Y être présent tôt, poster le draft dès le `-00` |
| Cession BCP 78/79 non validée en interne | Dépôt irréversible sur un document dont on ne maîtrise plus les droits | Étape 3 avant l'étape 4 |

---

## Annexe A — Fiche d'enregistrement, prête à recopier

```text
Registry : Underscored and Globally Scoped DNS Node Names
           (IANA, DNS Parameters — créé par la RFC 8552)

RR Type    : TXT
_NODE NAME : _a2a
Reference  : <l'Internet-Draft, avec son URL datatracker>
```

## Annexe B — Extrait normatif à reprendre dans l'I-D

À transposer depuis `DOMAIN-CERTIFICATION.md` :

- §3.1 Nom, y compris la clause de coexistence par `v=A2A1`
- §3.2 Données de l'enregistrement (tags, concaténation des character-strings selon RFC 7208 §3.3, ignorance des tags inconnus, et la raison pour laquelle l'`agentId` est dans la donnée et jamais dans le nom — insensibilité à la casse des noms DNS contre sensibilité à la casse du base64url)
- §3.3 Correspondance, y compris « un enregistrement malformé ne doit pas faire échouer la résolution »
- §3.4 Délégation par CNAME
- §3.5 Permanence de l'enregistrement
- §1.1 et §1.2 comme motivation, §9 comme « ce que ça n'affirme pas »
- §5.4 (suffixes publics, A-labels) et §9 (affichage) comme considérations de sécurité

## Annexe C — Liens

- Registre IANA : `https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml`
- RFC 8552 (création du registre) : `https://www.rfc-editor.org/rfc/rfc8552.html`
- RFC 8553 (BCP 222, mise en conformité des specs existantes) : `https://www.rfc-editor.org/rfc/rfc8553.html`
- Dépôt d'un Internet-Draft : `https://datatracker.ietf.org/submit/`
- Enregistrement de paramètres, aide IANA : `https://www.iana.org/help/protocol-registration`
- CG Agent Identity Registry Protocol : `https://www.w3.org/community/agent-identity/`
- Participants du CG : `https://www.w3.org/community/agent-identity/participants`
- CG AI Agent Protocol : `https://www.w3.org/community/agentprotocol`
- Projet A2A : `https://github.com/a2aproject/A2A`
