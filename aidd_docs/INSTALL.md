# INSTALL.md — murmure

Vision technique et guide d'installation.

**Date** : 2026-07-31, révisé le 2026-08-01
**Statut** : **v1 livrée sur macOS et Linux.** Windows ne fonctionne pas — arti
se fige au premier consensus, voir `aidd_docs/arti-windows-hang.md`.
**Source amont** : `aidd_docs/brainstorm/2026_07_30-messagerie-pair-a-pair-terminal.md`

> Ce document a été écrit avant la première ligne de code. Les sections
> **Decisions**, **Audit summary** et **Ce que le choix C coûte** décrivent le
> raisonnement d'origine et restent exactes ; elles sont conservées comme
> archive. Les sections **Stack summary**, **Architecture**, **Folder
> structure** et **Install steps** décrivent le code réel et ont été corrigées
> le 2026-08-01. Là où la réalité a démenti le plan, c'est marqué sur place
> plutôt que réécrit en silence — un plan dont on efface les erreurs
> n'apprend rien à la relecture.

---

## Vision

> Messagerie terminal pair-à-pair chiffrée, sans serveur, sans compte, sans métadonnées centralisées.

murmure fait communiquer deux personnes qui se connaissent déjà, de machine à machine, sans
qu'aucun intermédiaire ne puisse lire les messages **ni savoir qui parle à qui**. C'est ce second
point qui définit le projet : le chiffrement de bout en bout est acquis partout, y compris chez
Signal et WhatsApp ; la confidentialité du **graphe social** ne l'est nulle part.

Le différenciateur tient en une phrase : aucune société ne peut fermer le service, le facturer,
ou changer ses conditions — parce qu'il n'y a pas de service, seulement deux machines et un
réseau public. Cible : cercles d'amis techniques, moins de dix utilisateurs, coût nul et
définitif.

---

## Decisions

| Décision | Choix | Pourquoi |
| --- | --- | --- |
| Architecture | Monolithe, **une seule crate binaire**, avec un trait `Transport` à deux implémentations | Un développeur solo, moins de dix utilisateurs. La seule abstraction posée est celle du transport, parce qu'il y aura réellement deux implémentations — pas une interface spéculative. |
| **Séparation contrôle / données** | **Tor porte le contrôle, un canal direct porte les données** | Le débit de Tor (0,1-0,25 Mo/s) est sans conséquence pour du texte et rédhibitoire pour des fichiers. Découpler les deux permet de payer le prix de l'anonymat là où il sert, et pas ailleurs. Restaure l'échelle à trois chemins du brainstorm. |
| Langage | **Rust** (MSRV 1.91) | Seul langage maîtrisé qui donne à la fois l'écosystème Tor natif, un binaire unique multi-OS, et pas de runtime à installer chez le correspondant. |
| Interface | **ratatui + crossterm**, TUI | Exigence « mode texte riche, pas de fenêtre graphique ». crossterm couvre Windows, ce qui répond à la réserve posée sur cet OS. ⚠️ **Démenti le 2026-08-01, mais pas par crossterm** : la TUI s'affiche correctement sous Windows Terminal ; c'est arti qui se fige avant. |
| Transport — plan de contrôle | **arti** — service onion Tor v3 (`arti-client`, feature `onion-service-service`) | Le seul des trois candidats qui ne trahit pas l'objectif métadonnées. Supprime aussi entièrement le problème du NAT, y compris en 4G/CGNAT. Porte la découverte, l'authentification, la présence et **tout le texte**. ✅ Vérifié le 2026-08-01 entre macOS et Linux, sur le même réseau **et** via un partage de connexion 5G — donc deux NAT et deux FAI différents. |
| Transport — plan de données | **`quinn`** (QUIC brut), à la demande, **v2** | Pour les fichiers et images uniquement. Les candidats s'échangent par le canal Tor déjà authentifié, puis connexion directe à pleine vitesse. Échec ⇒ repli sur Tor, lent mais fonctionnel. |
| Annuaire identifiant → adresse | **Annuaire distribué de Tor (HSDir)** | Résout la dernière inconnue technique du brainstorm sans rien héberger. Les descripteurs v3 sont chiffrés en aveugle : un répertoire ne peut pas énumérer les services qu'il relaie. |
| Identité | **Clé ed25519 = adresse `.onion` v3**, graine de 32 octets possédée par murmure, déposée dans le keystore arti (`ArtiNativeKeystore`) | L'exigence « identifiant dérivé de la clé, inusurpable » n'est pas à implémenter : c'est la définition de l'adresse onion v3. ✅ Tranché le 2026-07-31 : murmure **fournit** sa clé à arti via `launch_onion_service_with_hsid`, il ne la lit pas. Voir « La propriété de la clé d'identité — tranchée ». |
| Authentification du correspondant | **Restricted discovery** (Arti ≥ 1.7.0), clés client **x25519** | Un service onion authentifie le serveur mais pas le client. La restricted discovery restreint jusqu'à la *récupération du descripteur* aux seuls contacts autorisés : « entre amis uniquement » devient une propriété du transport. |
| Intégrité des transferts | ~~`bao-tree`~~ → **BLAKE3 du fichier entier** | ❌ **Renversé le 2026-08-01, en écrivant `files.rs`.** Le streaming vérifié défend contre une source qu'on n'a pas choisie ; ici le flux est un circuit onion déjà chiffré et authentifié, et le pair est authentifié par l'adresse `.onion` comparée à l'oral. Un expéditeur qui voudrait envoyer de mauvais octets proposerait simplement un autre fichier. Ce qu'il fallait vraiment, c'est l'intégrité contre la corruption et une **identité de transfert** pour reprendre au bon endroit : un hash du fichier entier donne les deux, sans dépendance supplémentaire. Le fichier partiel est nommé d'après ce hash, ce qui rend structurellement impossible de recoller deux fichiers différents. Raisonnement complet en tête de `src/files.rs`. |
| Chiffrement du canal | **Aucune couche ajoutée** — celui de Tor (ntor v3) | Décision délibérée. Empiler du Noise sur un circuit onion ajoute une surface d'erreur sans gain : la crypto maison est exclue, et une composition maison de primitives auditées en est une forme. |
| Stockage local | **Fichiers chiffrés `chacha20poly1305`**, pas de SGBD | Carnet de moins de dix contacts et un historique par conversation. SQLite serait une dépendance pour ce qu'un fichier scellé fait. |
| Hébergement | **Aucun** — le réseau Tor, 0 €/mois définitivement | Contrainte dure. Aucun serveur opéré, aucun compte, aucune facture possible. |
| Distribution | Binaire unique **et** `cargo install` | Rust rend l'arbitrage sans objet : les deux sortent de la même compilation. |

---

## Stack summary

État réel du `Cargo.toml` au 2026-08-01. Chaque dépendance y porte le
commentaire qui dit pourquoi elle est là — ce tableau n'en est que l'index.

| Couche | Crate / techno | Version réelle |
| --- | --- | --- |
| Transport contrôle & annuaire | `arti-client` (features `onion-service-service`, `onion-service-client`, `experimental-api`, `restricted-discovery`, `static-sqlite`, `rustls`) | **=0.44.0**, épinglé |
| Crates arti nommées directement | `tor-hsservice`, `tor-hscrypto`, `tor-llcrypto`, `tor-keymgr`, `tor-cell`, `tor-rtcompat` | **=0.44.0**, épinglées |
| Runtime async | `tokio` | 1.x, feature `full` |
| Interface terminal | `ratatui` + `crossterm` | ratatui **0.30.2** / crossterm **0.29** (`event-stream`) |
| Identité | ~~`ed25519-dalek`~~ → `tor-llcrypto` | Jamais ajoutée : arti réexporte déjà ed25519 et curve25519, et une seconde copie de dalek dans l'arbre voudrait dire deux types incompatibles pour la même clé. |
| Chiffrement au repos | `chacha20poly1305` | **0.11**, feature `zeroize` |
| Effacement mémoire | `zeroize` | 1.x — déjà tiré par arti, donc gratuit |
| Intégrité des fichiers | ~~`bao-tree`~~ → `blake3` seul | Voir la ligne « Intégrité des transferts » des décisions. |
| Presse-papiers | `data-encoding` | 2.x — base64 pour OSC 52, déjà tiré par arti |
| Sérialisation du protocole | `serde` + `postcard` | 1.x / 1.x |
| Journalisation | `tracing` + `tracing-subscriber`, `safelog` | vers un fichier, jamais stdout — la TUI possède l'écran |
| Transport données (v2) | `quinn` | **Pas encore ajouté.** v2 n'est pas commencée. |
| Compilateur | Rust stable | **≥ 1.91** (MSRV imposé par arti 0.44) |

> **`static-sqlite` n'était pas prévu et n'est pas optionnel.** `tor-dirmgr`
> cache le consensus dans SQLite ; sans cette feature, l'édition de liens
> échoue sous Windows (`LNK1181: cannot open sqlite3.lib`, il n'y a pas de
> SQLite système) et sur un Linux nu sans `libsqlite3-dev`. Coûte une minute
> de compilation C et achète une seule recette de build sur les trois OS.

> **`rustls` plutôt que `native-tls`**, pour une raison qui tient au projet et
> pas au confort : native-tls est schannel sous Windows, Security.framework
> sous macOS, OpenSSL sous Linux — donc le ClientHello TLS annonce le système
> d'exploitation. Pour un outil dont la raison d'être est que personne
> n'apprenne qui parle à qui, que la couche transport annonce spontanément ce
> qu'on fait tourner va à contresens. rustls fait que tous les murmure se
> ressemblent.

**Intégrations externes** : le réseau Tor, et rien d'autre. Aucun service payant, aucun compte
tiers, aucun serveur à opérer.

> ⚠️ **Épingler strictement les versions arti.** Les crates arti sont en `0.x` avec une cadence de
> publication **mensuelle** et des cassures d'API à chaque montée. Écrire `arti-client = "=0.44.0"`,
> pas `"0.44"`. Prévoir une demi-soirée de migration à chaque montée volontaire.

> ⚠️ **Coût de migration connu : `experimental-api`.** Le jalon keystore a forcé deux features
> supplémentaires sur `arti-client` — `onion-service-client` (indispensable pour composer une
> adresse `.onion`) et **`experimental-api`**, qui seule expose
> `launch_onion_service_with_hsid`. Une feature expérimentale n'offre aucune garantie de
> stabilité, même entre deux versions mineures : elle peut disparaître ou changer de signature à
> la prochaine montée. La dette est bornée à dessein — un seul appel, dans une seule fonction
> (`transport::tor::launch_with_identity`), documentée comme point de bascule vers la route B, qui
> n'utilise que de l'API stable (`ArtiNativeKeystore`, `KeyMgrBuilder`, `KeyMgr::insert`,
> `launch_onion_service`). À chaque montée d'arti : vérifier cet appel en premier.
>
> Ni l'une ni l'autre de ces features n'a ajouté de crate au graphe : `tor-hsclient` et
> `tor-hscrypto` étaient déjà résolus. Les features expérimentales d'arti sont de simples features
> cargo — aucun `RUSTFLAGS`, aucun `--cfg`, aucun `.cargo/config.toml`.

---

## Architecture

Tel que construit. En pointillés, ce qui est prévu et non écrit.

```mermaid
graph TD
    User([Utilisateur]) --> UI[ui — ratatui, souris, presse-papiers]
    UI --> Main[main — commandes, boucle d'inactivité]
    Main --> Contacts[contacts — carnet scellé]
    Main --> Chat[chat — une conversation à la fois]
    Chat --> Files[files — offre, hash, reprise, noms sûrs]
    Chat --> Proto[proto — trames longueur-préfixées]
    Proto --> TorPath[transport::tor — plan de contrôle, permanent]
    TorPath --> Arti[[arti-client]]
    Arti --> TorNet{{Réseau Tor}}
    Identity[identity — graine 32 o = adresse .onion] --> TorPath
    Identity --> Store
    Contacts --> Store[store — chacha20poly1305]
    Store --> Disk[(Fichiers scellés)]
    Files --> Incoming[(incoming/)]
    Proto -. v2 : échange de candidats .-> DirectPath
    DirectPath[transport::direct — v2, non écrit]:::todo -.-> Quinn[[quinn]]:::todo
    Quinn -.-> Net{{Connexion directe}}:::todo
    classDef todo stroke-dasharray: 5 5,color:#888
```

La frontière structurante passe entre `proto` et `transport`. `proto` ne connaît que des trames
sérialisées et un pair identifié ; `transport::tor` ne connaît que des octets et une adresse. La
frontière est donc bien là où elle était prévue — mais elle est tenue par la discipline des
signatures, pas par un trait. Voir « Folder structure ».

**Le plan de contrôle Tor est permanent et porte tout** : découverte, authentification, présence,
messages texte, et la négociation du plan de données. **Le plan de données direct est ouvert à la
demande, uniquement pour les fichiers**, puis refermé. Cette asymétrie est le cœur de
l'architecture : le prix de l'anonymat est payé là où il ne coûte rien (quelques centaines
d'octets par message) et évité là où il fait mal (des mégaoctets).

`identity` est la racine : la clé ed25519 produit l'adresse `.onion`, donc l'identifiant public.
Perdre la machine reste perdre l'identité, conformément à l'hypothèse posée au brainstorm.

### La propriété de la clé d'identité — tranchée

> ✅ **Réserve levée le 2026-07-31, en code et en exécution.** Le programme **peut** fournir sa
> propre clé ed25519 à arti. `identity` reste donc la racine de l'architecture telle qu'elle est
> dessinée ci-dessus : murmure possède la graine, arti n'en est que le consommateur. La branche
> alternative — inverser la dépendance et *lire* la clé depuis le keystore — est abandonnée.

**L'API.** `TorClient::launch_onion_service_with_hsid(config, id_keypair: HsIdKeypair)`
(`arti-client-0.44.0/src/client.rs:1998`), derrière les features `onion-service-service` +
`experimental-api`. Elle appelle
`KeyMgr::insert::<HsIdKeypair>(kp, &HsIdKeypairSpecifier::new(nickname), KeystoreSelector::Primary, false)`
puis délègue à `launch_onion_service`. Le `false` est un `overwrite` : arti **refuse d'écraser**
une clé existante, exactement le comportement voulu.

**Pourquoi arti ne génère alors rien.** `tor_hsservice::maybe_generate_hsid`
(`tor-hsservice-0.44.0/src/lib.rs:586`) interroge d'abord `HsIdPublicKeySpecifier` et ne génère que
si la recherche est vide. `KeyMgr::get_from_store` (`tor-keymgr-0.44.0/src/mgr.rs:566-583`) se
rabat sur le spécificateur *keypair* quand la clé publique est absente. La clé insérée est donc
trouvée, et arti journalise `Using existing identity for service murmure` — vérifié à l'exécution.

**La chaîne de conversion**, entièrement dans les crates arti, sans code cryptographique maison :

```
[u8; 32] graine  ->  ed25519::Keypair  ->  ed25519::ExpandedKeypair  ->  HsIdKeypair
                                                                     ->  HsIdKey -> HsId (.onion)
```

`HsIdKeypair` est un newtype sur `ExpandedKeypair` (`tor-hscrypto-0.44.0/src/pk.rs:81`), et
`ExpandedKeypair: From<&ed25519::Keypair>` (`tor-llcrypto-0.44.0/src/pk/ed25519.rs:237`).

**La preuve retenue n'est pas une lecture de log** mais une comparaison d'octets : `identity.rs`
calcule l'adresse `.onion` localement à partir de la graine, sans jamais toucher au keystore, et le
programme avorte bruyamment si l'adresse publiée par arti en diffère.

**Route B, gardée en réserve.** Construire un
`ArtiNativeKeystore::from_path_and_mistrust(<state_dir>/keystore, permissions)` et un
`KeyMgrBuilder`, insérer sous `HsIdKeypairSpecifier`, puis appeler le `launch_onion_service`
non expérimental. arti-client construit son propre keystore exactement à `<state_dir>/keystore`
(`arti-client-0.44.0/src/client.rs:320-350`), les deux s'accordent donc sur le disque. Toute la
remise à niveau tient dans le corps d'une seule fonction, `transport::tor::launch_with_identity`.

**Un piège découvert à l'exécution.** `KeyMgr::insert` avec `overwrite = false` renvoie
`KeyAlreadyExists` dès que le keystore contient déjà une clé pour ce surnom — **y compris la
nôtre**, au second lancement. Ce n'est pas une erreur : `launch_with_identity` l'intercepte et
publie sur la clé stockée. C'est la comparaison d'octets, et elle seule, qui distingue « c'est bien
notre clé » de « quelqu'un d'autre occupe ce surnom ».

---

## Folder structure

Réel au 2026-08-01. Le plan d'origine est conservé dessous, avec ce qui l'a
démenti.

```
murmure/
├── Cargo.toml                  # une seule crate, versions arti épinglées avec "="
├── src/
│   ├── main.rs                 # commandes tapées, boucle d'inactivité, publication
│   ├── identity.rs             # graine 32 o, adresse .onion, clé de découverte
│   ├── transport/
│   │   ├── mod.rs              # pas de trait Transport — dit pourquoi (voir plus bas)
│   │   └── tor.rs              # arti : publie, autorise, appelle
│   ├── proto.rs                # trames longueur-préfixées : texte, offre, chunk, ping
│   ├── chat.rs                 # une conversation : clavier, réception, transfert
│   ├── contacts.rs             # carnet scellé, adresses + clés de découverte
│   ├── files.rs                # offre, hash, reprise, noms sûrs, nettoyage d'affichage
│   ├── store.rs                # scellement chacha20poly1305 sur disque
│   ├── onion.rs                # validation d'adresse et de clé, empreinte courte
│   └── ui.rs                   # ratatui : historique, saisie, souris, presse-papiers
└── aidd_docs/
    ├── INSTALL.md
    ├── arti-windows-hang.md    # rapport de bug amont, prêt à déposer
    └── brainstorm/
        └── 2026_07_30-messagerie-pair-a-pair-terminal.md
```

Trois écarts avec le plan, tous délibérés :

- **`ui/` n'a pas été éclaté en trois fichiers.** `ui.rs` tient dans un seul
  fichier et ne parle qu'à deux canaux ; le découper en `mod.rs` + `chat.rs` +
  `contacts.rs` aurait créé trois fichiers pour une seule boucle de rendu.
- **`history.rs` n'existe pas.** Rien n'est conservé entre deux lancements. Le
  mode scellé reste possible — `store.rs` est écrit pour ça et le carnet s'en
  sert déjà — mais tant que personne ne l'a demandé, ne rien écrire sur le
  disque est la meilleure propriété de confidentialité disponible, pas un
  manque.
- **`tests/loopback.rs` n'existe pas.** Les tests d'intégration réels vivent
  dans `chat.rs` : deux conversations sur un duplex en mémoire, qui réagissent
  à ce qui s'affiche à l'écran plutôt qu'à des frappes préprogrammées. Ils ont
  trouvé deux vraies bogues de concurrence qu'un aller-retour en boucle locale
  n'aurait pas vues.

**Et surtout : le trait `Transport` n'est pas écrit.** C'était « la seule
abstraction du projet » ; elle attend sa seconde implémentation pour exister.
Une interface à implémentation unique ne factorise rien, elle déplace
seulement le code d'un fichier à l'autre. `transport/mod.rs` porte cette
décision en toutes lettres pour que la prochaine lecture ne la prenne pas pour
un oubli.

---

## Feuille de route des transports

Le débit de Tor est sans conséquence pour du texte et pénible pour des fichiers. Plutôt que de
tout construire d'emblée, l'échelle se monte par paliers, chacun livrable.

| Étape | Contenu | Ce que ça couvre | Effort |
| --- | --- | --- | --- |
| **v1** | **Tor seul.** Texte fluide, fichiers lents mais fonctionnels. | Tout le monde, partout, y compris 4G et CGNAT. | Le gros du travail |
| **v2** | ✅ **Faite le 2026-08-02, mais pas comme prévu.** Le plan disait « repli **silencieux** » et automatique ; c'est corrigé. Un chemin direct qui s'active tout seul fait fuiter la relation sans que personne s'en aperçoive — les deux FAI voient ces deux IP s'échanger des données. Donc : `/send --direct` explicite, fichier par fichier, et c'est l'`/accept` du destinataire qui ouvre le port, après qu'on lui a dit ce que ça expose. Refuser la route sans refuser le fichier reste possible. | ⚠️ **En réalité : le réseau local, et rien d'autre.** Le plan annonçait « NAT full-cone, UPnP, redirection de port » ; rien de tout ça ne marche avec ce qui est écrit. `candidates()` n'annonce que des adresses privées — connaître son IP publique demanderait STUN ou un tiers, que la conception interdit — et le port est éphémère, donc il n'y a rien de fixe à rediriger. Un `--direct` distant retombe sur Tor à tous les coups. Rendre une redirection de port utilisable demanderait un port fixe **et** un moyen pour l'opérateur de déclarer son adresse publique. | Un week-end |
| **v3** | **Perçage de NAT** en ouverture simultanée temporisée. Réflexion d'adresse mutuelle : chacun renvoie par Tor l'adresse source qu'il a observée, à la manière d'ICE — aucun STUN, aucun tiers. | La majorité des NAT restrictifs. Jamais le NAT symétrique. | Là est la vraie difficulté |

Toute la complexité est concentrée en v3, et la v2 en est débarrassée. Ne pas la construire avant
d'avoir mesuré que le taux d'échec de la v2 gêne réellement.

**Ce qui rend ce montage possible sans aucun serveur** : le plan de contrôle Tor est déjà un canal
de signalisation authentifié entre les deux pairs. C'est précisément le service qu'un relais tiers
(iroh/n0, TURN, DERP) rend habituellement — donc l'ayant, on n'a plus besoin d'eux.

> **Rejeté explicitement** : auto-héberger un relais (`iroh-relay` sur une VPS) pour récupérer la
> découverte d'adresse publique. Cela réintroduit un serveur à opérer, un coût mensuel, et un point
> de panne unique — la contrainte que le projet existe pour supprimer.

> **Rejeté explicitement** : utiliser `iroh` avec `RelayMode::Disabled` comme plan de données. Une
> fois ses relais et sa découverte désactivés, il ne reste d'iroh que `iroh-blobs`, payé d'une
> seconde API en `0.x` posée sur une pile dont on neutralise la moitié des mécanismes. `bao-tree`
> seul donne la propriété recherchée — la vérification bloc par bloc — sans ce coût.
>
> ⚠️ **Le rejet d'iroh tient toujours, mais son argument de repli est tombé** : `bao-tree` a été
> écarté à son tour en écrivant `files.rs` (voir les décisions). La propriété « vérification bloc
> par bloc » s'est révélée ne pas être celle dont murmure avait besoin — ce qu'il fallait, c'était
> une identité de transfert pour la reprise. iroh reste écarté sur son motif d'origine, qui est de
> conception et non technique : le relais observe qui parle à qui.

---

## Install steps

Installation manuelle — ce document ne génère aucun fichier.

1. **Installer Rust ≥ 1.91** : `rustup toolchain install stable && rustup default stable`, puis
   vérifier avec `rustc --version` (arti 0.44 impose 1.91 en MSRV).
2. **Initialiser la crate** : `cargo init murmure --bin` à la racine du dépôt existant.
3. ~~**Ajouter les dépendances**~~ — la liste réelle a divergé de celle-ci ; voir « Stack summary »,
   ou plus simplement le `Cargo.toml`, qui porte le pourquoi de chaque ligne. Ce qui reste vrai :
   **épingler arti à l'exact** (`=0.44.0`, pas `0.44`).
4. **Vérifier que la compilation passe sur les trois OS visés** avant d'écrire la moindre ligne de
   logique. arti tire une chaîne de dépendances conséquente ; découvrir un problème de
   compilation Windows après trois soirées de code coûte cher. À noter : docs.rs signale un échec
   de build pour `arti-client` 0.44.0 (0.43.0 est la dernière version qui y compile) —
   vraisemblablement un artefact de leur bac à sable, mais à confirmer par un `cargo build` local.
5. ~~**Trancher la question du keystore.**~~ ✅ Fait le 2026-07-31 : le programme fournit sa propre
   clé, `identity.rs` est bien la racine de l'architecture. Voir « La propriété de la clé
   d'identité — tranchée ».
6. ~~**Premier jalon exécutable.**~~ ✅ Franchi le 2026-07-31. `cargo run` publie le service onion
   sous une clé générée par murmure, affiche l'adresse `.onion`, et un second `TorClient` sur la
   même machine s'y connecte et reçoit son écho. Environ 9 s à froid sur un état déjà amorcé,
   23 s sur une machine vierge. Plan et critères d'acceptation :
   `aidd_docs/tasks/2026_07/2026_07_31-keystore-onion-milestone.md`.
7. ~~**Second jalon**~~ ✅ **Franchi le 2026-08-01.** Le critère de réussite du brainstorm est
   atteint : deux machines (macOS et Linux), comparaison d'empreinte à l'oral, messages, puis un
   fichier avec accord explicite du destinataire et reprise après coupure. Vérifié sur le même
   réseau **et** via un partage de connexion 5G, donc deux NAT et deux FAI. La restricted
   discovery a été validée dans la foulée : le service se reconfigure à chaud au premier `/add`,
   sans redémarrage.

**Pour installer et utiliser murmure, ce document n'est plus le bon endroit** :
`README.md` pour l'usage, `POUR-TON-POTE.md` pour une installation pas à pas
depuis le bundle git. Les étapes ci-dessus sont conservées comme trace de
l'ordre dans lequel le projet a été monté.

### Ce que la v1 livre réellement

- Service onion v3 sous une clé possédée par murmure, adresse vérifiée par
  comparaison d'octets contre la graine.
- **Restricted discovery** : sans contact, le service est visible de qui a
  l'adresse ; au premier `/add`, le descripteur devient illisible pour tout
  autre que les contacts autorisés. Bascule à chaud.
- Conversation texte, un appel à la fois, avec empreinte courte à comparer.
- **Transfert de fichier** avec accord explicite du destinataire, reprise après
  coupure indexée par le hash, et vérification avant de donner son vrai nom au
  fichier.
- TUI : historique défilable, glisser-déposer, `Ctrl-V`, sélection souris avec
  copie au relâchement, `/copy` par OSC 52.

### Posture de sécurité, au-delà du transport

Trois défenses qui ne figuraient pas au plan et qu'il a fallu écrire :

- **Le nom de fichier d'un pair est une frontière de confiance.** Il devient un
  chemin sur le disque, donc `files::safe_name` jette tout composant de chemin
  et refuse les caractères de contrôle et les surcharges bidi Unicode — un
  `U+202E` fait lire `innocentexe.png` à ce qui reste un exécutable.
- **Le texte d'un pair aussi.** Il part vers un terminal, qui obéit aux
  séquences d'échappement : un ESC brut permet d'écraser le presse-papiers
  d'en face via OSC 52. Nettoyé par `files::sanitize_for_display`.
- **La graine et les clés dérivées s'effacent à la libération** (`zeroize`),
  y compris le carnet déchiffré, qui est le graphe social en clair.

Aucune de ces trois n'était visible depuis le plan : elles viennent d'un audit
mené une fois le code écrit.

---

## Audit summary

Résultat de l'audit mené à l'action 03.

| Candidat | Verdict | Note |
| --- | --- | --- |
| **A. iroh** (QUIC + hole punching + relais n0) | ⚠️ | `iroh-blobs` offre le transfert reprenable, mais le relais observe qui parle à qui — la métadonnée même que le projet existe pour cacher — et il est opéré par une société. |
| **B. rust-libp2p** (Noise + Kademlia + DCUtR) | ❌ | Une DHT à moins de dix nœuds ne fonctionne pas ; se rabattre sur la DHT publique IPFS publie le graphe social dans un annuaire mondial que des crawlers moissonnent et republient. |
| **C. arti / onion v3** | ⚠️ | **Retenu.** Tient l'objectif métadonnées, supprime l'inconnue de l'annuaire, annule le problème du NAT — au prix d'une latence de décrochage et d'un débit bien plus lourds qu'estimé initialement. Aucun bloqueur. |

**Périmètre de l'audit, honnêtement** : les candidats B et C ont fait l'objet d'un audit
indépendant mené par un agent, sources à l'appui. Le verdict A repose sur un jugement direct, non
audité — sans conséquence, puisque A est écarté sur un critère de conception (le relais observe le
graphe social) et non sur un point technique contestable.

Le verdict de C est passé de ✅ à ⚠️ après audit : les réserves sont réelles et chiffrées ci-dessous,
mais aucune n'est rédhibitoire, et le choix reste le seul des trois compatible avec la raison d'être
du projet.

### Ce que le NAT devient avec un service onion

Point de conception qui mérite d'être explicite, car il est contre-intuitif : **un service onion
n'accepte jamais de connexion entrante**. Le service ouvre des circuits *sortants* vers ses points
d'introduction, publie son descripteur *sortant*, et rejoint son correspondant sur un point de
rendez-vous que les deux atteignent *en sortant*. Les deux moitiés se rejoignent au milieu.

Conséquence : CGNAT, NAT symétrique, 4G/5G, wifi public, réseau d'entreprise — si du TCP sortant
passe, murmure passe. Le risque « le chemin direct ne marchera pas pour tout le monde » du
brainstorm disparaît, ainsi que tout besoin de traversée NAT, de hole punching et de relais de
secours. Seul un réseau bloquant Tor lui-même par inspection de paquets pose problème : le recours
est les bridges et les transports enfichables, qui se configurent manuellement.

### Ce que le choix C coûte, chiffré

Ces chiffres viennent de l'audit du 2026-07-31 et **corrigent une estimation initiale trop
optimiste** (1 à 3 s annoncés à tort). Ils pèsent sur le **plan de contrôle** ; le plan de données
direct (v2) les contourne pour les fichiers.

- **Décrochage : 7 à 50 s, 13 à 20 s en moyenne** (PETS 2025). Le circuit fait six relais — trois
  côté client, trois côté service, rendez-vous compris. C'est le coût d'ouverture d'une
  conversation, **pas** celui d'un message : une fois le circuit établi, les messages passent en
  sous-seconde. Le modèle « coup de fil » tient, mais la sonnerie est longue et la TUI doit
  l'afficher franchement plutôt que de paraître figée.
- **Débit : 0,1 à 0,25 Mo/s**, plafond ~0,5 dans les bonnes conditions. Le trafic onion-vers-onion
  souffre d'un contrôle de congestion moins abouti que le reste du réseau. Une photo de 5 Mo prend
  une minute, un fichier de 100 Mo prend une heure. En contrepartie, ce trafic ne traverse aucun
  nœud de sortie : il ne consomme pas la ressource rare et contestée de Tor, l'usage est légitime.
  **À relativiser** : un message texte fait quelques centaines d'octets, donc ce débit en fait
  passer plus d'un millier par seconde. La messagerie n'est pas bridée — seuls les fichiers le
  sont, et c'est ce que le plan de données direct (v2) vient corriger.
- **Circuits recyclables.** Tor applique ses propres politiques d'expiration et de rotation.
  Concevoir pour des reconnexions fréquentes, jamais pour un canal permanent. Combiné au débit
  ci-dessus, cela rend la reprise de transfert **structurellement obligatoire** — un transfert de
  quelques dizaines de Mo a de bonnes chances d'être interrompu au moins une fois.
- **Présence : aucun ping bon marché n'existe.** Savoir si un contact est joignable exige un
  circuit complet, donc 7 à 50 s par contact. L'« indicateur de présence dès la v1 » du brainstorm
  est bien plus cher que supposé. Piste : ne montrer la présence que pour les conversations déjà
  ouvertes (heartbeat applicatif sur circuit établi, gratuit), et remplacer le reste par une action
  « appeler » explicite. À trancher au design.
- **Premier contact plus lourd que prévu.** L'identifiant à échanger n'est pas seulement l'adresse
  `.onion` : la restricted discovery ajoute une clé client **x25519**, et l'échange est
  **asymétrique** — chacun doit inscrire la clé de l'autre dans ses `authorized_clients`. À
  vérifier que le tout reste comparable à l'oral sous forme d'empreinte courte.
- **Un seul chemin réseau en v1.** L'échelle direct → assisté → relayé du brainstorm devient une
  v2. Si Tor est bloqué sur le réseau de l'utilisateur, il faut passer par des bridges.

### Les deux pièges qui coûteront une soirée

Le piège historique numéro 1 — l'import d'une clé ed25519 personnalisée dans le keystore arti — est
levé depuis le 2026-07-31 ; il a coûté une soirée, comme prévu. Restent :

1. **L'absence de mécanisme de présence bon marché** — à budgéter dans l'UX de la TUI dès le
   départ, pas en rustine.
2. **Le débit combiné aux circuits recyclables** — la segmentation et la reprise doivent être dans
   la conception initiale de `files.rs`.

### Ce qui reste ouvert après ce document

- ~~**La reprise de transfert entre sessions**~~ ✅ **Résolu le 2026-08-01**, et sans le mécanisme
  prévu. Pas de journal d'état, pas de liste de blocs reçus : le fichier partiel est **nommé
  d'après le hash BLAKE3 du fichier entier**, avec l'extension `.part`. Sa taille *est* l'état de
  reprise, et un partiel portant un hash donné ne peut être qu'un préfixe du fichier qui a ce
  hash — donc recoller deux fichiers différents est structurellement impossible plutôt
  qu'interdit par une vérification. Rien à noter, rien à nettoyer, rien à corrompre.

- ⚠️ **Windows ne fonctionne pas.** arti se fige pendant le téléchargement du premier consensus,
  un cœur à 100 %, sur **deux machines et deux réseaux indépendants**, avec le CLI `arti` seul
  comme avec `arti-client` embarqué. Sept hypothèses éliminées avec preuves (réseau, horloge, TLS,
  compression, code applicatif, blocage de verrou, contrôle de congestion #2651). Cause racine non
  trouvée : il faudrait attacher un débogueur natif pour voir quel fil tourne en boucle. Rapport
  amont rédigé et prêt à déposer — `aidd_docs/arti-windows-hang.md`. En attendant, murmure est
  macOS et Linux.
- **Le réglage du coût de la présence**, désormais chiffré comme le vrai problème d'UX du projet.
  Complication découverte au jalon keystore : `OnionServiceStatus::state()` **n'est pas un oracle
  de joignabilité**. L'état agrégé reste `Bootstrapping` dès que l'un des deux composants (gestion
  des points d'introduction, publication du descripteur) l'est encore
  (`tor-hsservice-0.44.0/src/status.rs:232`), et aucun accesseur public ne donne le détail par
  composant. Observé en conditions réelles : le descripteur est publié, le service répond aux
  connexions, et le statut annonce toujours `Bootstrapping`. **Ne pas brancher un indicateur de
  présence dessus** — il sous-déclare. La seule preuve de joignabilité est une connexion réussie,
  ce qui renchérit encore le coût de la présence.
- ~~**La forme de l'identifiant échangé au premier contact**~~ ✅ **Réglé, et l'asymétrie
  redoutée n'a pas eu lieu.** murmure dérive **une seule** clé de découverte de sa graine et la
  présente à tout le monde, au lieu d'une paire par service à joindre. L'échange redevient donc
  symétrique et en un coup : chacun donne `<adresse> <clé>` une fois, `/copy` met les deux dans le
  presse-papiers dans l'ordre où `/add` les attend. L'empreinte courte reste celle de l'adresse
  seule, donc toujours comparable à l'oral. Coût accepté : deux contacts qui comparent leurs
  notes voient la même clé publique et en déduisent qu'ils parlent à la même personne — ils
  détiennent déjà tous deux la même adresse `.onion`, qui le dit plus directement. Raisonnement
  complet sur `Identity::discovery_secret`.
- **Les vanguards ne sont pas activés.** La feature `vanguards` d'`arti-client` est absente de
  `Cargo.toml`. Sans elle, les chemins du service onion sont plus exposés à l'énumération des
  points d'introduction que ce qu'une mise en production demanderait. Hors périmètre du jalon
  keystore ; à trancher avant le second jalon (deux machines, deux villes).
- **Le coût de migration de `experimental-api`.** Voir la note de la section Stack summary.

---

## Sources

- [Arti 1.2.0 — `onion-service-service` rendu non-expérimental](https://blog.torproject.org/arti_1_2_0_released/)
- [Arti 1.7.0 — stabilisation de la restricted discovery](https://blog.torproject.org/arti_1_7_0_released/)
- [`arti-client` sur crates.io](https://crates.io/crates/arti-client)
- [`tor-hsservice` — implémentation côté service du protocole onion](https://docs.rs/tor-hsservice/latest/tor_hsservice/)
- [`tor_keymgr` — gestion des clés et keystore](https://tpo.pages.torproject.net/core/doc/rust/tor_keymgr/index.html)
- [PETS 2025 — Improving the Performance and Security of Tor's Onion Services](https://petsymposium.org/popets/2025/popets-2025-0029.pdf) (chiffres de latence)
- [Tor Metrics — OnionPerf latencies](https://metrics.torproject.org/onionperf-latencies.html)
- [`ratatui`](https://crates.io/crates/ratatui) · [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) · [`zeroize`](https://crates.io/crates/zeroize)
- [OSC 52 — écriture du presse-papiers par séquence d'échappement](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html)
- [Unicode UAX #9 — algorithme bidirectionnel](https://www.unicode.org/reports/tr9/) (les caractères refusés dans les noms de fichiers)
