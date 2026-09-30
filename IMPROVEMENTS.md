# Feuille de Route et Améliorations Futures — Murmure

Ce document rassemble l'ensemble des pistes d'amélioration, des axes de recherche et des évolutions techniques identifiés lors des audits de sécurité, des revues d'architecture et des retours d'expérience sur le projet **Murmure**.

---

## 1. Sécurité & Cryptographie Avancée

### 🔐 A. Couche E2E Applicative avec Ratchet (PFS au niveau message) — ✅ DONE (2026-09-29)
- **Constat actuel :** La confidentialité reposait sur le circuit de transport Tor (ou le flux TLS 1.3 de QUIC) seul, avec une clé fixe dérivée de la graine.
- **Amélioration :** Intégrer un protocole cryptographique de bout en bout avec renouvellement continu des clés au niveau message. Choix retenu après discussion : **Double Ratchet** (spec Signal) plutôt que Noise_IK, parce que Noise_IK ne fait qu'un DH par session — une compromission de la graine pendant un appel actif déchiffrerait tout ce qui suit sous cette session, ce qui ne satisfait pas l'exigence de post-compromise security demandée ici.
- **Bénéfice :** Garantit une *Perfect Forward Secrecy* (PFS) et une *Post-Compromise Security* même en cas de compromission ultérieure de la graine d'identité ou d'inspection mémoire.
- **Fait (étape 1/3, 2026-08-30) :** l'accord de clé initial. Chaque `proto::handshake` génère maintenant une paire X25519 fraîche par connexion (jamais écrite sur disque, jamais dérivée de la graine), échangée dans le HELLO et **liée à la signature Ed25519** — le challenge signé devient `AUTH_CONTEXT || signer || verifier || nonce || clé_éphémère_du_signataire` au lieu de juste `AUTH_CONTEXT || signer || verifier || nonce`. Ça ferme la faille MITM identifiée en examinant 3A (un attaquant actif ne peut plus accepter la preuve d'identité tout en substituant sa propre clé DH, puisque la signature couvre maintenant les deux). Le secret partagé DH devient la racine du ratchet via `blake3::derive_key`. `VERSION` passe à 6 → 7 (rupture de compatibilité assumée, comme pour toute évolution de `Message`/du handshake dans ce projet).
  - Fichiers : `src/proto.rs` (`HELLO_LEN` 73→105 octets, `handshake()` retourne maintenant `(HsId, Zeroizing<[u8;32]>)`, `challenge()` prend un 4ᵉ paramètre), `src/link.rs`, `src/chat.rs` (appelants mis à jour).
  - Tests : nouveau test `both_sides_derive_the_same_root_key_and_a_fresh_one_next_time` (les deux côtés dérivent la même clé racine ; deux handshakes successifs entre les mêmes identités donnent des clés différentes). Suite complète (167 tests) verte, `cargo clippy --all-targets -- -D warnings` propre.
- **Fait (étapes 2/3 et 3/3, 2026-09-29) :** `src/ratchet.rs`, Double Ratchet (spec Signal) : une clé par trame (KDF_CK en BLAKE3 keyed), un ratchet DH à chaque changement de sens (KDF_RK en BLAKE3 derive_key + XOF), ChaCha20-Poly1305 avec l'en-tête `clé DH || pn || n` en données associées. L'appelant joue Alice et fait un pas DH immédiat ; le répondant peut parler en premier sur une chaîne dérivée de la racine. `Link` scelle chaque trame (`proto::write_sealed` / `read_sealed`), le ratchet étant partagé entre les tâches d'écriture et de lecture. Les keepalives dans les deux sens font tourner le ratchet DH environ chaque minute sur une connexion ouverte. `VERSION` 8 → 9.
  - **Écart assumé avec le plan :** pas de table de clés sautées. Un ratchet vit sur un seul flux Tor, ordonné et sans perte ; une trame est la suivante attendue ou la connexion est cassée (et la suivante repart d'un handshake neuf). Moins de code, et rien qu'un pair hostile puisse remplir. À revoir si des trames peuvent un jour arriver par deux chemins.
  - Tests : 6 dans `ratchet` (aller-retour quel que soit qui parle en premier, trames croisées, clé différente par trame, rotation DH à la réponse, rejeu/trou/altération d'en-tête ou de corps refusés, inconnu incapable de lire) ; le test d'accord du handshake vérifie maintenant que les deux ratchets interopèrent et qu'un second handshake ne peut pas lire le premier. 177 tests verts, test Tor réel vert.

### 🔑 B. Dérivation et Séparation Stricte des Sous-Clés Cryptographiques — ⏭️ SKIPPED
- **Constat actuel :** La clé Ed25519 de l'Onion Service v3 (`HsId`) est également utilisée pour signer le défi d'authentification applicatif (`proto::handshake`).
- **Amélioration :** Dériver une sous-clé Ed25519 dédiée à l'authentification applicative via BLAKE3 KDF (`"murmure 2026 handshake auth"`).
- **Bénéfice :** Respecte le principe fondamental de séparation des clés cryptographiques par usage.
- **Pourquoi non appliqué (2026-08-30) :** l'architecture actuelle fait de l'adresse `.onion` la clé publique elle-même (`src/identity.rs:248-250`), et `proto::handshake` vérifie la signature *directement contre cette adresse* — un choix documenté et délibéré ("no certificate, no third party and no new key", `src/proto.rs:80-82`). Passer à une sous-clé casse cette propriété : le vérifieur ne connaît que l'`.onion` du pair, pas sa sous-clé, donc il faudrait un certificat sur le fil (la clé maître signe la sous-clé), une étape de vérification en plus, et un bump de version protocole (`VERSION` dans `src/proto.rs`). Ce n'est pas un petit patch mais une mini-PKI ajoutée à un design qui n'en veut pas. Le gain de sécurité est marginal ici : une fuite de la seed compromet tout de toute façon, sous-clé ou pas.

### 🛡️ C. Protection de la Graine au Repos par Passphrase (KDF Argon2id) — ✅ DONE (2026-08-30)
- **Constat actuel :** La graine d'identité (`identity.seed`) est stockée en clair sur le disque avec des permissions `0600`.
- **Amélioration :** Proposer en option le chiffrement de `identity.seed` par un mot de passe utilisateur via **Argon2id** (ou scrypt/PBKDF2) au lancement.
- **Bénéfice :** Empêche l'extraction immédiate de l'identité en cas d'accès physique ou de saisie du disque machine éteinte (sans chiffrement FDE).
- **Fait :** `src/identity.rs` — format opt-in : `MURM1E` (magic 6 octets) + sel 16 octets + `XChaCha20-Poly1305` (réutilise `store::seal`/`open`) sur la graine, clé dérivée par Argon2id (`argon2` crate, `Argon2::default()`, `hash_password_into`). Détection automatique au chargement (`is_encrypted`) : fichier brut de 32 octets → comportement inchangé, fichier avec le magic → prompt de passphrase (`rpassword`, pas d'écho terminal) ou `MURMURE_SEED_PASSPHRASE` en variable d'env pour l'automatisation/tests. Deux commandes utilitaires, dans le style env-var du projet (`MURMURE_DIR`, `MURMURE_INCOMING_QUOTA`) puisqu'il n'y a pas de parseur d'arguments ici : `MURMURE_ENCRYPT_IDENTITY=1 murmure` chiffre une graine existante (confirmation de la passphrase par double saisie), `MURMURE_DECRYPT_IDENTITY=1 murmure` la ramène en clair. Les deux s'exécutent avant Tor/la TUI et quittent aussitôt. Refuse de chiffrer un fichier déjà chiffré (renvoie vers la commande de déchiffrement d'abord) et de déchiffrer un fichier déjà en clair.
- **Format v2 (2026-09-30) :** `MURM2E` + coût Argon2id écrit dans le fichier (`m`, `t`, `p` en u32 LE : 64 MiB, 3 passes, 1 voie) + sel + scellé. Un fichier `MURM1E` (coût par défaut d'argon2 : 19 MiB, t=2) s'ouvre toujours et est réécrit en v2 au chargement suivant, là où la passphrase est saisie. Un coût hors bornes est refusé avant de lancer Argon2.
- **Testé :** 4 tests unitaires (`identity::test::encrypted_seed_bytes_round_trip_under_the_right_passphrase`, `a_wrong_passphrase_cannot_open_an_encrypted_seed`, `a_plain_seed_file_is_not_mistaken_for_an_encrypted_one`, `encrypt_then_decrypt_at_rest_round_trips_through_disk`), suite complète 157/158 verte (1 ignoré), clippy `--all-targets -D warnings` propre. Vérifié aussi avec le vrai binaire (chiffrement, refus sur mauvaise passphrase, déchiffrement, garde double-chiffrement) — sha256 de la graine identique avant/après l'aller-retour.

### ⏱️ D. Jitter Aléatoire sur les Keepalives de Présence (Anti-Analyse de Trafic) — ✅ DONE (2026-08-30)
- **Constat actuel :** Les paquets `Ping` de présence sont envoyés toutes les 60 secondes fixes sur le circuit Tor.
- **Amélioration :** Introduire une variation aléatoire (*jitter* entre 45s et 75s) et du faux trafic optionnel (*padding*).
- **Bénéfice :** Réduit la signature temporelle identifiable par un nœud de garde Tor ou un FAI observant la connexion.
- **Fait :** `src/link.rs` — nouveau `JITTER = 15s` à côté de `KEEPALIVE = 60s` ; `keepalive_delay()` tire un délai uniforme dans `[45s, 75s)` à chaque battement. `tokio::time::interval` (grille fixe) remplacé par `tokio::time::sleep` par itération, sinon le jitter n'aurait aucun effet. Padding optionnel non fait — hors scope, pas demandé. Tests `link::tests::*` (8/8) verts, `cargo build` propre.

### 💾 E. Quota de Stockage et Gestion des Fichiers Entrants — ✅ DONE (2026-08-30)
- **Amélioration :** Implémenter une limite de taille globale configurable pour le répertoire `.murmure/incoming/` et alerter l'utilisateur avant acceptation de gros fichiers si l'espace disque restant est insuffisant.
- **Fait :** `src/files.rs` — `incoming_quota()` lit `MURMURE_INCOMING_QUOTA` (octets, défaut 10 GiB dans `DEFAULT_INCOMING_QUOTA`) ; `dir_size()` totalise les octets déjà présents dans `incoming/`. `src/chat.rs::accept()` refuse (`bail!`) avant d'ouvrir tout fichier, sur les deux chemins (Tor et direct), si `used + remaining > quota`. Testé : `files::tests::dir_size_*`, `files::tests::quota_*`, suite complète 148/148 verte, clippy propre.
- **Non fait (scope réduit, volontaire) :** pas de vérification de l'espace disque réel de l'OS (`statvfs`/`GetDiskFreeSpaceEx`) — demanderait une nouvelle dépendance pour un gain marginal vu qu'un quota sur `incoming/` couvre déjà le risque principal (un pair qui remplit le disque). Voir le commentaire `ponytail:` dans `dir_size()`.

---

## 2. Compatibilité & Support Plateformes (Windows)

### 🪟 A. Déblocage du Support Windows via Démon Tor Externe — ⏭️ SKIPPED (2026-09-29) : plus nécessaire, la cause du blocage est trouvée et corrigée (voir 2B).
- **Constat actuel :** L'amorçage d'Arti (`arti-client`) se fige en boucle CPU lors du téléchargement du consensus sous Windows (`aidd_docs/arti-windows-hang.md`).
- **Amélioration :** 
  - Ajouter un backend optionnel dans `src/transport/tor.rs` capable de communiquer avec un binaire `tor.exe` local (Tor C / Tor Expert Bundle) via son port de contrôle (`ControlPort` / commande `ADD_ONION`).
  - Permet d'offrir un binaire Windows pleinement fonctionnel immédiatement sans dépendre de la résolution du bug amont d'Arti.

### 🐛 B. Suivi et Contribution au Bug Amont Arti — 🟡 PARTIEL (2026-09-29)
- **Fait :** cause trouvée depuis une session Claude sur une machine Windows : boucle infinie dans `saturating-time` 0.4.0 (dépendance de `tor-netdoc`/`tor-cert`), pas dans arti. Copie corrigée dans `patches/saturating-time` via `[patch.crates-io]` ; bootstrap Tor OK sous Windows en 12,9 s. Détails en tête de `aidd_docs/arti-windows-hang.md`.
- **Reste :** ~~signaler le bug à arti~~ déjà signalé par d'autres (arti#2678, arti#2726 avec un correctif) ; retirer notre copie dès qu'une release d'arti embarque la correction. Contexte du signalement envisagé : signaler le bug à arti (gitlab.torproject.org/tpo/core/arti) : saturating-time fait désormais partie du monorepo arti, le dépôt codeberg est archivé depuis le 2026-09-24, et `main` boucle toujours — décision de l'utilisateur. Puis un binaire Windows dans la release, et deux soucis de tests propres à Windows (séparateur de chemin dans un test UI, dials loopback QUIC intermittents).
- **Action :** Soumettre officiellement le rapport d'anomalie détaillé [`aidd_docs/arti-windows-hang.md`](file:///home/thibault-savenkoff/murmure/aidd_docs/arti-windows-hang.md) à l'équipe du Tor Project sur [gitlab.torproject.org/tpo/core/arti](https://gitlab.torproject.org/tpo/core/arti) et suivre l'avancement de l'intégration CI Windows (#450).

### 🐧 C. Documentation et Profil WSL 2 — ✅ DONE (2026-09-29)
- **Action :** Documenter pour les utilisateurs Windows actuels l'utilisation transparente et sans configuration de Murmure dans WSL 2 avec Windows Terminal.
- **Fait :** section « On Windows, through WSL 2 » du `README.md` : installation, lancer depuis le home Linux (sur `/mnt/c` le contrôle des permissions de `identity.seed` échoue), fichiers reçus via `\\wsl$`, presse-papier OK, `/view` non (Windows Terminal ne parle que Sixel), `networkingMode=mirrored` pour `/send --direct`, sinon repli sur Tor. Non testé sur une vraie machine Windows.

---

## 3. Réseau & Nouveaux Modes de Transport

### 🔌 A. Mode de Connexion Directe Hors-Tor (`/dial IP:PORT`) — ⏭️ SKIPPED
- **Principe :** Permettre d'établir une session sécurisée directe de machine à machine (ex: `murmure --dial 192.168.1.50:7777` ou sur IPv6 publique) en utilisant le moteur QUIC + TLS 1.3 avec épinglage de certificat (`src/transport/direct.rs`).
- **Cas d'usage :** Communication instantanée en réseau local (LAN), sur un VPN privé (WireGuard/Tailscale) ou en cas de coupure/censure totale du réseau Tor.
- **Pourquoi non appliqué (2026-08-30) :** investigation faite jusqu'au bout, ce n'est pas du câblage, c'est un changement de protocole. `proto::handshake` et `link::Link::open` sont bien génériques sur le transport (`AsyncRead + AsyncWrite`), donc à première vue il suffirait de brancher `transport/direct.rs` (QUIC) dessus au lieu de Tor. Mais le challenge signé pendant le handshake (`src/proto.rs:186-192`, fonction `challenge()`) ne contient que `AUTH_CONTEXT || signer || verifier || nonce` — rien qui lie la signature au canal TLS (pas de hash de certificat, pas d'exporter TLS). Sur Tor ce n'est pas un problème : l'adresse `.onion` *est* la clé, il n'y a personne à mettre au milieu. Sur IP brute, un attaquant sur le chemin peut terminer le TLS non épinglé, relayer le challenge/réponse tel quel vers le vrai pair, et ensuite lire/injecter tout le trafic — le MITM n'est pas empêché par l'authentification applicative telle qu'elle existe aujourd'hui. Faire cette feature correctement (comme demandé : "avec épinglage de certificat") veut dire soit lier la signature au canal (nouveau format de challenge, bump de `VERSION` — même famille de changement que 1B), soit dériver une paire de clés stable pour le certificat direct et la stocker dans le carnet de contacts à côté de l'adresse onion. Les deux sont un vrai chantier protocolaire, pas une soirée de câblage. Reporté, même famille que 1B/3B : périmètre trop large pour être fait "en même temps" que le reste du lot sans revue dédiée.

### 🤝 B. Transport P2P Alternatif avec Traversée NAT (Iroh / libp2p) — ⏭️ SKIPPED
- **Principe :** Réintroduire le *Chemin 2 (Assisté)* du brainstorm initial en intégrant une couche de transport basée sur **Iroh** (Rust, QUIC, STUN/DERP).
- **Bénéfice :** Connexions directes quasi-instantanées avec traversée automatique des box/NAT, en conservant l'adressage par clé publique Ed25519.
- **Pourquoi non appliqué (2026-08-30) :** même famille de conflit que 1B. Iroh route par défaut via des relais DERP publics et établit des chemins hors-Tor — exactement ce que le design du projet évite pour ne jamais exposer l'IP réelle d'un pair à un tiers ou à son interlocuteur. Ajouter Iroh, c'est ajouter un mode de fonctionnement qui affaiblit la propriété d'anonymat pour laquelle Murmure existe. Le transport direct QUIC déjà présent (`src/transport/direct.rs`, voir 3A) couvre le cas "connexion directe" sans ce compromis, à condition que les deux pairs se dévoilent leur IP volontairement (LAN/VPN).

### 🔄 C. Rotation Forcée des Descripteurs après Révocation (`/forget`) — 🟡 PARTIEL (2026-09-29)
- **Amélioration :** Forcer la rotation immédiate des points d'introduction et du descripteur de service caché lors de la suppression d'un contact (`/forget`), dès que l'API de rotation sera exposée par Arti.
- **Fait :** le handshake prouve l'identité de l'appelant, donc un contact oublié qui garde une copie du descripteur est refusé dès la connexion (`Contacts::admits`, tant que le carnet n'est pas vide). Il ne peut plus parler, laisser de message ni proposer de fichier.
- **Reste :** la rotation elle-même. arti 0.46 n'a toujours pas d'API pour forcer de nouveaux points d'introduction, donc un contact oublié peut encore savoir si on est en ligne jusqu'à la rotation naturelle.

---

## 4. Fonctionnalités & Expérience Utilisateur (UI/UX)

### 🖼️ A. Rendu d'Images en Mode Texte dans le Terminal — 🟡 PARTIEL (2026-08-30)
- **Principe :** Exploiter les protocoles graphiques modernes de terminaux (**Kitty Graphics Protocol**, **Sixel**, **iTerm2 inline images**) pour afficher les images reçues directement dans la fenêtre de conversation (pour les terminaux compatibles comme Kitty, WezTerm, Ghostty, iTerm2).
- **Fait :** Kitty Graphics Protocol (+ WezTerm/Ghostty qui le copient) et iTerm2 inline images — ✅. Nouvelle commande `/view <path>` (`src/main.rs`) : détection du protocole par variables d'environnement (`src/image.rs::supported()`), lecture du fichier, encodage en séquence d'échappement, envoyée à la TUI via un nouveau `Update::ShowImage` (`src/ui.rs`). Pas d'affichage automatique à la réception : la TUI de murmure (ratatui) redessine chaque cellule depuis un buffer à chaque frame, une séquence d'échappement collée dans une ligne de transcript serait dessinée comme du texte littéral, pas interprétée par le terminal. `/view` quitte donc l'écran alternatif, écrit les octets bruts, attend une touche, puis revient (`show_image_blocking`) — testé en conditions réelles dans tmux avec `KITTY_WINDOW_ID=1` : sortie propre de la TUI, prompt affiché, retour propre et redessin complet après la touche, aucun blocage ni corruption. Chemin d'erreur (extension non supportée, terminal non compatible) vérifié aussi.
- **Non fait (scope réduit, volontaire) :** **Sixel** — contrairement à Kitty/iTerm2 qui acceptent le fichier image tel quel (le terminal décode), Sixel exige que l'*émetteur* fournisse déjà un bitmap Sixel : il faudrait décoder les pixels, quantifier les couleurs et ré-encoder, ce qui veut dire ajouter une dépendance `image` (et un encodeur Sixel) pour un protocole minoritaire face à Kitty/iTerm2. Voir le commentaire `ponytail:` dans `src/image.rs`. Kitty lui-même n'accepte que du PNG brut ici (pas de JPEG/GIF sans décodage préalable) — même raison, même compromis documenté dans le code.
- **Testé :** 6 tests unitaires (`src/image.rs::tests::*` : extensions reconnues, encodage Kitty/iTerm2, refus d'un non-PNG sous Kitty, découpage en plusieurs morceaux pour un gros fichier), suite complète 166/167 verte (1 ignoré), clippy `--all-targets -D warnings` propre.

### 👥 B. Salons / Groupes Fermés Éphémères — ✅ DONE (2026-09-29)
- **Principe :** Permettre la création d'un salon éphémère à plusieurs pairs sans serveur, où chaque message est diffusé de manière chiffrée à tous les membres connectés du groupe (topologie maillée en étoile ou anneau).
- **Fait (texte) :** `src/room.rs` + `/room new|invite|join|decline|leave` (`src/main.rs`). Un seul mécanisme couvre les deux topologies : chaque ligne est signée par une clé Ed25519 propre au salon et numérotée, et chaque membre la retransmet une fois à ses liens du salon (dédup par `seq`). En étoile, l'hôte relaie entre membres qui ne sont pas contacts ; en maillage, les contacts se relient directement. Pas de clé de groupe : chiffrement = ratchet de chaque lien. Le roster ne contient que des clés de salon et des tags `BLAKE3(room_id, adresse)`, donc aucun membre n'apprend d'adresse qu'il n'avait pas. Un contact n'est nommé qu'après `RoomHello` sur son propre lien ; un roster contradictoire est signalé (`Event::Mismatch`). `VERSION` 11.
- **Fichiers (fait) :** `src/roomfiles.rs`, `/room send|files|get` et glisser-déposer dans un salon. Un fichier est annoncé comme une ligne signée (`RoomFile`, hash signé par l'auteur), rien ne bouge avant `/room get`. On demande (`RoomFetch`) à celui qui nous l'a annoncé : l'auteur en maillage, l'hôte en étoile. L'hôte relaie en stockant d'abord le fichier entier (dans `<run dir>/relay`, vidé à la fin du salon) puis en le servant : ça découple le lien lent du lien rapide et ne bloque jamais la boucle idle. Envoi en tâche de fond via `Pool::sender`. Vérification du hash signé à l'arrivée ; seul le pair à qui on a demandé peut envoyer les octets ; personne hors du salon n'est servi ; quota commun avec `incoming/`. `VERSION` 12.
- **Non fait :** salon qui survit au départ de l'hôte ; salon pendant un appel 1-à-1 (les trames du salon sur le lien de l'appel sont perdues) ; fichiers de salon hors Tor (QUIC direct).
- **Testé (fichiers) :** 4 tests `roomfiles::tests::*` (relais complet auteur → hôte → membre, octets substitués rejetés, octets d'un autre pair ignorés, hors-salon non servi) + `room::tests::a_file_is_announced_like_a_line_and_its_hash_cannot_be_swapped`. Live : 3 Mo en maillage (< 10 s), 2 Mo relayés par l'hôte en étoile (25 s), SHA-256 identiques, copie de relais effacée à la fin du salon.
- **Testé :** 10 tests `room::tests::*` (étoile, maillage sans doublon, relais qui modifie une ligne rejeté, rejeu ignoré, hors-salon ignoré, tags, hôte menteur détecté, départ hôte/membre, join non invité refusé), suite 189/190 verte, clippy propre. Test live (3 instances sur srv-tsa via Tor, 2026-09-29) : étoile (bob et carol se voient en `~empreinte`, l'hôte relaie), fin du salon au départ de l'hôte, maillage (bob et carol contacts : `~xxxx is carol`, ligne affichée une seule fois), départ d'un membre vu par les autres.

### 🔍 C. Recherche dans l'Historique — ✅ DONE (2026-08-30)
- **Principe :** Ajouter une commande `/search <terme>` permettant de filtrer rapidement les messages passés dans l'historique chiffré.
- **Fait :** `History::search()` dans `src/history.rs` — filtre insensible à la casse sur toutes les conversations, plafonné à `SHOWN` comme `/history`. Commande `/search <terme>` ajoutée dans `src/main.rs`, listée dans `/help`. Vérifié que `/search` tapé pendant un appel tombe sur `Typed::UnknownCommand` (`classify()`, `src/chat.rs`) et ne part jamais sur le fil comme message. Testé : `history::tests::search_finds_a_word_case_insensitively_across_conversations`, suite complète 149/150 verte (1 ignoré, réseau Tor réel), clippy propre.

### ⌨️ D. Ergonomie et Autocomplétion — ✅ DONE (2026-09-29)
- **Améliorations :**
  - Autocomplétion des commandes et des noms de contacts avec `Tab` — ✅ DONE.
  - Indicateur visuel d'état de synchronisation de l'Outbox — ✅ DONE (2026-09-29). Une ligne `/tell` finit par `[waiting]`, remplacé sur place par `[delivered]` quand le destinataire accuse réception de ce message précis (`Update::Delivered(id)`, id de l'outbox porté par la ligne). Pas d'état `[envoyé]` intermédiaire : poser une trame sur un lien ne prouve pas qu'elle est arrivée, seul l'accusé de réception le prouve. Test : `ui::tests::a_tell_turns_from_waiting_to_delivered`.
  - Thèmes de couleurs personnalisables pour l'interface TUI — ⏭️ SKIPPED : aucun besoin concret, les couleurs suivent déjà le thème du terminal.
- **Fait :** `src/ui.rs` — `App::complete()` : sur `Tab`, complète le mot courant (commande si premier mot commençant par `/`, sinon nom de contact) ; complétion pleine + espace si un seul candidat, sinon extension au plus long préfixe commun. Liste des contacts poussée depuis `src/main.rs` via `Update::Contacts` au démarrage, après `/add` et après `/forget`. `COMMANDS` est une liste à jour à la main (duplicat volontaire des verbes de `main.rs`/`chat.rs` — dérive possible si un verbe est ajouté sans y penser). Testé : 4 tests unitaires (`tab_completes_a_unique_command`, `tab_extends_to_the_longest_common_prefix_on_ambiguity`, `tab_completes_a_contact_name_after_the_first_word`, `tab_does_nothing_on_no_match_or_an_empty_word`), suite complète 153/154 verte (1 ignoré), clippy `--all-targets -D warnings` propre. Vérifié en conditions réelles (TUI lancée dans tmux, bootstrap Tor complet) : `/he` + `Tab` → `/help ` fonctionne.

### 📦 E. Sauvegarde et Restauration (Mnémonique BIP-39) — ✅ DONE (2026-08-30)
- **Principe :** Permettre l'exportation et la restauration de la graine d'identité de 32 octets sous forme d'une phrase de passe de 24 mots (format standard BIP-39), facilitant la sauvegarde sur papier.
- **Fait :** `src/identity.rs` — `mnemonic_phrase()` encode les 32 octets de la graine en phrase de 24 mots (crate `bip39`) ; `seed_from_mnemonic()` fait l'inverse et rejette une phrase au checksum invalide (mot mal recopié) plutôt que de générer silencieusement une autre identité. Deux modes utilitaires dans `src/main.rs`, même style env-var que 1C : `MURMURE_EXPORT_MNEMONIC=1 murmure` affiche la phrase et quitte ; `MURMURE_RESTORE_MNEMONIC="mot1 mot2 ..." murmure` régénère `identity.seed` à partir de la phrase — refuse d'écraser une identité déjà présente (`restore` sert à récupérer une graine perdue, pas à en remplacer une active).
- **Testé :** 4 tests unitaires (`a_mnemonic_phrase_round_trips_back_to_the_same_seed`, `a_phrase_with_a_bad_checksum_is_rejected`, `restore_from_mnemonic_writes_a_seed_matching_the_original`, `restore_from_mnemonic_refuses_to_clobber_an_existing_seed`), suite complète 161/162 verte (1 ignoré), clippy `--all-targets -D warnings` propre. Vérifié aussi avec le vrai binaire : export → suppression du fichier → restore → sha256 identique à l'original, et garde anti-écrasement confirmée.

---

## 5. Industrialisation & Packaging

- [x] **Intégration Continue (CI) Multi-Plateforme** — ✅ DÉJÀ FAIT (constaté le 2026-08-30) : `.github/workflows/ci.yml` fait tourner tests + clippy sur Linux/macOS à chaque push/PR, plus un audit hebdomadaire des dépendances (`rustsec/audit-check`). `rustfmt --check` volontairement absent — le commentaire du fichier explique pourquoi (rustfmt casserait 450 lignes de style délibéré, à activer le jour où un deuxième contributeur écrit du code ici).
- [x] **Releases Automatisées** — ✅ DÉJÀ FAIT (constaté le 2026-08-30) : `.github/workflows/release.yml` publie sur chaque tag `v*` des binaires Linux `x86_64`/`aarch64` et macOS universel (Intel+Apple Silicon via `lipo`), avec attestation de provenance et `SHA256SUMS`. Plus complet que ce que demandait la fiche (signature de provenance en plus).
- [ ] **Gestionnaires de paquets :** Création de formules pour **Homebrew** (macOS/Linux), paquets **AUR** (Arch Linux) et paquets Debian/Ubuntu (`.deb`). — seul point encore ouvert de la section 5.

## 6. Audit du code complet (2026-09-29) — corrections P0 à P2

Relecture de tout `src/`, faite après la v0.1.0-beta.2. Treize commits, **aucun bump de `VERSION`** (reste 12) : les correctifs restent compatibles avec les pairs en beta.2.

### P0 — Sécurité et confidentialité
- ✅ **Keystore arti en mémoire et vanguards** (`86a27ed`) : le keystore sur disque écrivait en clair la clé d'identité et un dossier par contact. L'ancien `state/keystore` est supprimé au démarrage.
- ✅ **IP candidates canoniques, caractères invisibles, noms Windows** (`87c3ee9`) : `::ffff:127.0.0.1` ne passe plus le filtre loopback.
- ✅ **Délais anti-DoS** (`64034c3`) : accept QUIC concurrent avec jeton, handshake entrant hors de la boucle, délais d'écriture et de lecture.

### P1 — Bugs
- ✅ **Transferts pendant un appel** (`451c46b`) : repli Tor après `DirectFailed`, `Post` au nom bizarre, `FileReject` ciblé, `/cancel` côté receveur, chips périmés.
- ✅ **`main.rs`** (`a350c45`) : `/tell` découpé par mots, `/view ~`, `/tell` en attente livré après un `/call`, envoi des derniers messages avant de quitter.
- ✅ **Fenêtre de dédup partagée `Seen`** (`21ba66d`) : lignes de salon hors ordre, `seen_above` borné à 256.
- ✅ **Salons** (`dea7c1e`) : membre perdu par l'hôte prévenu à sa ligne suivante, invitation remplacée déclinée, expiration à 10 min, 256 fichiers au plus.
- ✅ **Carnet** (`d1f4334`) : une adresse déjà enregistrée sous un autre nom est refusée.

### P2 — Performance et confort
- ✅ **Pool** (`b624932`) : envoi borné à 5 s, puis le lien est coupé ; un upload de salon laisse la moitié de la file libre.
- 🟡 **Fichiers de salon** (`1ec8d34`) : hash et copies sur le pool bloquant, quota partagé entre téléchargements, un seul flux par demande, nom vérifié à l'annonce. Non fait : relancer vers un *autre* pair après un blocage ; le hash est encore attendu dans la boucle (événement de fin à faire si les fichiers de plusieurs Go comptent).
- ✅ **Interface** (`e210e0f`) : nombre de lignes en cache, largeur d'affichage (`unicode-width`), sélection stable quand l'historique évince.
- ✅ **Identité et stockage** (`b17bddf`) : tampon du seed en `Zeroizing`, format `MURM2E` avec le coût Argon2 dans le fichier, fsync du répertoire après rename.
- ✅ **Répertoire de données de la plateforme** (`e822567`) : `MURMURE_DIR`, sinon `./.murmure` s'il existe, sinon `~/.local/share/murmure` et équivalents.

### P3 — Proposé, à valider
`/verify` (numéro de sécurité de 60 chiffres), notifications (`\a` hors focus), messages multi-lignes, salons et réception pendant un appel, MSRV et clippy Windows/macOS en CI.
