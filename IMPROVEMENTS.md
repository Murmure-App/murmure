# Feuille de Route et Améliorations Futures — Murmure

Ce document rassemble l'ensemble des pistes d'amélioration, des axes de recherche et des évolutions techniques identifiés lors des audits de sécurité, des revues d'architecture et des retours d'expérience sur le projet **Murmure**.

---

## 1. Sécurité & Cryptographie Avancée

### 🔐 A. Couche E2E Applicative avec Ratchet (PFS au niveau message)
- **Constat actuel :** La confidentialité repose sur le circuit de transport Tor (ou le flux TLS 1.3 de QUIC). Le lien Tor reste ouvert de manière persistante pour chaque session.
- **Amélioration :** Intégrer un protocole cryptographique de bout en bout avec renouvellement continu des clés au niveau message (ex: **Noise Protocol Framework** `Noise_IK` ou **Double Ratchet** Signal).
- **Bénéfice :** Garantit une *Perfect Forward Secrecy* (PFS) et une *Post-Compromise Security* même en cas de compromission ultérieure de la graine d'identité ou d'inspection mémoire.

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

### 🪟 A. Déblocage du Support Windows via Démon Tor Externe
- **Constat actuel :** L'amorçage d'Arti (`arti-client`) se fige en boucle CPU lors du téléchargement du consensus sous Windows (`aidd_docs/arti-windows-hang.md`).
- **Amélioration :** 
  - Ajouter un backend optionnel dans `src/transport/tor.rs` capable de communiquer avec un binaire `tor.exe` local (Tor C / Tor Expert Bundle) via son port de contrôle (`ControlPort` / commande `ADD_ONION`).
  - Permet d'offrir un binaire Windows pleinement fonctionnel immédiatement sans dépendre de la résolution du bug amont d'Arti.

### 🐛 B. Suivi et Contribution au Bug Amont Arti
- **Action :** Soumettre officiellement le rapport d'anomalie détaillé [`aidd_docs/arti-windows-hang.md`](file:///home/thibault-savenkoff/murmure/aidd_docs/arti-windows-hang.md) à l'équipe du Tor Project sur [gitlab.torproject.org/tpo/core/arti](https://gitlab.torproject.org/tpo/core/arti) et suivre l'avancement de l'intégration CI Windows (#450).

### 🐧 C. Documentation et Profil WSL 2
- **Action :** Documenter pour les utilisateurs Windows actuels l'utilisation transparente et sans configuration de Murmure dans WSL 2 avec Windows Terminal.

---

## 3. Réseau & Nouveaux Modes de Transport

### 🔌 A. Mode de Connexion Directe Hors-Tor (`/dial IP:PORT`)
- **Principe :** Permettre d'établir une session sécurisée directe de machine à machine (ex: `murmure --dial 192.168.1.50:7777` ou sur IPv6 publique) en utilisant le moteur QUIC + TLS 1.3 avec épinglage de certificat (`src/transport/direct.rs`).
- **Cas d'usage :** Communication instantanée en réseau local (LAN), sur un VPN privé (WireGuard/Tailscale) ou en cas de coupure/censure totale du réseau Tor.

### 🤝 B. Transport P2P Alternatif avec Traversée NAT (Iroh / libp2p) — ⏭️ SKIPPED
- **Principe :** Réintroduire le *Chemin 2 (Assisté)* du brainstorm initial en intégrant une couche de transport basée sur **Iroh** (Rust, QUIC, STUN/DERP).
- **Bénéfice :** Connexions directes quasi-instantanées avec traversée automatique des box/NAT, en conservant l'adressage par clé publique Ed25519.
- **Pourquoi non appliqué (2026-08-30) :** même famille de conflit que 1B. Iroh route par défaut via des relais DERP publics et établit des chemins hors-Tor — exactement ce que le design du projet évite pour ne jamais exposer l'IP réelle d'un pair à un tiers ou à son interlocuteur. Ajouter Iroh, c'est ajouter un mode de fonctionnement qui affaiblit la propriété d'anonymat pour laquelle Murmure existe. Le transport direct QUIC déjà présent (`src/transport/direct.rs`, voir 3A) couvre le cas "connexion directe" sans ce compromis, à condition que les deux pairs se dévoilent leur IP volontairement (LAN/VPN).

### 🔄 C. Rotation Forcée des Descripteurs après Révocation (`/forget`)
- **Amélioration :** Forcer la rotation immédiate des points d'introduction et du descripteur de service caché lors de la suppression d'un contact (`/forget`), dès que l'API de rotation sera exposée par Arti.

---

## 4. Fonctionnalités & Expérience Utilisateur (UI/UX)

### 🖼️ A. Rendu d'Images en Mode Texte dans le Terminal
- **Principe :** Exploiter les protocoles graphiques modernes de terminaux (**Kitty Graphics Protocol**, **Sixel**, **iTerm2 inline images**) pour afficher les images reçues directement dans la fenêtre de conversation (pour les terminaux compatibles comme Kitty, WezTerm, Ghostty, iTerm2).

### 👥 B. Salons / Groupes Fermés Éphémères
- **Principe :** Permettre la création d'un salon éphémère à plusieurs pairs sans serveur, où chaque message est diffusé de manière chiffrée à tous les membres connectés du groupe (topologie maillée en étoile ou anneau).

### 🔍 C. Recherche dans l'Historique — ✅ DONE (2026-08-30)
- **Principe :** Ajouter une commande `/search <terme>` permettant de filtrer rapidement les messages passés dans l'historique chiffré.
- **Fait :** `History::search()` dans `src/history.rs` — filtre insensible à la casse sur toutes les conversations, plafonné à `SHOWN` comme `/history`. Commande `/search <terme>` ajoutée dans `src/main.rs`, listée dans `/help`. Vérifié que `/search` tapé pendant un appel tombe sur `Typed::UnknownCommand` (`classify()`, `src/chat.rs`) et ne part jamais sur le fil comme message. Testé : `history::tests::search_finds_a_word_case_insensitively_across_conversations`, suite complète 149/150 verte (1 ignoré, réseau Tor réel), clippy propre.

### ⌨️ D. Ergonomie et Autocomplétion — 🟡 PARTIEL (2026-08-30)
- **Améliorations :**
  - Autocomplétion des commandes et des noms de contacts avec `Tab` — ✅ DONE.
  - Indicateur visuel d'état de synchronisation de l'Outbox (`[envoyé]`, `[reçu]`) — non fait.
  - Thèmes de couleurs personnalisables pour l'interface TUI — non fait.
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
