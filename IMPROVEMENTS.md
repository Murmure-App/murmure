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

### 🛡️ C. Protection de la Graine au Repos par Passphrase (KDF Argon2id)
- **Constat actuel :** La graine d'identité (`identity.seed`) est stockée en clair sur le disque avec des permissions `0600`.
- **Amélioration :** Proposer en option le chiffrement de `identity.seed` par un mot de passe utilisateur via **Argon2id** (ou scrypt/PBKDF2) au lancement.
- **Bénéfice :** Empêche l'extraction immédiate de l'identité en cas d'accès physique ou de saisie du disque machine éteinte (sans chiffrement FDE).

### ⏱️ D. Jitter Aléatoire sur les Keepalives de Présence (Anti-Analyse de Trafic) — ✅ DONE (2026-08-30)
- **Constat actuel :** Les paquets `Ping` de présence sont envoyés toutes les 60 secondes fixes sur le circuit Tor.
- **Amélioration :** Introduire une variation aléatoire (*jitter* entre 45s et 75s) et du faux trafic optionnel (*padding*).
- **Bénéfice :** Réduit la signature temporelle identifiable par un nœud de garde Tor ou un FAI observant la connexion.
- **Fait :** `src/link.rs` — nouveau `JITTER = 15s` à côté de `KEEPALIVE = 60s` ; `keepalive_delay()` tire un délai uniforme dans `[45s, 75s)` à chaque battement. `tokio::time::interval` (grille fixe) remplacé par `tokio::time::sleep` par itération, sinon le jitter n'aurait aucun effet. Padding optionnel non fait — hors scope, pas demandé. Tests `link::tests::*` (8/8) verts, `cargo build` propre.

### 💾 E. Quota de Stockage et Gestion des Fichiers Entrants
- **Amélioration :** Implémenter une limite de taille globale configurable pour le répertoire `.murmure/incoming/` et alerter l'utilisateur avant acceptation de gros fichiers si l'espace disque restant est insuffisant.

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

### 🤝 B. Transport P2P Alternatif avec Traversée NAT (Iroh / libp2p)
- **Principe :** Réintroduire le *Chemin 2 (Assisté)* du brainstorm initial en intégrant une couche de transport basée sur **Iroh** (Rust, QUIC, STUN/DERP).
- **Bénéfice :** Connexions directes quasi-instantanées avec traversée automatique des box/NAT, en conservant l'adressage par clé publique Ed25519.

### 🔄 C. Rotation Forcée des Descripteurs après Révocation (`/forget`)
- **Amélioration :** Forcer la rotation immédiate des points d'introduction et du descripteur de service caché lors de la suppression d'un contact (`/forget`), dès que l'API de rotation sera exposée par Arti.

---

## 4. Fonctionnalités & Expérience Utilisateur (UI/UX)

### 🖼️ A. Rendu d'Images en Mode Texte dans le Terminal
- **Principe :** Exploiter les protocoles graphiques modernes de terminaux (**Kitty Graphics Protocol**, **Sixel**, **iTerm2 inline images**) pour afficher les images reçues directement dans la fenêtre de conversation (pour les terminaux compatibles comme Kitty, WezTerm, Ghostty, iTerm2).

### 👥 B. Salons / Groupes Fermés Éphémères
- **Principe :** Permettre la création d'un salon éphémère à plusieurs pairs sans serveur, où chaque message est diffusé de manière chiffrée à tous les membres connectés du groupe (topologie maillée en étoile ou anneau).

### 🔍 C. Recherche dans l'Historique
- **Principe :** Ajouter une commande `/search <terme>` permettant de filtrer rapidement les messages passés dans l'historique chiffré.

### ⌨️ D. Ergonomie et Autocomplétion
- **Améliorations :**
  - Autocomplétion des commandes (`/call`, `/history`, `/forget`, `/send`) et des noms de contacts avec la touche `Tab`.
  - Indicateur visuel d'état de synchronisation de l'Outbox (messages en attente de remise avec statut `[envoyé]`, `[reçu]`).
  - Thèmes de couleurs personnalisables pour l'interface TUI (ex: Nord, Gruvbox, Monokai, High Contrast).

### 📦 E. Sauvegarde et Restauration (Mnémonique BIP-39)
- **Principe :** Permettre l'exportation et la restauration de la graine d'identité de 32 octets sous forme d'une phrase de passe de 24 mots (format standard BIP-39), facilitant la sauvegarde sur papier.

---

## 5. Industrialisation & Packaging

- [ ] **Intégration Continue (CI) Multi-Plateforme :** Mise en place d'un workflow GitHub Actions automatisant les tests, le lint (`clippy`) et le formatage (`rustfmt`) sur Linux et macOS.
- [ ] **Releases Automatisées :** Publication automatique de binaires précompilés et signés pour chaque version (Linux `x86_64` / `aarch64`, macOS Intel / Apple Silicon).
- [ ] **Gestionnaires de paquets :** Création de formules pour **Homebrew** (macOS/Linux), paquets **AUR** (Arch Linux) et paquets Debian/Ubuntu (`.deb`).
