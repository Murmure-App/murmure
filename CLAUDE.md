## Current state

_Updated 2026-09-29._

### Decisions
- Roadmap `IMPROVEMENTS.md` (racine du repo) est suivi item par item ; chaque item terminé/reporté est marqué inline (✅/⏭️/🟡) directement dans ce fichier, pas seulement dans le chat.
- 1B, 3A et 3B reportés (⏭️ SKIPPED, justifiés dans `IMPROVEMENTS.md`) : tous les trois changeraient le format du handshake/protocole (bump de `VERSION`) sans bénéfice suffisant ou en conflit avec le design anti-corrélation IP du projet (Iroh/DERP pour 3B ; QUIC non épinglé pour 3A tant que le challenge ne lie pas la signature au canal).
- 1A (ratchet E2E, PFS au niveau message) : Double Ratchet choisi plutôt que Noise_IK, car Noise_IK ne fait qu'un DH par session et ne satisfait pas l'exigence de post-compromise security demandée par le roadmap.

### In flight
- 1A est en cours, étape 1/3 terminée (`6bc3513`) : `proto::handshake` échange une clé X25519 éphémère par connexion. La clé racine DH est calculée et vérifiée identique des deux côtés (test dédié) et sert de racine au ratchet (voir plus bas).
- 2026-09-29, fusion de `git-sync/main` dans `main` (depuis srv-tsa-new) : le handshake combine désormais la clé éphémère de `6bc3513` et le correctif de `31add01`. Un seul message signé couvre `AUTH_CONTEXT(v3) || rôle (CALLER/ANSWERER) || signataire || vérificateur || nonce || clé éphémère du signataire`, et l'appelant refuse de signer si l'identité annoncée n'est pas l'adresse qu'il a composée (`handshake(.., dialled: Option<HsId>)`). Ça ferme l'usurpation par relais (un contact commun relaie le défi de Bob au service onion d'Alice), que la clé éphémère seule ne bloquait pas tant que le ratchet ne chiffre rien. `VERSION` passe à 8 (les deux branches avaient chacune un 7 incompatible). Contexte KDF `murmure 2026 ratchet root` inchangé, car la forme du secret partagé n'a pas bougé.
- 2026-09-29 : 1A terminé (étapes 2/3 et 3/3). `src/ratchet.rs` chiffre chaque trame de `Link` ; pas de table de clés sautées (flux ordonné, voir `IMPROVEMENTS.md`). `VERSION` 9. La clé racine de l'étape 1 sert désormais.

### Traps
- `curve25519::EphemeralSecret::random_from_rng` (tor-llcrypto) exige `rand_core` 0.10, mais le reste du projet est sur `rand` 0.8 — `OsRng` de `rand` 0.8 ne satisfait pas ce bound. Contournement : remplir les 32 octets soi-même via `OsRng.fill_bytes` puis `curve25519::StaticSecret::from(bytes)`, exactement comme le nonce du handshake est déjà généré.
- Toujours faire `cargo build --bin murmure` juste avant un smoke test live sur `./target/debug/murmure` — `cargo test`/`cargo clippy` ne rafraîchissent pas forcément ce binaire précis, source d'un faux diagnostic une fois déjà.
