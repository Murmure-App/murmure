## Current state

_Updated 2026-09-14._

### Decisions
- Roadmap `IMPROVEMENTS.md` (racine du repo) est suivi item par item ; chaque item terminé/reporté est marqué inline (✅/⏭️/🟡) directement dans ce fichier, pas seulement dans le chat.
- 1B, 3A et 3B reportés (⏭️ SKIPPED, justifiés dans `IMPROVEMENTS.md`) : tous les trois changeraient le format du handshake/protocole (bump de `VERSION`) sans bénéfice suffisant ou en conflit avec le design anti-corrélation IP du projet (Iroh/DERP pour 3B ; QUIC non épinglé pour 3A tant que le challenge ne lie pas la signature au canal).
- 1A (ratchet E2E, PFS au niveau message) : Double Ratchet choisi plutôt que Noise_IK, car Noise_IK ne fait qu'un DH par session et ne satisfait pas l'exigence de post-compromise security demandée par le roadmap.

### In flight
- 1A est en cours, étape 1/3 terminée et commitée (`6bc3513`) : `proto::handshake` échange maintenant une clé X25519 éphémère par connexion, liée à la signature Ed25519 (le challenge signé inclut la clé éphémère du signataire — ferme une faille MITM identifiée en étudiant 3A). `VERSION` 6→7. La clé racine DH est calculée et vérifiée identique des deux côtés (test dédié) mais **n'est pas encore utilisée** : les messages ne sont pas chiffrés par cette couche.
- Étapes 2/3 et 3/3 restantes, pas commencées : la boucle Double Ratchet elle-même (avance par message, ratchet DH complet au changement de sens, table de clés sautées bornée contre un pair malveillant), puis son branchement sur `write_frame`/`read_frame` dans `src/proto.rs`. Chantier estimé 5-7 jours au total, prévu pour une session dédiée séparée.

### Traps
- `curve25519::EphemeralSecret::random_from_rng` (tor-llcrypto) exige `rand_core` 0.10, mais le reste du projet est sur `rand` 0.8 — `OsRng` de `rand` 0.8 ne satisfait pas ce bound. Contournement : remplir les 32 octets soi-même via `OsRng.fill_bytes` puis `curve25519::StaticSecret::from(bytes)`, exactement comme le nonce du handshake est déjà généré.
- Toujours faire `cargo build --bin murmure` juste avant un smoke test live sur `./target/debug/murmure` — `cargo test`/`cargo clippy` ne rafraîchissent pas forcément ce binaire précis, source d'un faux diagnostic une fois déjà.
