# murmure — messagerie pair-à-pair en terminal

**Date** : 2026-07-30
**Statut** : idée clarifiée, prête pour l'étape suivante

---

## L'idée

Une messagerie en terminal entre personnes qui se connaissent déjà. Les messages vont
d'une machine à l'autre sans qu'aucun intermédiaire puisse les lire, ni savoir qui parle
à qui. Rien à payer, rien à héberger, aucun compte.

## Le besoin derrière

Ne dépendre de personne, et ne rien débourser. Ce n'est pas la confidentialité du contenu
qui motive le projet — le chiffrement de bout en bout la donne déjà, y compris chez Signal
ou WhatsApp. Ce que ces produits ne donnent pas, et que ce projet vise :

- Personne ne sait **qui parle à qui**, ni quand.
- Aucune société ne peut fermer, facturer, ou changer ses conditions.
- Aucun annuaire central à qui faire confiance pour la clé publique de son correspondant.

## Ce qui est décidé

### Identité

Chaque utilisateur génère une paire de clés sur sa machine. Son identifiant public en est
**dérivé** — il ne change jamais, et il n'est pas son adresse IP. Le dériver de la clé
signifie que revendiquer cette identité exige de posséder la clé privée : un imposteur ne
peut pas se placer sous l'identifiant de quelqu'un d'autre.

### Premier contact

Les deux personnes s'échangent leur identifiant par n'importe quel canal, **même non
sécurisé** (SMS, WhatsApp, mail). Le canal n'a pas besoin d'être sûr : un identifiant
public est fait pour être vu. Le seul risque est qu'on le **remplace** en route, et c'est
la comparaison d'une courte empreinte à l'oral qui l'écarte — la voix de la personne est
l'authentification.

Entre amis uniquement. **Le cas de deux inconnus est explicitement hors périmètre**, et
sans solution : sans rien de commun au départ, aucune technique ne distingue un
correspondant d'un imposteur.

### Connexion — trois chemins

Le programme les essaye **dans l'ordre**, automatiquement. L'utilisateur ne choisit rien
par défaut.

1. **Direct** — connexion de machine à machine, port ouvert sur la box.
2. **Assisté** — traversée de NAT avec l'aide d'infrastructure publique gratuite.
3. **Relayé** — réseau Tor.

Deux modes d'installation :

- **Simple** : ne demande rien, essaye les trois dans l'ordre.
- **Personnalisée** : permet d'imposer un chemin précis. Techniquement, un interrupteur
  par-dessus l'échelle, pas un second programme.

### Messages

Aucun stockage intermédiaire. Les deux correspondants doivent être connectés **en même
temps** — c'est un coup de fil, pas un SMS. Un message qui échoue revient à l'envoyeur
après plusieurs tentatives, comme un recommandé.

### Contenus

Texte, images et fichiers. **Rien n'atterrit sur le disque sans confirmation explicite**
du destinataire. Les images ne sont pas affichées dans le terminal en v1 (certains
terminaux modernes en sont capables — à revoir plus tard, pas maintenant).

Un transfert interrompu **reprend où il s'était arrêté**.

### Usage

Carnet de contacts, plusieurs conversations, et **indicateur de présence** (qui est
joignable) dès la v1.

### Historique

Deux modes, au choix de l'utilisateur :

- **Rien n'est conservé** — on quitte, tout disparaît.
- **Conservé chiffré** sur le disque.

**Jamais en clair**, quel que soit le mode.

### Forme

Interface en mode texte riche dans le terminal : couleurs, cadres, zones qui se
rafraîchissent, raccourcis clavier. Pas de fenêtre graphique, pas d'application web.

---

## Critère de réussite

> Deux machines, deux réseaux différents, deux villes. Chacun lance la commande. Ils
> comparent une empreinte à l'oral, elle correspond. L'un tape une phrase, l'autre la voit
> apparaître. L'un envoie un fichier, l'autre reçoit une demande de confirmation, accepte,
> et le fichier arrive intact.

---

## Ce qui reste ouvert

### À trancher au design

| Sujet | La question |
| --- | --- |
| **Le carnet identifiant → adresse** | Pour les chemins 1 et 2, quelque chose doit traduire l'identifiant en adresse du jour. Un serveur (refusé), une table distribuée entre utilisateurs (vide tant qu'il n'y a pas de foule — le projet démarre à deux), ou s'appuyer sur le carnet déjà peuplé de Tor. Dernière vraie inconnue technique du projet. |
| **Le coût de la présence** | Sans serveur, savoir qui est joignable veut dire interroger chaque contact en boucle. Coût réseau permanent, et signale sa propre présence à tous ses contacts en continu. Le compromis reste à régler. |
| **La reprise de transfert entre sessions** | Où vit l'état d'un transfert partiel si les deux se déconnectent, et comment vérifier l'intégrité au bout. |

### Hypothèses posées, à confirmer

- Le chiffrement s'appuie sur un **protocole établi et audité**, jamais sur une
  construction maison. La cryptographie faite soi-même échoue silencieusement.
- **Une identité par machine.** Utiliser le même compte sur deux ordinateurs n'est pas prévu.
- **Perdre la machine, c'est perdre l'identité.** Aucune sauvegarde ni récupération de clé.

### Risques assumés

- Sur les chemins 1 et 2, **le correspondant voit l'adresse IP**, donc approximativement la
  ville. Acceptable entre amis, validé. Seul le chemin 3 (relayé) la masque.
- **Le chemin direct ne marchera pas pour tout le monde.** En 4G et chez certains
  opérateurs, la machine n'a aucune adresse joignable, quoi que fasse l'utilisateur.

---

## Ordre de grandeur

| Périmètre | Estimation |
| --- | --- |
| Noyau chiffré, une conversation, un seul chemin réseau | quelques soirées |
| + carnet de contacts, présence, plusieurs conversations | +2 à 3 semaines |
| + reprise de transfert de fichiers | +1 semaine |
| + les deux autres chemins réseau | +2 à 4 semaines |

Projet complet : plusieurs mois de soirées pour une personne seule.

---

## Étape suivante

Choisir l'architecture technique et la pile avant d'écrire du code. Le langage conditionne
les bibliothèques de chiffrement, de terminal et de réseau — autant que ce choix soit fait
une bonne fois.
