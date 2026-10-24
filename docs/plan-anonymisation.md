# Plan : anonymisation des dumps de base de données TYPO3

Branche : `feat/anonymize-database` (dépôt `toumoro/tm-workflows`)
Dernière mise à jour : 2026-10-23

## Objectif

Produire, à côté du `latest.sql` actuel, un second fichier **`latest_anonymized.sql`** dans le bucket TMDT, sans modifier le processus existant.

- Le chemin actuel `Export → Upload → latest.sql` ne doit pas changer.
- L'anonymisation est **opt-in par projet** et **ne peut pas faire échouer** le workflow.
- Les règles sont en deux niveaux : un **socle commun** dans `tm-workflows`, et un **fichier par projet** dans chaque dépôt client pour le cas par cas.
- Hors périmètre pour l'instant : Codespaces, fichiers (`fileadmin`), secrets techniques (webhooks, SMTP, etc.). On anonymise uniquement les données personnelles de la base.

## Décisions prises

| Sujet | Décision |
|---|---|
| Où anonymiser | Dans le workflow GitHub, dans un **nouveau job** `Anonymize`, en parallèle de `Upload` |
| Activation | Variable `TM_ANONYMIZE=true` dans le dépôt client (opt-in) |
| Isolation des échecs | `continue-on-error: true` au niveau du job |
| Base temporaire | Conteneur MySQL jetable démarré **par le script lui-même** (pas de bloc `services:`) : même code en local et sur GitHub |
| Code central | **Action composite** dans `actions/anonymize-database/` : un workflow réutilisable ne voit pas ses propres fichiers, une action composite oui (`github.action_path`) |
| Règles projet | `.github/anonymize.yml` dans le dépôt client ; modèle dans `templates/anonymize.yml` |
| Priorité des règles | Projet > core ; nom exact > motif (`cache_*`) |
| Tables sans règle | L'anonymisation échoue et liste les tables à classer (liste blanche stricte) |
| Logs | Jamais de valeurs : uniquement des noms de tables et colonnes et des nombres. Erreurs MySQL réduites à leur code |
| Format de sortie | `latest_anonymized.sql`, non compressé, comme `latest.sql` |

## Étape 1 : action d'anonymisation (FAITE, commit `930a3b6`)

### Fichiers

```
actions/anonymize-database/
├── action.yml            # setup-python, pyyaml, lance anonymize.py
├── anonymize.py          # import → règles → contrôles → export
└── rules/typo3-core.yml  # règles communes
templates/anonymize.yml   # exemple de règles projet pour les dépôts clients
docs/plan-anonymisation.md
```

### Fonctionnement de `anonymize.py`

1. Vérifie que le dump existe, charge et valide les règles core et projet.
2. Démarre un conteneur `mysql:8.0` nommé `tm-anonymize-<pid>-<aléa>` avec un mot de passe aléatoire.
3. Importe le dump (`.sql` ou `.sql.gz`) dans la base `typo3_anonymize`.
4. Refuse de continuer si le dump a créé une autre base (`USE`/`CREATE DATABASE`) ou si la base est vide.
5. Classe chaque table ; arrêt avec le **code 2** si des tables n'ont pas de règle.
6. Applique `truncate` et `update`, puis contrôle le résultat (table vide, colonne égale à la valeur attendue).
7. Scanne les courriels dans les colonnes texte conservées : il compte les adresses hors domaines autorisés, sans jamais les afficher. Avec `block`, arrêt avec le **code 3**.
8. Exporte avec `mysqldump` vers un fichier `.partial`, renommé seulement en cas de succès.
9. Supprime le conteneur dans tous les cas (sauf `--keep-container`).

Options locales : `--keep-container`, `--verbose-errors` (affiche les erreurs MySQL complètes, qui peuvent contenir des données ; **jamais en CI**).

### Format des règles

```yaml
settings:
  email_scan: warn            # warn | block | off
  allowed_email_domains:      # cumulés : défaut + core + projet
    - client.example

tables:
  ma_table: keep
  "cache_*": truncate
  fe_users:
    update:
      email: email            # user<uid>@example.invalid
      name: full_name         # Prenom<uid> Nom<uid>
      telephone: empty        # '' (ou 0 pour une colonne numérique)
      mfa: null
      password: invalid_password   # '!anonymized'
      note: {fixed: "Texte fictif"}
      autre: {sql: "CONCAT('x', uid)"}   # non contrôlée après coup
```

Stratégies : `email`, `username`, `first_name`, `last_name`, `full_name` (exigent une colonne `uid`), `empty`, `null`, `invalid_password`, `{fixed: ...}`, `{sql: ...}`.
Les tables absentes du dump et les colonnes absentes d'une table sont ignorées.

### Contenu des règles core (`rules/typo3-core.yml`)

- **update** : `fe_users`, `be_users` (si présente), `sys_file_metadata` (champs EXT:filemetadata), `tx_scheduler_task.tx_reports_notification_email`
Uniquement les tables du core TYPO3. Les extensions tierces (Solr, Powermail…) et les extensions maison Toumoro sont classées dans le `.github/anonymize.yml` de chaque projet ; `templates/anonymize.yml` donne des exemples pour Solr et Powermail.

- **truncate** : sessions, `sys_log`, `sys_history`, `sys_http_report`, `sys_lockedrecords`, `sys_preview`, `sys_messenger_messages`, `sys_note`, `cache_*`, `cf_*`, `index_*` (indexed_search)
- **keep** : contenu, structure, fichiers, configuration backend, `sys_refindex` (index calculé, sans valeurs des enregistrements)

### Tests réalisés (en local, Docker Desktop / WSL)

| Test | Résultat |
|---|---|
| Dump réel d'un projet, sans règles projet | Code 2, tables spécifiques au projet listées |
| Même dump avec des règles projet | OK en ~45 s (66 tables) |
| Dump fictif `.gz` avec 2 `fe_users` | OK, aucune valeur d'origine restante |
| Réimport du résultat | OK |
| Erreur MySQL contenant une donnée (Duplicate entry) | Seul le code `ERROR 1062` est affiché, aucun fichier produit |
| Mode `block` | Code 3, aucun fichier produit |
| Dump introuvable / échec de `docker run` | Message clair, aucun conteneur orphelin |

### Reproduire les tests sur un autre poste

Prérequis : Docker, Python 3, PyYAML (`pip install pyyaml` ou `apt install python3-yaml`). **Ne jamais commiter de dump réel.**

Règles projet de test : partir de `templates/anonymize.yml` et classer les tables listées par le premier lancement (code 2).

Commande :

```bash
python3 actions/anonymize-database/anonymize.py \
  --dump /chemin/latest.sql \
  --output /tmp/latest_anonymized.sql \
  --core-rules actions/anonymize-database/rules/typo3-core.yml \
  --project-rules /chemin/anonymize.yml
```

Dump fictif pour tester `fe_users` (si le dump de test n'en contient aucune ligne) : prendre le `CREATE TABLE fe_users` d'un dump réel, puis insérer des lignes inventées (nom, courriel, téléphone, hash `$argon2i$...`, `mfa`). Vérifier ensuite qu'aucune valeur inventée ne reste dans la sortie (`grep -c`).

## À valider avant le pilote

- [ ] Classement des tables du projet pilote (dans son `.github/anonymize.yml`, pas dans ce dépôt).
- [x] Courriels dans le contenu conservé : acceptés, ce n'est pas de l'information confidentielle. Le scan reste en `warn`.
- [x] Mots de passe remplacés par `!anonymized` : accepté (plus aucune connexion possible avec les comptes existants).
- [x] `sys_refindex` : conservée (`keep`), pas de reconstruction nécessaire après l'import.
- [ ] `sys_webhook` / `sys_reaction` conservées (secrets techniques, pas des données personnelles).

## Étape 2 : brancher le job `Anonymize` dans `copy-database.yml` (FAITE, non testée sur GitHub)

Job `Anonymize` ajouté **sans toucher** aux jobs `Export` et `Upload` :

- `if: vars.TM_ANONYMIZE == 'true'`, `needs: Export`, `continue-on-error: true`.
- Récupère le dépôt client (pour `.github/anonymize.yml`), puis `toumoro/tm-workflows` à la référence `tools-ref` dans `.tm-workflows/`, et appelle l'action locale `./.tm-workflows/actions/anonymize-database`.
- Télécharge l'artifact `db-dump`, anonymise `dump/latest.sql.gz`, envoie `latest_anonymized.sql` dans `<projet>/latest_anonymized.sql` avec le rôle TMDT.

Nouvelle entrée du workflow : `tools-ref` (défaut `v1`). `uses:` n'accepte pas d'expression, d'où le `checkout` du dépôt (public) à cette référence.

Pièges :

1. **Référence de l'action (réglé).** Sans `tools-ref`, le workflow de la branche irait chercher l'action dans `v1`, où elle n'existe pas encore. Pendant le pilote, passer `tools-ref: feat/anonymize-database`.
2. **`TM_ANONYMIZE` doit être une variable de dépôt (ou d'organisation), pas d'environnement.** Le `if:` d'un job est évalué avant que l'environnement ne soit chargé.
3. **IAM (vérifié)** : le rôle TMDT peut écrire `<projet>/latest_anonymized.sql`.
4. **Version MySQL** : un dump produit par `mysqldump` 8.0 depuis un serveur 8.4 s'importe bien en `mysql:8.0`. L'entrée `mysql-image` permet de changer de version au besoin.

## Étape 3 : pilote sur un projet client (FAIT, sauf le point 6)

Run nominal et test d'échec réussis : en cas d'échec de `Anonymize`, le run reste vert et `latest.sql` est envoyé. Le `latest_anonymized.sql` du run précédent reste alors dans S3, sans mise à jour.

1. Ajouter `.github/anonymize.yml` avec les règles validées.
2. Ajouter la variable de dépôt `TM_ANONYMIZE=true`.
3. Pointer temporairement le workflow du projet vers `toumoro/tm-workflows/.github/workflows/copy-database.yml@feat/anonymize-database`, avec `tools-ref: feat/anonymize-database` dans `with:`.
4. Lancer le workflow (`workflow_dispatch`). Vérifier : `latest.sql` toujours envoyé, job `Anonymize` vert, `latest_anonymized.sql` présent dans S3, résumé du job sans valeurs sensibles.
5. Tester l'échec : retirer une règle et vérifier que le run reste vert et que `latest.sql` est quand même envoyé.
6. Après la release, remettre `@v1` et retirer `tools-ref` dans le dépôt du projet.

## Étape 4 : release

- Commit `feat:` → version mineure (v1.11.0) ; le tag flottant `v1` se déplace.
- Aucun impact pour les projets sans `TM_ANONYMIZE`.
- Vérifier après la release que `v1.11` est bien créé (voir le bug du tag flottant plus bas).

## Plus tard (hors périmètre actuel)

- Faire consommer `latest_anonymized.sql` par `tmdt` et Codespaces, puis envisager qu'il remplace `latest.sql`.
- Supprimer alors l'artifact GitHub `db-dump`, visible par toute personne qui lit le dépôt client pendant 24 h, en fusionnant les jobs (nécessite boto3 ou l'AWS CLI dans l'image `tm-ansible`, qui ne l'a **pas** aujourd'hui).
- Gérer les autres projets : lancer une première fois sans règles projet, classer les tables listées. Le skill `typo3-db-audit` peut aider sur l'ensemble des projets.

## Problèmes relevés dans l'analyse de `copy-database.yml` (indépendants de l'anonymisation)

| # | Problème | Correctif proposé |
|---|---|---|
| 1 | `Stop bastion` ne tourne pas si `Export DB` échoue : le bastion reste allumé | `if: ${{ always() && vars.TM_DB_ENV_TYPE == 'ecs' }}` |
| 2 | Identifiants AWS du rôle client limités à 20 min (démarrage bastion + SSM + export) | Augmenter `role-duration-seconds` ou reprendre le rôle avant l'arrêt |
| 3 | Aucun `concurrency` ; le bastion est éteint même s'il était allumé avant | Mémoriser l'état initial ; `concurrency` par bastion |
| 4 | Dump de prod en artifact GitHub pendant 24 h | Voir « Plus tard » |
| 5 | Image `tm-ansible:latest` non figée | Tag versionné ou digest |
| 6 | `manage-instance.yml` attend l'état EC2 mais pas la disponibilité de SSM | Attendre que l'instance soit en ligne dans SSM |
| 7 | Dump brut laissé sur le serveur de prod dans `/tmp/dump/latest.sql.gz` (nettoyage commenté dans `tm-ansible`) | Réactiver le nettoyage dans `playbooks/general/run-export-db.yml` |
| 8 | `release.yml` : `git describe` peut renvoyer `v1`, donc `v1.10` n'a pas été déplacé (pointe sur `bb1aec6`) | Utiliser `git describe --tags --abbrev=0 --match 'v*.*.*'` |
| 9 | `ANSIBLE_VERBOSITY` vide si la variable n'est pas définie (à vérifier) | Valeur par défaut `'0'` |
| 10 | Commentaire du cron : 9h UTC = 5h l'été, 4h l'hiver | Corriger le commentaire |

## Pièges rencontrés en local

- `python3 -m venv` indisponible sur le poste WSL (paquet `python3.12-venv` absent) ; la PyYAML système (6.0.1) suffit.
- Docker Desktop peut se bloquer (`ports are not available: unable to list exposed ports`) : quitter Docker Desktop, lancer `wsl --shutdown`, puis le relancer.
- `wsl --shutdown` vide `/tmp` : ne pas y garder les fichiers de test.

## Reprendre sur un autre poste

```bash
git fetch origin
git checkout feat/anonymize-database
# relire ce fichier, puis : étape 3 (pilote)
```
