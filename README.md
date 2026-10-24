# tm-workflows

Workflows GitHub Actions partagés de Toumoro, appelés depuis les dépôts clients avec `@v1`.

| Fichier | Rôle |
|---|---|
| `.github/workflows/deploy-ssm.yml` | Déploiement Docker + TYPO3 via SSM |
| `.github/workflows/copy-database.yml` | Export de la base de prod vers S3, avec version anonymisée en option |
| `actions/anonymize-database/` | Action d'anonymisation d'un dump MySQL |
| `templates/` | Fichiers à copier dans les dépôts clients |
| `.github/workflows/release.yml` | Versions et tags de ce dépôt |

## Déploiement : `deploy-ssm.yml`

Lance dans l'image `ghcr.io/toumoro/tm-ansible` les playbooks `docker-deploy.yml` puis `typo3-deploy.yml`, sur le serveur joint par SSM.

Appel : `templates/continuous-delivery.yml` (push sur `prod`, `staging` ou `migration` → environnement `production`, `staging` ou `migration`).

| Entrée / secret | |
|---|---|
| `environment` | Environnement GitHub dont les variables sont lues |
| `aws-deploy-role-arn` | Rôle AWS (OIDC) du compte client |

Variables GitHub transmises aux playbooks : `AWS_SSM_BUCKET`, `TM_INSTANCE_ID`, `SERVER_USERNAME`, `PROJECT_CLIENT`, `TM_TYPO3_CONTAINER`, `DOCKER_PULL_POLICY`, `DOCKER_BUILD_POLICY`, `ANSIBLE_VERBOSITY`, `ANSIBLE_PYTHON_INTERPRETER` (défaut `auto_silent`), `aws-region` (défaut `ca-central-1`).

## Export de base : `copy-database.yml`

| Job | Rôle |
|---|---|
| `Export` | Démarre le bastion (si `ecs`), exporte la base (`DUMP_TYPE=partial`), arrête le bastion, garde le dump en artifact 24 h |
| `Upload` | Envoie `latest.sql` dans `s3://<TM_TMDT_BUCKET_NAME>/<TM_TMDT_PROJECT_NAME>/` |
| `Anonymize` | Si `TM_ANONYMIZE=true` : envoie `latest_anonymized.sql` au même endroit. Un échec n'affecte ni le run ni `latest.sql` |

Appel : `templates/database-export.yml` (lun-ven à 9h UTC, et manuel).

| Entrée / secret | |
|---|---|
| `environment` | Environnement GitHub dont les variables sont lues |
| `tools-ref` | Référence de tm-workflows pour l'action d'anonymisation (défaut `v1`) |
| `aws-oidc-role-arn` | Rôle du compte client : export |
| `tm-tmdt-aws-oidc-role-arn` | Rôle du compte TMDT : envoi dans S3 |

| Variable GitHub | |
|---|---|
| `TM_DB_ENV_TYPE` | `onpremise`, `ecs` ou `ec2` |
| `TM_INSTANCE_ID`, `SERVER_USER_NAME`, `TM_DUMP_INSTANCE_NAME`, `TM_SSM_TRANSFER_BUCKET_NAME` | Cible et transfert de l'export |
| `TM_TMDT_BUCKET_NAME`, `TM_TMDT_PROJECT_NAME` | Destination S3 |
| `AWS_REGION` | Défaut `ca-central-1` |
| `ANSIBLE_VERBOSITY`, `ANSIBLE_PYTHON_INTERPRETER` | Options Ansible |
| `TM_ANONYMIZE` | `true` active `Anonymize`. Variable de **dépôt** (ou d'organisation), pas d'environnement |

## Anonymisation : `actions/anonymize-database`

Importe le dump dans un conteneur MySQL jetable, applique les règles, contrôle le résultat, puis exporte un nouveau fichier SQL. Les logs ne contiennent aucune valeur du dump.

### Mise en place dans un projet

1. Copier `templates/anonymize.yml` dans `.github/anonymize.yml`.
2. Ajouter la variable de dépôt `TM_ANONYMIZE=true`.
3. Lancer l'export : le job liste les tables sans règle (code 2). Les classer, puis relancer.

### Entrées de l'action

| Entrée | Défaut | |
|---|---|---|
| `dump` | | Dump source (`.sql` ou `.sql.gz`) |
| `output` | `latest_anonymized.sql` | Fichier produit |
| `project-rules` | `.github/anonymize.yml` | Règles du projet (facultatif) |
| `core-rules` | `typo3-core` | Fichier de `rules/` sans `.yml`, ou `none` |
| `mysql-image` | `mysql:8.0` | Image de la base jetable |

### Règles

Chaque table du dump doit être classée, sinon l'anonymisation s'arrête. Les règles du projet l'emportent sur les règles communes ; un nom exact l'emporte sur un motif. Les tables et colonnes absentes du dump sont ignorées.

```yaml
settings:
  email_scan: warn              # warn | block | replace | off
  allowed_email_domains:        # jamais signalées ni remplacées (+ example.invalid, toumoro.com)
    - client.com
  key_column: uid               # clé des stratégies email, username… (défaut uid)

tables:
  sys_log: truncate             # vidée
  "cache_*": truncate           # motif
  pages: keep                   # conservée telle quelle
  fe_users:
    update:                     # colonnes remplacées
      email: email
      password: invalid_password
  wp_users:
    key: ID                     # clé propre à cette table
    update:
      user_email: email
```

| Stratégie | Résultat |
|---|---|
| `email` | `user<clé>@example.invalid` |
| `username` | `user<clé>` |
| `first_name`, `last_name`, `full_name` | `Prenom<clé>`, `Nom<clé>`, `Prenom<clé> Nom<clé>` |
| `empty` | `''` ; `0` si numérique ; date : `NULL` si permis, sinon `2000-01-01` |
| `null` | `NULL` |
| `invalid_password` | `!anonymized` (aucune connexion possible) |
| `{fixed: "texte"}` | Valeur fixe |
| `{sql: "expression"}` | Expression SQL, non contrôlée après coup |

`empty` ne gère pas les colonnes `ENUM` et `JSON` : utiliser `null` ou `{fixed: ...}`.

### Courriels du contenu : `email_scan`

Porte sur les colonnes texte et binaires conservées (tables `keep`, colonnes non remplacées des tables `update`), dont `l10n_diffsource`, la copie JSON du contenu source des traductions.

| Valeur | Effet |
|---|---|
| `warn` | Compte les adresses hors domaines autorisés, sans bloquer |
| `block` | Arrête l'anonymisation (code 3) |
| `replace` | Remplace chaque adresse par `contact-<hachage>@example.invalid`, la même pour une même adresse dans tout le dump. Les adresses dans une valeur PHP sérialisée restent en place et sont signalées |
| `off` | Aucun scan |

### Codes de sortie

| Code | Cause |
|---|---|
| 1 | Erreur (règle invalide, import, contrôle échoué…) |
| 2 | Tables sans règle |
| 3 | Courriels détectés avec `block` |

### Test local

Prérequis : Docker, Python 3, PyYAML. Ne jamais commiter de dump réel.

```bash
python3 actions/anonymize-database/anonymize.py \
  --dump latest.sql.gz \
  --output latest_anonymized.sql \
  --core-rules actions/anonymize-database/rules/typo3-core.yml \
  --project-rules ../projet/.github/anonymize.yml
```

`--keep-container` garde la base pour inspection ; `--verbose-errors` affiche les erreurs MySQL complètes, qui peuvent contenir des données (jamais en CI).

## Versions

semantic-release sur `main` : `feat:` → version mineure, `fix:` → correctif. Les tags flottants `v1` et `v1.x` sont ensuite déplacés sur la nouvelle version. Les dépôts clients appellent `@v1`.
