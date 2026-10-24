#!/usr/bin/env python3
"""Anonymise un dump MySQL dans un conteneur jetable, contrôle puis exporte le résultat.

Les logs n'affichent aucune valeur du dump (noms de tables, de colonnes et nombres
seulement) : ils sont lisibles par quiconque accède au dépôt.
"""

import argparse
import fnmatch
import gzip
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import time

import yaml

DB_NAME = "anonymize"
SYSTEM_DATABASES = {"information_schema", "mysql", "performance_schema", "sys", DB_NAME}

IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$")
TABLE_PATTERN = re.compile(r"^[A-Za-z0-9_*?\[\]]+$")
# Sur des octets : un courriel est en ASCII quel que soit le jeu de caractères.
EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,}))")
FILE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "avif"}  # ex. logo@2x.png
# Valeur PHP sérialisée : modifier la longueur d'une chaîne la casse.
SERIALIZED = re.compile(rb's:[0-9]+:"')
SERIALIZED_SQL = "'s:[0-9]+:\"'"

TEXT_TYPES = {"char", "varchar", "tinytext", "text", "mediumtext", "longtext"}
NUMERIC_TYPES = {"tinyint", "smallint", "mediumint", "int", "bigint", "decimal", "float", "double", "bit"}
# « empty » sur une date NOT NULL (NULL si la colonne l'accepte).
EMPTY_DATES = {
    "date": "'2000-01-01'",
    "datetime": "'2000-01-01 00:00:00'",
    "timestamp": "'2000-01-01 00:00:00'",
    "time": "'00:00:00'",
    "year": "2000",
}

# Valeurs fictives dérivées de la clé de la table (uid pour TYPO3).
KEY_STRATEGIES = {
    "email": "CONCAT('user', {key}, '@example.invalid')",
    "username": "CONCAT('user', {key})",
    "first_name": "CONCAT('Prenom', {key})",
    "last_name": "CONCAT('Nom', {key})",
    "full_name": "CONCAT('Prenom', {key}, ' Nom', {key})",
}
STATIC_STRATEGIES = {
    "null": "NULL",
    "invalid_password": "'!anonymized'",  # ne correspond à aucun format de hash connu
}

DEFAULT_SETTINGS = {
    "email_scan": "warn",  # warn | block | replace | off
    "key_column": "uid",   # colonne des stratégies basées sur la clé
    "allowed_email_domains": ["example.invalid"],
}


class AnonymizeError(Exception):
    def __init__(self, message, exit_code=1):
        super().__init__(message)
        self.exit_code = exit_code


def log(message=""):
    print(message, flush=True)


def sql_string(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


# --------------------------------------------------------------------------
# Règles
# --------------------------------------------------------------------------

def load_rules(path, label):
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise AnonymizeError(f"{label} : le fichier doit contenir un objet YAML")

    tables = data.get("tables") or {}
    settings = data.get("settings") or {}
    if not isinstance(tables, dict) or not isinstance(settings, dict):
        raise AnonymizeError(f"{label} : 'tables' et 'settings' doivent être des objets")

    for table, rule in tables.items():
        if not TABLE_PATTERN.match(str(table)):
            raise AnonymizeError(f"{label} : nom de table invalide '{table}'")
        if rule in ("keep", "truncate"):
            continue
        if (not isinstance(rule, dict) or "update" not in rule or not set(rule) <= {"update", "key"}
                or not isinstance(rule["update"], dict)):
            raise AnonymizeError(f"{label} : règle invalide pour '{table}' (keep, truncate ou update)")
        if "key" in rule and not IDENTIFIER.match(str(rule["key"])):
            raise AnonymizeError(f"{label} : clé invalide pour '{table}'")
        for column, strategy in rule["update"].items():
            if strategy is None:  # « null » non cité en YAML
                strategy = rule["update"][column] = "null"
            if not IDENTIFIER.match(str(column)):
                raise AnonymizeError(f"{label} : nom de colonne invalide '{table}.{column}'")
            validate_strategy(strategy, f"{label} : {table}.{column}")

    if settings.get("email_scan", "warn") not in ("warn", "block", "replace", "off"):
        raise AnonymizeError(f"{label} : settings.email_scan doit valoir warn, block, replace ou off")
    if "key_column" in settings and not IDENTIFIER.match(str(settings["key_column"])):
        raise AnonymizeError(f"{label} : settings.key_column invalide")
    return {"tables": tables, "settings": settings}


def validate_strategy(strategy, context):
    if isinstance(strategy, dict):
        if len(strategy) == 1 and ("fixed" in strategy or "sql" in strategy):
            return
    elif strategy in KEY_STRATEGIES or strategy in STATIC_STRATEGIES or strategy == "empty":
        return
    raise AnonymizeError(f"{context} : stratégie inconnue '{strategy}'")


def merge_settings(core, project):
    settings = dict(DEFAULT_SETTINGS)
    settings.update({k: v for k, v in core.items() if k != "allowed_email_domains"})
    settings.update({k: v for k, v in project.items() if k != "allowed_email_domains"})
    domains = set(DEFAULT_SETTINGS["allowed_email_domains"])
    domains.update(core.get("allowed_email_domains") or [])
    domains.update(project.get("allowed_email_domains") or [])
    settings["allowed_email_domains"] = sorted(d.lower() for d in domains)
    return settings


def resolve_rule(table, layers):
    """Les règles du projet l'emportent sur les communes ; un nom exact l'emporte sur un motif."""
    for label, tables in layers:
        if table in tables:
            return tables[table], label
        for pattern, rule in tables.items():
            if any(c in pattern for c in "*?[") and fnmatch.fnmatchcase(table, pattern):
                return rule, label
    return None, None


# --------------------------------------------------------------------------
# Base jetable
# --------------------------------------------------------------------------

class Database:
    def __init__(self, image, verbose_errors=False):
        self.image = image
        self.verbose_errors = verbose_errors
        self.container = f"tm-anonymize-{os.getpid()}-{secrets.token_hex(3)}"
        self.password = secrets.token_hex(16)
        self.started = False

    def _client(self, program, *args):
        return [
            "docker", "exec", "-i", "-e", f"MYSQL_PWD={self.password}", self.container,
            program, "-h127.0.0.1", "-uroot", "--default-character-set=utf8mb4", *args,
        ]

    def _error(self, context, stderr):
        """Ne garde que le code d'erreur : un message MySQL peut citer une valeur (Duplicate entry)."""
        text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else stderr
        if self.verbose_errors:
            return AnonymizeError(f"{context}\n{text.strip()}")
        codes = re.findall(r"ERROR \d+ \(\w+\)(?: at line \d+)?", text)
        detail = codes[0] if codes else "erreur MySQL (relancer avec --verbose-errors en local)"
        return AnonymizeError(f"{context} : {detail}")

    def start(self):
        self.started = True  # docker run peut échouer après avoir créé le conteneur
        result = subprocess.run(
            ["docker", "run", "-d", "--name", self.container,
             "-e", f"MYSQL_ROOT_PASSWORD={self.password}", "-e", f"MYSQL_DATABASE={DB_NAME}",
             self.image],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise AnonymizeError(f"Démarrage du conteneur MySQL échoué : "
                                 f"{result.stderr.decode('utf-8', 'replace').strip()}")
        # Le serveur temporaire de l'entrypoint n'écoute pas en TCP : 127.0.0.1 atteint le serveur final.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            probe = subprocess.run(self._client("mysql", "-e", "SELECT 1"), capture_output=True)
            if probe.returncode == 0:
                return
            time.sleep(2)
        raise AnonymizeError("MySQL n'a pas démarré dans le délai prévu")

    def stop(self):
        if self.started:
            subprocess.run(["docker", "rm", "-f", "-v", self.container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def import_dump(self, path):
        opener = gzip.open if path.endswith(".gz") else open
        process = subprocess.Popen(
            self._client("mysql", "--max-allowed-packet=1G", DB_NAME),
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            with opener(path, "rb") as source:
                shutil.copyfileobj(source, process.stdin, 1024 * 1024)
            process.stdin.close()
        except BrokenPipeError:
            pass  # mysql s'est arrêté sur une erreur ; on la lit ci-dessous
        stderr = process.stderr.read()
        if process.wait() != 0:
            raise self._error("Import du dump échoué", stderr)

    def execute(self, sql, context):
        result = subprocess.run(self._client("mysql", DB_NAME), input=sql.encode(), capture_output=True)
        if result.returncode != 0:
            raise self._error(context, result.stderr)

    def query(self, sql, context):
        result = subprocess.run(self._client("mysql", "-N", "-B", DB_NAME),
                                input=sql.encode(), capture_output=True)
        if result.returncode != 0:
            raise self._error(context, result.stderr)
        lines = result.stdout.decode("utf-8", "replace").split("\n")
        return [line.split("\t") for line in lines if line != ""]

    def count(self, table, where="1"):
        return int(self.query(f"SELECT COUNT(*) FROM `{table}` WHERE {where}", f"Comptage {table}")[0][0])

    def export(self, output):
        partial = output + ".partial"
        with open(partial, "wb") as target:
            result = subprocess.run(
                self._client("mysqldump", "--single-transaction", "--no-tablespaces",
                             "--set-gtid-purged=OFF", "--skip-dump-date", DB_NAME),
                stdout=target, stderr=subprocess.PIPE,
            )
        if result.returncode != 0:
            os.unlink(partial)
            raise self._error("Export du dump anonymisé échoué", result.stderr)
        os.replace(partial, output)


# --------------------------------------------------------------------------
# Traitement
# --------------------------------------------------------------------------

def read_schema(db):
    extra = [row[0] for row in db.query("SHOW DATABASES", "Liste des bases") if row[0] not in SYSTEM_DATABASES]
    if extra:
        # USE ou CREATE DATABASE dans le dump : des données hors de la base traitée.
        raise AnonymizeError(f"Le dump a créé d'autres bases que {DB_NAME} : {', '.join(extra)}")

    tables = {
        row[0]: {}
        for row in db.query(
            "SELECT TABLE_NAME FROM information_schema.TABLES "
            f"WHERE TABLE_SCHEMA = '{DB_NAME}' AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME",
            "Liste des tables",
        )
    }
    for table, column, data_type, nullable in db.query(
        "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM information_schema.COLUMNS "
        f"WHERE TABLE_SCHEMA = '{DB_NAME}' ORDER BY TABLE_NAME, ORDINAL_POSITION",
        "Liste des colonnes",
    ):
        if table in tables:
            tables[table][column] = (data_type.lower(), nullable == "YES")
    if not tables:
        raise AnonymizeError("Le dump importé ne contient aucune table")
    return tables


def strategy_sql(strategy, column, key):
    data_type, nullable = column
    if isinstance(strategy, dict):
        return strategy["sql"] if "sql" in strategy else sql_string(strategy["fixed"])
    if strategy == "empty":
        if data_type in NUMERIC_TYPES:
            return "0"
        if data_type in EMPTY_DATES:
            return "NULL" if nullable else EMPTY_DATES[data_type]
        return "''"
    if strategy in KEY_STRATEGIES:
        return KEY_STRATEGIES[strategy].format(key=f"`{key}`")
    return STATIC_STRATEGIES[strategy]


def classify(tables, layers):
    plan, unclassified = [], []
    for table in tables:
        rule, source = resolve_rule(table, layers)
        if rule is None:
            unclassified.append(table)
        else:
            plan.append((table, rule, source))
    return plan, unclassified


def apply_truncate(db, table):
    rows = db.count(table)
    db.execute(f"TRUNCATE TABLE `{table}`;", f"Vidage de {table}")
    if db.count(table) != 0:
        raise AnonymizeError(f"{table} contient encore des lignes après le vidage")
    log(f"  truncate  {table:<45} {rows} lignes supprimées")


def apply_update(db, table, columns, updates, key):
    present = {c: s for c, s in updates.items() if c in columns}
    missing = sorted(set(updates) - set(present))
    needs_key = any(not isinstance(s, dict) and s in KEY_STRATEGIES for s in present.values())
    if needs_key and key not in columns:
        raise AnonymizeError(f"{table} : les stratégies basées sur la clé exigent une colonne {key} "
                             "(settings.key_column ou key: dans la règle)")

    rows = db.count(table)
    if present and rows:
        assignments = {c: strategy_sql(s, columns[c], key) for c, s in present.items()}
        sql = ", ".join(f"`{c}` = {expr}" for c, expr in assignments.items())
        db.execute(f"UPDATE `{table}` SET {sql};", f"Anonymisation de {table}")

        # Contrôle : chaque colonne a la valeur attendue (sauf {sql: ...}).
        for column, strategy in present.items():
            if isinstance(strategy, dict) and "sql" in strategy:
                continue
            remaining = db.count(table, f"NOT (`{column}` <=> {assignments[column]})")
            if remaining:
                raise AnonymizeError(f"{table}.{column} : {remaining} lignes non anonymisées")

    note = f" (colonnes absentes ignorées : {', '.join(missing)})" if missing else ""
    log(f"  update    {table:<45} {rows} lignes, {len(present)} colonnes{note}")


def split_emails(value, allowed_domains):
    """Sépare les courriels d'une valeur : (hors domaines autorisés, laissés intacts)."""
    foreign, kept = [], []
    for match in EMAIL.finditer(value):
        domain, tld = match.group(1).decode().lower(), match.group(2).decode().lower()
        allowed = any(domain == d or domain.endswith("." + d) for d in allowed_domains)
        (kept if tld in FILE_EXTENSIONS or allowed else foreign).append(match.group(0))
    return foreign, kept


def scanned_columns(tables, plan):
    """Colonnes texte non remplacées des tables conservées."""
    for table, rule, _ in plan:
        if rule == "truncate":
            continue
        updated = set(rule["update"]) if isinstance(rule, dict) else set()
        for column, (data_type, _) in tables[table].items():
            if data_type in TEXT_TYPES and column not in updated:
                yield table, column


def column_values(db, table, column):
    """Valeurs contenant @, en hexadécimal : le mode batch de mysql échappe les sauts de ligne."""
    rows = db.query(f"SELECT HEX(`{column}`) FROM `{table}` WHERE `{column}` LIKE '%@%'",
                    f"Analyse de {table}.{column}")
    return [bytes.fromhex(value) for (value,) in rows]


def scan_emails(db, tables, plan, allowed_domains):
    """Compte les adresses hors domaines autorisés, sans jamais les afficher."""
    findings = []
    for table, column in scanned_columns(tables, plan):
        count = sum(len(split_emails(value, allowed_domains)[0]) for value in column_values(db, table, column))
        if count:
            findings.append((table, column, count))
    return findings


def fake_email(address, salt):
    digest = hashlib.blake2b(address.lower(), key=salt, digest_size=5).hexdigest()
    return f"contact-{digest}@example.invalid"


def replace_emails(db, tables, plan, allowed_domains):
    """Remplace les adresses hors domaines autorisés par des adresses fictives.

    Même adresse, même adresse fictive dans tout le dump ; sel aléatoire à chaque exécution.
    Retourne aussi, par colonne, le nombre d'adresses laissées en place : valeurs PHP
    sérialisées et adresses contenues dans une adresse conservée (a@client.co dans a@client.com).
    """
    salt = secrets.token_bytes(16)
    replaced, left = [], {}
    for table, column in scanned_columns(tables, plan):
        occurrences, protected, skipped = {}, set(), 0
        for value in column_values(db, table, column):
            foreign, kept = split_emails(value, allowed_domains)
            if SERIALIZED.search(value):
                skipped += len(foreign)
                continue
            protected.update(kept)
            for address in foreign:
                occurrences[address] = occurrences.get(address, 0) + 1

        # REPLACE agit sur des sous-chaînes : plus longues d'abord, jamais une adresse
        # contenue dans une adresse conservée.
        targets = []
        for address in sorted(occurrences, key=len, reverse=True):
            if any(address in other for other in protected):
                skipped += occurrences[address]
                protected.add(address)
            else:
                targets.append(address)

        for start in range(0, len(targets), 50):
            expr = f"`{column}`"
            for address in targets[start:start + 50]:
                expr = f"REPLACE({expr}, {sql_string(address.decode())}, {sql_string(fake_email(address, salt))})"
            db.execute(f"UPDATE `{table}` SET `{column}` = {expr} WHERE `{column}` LIKE '%@%' "
                       f"AND NOT REGEXP_LIKE(`{column}`, {SERIALIZED_SQL}, 'c');",
                       f"Remplacement des courriels de {table}.{column}")
        if targets:
            replaced.append((table, column, sum(occurrences[a] for a in targets)))
        if skipped:
            left[(table, column)] = skipped
    return replaced, left


def write_summary(lines):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


def run(args):
    if not os.path.isfile(args.dump):
        raise AnonymizeError(f"Dump introuvable : {args.dump}")
    if args.core_rules:
        core = load_rules(args.core_rules, "Règles communes")
        log(f"Règles communes : {args.core_rules}")
    else:
        core = {"tables": {}, "settings": {}}
        log("Aucune règle commune")
    if args.project_rules and os.path.exists(args.project_rules):
        project = load_rules(args.project_rules, "Règles projet")
        log(f"Règles projet : {args.project_rules}")
    else:
        project = {"tables": {}, "settings": {}}
        log("Aucune règle projet")
    settings = merge_settings(core["settings"], project["settings"])
    layers = [("projet", project["tables"]), ("core", core["tables"])]

    db = Database(args.mysql_image, args.verbose_errors)
    try:
        log(f"Démarrage de la base jetable ({args.mysql_image})")
        db.start()
        log("Import du dump")
        db.import_dump(args.dump)

        tables = read_schema(db)
        plan, unclassified = classify(tables, layers)
        if unclassified:
            log(f"\n{len(unclassified)} table(s) sans règle. Les classer (keep, truncate ou update) "
                "dans les règles du projet :")
            for table in unclassified:
                log(f"  - {table}")
            write_summary(["### Anonymisation : tables sans règle", *[f"- `{t}`" for t in unclassified]])
            raise AnonymizeError("Anonymisation interrompue : tables sans règle", exit_code=2)

        log(f"\n{len(plan)} tables classées")
        for table, rule, _ in plan:
            if rule == "truncate":
                apply_truncate(db, table)
            elif isinstance(rule, dict):
                apply_update(db, table, tables[table], rule["update"], rule.get("key", settings["key_column"]))
        kept = sum(1 for _, rule, _ in plan if rule == "keep")
        log(f"  keep      {kept} tables conservées telles quelles")

        mode = settings["email_scan"]
        expected = {}
        if mode == "replace":
            replaced, expected = replace_emails(db, tables, plan, settings["allowed_email_domains"])
            log(f"\n{sum(n for _, _, n in replaced)} courriels remplacés par des adresses fictives")
            for table, column, count in replaced:
                log(f"  {table}.{column} : {count}")
        if mode != "off":
            findings = scan_emails(db, tables, plan, settings["allowed_email_domains"])
            # Contrôle : il ne reste que les adresses laissées en place volontairement.
            if mode == "replace" and {(t, c): n for t, c, n in findings} != expected:
                raise AnonymizeError("Contrôle du remplacement des courriels échoué")
            if findings:
                if mode == "replace":
                    title = "Courriels laissés en place (valeurs PHP sérialisées ou adresses imbriquées)"
                else:
                    title = "Courriels hors domaines autorisés"
                log(f"\n{title}, valeurs non affichées :")
                for table, column, count in findings:
                    log(f"  {table}.{column} : {count}")
                write_summary([f"### Anonymisation : {title[0].lower()}{title[1:]}",
                               *[f"- `{t}.{c}` : {n}" for t, c, n in findings]])
                if mode == "block":
                    raise AnonymizeError("Anonymisation interrompue : courriels détectés", exit_code=3)
            else:
                log("\nAucun courriel hors domaines autorisés")

        log(f"\nExport vers {args.output}")
        db.export(args.output)
        log("Anonymisation terminée")
    finally:
        if args.keep_container:
            log(f"Conteneur conservé : {db.container}")
        else:
            db.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dump", required=True, help="dump source (.sql ou .sql.gz)")
    parser.add_argument("--output", required=True, help="fichier SQL anonymisé à produire")
    parser.add_argument("--core-rules", default="", help="règles communes (ex. rules/typo3-core.yml)")
    parser.add_argument("--project-rules", default="")
    parser.add_argument("--mysql-image", default="mysql:8.0")
    parser.add_argument("--keep-container", action="store_true", help="débogage local uniquement")
    parser.add_argument("--verbose-errors", action="store_true",
                        help="affiche les erreurs MySQL complètes (peuvent contenir des données) ; local uniquement")
    args = parser.parse_args()
    try:
        run(args)
    except AnonymizeError as error:
        log(f"\nERREUR : {error}")
        sys.exit(error.exit_code)


if __name__ == "__main__":
    main()
