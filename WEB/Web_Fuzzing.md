# Web Fuzzing Tools

## Installation Initiale

### Go, Python et PIPX
```bash
# Update système
sudo apt update

# Installation Go
sudo apt install -y golang

# Installation Python
sudo apt install -y python3 python3-pip

# Installation et configuration PIPX
sudo apt install pipx
pipx ensurepath
sudo pipx ensurepath --global

# Vérification des versions
go version
python3 --version
```

## FFUF (Fuzz Faster U Fool)

### Installation
```bash
go install github.com/ffuf/ffuf/v2@latest
```

### Cas d'Usage
- **Directory/File Enumeration** : Découvrir des répertoires et fichiers cachés
- **Parameter Discovery** : Trouver et tester des paramètres dans les applications web
- **Brute-Force Attack** : Attaques par force brute pour credentials ou informations sensibles

## Gobuster

### Installation
```bash
go install github.com/OJ/gobuster/v3@latest
```

### Cas d'Usage
- **Content Discovery** : Scanner et trouver du contenu web caché (directories, files, virtual hosts)
- **DNS Subdomain Enumeration** : Identifier les sous-domaines
- **WordPress Content Detection** : Utiliser des wordlists spécifiques pour WordPress

## FeroxBuster

### Installation
```bash
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin
```

### Cas d'Usage
- **Recursive Scanning** : Scans récursifs pour découvrir directories et fichiers imbriqués
- **Unlinked Content Discovery** : Identifier du contenu non lié dans l'application
- **High-Performance Scans** : Haute performance grâce à Rust

## wenum (fork de wfuzz)

### Installation
```bash
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

### Cas d'Usage
- **Directory/File Enumeration** : Découvrir des répertoires et fichiers cachés
- **Parameter Discovery** : Trouver et tester des paramètres
- **Brute-Force Attack** : Attaques par force brute

### Notes
- Syntaxe interchangeable avec wfuzz
- Peut remplacer wfuzz si nécessaire
- Utilise PIPX pour éviter les conflits de packages

## Notes Importantes

- **FFUF** : Rapide, flexible, excellent pour le fuzzing général
- **Gobuster** : Simple, efficace, bon pour les débutants
- **FeroxBuster** : Récursif par nature, excellent pour le "forced browsing"
- **wenum/wfuzz** : Très versatile, idéal pour le parameter fuzzing

---

# Directory and File Fuzzing
---

# Directory and File Fuzzing - Cheat Sheet

## Concept

Le fuzzing de répertoires et fichiers vise à découvrir des ressources cachées sur une application web :
- Données sensibles (backups, configs, logs avec credentials)
- Contenu obsolète (anciennes versions vulnérables)
- Ressources de développement (environnements de test, panels admin)
- Fonctionnalités cachées (endpoints non documentés)

**Important** : Ces zones cachées ont souvent des mesures de sécurité moins robustes que les composants publics.

---

## Wordlists

### SecLists
Repository GitHub : https://github.com/danielmiessler/SecLists

**Localisation** :
- PwnBox : `/usr/share/seclists/`
- Autres distros : Vérifier la casse (`SecLists` vs `seclists`)

### Wordlists Courantes
```bash
# Wordlist généraliste (point de départ)
/usr/share/seclists/Discovery/Web-Content/common.txt

# Wordlist moyenne pour directories
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Wordlist large pour directories
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

# Wordlist massive (directories + files)
/usr/share/seclists/Discovery/Web-Content/big.txt
```

---

## Fuzzing avec FFUF

### Fonctionnement
1. **Wordlist** : Liste de noms potentiels de directories/files
2. **URL avec FUZZ keyword** : Placeholder remplacé par les entrées de la wordlist
3. **Requêtes** : Itération sur la wordlist et envoi de requêtes HTTP
4. **Analyse** : Analyse des réponses (status codes, content length, etc.)

### Directory Fuzzing
```bash
# Fuzzing de base pour directories
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://TARGET/FUZZ

# Options principales :
# -w : Chemin vers la wordlist
# -u : URL cible (FUZZ = placeholder)
```

**Résultat attendu** : Status codes (301, 200, 403, etc.) indiquant des directories existants

### File Fuzzing

#### Extensions Communes
- `.php` : Code PHP (server-side)
- `.html` : Structure de pages web
- `.txt` : Fichiers texte (logs, info)
- `.bak` : Fichiers de backup (peuvent contenir credentials, API keys)
- `.js` : Code JavaScript
```bash
# Fuzzing de fichiers avec extensions multiples
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://TARGET/directory/FUZZ -e .php,.html,.txt,.bak,.js -v

# Options :
# -e : Extensions à tester
# -v : Mode verbose (détails complets)
```

**Exemple de cibles critiques** :
- `config.php.bak` → Credentials DB, API keys
- `test.php` → Scripts vulnérables
- `backup.sql` → Dumps de base de données

## Workflow Standard
```bash
# 1. Directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://TARGET/FUZZ

# 2. File fuzzing dans les directories découverts
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://TARGET/discovered_dir/FUZZ -e .php,.html,.txt,.bak,.js -v

# 3. Analyser les résultats (status codes, sizes)
# - 200 : Fichier accessible
# - 301 : Redirection (directory existant)
# - 403 : Accès interdit (mais existe)
# - 404 : Non trouvé
```

## Tips

- Toujours vérifier la casse du chemin SecLists sur la distro
- Status code 301 = directory trouvé → approfondir
- Fichiers `.bak` et `.txt` = cibles prioritaires (info leaks)
- Mode verbose (`-v`) pour détails complets des découvertes
- Adapter les extensions selon la tech stack détectée

## Analyse des Résultats

**Métriques importantes** :
- **Status Code** : Type de réponse HTTP
- **Size** : Taille du contenu (détecte pages identiques)
- **Words/Lines** : Nombre de mots/lignes (filtrage)
- **Duration** : Temps de réponse

**Priorisation** :
1. Fichiers de backup (`.bak`)
2. Fichiers de configuration
3. Scripts de test/développement
4. Directories avec status 403 (existent mais interdits)

---

# Recursive Fuzzing

## Concept

Le recursive fuzzing permet d'explorer automatiquement les structures de répertoires imbriqués sans intervention manuelle à chaque niveau découvert.

### Fonctionnement en 3 Étapes

1. **Initial Fuzzing**
   - Début au web root (`/`)
   - Envoi de requêtes basées sur la wordlist
   - Analyse des réponses (HTTP 200 OK = directory existe)

2. **Directory Discovery and Expansion**
   - Chaque directory trouvé devient une nouvelle branche
   - Exemple : `admin` trouvé → nouvelle branche `http://target/admin/`
   - Le fuzzer relance le processus sur cette nouvelle branche

3. **Iterative Depth**
   - Répétition du processus pour chaque directory découvert
   - Continue jusqu'à la profondeur limite ou absence de nouveaux directories

**Analogie** : Structure en arbre où le web root est le tronc et chaque directory est une branche explorée récursivement.

## Avantages

- **Efficacité** : Automatisation vs exploration manuelle
- **Exhaustivité** : Exploration systématique de toutes les branches
- **Réduction du travail manuel** : Pas besoin de relancer manuellement pour chaque directory
- **Scalabilité** : Essentiel pour les grandes applications web

## Recursive Fuzzing avec FFUF

### Commande de Base
```bash
# Fuzzing récursif basique
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://TARGET/FUZZ -e .html -recursion

# Options :
# -recursion : Active le mode récursif
# -ic : Ignore les commentaires dans la wordlist (lignes commençant par #)
# -v : Mode verbose
# -e : Extensions à tester
```

### Workflow du Fuzzing Récursif
```
1. Fuzzing du web root → Trouve /level1
   └─> Nouvelle job : http://TARGET/level1/FUZZ
       
2. Fuzzing de /level1 → Trouve /level2 et /level3
   ├─> Nouvelle job : http://TARGET/level1/level2/FUZZ
   └─> Nouvelle job : http://TARGET/level1/level3/FUZZ

3. Fuzzing de /level2 → Trouve index.html
4. Fuzzing de /level3 → Trouve index.html (size différente = suspect)
```

## Contrôle et Responsabilité

### Problématiques
- **Resource-intensive** : Peut surcharger le serveur cible
- **Requêtes excessives** : Risque de trigger des mécanismes de sécurité
- **Performance** : Impact possible sur la disponibilité du service

### Options de Limitation
```bash
# Contrôle de la profondeur (2 niveaux max)
ffuf -w wordlist.txt -ic -u http://TARGET/FUZZ -e .html -recursion -recursion-depth 2

# Contrôle du rate (500 requêtes/seconde max)
ffuf -w wordlist.txt -ic -u http://TARGET/FUZZ -e .html -recursion -rate 500

# Timeout par requête
ffuf -w wordlist.txt -ic -u http://TARGET/FUZZ -e .html -recursion -timeout 10

# Combinaison complète (recommandé)
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -ic \
     -u http://TARGET/FUZZ \
     -e .html \
     -recursion \
     -recursion-depth 2 \
     -rate 500 \
     -timeout 10
```

## Options Principales

| Option | Description |
|--------|-------------|
| `-recursion` | Active le fuzzing récursif |
| `-recursion-depth N` | Limite la profondeur (N niveaux max) |
| `-rate N` | Limite à N requêtes/seconde |
| `-timeout N` | Timeout de N secondes par requête |
| `-ic` | Ignore les commentaires dans la wordlist |
| `-v` | Mode verbose (détails complets) |

## Tips

- **Toujours limiter la profondeur** : `-recursion-depth 2` ou `3` pour éviter la surcharge
- **Contrôler le rate** : `-rate 500` pour être plus discret
- **Analyser les sizes** : Fichiers de taille différente = contenu potentiellement intéressant
- **Mode verbose** : Essential pour suivre la progression et les branches explorées
- **Status 301** : Indique un directory → sera exploré récursivement
- **Wordlist comments** : Toujours utiliser `-ic` avec SecLists

## Exemple d'Analyse
```
[Status: 301] → /level1        (Directory trouvé, ajout à la queue)
[INFO] Adding job: /level1/FUZZ

[Status: 200] → /level1/index.html      (Fichier trouvé, size: 96)
[Status: 301] → /level1/level2          (Directory trouvé, ajout à la queue)
[Status: 301] → /level1/level3          (Directory trouvé, ajout à la queue)

[Status: 200] → /level1/level2/index.html    (Size: 96)
[Status: 200] → /level1/level3/index.html    (Size: 126) ← Size différente = suspect!
```

**Action** : Investiguer `/level1/level3/index.html` en priorité (taille différente = contenu unique potentiel)

---

# Parameter and Value Fuzzing

---

# Parameter and Value Fuzzing

## Concept des Paramètres

Les paramètres sont les variables qui transportent l'information entre le navigateur et le serveur, influençant le comportement de l'application.

### GET Parameters

**Localisation** : Visibles dans l'URL après le `?`
```http
https://example.com/search?query=fuzzing&category=security
```

- `query` = paramètre avec valeur "fuzzing"
- `category` = paramètre avec valeur "security"
- Séparés par `&` pour paramètres multiples
- **Analogie** : Comme une carte postale (information visible)
- **Usage** : Actions sans modification du state serveur (recherche, filtrage)

### POST Parameters

**Localisation** : Dans le body de la requête HTTP (non visible dans l'URL)
```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=your_username&password=your_password
```

- **Analogie** : Comme une enveloppe scellée (information cachée)
- **Usage** : Données sensibles (credentials, infos personnelles, financières)

**Encodages courants** :
- `application/x-www-form-urlencoded` : Key-value pairs (username=value&password=value)
- `multipart/form-data` : Upload de fichiers + données

## Pourquoi Fuzzer les Paramètres ?

Les paramètres sont des **gateways** pour interagir avec l'application :

- **Product ID** modifié → Erreurs de prix, accès non autorisé
- **Hidden parameter** modifié → Fonctionnalités cachées, fonctions admin
- **Search query** malveillante → XSS, SQLi

## GET Parameter Fuzzing avec wenum

### Installation
```bash
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

### Reconnaissance Manuelle
```bash
# Test sans paramètre
curl http://TARGET/get.php
# Réponse : Invalid parameter value x:

# Test avec valeur basique
curl http://TARGET/get.php?x=1
# Réponse : Invalid parameter value x: 1
```

### Fuzzing Automatique
```bash
# Fuzzing du paramètre GET
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://TARGET/get.php?x=FUZZ"

# Options :
# -w : Wordlist
# --hc 404 : Hide status code 404 (par défaut wenum log toutes les requêtes)
# FUZZ : Placeholder remplacé par les valeurs de la wordlist
```

## POST Parameter Fuzzing avec FFUF

### Reconnaissance Manuelle
```bash
# Test avec body vide
curl -d "" http://TARGET/post.php
# Réponse : Invalid parameter value y:

# Options :
# -d : POST request avec data dans le body
```

### Fuzzing Automatique
```bash
# Fuzzing du paramètre POST
ffuf -u http://TARGET/post.php \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "y=FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200 \
     -v

# Options :
# -X POST : Méthode HTTP POST
# -H : Header Content-Type
# -d "y=FUZZ" : Data dans le body (FUZZ = placeholder)
# -mc 200 : Match status code 200 uniquement
# -v : Mode verbose
```

## Workflow Standard

### GET Parameters
```bash
# 1. Reconnaissance manuelle
curl http://TARGET/endpoint?param=test

# 2. Fuzzing automatique
wenum -w wordlist.txt --hc 404 -u "http://TARGET/endpoint?param=FUZZ"

# 3. Validation de la valeur trouvée
curl http://TARGET/endpoint?param=validvalue
```

### POST Parameters
```bash
# 1. Reconnaissance manuelle
curl -d "param=test" http://TARGET/endpoint

# 2. Fuzzing automatique
ffuf -u http://TARGET/endpoint -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "param=FUZZ" -w wordlist.txt -mc 200

# 3. Validation de la valeur trouvée
curl -d "param=validvalue" http://TARGET/endpoint
```

## Options Principales

### wenum (GET)

| Option | Description |
|--------|-------------|
| `-w` | Wordlist à utiliser |
| `--hc CODE` | Hide status code (ex: `--hc 404`) |
| `-u` | URL cible avec FUZZ placeholder |

### ffuf (POST)

| Option | Description |
|--------|-------------|
| `-X POST` | Méthode HTTP POST |
| `-H` | Header HTTP (Content-Type) |
| `-d` | Data dans le body de la requête |
| `-mc CODE` | Match status code spécifique |
| `-v` | Mode verbose |
| `-w` | Wordlist à utiliser |

---

# Virtual Host and Subdomain Fuzzing

---

# Virtual Host and Subdomain Fuzzing

## Concepts

**Virtual Hosts** : Plusieurs sites sur un serveur/IP, identifiés via `Host` header HTTP  
**Subdomains** : Extensions d'un domaine (blog.example.com), résolus via DNS

## VHost Fuzzing avec Gobuster

### Setup
```bash
# Ajouter le domaine au /etc/hosts
echo "TARGET_IP domain.htb" | sudo tee -a /etc/hosts
```

### Commande
```bash
# VHost fuzzing
gobuster vhost -u http://domain.htb:PORT -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain

# Options principales :
# vhost : Mode VHost fuzzing
# --append-domain : Crucial, ajoute le domaine de base à chaque mot
```

### Test Manuel
```bash
# Vérifier un vhost trouvé
curl -H "Host: admin.domain.htb" http://TARGET_IP:PORT
```

## Subdomain Fuzzing avec Gobuster

### Commande
```bash
# Subdomain enumeration
gobuster dns -d domain.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Note : Versions récentes utilisent --domain au lieu de -d
gobuster dns --domain domain.com -w wordlist.txt
```

### Wordlists
```bash
# Rapide (5000)
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Moyen (20000)
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Exhaustif (110000)
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### Vérification DNS
```bash
dig subdomain.domain.com
nslookup subdomain.domain.com
```

## Options Utiles
```bash
# VHost avec filtering
gobuster vhost -u http://domain.htb -w wordlist.txt --append-domain --exclude-length 100

# DNS avec plus de threads
gobuster dns -d domain.com -w wordlist.txt -t 50

# VHost avec timeout custom
gobuster vhost -u http://domain.htb -w wordlist.txt --append-domain --timeout 5s
```

## Status Codes (VHost)

- **200** : VHost valide et accessible
- **403** : Existe mais accès interdit
- **404** : Non trouvé
- **400** : Requête malformée

## Tips

- `--append-domain` obligatoire pour VHost fuzzing
- Subdomains dev/staging/test souvent moins sécurisés
- Attention aux wildcard DNS (faux positifs)
- Toujours vérifier version Gobuster pour syntaxe `-d` vs `--domain`

---

Filtering Fuzzing Output

---

# Filtering Fuzzing Output

## Gobuster

### Options de Filtrage (mode `dir` uniquement)
```bash
# Include uniquement certains status codes
gobuster dir -u http://target.com -w wordlist.txt -s 200,301,302

# Exclude certains status codes
gobuster dir -u http://target.com -w wordlist.txt -b 404,403

# Exclude certaines tailles de réponse
gobuster dir -u http://target.com -w wordlist.txt --exclude-length 0,404

# Combinaison
gobuster dir -u http://target.com -w wordlist.txt -s 200,301 --exclude-length 0
```

## FFUF

### Options de Filtrage
```bash
# Match status codes spécifiques
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200

# Filter (exclude) status codes
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404,401,302

# Filter par taille (exclude)
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 0-1023

# Match par taille (include)
ffuf -u http://target.com/FUZZ -w wordlist.txt -ms 3456

# Filter par nombre de mots
ffuf -u http://target.com/FUZZ -w wordlist.txt -fw 219

# Match par nombre de mots
ffuf -u http://target.com/FUZZ -w wordlist.txt -mw 5-10

# Filter par nombre de lignes
ffuf -u http://target.com/FUZZ -w wordlist.txt -fl 10

# Match par nombre de lignes
ffuf -u http://target.com/FUZZ -w wordlist.txt -ml 20

# Match par temps de réponse (TTFB)
ffuf -u http://target.com/FUZZ -w wordlist.txt -mt >500

# Combinaisons
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200 -fw 427 -ms >500
ffuf -u http://target.com/FUZZ.bak -w wordlist.txt -fs 0-10239 -ms 10240-102400
```

**Default matcher** : `200-299,301,302,307,401,403,405,500`

## wenum

### Options de Filtrage
```bash
# Hide status codes
wenum -w wordlist.txt --hc 404,400,500 -u http://target.com/FUZZ

# Show status codes uniquement
wenum -w wordlist.txt --sc 200,301,302 -u http://target.com/FUZZ

# Hide par nombre de lignes
wenum -w wordlist.txt --hl 50 -u http://target.com/FUZZ

# Show par nombre de lignes
wenum -w wordlist.txt --sl 10 -u http://target.com/FUZZ

# Hide par nombre de mots
wenum -w wordlist.txt --hw 100 -u http://target.com/FUZZ

# Show par nombre de mots
wenum -w wordlist.txt --sw 5-10 -u http://target.com/FUZZ

# Hide par taille (bytes)
wenum -w wordlist.txt --hs 10000 -u http://target.com/FUZZ

# Show par taille (bytes)
wenum -w wordlist.txt --ss 3456 -u http://target.com/FUZZ

# Hide par regex
wenum -w wordlist.txt --hr "Internal Server Error" -u http://target.com/FUZZ

# Show par regex
wenum -w wordlist.txt --sr "admin|password" -u http://target.com/FUZZ

# Filtres généraux
wenum -w wordlist.txt --filter "Login" -u http://target.com/FUZZ
wenum -w wordlist.txt --hard-filter "Login" -u http://target.com/FUZZ
```

## Feroxbuster

### Options de Filtrage
```bash
# Exclude URLs/patterns du scan
feroxbuster --url http://target.com -w wordlist.txt --dont-scan /uploads

# Filter par taille
feroxbuster --url http://target.com -w wordlist.txt -S 1024

# Filter par regex (body/headers)
feroxbuster --url http://target.com -w wordlist.txt -X "Access Denied"

# Filter par nombre de mots
feroxbuster --url http://target.com -w wordlist.txt -W 0-10

# Filter par nombre de lignes
feroxbuster --url http://target.com -w wordlist.txt -N 50-

# Filter status codes (denylist)
feroxbuster --url http://target.com -w wordlist.txt -C 404,500

# Filter réponses similaires
feroxbuster --url http://target.com -w wordlist.txt --filter-similar-to error.html

# Status codes allowlist
feroxbuster --url http://target.com -w wordlist.txt -s 200,204,301,302

# Combinaison
feroxbuster --url http://target.com -w wordlist.txt -s 200 -S 10240 -X "error"
```

## Quick Reference

| Tool | Match Code | Filter Code | Filter Size | Match Size |
|------|------------|-------------|-------------|------------|
| **ffuf** | `-mc` | `-fc` | `-fs` | `-ms` |
| **wenum** | `--sc` | `--hc` | `--hs` | `--ss` |
| **feroxbuster** | `-s` | `-C` | `-S` | N/A |
| **gobuster** | `-s` | `-b` | `--exclude-length` | N/A |

## Tips

- **Toujours filtrer les 404** : Réduire le bruit massivement
- **Analyser la baseline** : Identifier tailles/patterns répétitifs à filtrer
- **Combiner les filtres** : Status + size + words pour précision maximale
- **TTFB (Time to First Byte)** : Identifier comportements anormaux avec `-mt`
- **Regex filtering** : Puissant pour patterns complexes (wenum, feroxbuster)

---

# Validating Findings

## Pourquoi Valider ?

- **Confirmer** : Distinguer vulnérabilités réelles des faux positifs
- **Évaluer l'impact** : Comprendre la sévérité
- **Reproduire** : Répliquer de manière consistante
- **Prouver** : Collecter des preuves (PoC)

## Validation Manuelle avec curl

### Vérifier un Directory Listing
```bash
# Vérifier si un répertoire est browsable
curl http://target.com/backup/

# Vérifier les headers uniquement (sans télécharger le contenu)
curl -I http://target.com/backup/file.txt
```

### Analyser les Headers
```bash
# Exemple de headers à analyser
curl -I http://target.com/backup/password.txt

# Headers importants :
# Content-Type : Type de fichier (text/plain, application/sql, etc.)
# Content-Length : Taille (>0 = contenu présent, 0 = vide)
# Last-Modified : Date de modification
```

**Exemple de réponse** :
```http
HTTP/1.1 200 OK
Content-Type: text/plain;charset=utf-8
Content-Length: 171
```

- `Content-Length: 171` → Fichier non vide (suspect si fichier sensible)
- `Content-Length: 0` → Fichier vide (moins critique)

## Workflow de Validation
```bash
# 1. Reproduire la requête du fuzzer
curl http://target.com/discovered_path

# 2. Analyser les headers (sans télécharger)
curl -I http://target.com/discovered_file

# 3. Si nécessaire, télécharger pour analyse
curl http://target.com/file -o file_local

# 4. Vérifier le contenu de manière responsable
head -n 10 file_local  # Lire uniquement les premières lignes
```

## Fichiers Sensibles Communs

| Type | Extensions | Risque |
|------|-----------|--------|
| **Database dumps** | `.sql`, `.db` | Credentials, données sensibles |
| **Configuration** | `.config`, `.env`, `.ini` | API keys, secrets |
| **Backups** | `.bak`, `.old`, `.backup` | Code source, configs |
| **Source code** | `.php`, `.jsp`, `.asp` | Vulnérabilités, logique métier |

## Proof of Concept (PoC) Responsable

### Principes

- **Ne pas nuire** : Éviter d'endommager le système
- **Ne pas exfiltrer** : Ne pas télécharger de données sensibles
- **Prouver l'existence** : Démontrer sans exploiter

### Exemples
```bash
# SQLi : Obtenir la version (inoffensif)
# Au lieu de : ' OR 1=1--
# Utiliser : ' AND @@version--

# Directory Listing : Vérifier headers uniquement
curl -I http://target.com/backup/

# File Access : Lire uniquement les premiers octets
curl http://target.com/file -r 0-100
```

## Tips

- **Headers first** : Toujours vérifier headers avant de télécharger
- **Content-Length = 0** : Fichier vide, moins critique
- **Content-Type** : Identifier le type exact de fichier
- **Responsabilité** : Ne jamais accéder à des données sensibles réelles
- **Documentation** : Capturer screenshots/outputs pour le rapport
